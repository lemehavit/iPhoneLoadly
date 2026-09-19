use std::{
    fmt::Display,
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use idevice::{
    RemoteXpcClient,
    provider::RsdProvider,
    remote_pairing::{
        PAIRABLE_HOST_SERVICE_TYPE, PairableHost, PairableHostInfo, PeerDevice,
        RemotePairingClient, RpPairingFile, RpPairingSocket, RpPairingSocketProvider,
        connect_tls_psk_tunnel_native, errors::RemotePairingError,
    },
    services::{core_device::AppServiceClient, rsd::RsdHandshake},
    tcp::{adapter::Adapter, stream::AdapterStream},
};
use mdns_sd::{DaemonEvent, IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Mutex,
    task::AbortHandle,
    time::timeout,
};
use uuid::Uuid;
const DEFAULT_PAIRING_PORT: u16 = 52_345;

const SESSION_LIFETIME: Duration = Duration::from_secs(5 * 60);
const SERVICE_NAME: &str = "iPhoneLoadly";
const SERVICE_MODEL: &str = "Mac17,7";
const STATE_FILE: &str = "pairing-state.json";
const KEY_FILE: &str = "pairing-state.key";
// mdns-sd 0.20.3 defaults to 15; this API permits up to 30 and the
// PairableHost service label is 27 bytes after its leading underscore.
const MDNS_SERVICE_NAME_LIMIT: u8 = 30;
const MDNS_ANNOUNCE_TIMEOUT: Duration = Duration::from_secs(5);
const REMOTE_PAIRING_SERVICE_TYPE: &str = "_remotepairing._tcp.local.";
const REMOTE_DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const REMOTE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const POST_PAIR_BOOTSTRAP_STAGE: &str = "post_pair_bootstrap";
const POST_PAIR_TUNNEL_STAGE: &str = "post_pair_tunnel";
const POST_PAIR_RSD_STAGE: &str = "post_pair_rsd";
const POST_PAIR_TUNNEL_SERVICE_STAGE: &str = "post_pair_tunnel_service";
const POST_PAIR_COMMIT_STAGE: &str = "post_pair_commit";
const TUNNEL_SERVICE_NAME: &str = "com.apple.internal.dt.coredevice.untrusted.tunnelservice";
const CORE_DEVICE_APP_SERVICE_NAME: &str = "com.apple.coredevice.appservice";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsdProbeStage {
    Discovery,
    ValidatePairing,
    Tunnel,
    RsdHandshake,
    CoreDeviceService,
}

impl RsdProbeStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::ValidatePairing => "validatePairing",
            Self::Tunnel => "tunnel",
            Self::RsdHandshake => "rsdHandshake",
            Self::CoreDeviceService => "coreDeviceService",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsdProbeFailure {
    pub stage: RsdProbeStage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoreDeviceServiceOperation {
    ServiceLookup,
    ServiceConnect,
    ClientInit,
    ListApps,
}

impl CoreDeviceServiceOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceLookup => "service_lookup",
            Self::ServiceConnect => "service_connect",
            Self::ClientInit => "client_init",
            Self::ListApps => "list_apps",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CoreDeviceServiceFailure {
    operation: CoreDeviceServiceOperation,
    result: &'static str,
    error_kind: &'static str,
    appservice_present: bool,
}

impl CoreDeviceServiceFailure {
    const fn missing_service() -> Self {
        Self {
            operation: CoreDeviceServiceOperation::ServiceLookup,
            result: "missing",
            error_kind: "service_not_found",
            appservice_present: false,
        }
    }

    const fn timeout(operation: CoreDeviceServiceOperation, appservice_present: bool) -> Self {
        Self {
            operation,
            result: "timeout",
            error_kind: "timeout",
            appservice_present,
        }
    }

    fn from_error(
        operation: CoreDeviceServiceOperation,
        appservice_present: bool,
        error: &idevice::IdeviceError,
    ) -> Self {
        Self {
            operation,
            result: "error",
            error_kind: core_device_error_kind(error),
            appservice_present,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WirelessPairingMode {
    Off,
    Experimental,
    On,
}

impl WirelessPairingMode {
    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::Off)
    }

    fn parse(value: Option<&str>) -> Self {
        match value.map(str::trim) {
            Some("experimental") => Self::Experimental,
            Some("on") => Self::On,
            _ => Self::Off,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WirelessPairingConfig {
    pub mode: WirelessPairingMode,
    pub pairing_port: u16,
    pub interface: Option<String>,
    pub state_dir: PathBuf,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("wireless pairing port must be between 1024 and 65535")]
    InvalidPort,
    #[error("wireless pairing port is not a valid number")]
    InvalidPortNumber,
}

impl WirelessPairingConfig {
    pub fn from_env(default_state_dir: PathBuf) -> Result<Self, ConfigError> {
        let pairing_port = match std::env::var("IPHONELOADLY_PAIRING_PORT") {
            Ok(value) => value
                .parse::<u16>()
                .map_err(|_| ConfigError::InvalidPortNumber)?,
            Err(_) => DEFAULT_PAIRING_PORT,
        };
        validate_pairing_port(pairing_port)?;
        let interface = std::env::var("IPHONELOADLY_PAIRING_INTERFACE")
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty());
        let state_dir = std::env::var("IPHONELOADLY_WIRELESS_STATE_DIR")
            .ok()
            .map(PathBuf::from)
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(default_state_dir);
        Ok(Self {
            mode: WirelessPairingMode::parse(
                std::env::var("IPHONELOADLY_WIRELESS_PAIRING")
                    .ok()
                    .as_deref(),
            ),
            pairing_port,
            interface,
            state_dir,
        })
    }

    pub fn disabled(state_dir: PathBuf) -> Self {
        Self {
            mode: WirelessPairingMode::Off,
            pairing_port: DEFAULT_PAIRING_PORT,
            interface: None,
            state_dir,
        }
    }
}

fn validate_pairing_port(port: u16) -> Result<(), ConfigError> {
    if (1024..=u16::MAX).contains(&port) {
        Ok(())
    } else {
        Err(ConfigError::InvalidPort)
    }
}

#[derive(Debug, Error)]
pub enum PairingError {
    #[error("wireless pairing is disabled")]
    Disabled,
    #[error("another wireless pairing session is active")]
    Busy,
    #[error("pairing session was not found")]
    NotFound,
    #[error("pairing session is already terminal")]
    Terminal,
    #[error("pairing configuration is invalid")]
    Configuration,
    #[error("wireless pairing state is unavailable")]
    Storage,
    #[error("wireless pairing state is corrupted")]
    CorruptedState,
    #[error("pairing listener could not be started")]
    Listener,
    #[error("pairable-host advertisement could not be started")]
    Advertisement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PairingPhase {
    AwaitingDevice,
    AwaitingCodeEntry,
    VerifyingTransport,
    Ready,
    Failed,
    Cancelled,
    Expired,
}

impl PairingPhase {
    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Ready | Self::Failed | Self::Cancelled | Self::Expired
        )
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingSessionStatus {
    pub id: Uuid,
    pub phase: PairingPhase,
    #[serde(serialize_with = "serialize_expiry")]
    pub expires_at: u64,
    pub public_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_code: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Lockdown,
    RsdCoreDevice,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportVerificationResult {
    Verified(TransportKind),
    Rejected,
}

#[derive(Clone)]
pub struct WirelessPairingService {
    config: WirelessPairingConfig,
    store: Arc<PairingStore>,
    session: Arc<Mutex<Option<SessionRuntime>>>,
    start_lock: Arc<Mutex<()>>,
}

struct SessionRuntime {
    status: PairingSessionStatus,
    cancel: AbortHandle,
    resources: Arc<Mutex<Option<MdnsAdvertisement>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PairingFailure {
    stage: &'static str,
}

impl PairingFailure {
    fn from_display(stage: &'static str, _error: impl Display) -> Self {
        Self { stage }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PostPairCommitFailure {
    stage: &'static str,
    error_kind: &'static str,
}

impl PostPairCommitFailure {
    const fn new(stage: &'static str, error_kind: &'static str) -> Self {
        Self { stage, error_kind }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EstablishedPairingVerificationStage {
    AttemptPairVerify,
    ValidatePairing,
}

impl EstablishedPairingVerificationStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::AttemptPairVerify => "attempt_pair_verify",
            Self::ValidatePairing => "validate_pairing",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EstablishedPairingVerificationFailure {
    stage: EstablishedPairingVerificationStage,
    result: &'static str,
    error_kind: &'static str,
    remote_pairing_subcode: Option<i32>,
}

impl EstablishedPairingVerificationFailure {
    fn from_error(
        stage: EstablishedPairingVerificationStage,
        error: &idevice::IdeviceError,
    ) -> Self {
        Self {
            stage,
            result: "error",
            error_kind: idevice_error_kind(error),
            remote_pairing_subcode: remote_pairing_subcode(error),
        }
    }

    const fn timeout(stage: EstablishedPairingVerificationStage) -> Self {
        let error_kind = match stage {
            EstablishedPairingVerificationStage::AttemptPairVerify => "attempt_pair_verify_timeout",
            EstablishedPairingVerificationStage::ValidatePairing => "validate_pairing_timeout",
        };
        Self {
            stage,
            result: "timeout",
            error_kind,
            remote_pairing_subcode: None,
        }
    }

    const fn expired(stage: EstablishedPairingVerificationStage) -> Self {
        Self {
            stage,
            result: "timeout",
            error_kind: "session_expired",
            remote_pairing_subcode: None,
        }
    }
}

#[derive(Clone, Copy)]
enum EstablishedPairingVerificationTiming {
    Deadline(Instant),
    PerStep(Duration),
}

impl EstablishedPairingVerificationTiming {
    fn timeout_for(
        self,
        stage: EstablishedPairingVerificationStage,
    ) -> Result<Duration, EstablishedPairingVerificationFailure> {
        match self {
            Self::Deadline(deadline) => {
                let remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .min(REMOTE_CONNECT_TIMEOUT);
                if remaining.is_zero() {
                    Err(EstablishedPairingVerificationFailure::expired(stage))
                } else {
                    Ok(remaining)
                }
            }
            Self::PerStep(duration) => Ok(duration),
        }
    }
}

async fn verify_established_pairing<R: RpPairingSocketProvider>(
    client: &mut RemotePairingClient<R>,
    pairing_file: &RpPairingFile,
    timing: EstablishedPairingVerificationTiming,
) -> Result<(), EstablishedPairingVerificationFailure> {
    let attempt_stage = EstablishedPairingVerificationStage::AttemptPairVerify;
    let attempt_timeout = timing.timeout_for(attempt_stage)?;
    match timeout(attempt_timeout, client.attempt_pair_verify()).await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            return Err(EstablishedPairingVerificationFailure::from_error(
                attempt_stage,
                &error,
            ));
        }
        Err(_) => {
            return Err(EstablishedPairingVerificationFailure::timeout(
                attempt_stage,
            ));
        }
    }

    let validation_stage = EstablishedPairingVerificationStage::ValidatePairing;
    let validation_timeout = timing.timeout_for(validation_stage)?;
    let mut verification_file = pairing_file.clone();
    match timeout(
        validation_timeout,
        client.validate_pairing(&mut verification_file),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(EstablishedPairingVerificationFailure::from_error(
            validation_stage,
            &error,
        )),
        Err(_) => Err(EstablishedPairingVerificationFailure::timeout(
            validation_stage,
        )),
    }
}

impl WirelessPairingService {
    pub fn new(config: WirelessPairingConfig) -> Self {
        Self {
            store: Arc::new(PairingStore::new(config.state_dir.clone())),
            config,
            session: Arc::new(Mutex::new(None)),
            start_lock: Arc::new(Mutex::new(())),
        }
    }

    pub async fn start_wireless(&self) -> Result<PairingSessionStatus, PairingError> {
        if !self.config.mode.is_enabled() {
            return Err(PairingError::Disabled);
        }

        let _start_lock = self.start_lock.lock().await;
        {
            let mut current = self.session.lock().await;
            if let Some(runtime) = current.as_mut()
                && !runtime.status.phase.is_terminal()
            {
                if session_expired(&runtime.status, SystemTime::now()) {
                    runtime.status.phase = PairingPhase::Expired;
                    runtime.status.setup_code = None;
                    runtime.status.public_message = "The wireless pairing session expired.".into();
                    runtime.cancel.abort();
                    runtime.resources.lock().await.take();
                } else {
                    return Err(PairingError::Busy);
                }
            }
        }

        let material = self.store.load_or_create(SERVICE_NAME)?;
        let addresses = pairing_addresses(self.config.interface.as_deref())?;
        let listeners = bind_listeners(&addresses, self.config.pairing_port)?;
        let advertisement = advertise(
            &addresses,
            self.config.pairing_port,
            &material.host_info,
            &material.pairing_file,
            self.config.interface.as_deref(),
        )
        .await?;
        let id = Uuid::now_v7();
        let status = PairingSessionStatus {
            id,
            phase: PairingPhase::AwaitingDevice,
            expires_at: unix_seconds(SystemTime::now() + SESSION_LIFETIME),
            public_message: "Open pairing on the iPhone or iPad.".into(),
            setup_code: None,
        };
        let resources = Arc::new(Mutex::new(Some(advertisement)));
        let service = self.clone();
        let task_resources = resources.clone();
        let task = tokio::spawn(async move {
            service
                .run_pairing(listeners, id, material, task_resources)
                .await;
        });
        let runtime = SessionRuntime {
            status: status.clone(),
            cancel: task.abort_handle(),
            resources,
        };
        *self.session.lock().await = Some(runtime);
        Ok(status)
    }

    pub async fn status(&self, id: Uuid) -> Result<PairingSessionStatus, PairingError> {
        let mut current = self.session.lock().await;
        let runtime = current.as_mut().ok_or(PairingError::NotFound)?;
        if runtime.status.id != id {
            return Err(PairingError::NotFound);
        }
        if !runtime.status.phase.is_terminal()
            && session_expired(&runtime.status, SystemTime::now())
        {
            runtime.status.phase = PairingPhase::Expired;
            runtime.status.setup_code = None;
            runtime.status.public_message = "The wireless pairing session expired.".into();
            runtime.cancel.abort();
            runtime.resources.lock().await.take();
        }
        Ok(runtime.status.clone())
    }

    pub async fn cancel(&self, id: Uuid) -> Result<(), PairingError> {
        let mut current = self.session.lock().await;
        let runtime = current.as_mut().ok_or(PairingError::NotFound)?;
        if runtime.status.id != id {
            return Err(PairingError::NotFound);
        }
        if runtime.status.phase.is_terminal() {
            return Err(PairingError::Terminal);
        }
        runtime.cancel.abort();
        runtime.resources.lock().await.take();
        runtime.status.phase = PairingPhase::Cancelled;
        runtime.status.setup_code = None;
        runtime.status.public_message = "The wireless pairing session was cancelled.".into();
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn record_transport_result(
        &self,
        id: Uuid,
        result: TransportVerificationResult,
    ) -> Result<PairingSessionStatus, PairingError> {
        let mut current = self.session.lock().await;
        let runtime = current.as_mut().ok_or(PairingError::NotFound)?;
        if runtime.status.id != id {
            return Err(PairingError::NotFound);
        }
        if runtime.status.phase != PairingPhase::VerifyingTransport {
            return Err(PairingError::Terminal);
        }
        runtime.status.setup_code = None;
        match result {
            TransportVerificationResult::Verified(TransportKind::Lockdown) => {
                runtime.status.phase = PairingPhase::Ready;
                runtime.status.public_message =
                    "RemotePairing completed and Lockdown transport was verified.".into();
            }
            TransportVerificationResult::Verified(TransportKind::RsdCoreDevice) => {
                runtime.status.phase = PairingPhase::Ready;
                runtime.status.public_message =
                    "RemotePairing completed and RSD/CoreDevice transport was verified.".into();
            }
            TransportVerificationResult::Rejected => {
                runtime.status.phase = PairingPhase::Failed;
                runtime.status.public_message =
                    "RemotePairing completed but trusted transport could not be verified.".into();
            }
        }
        Ok(runtime.status.clone())
    }

    pub async fn probe_remote_pairing_rsd(&self) -> Result<(), RsdProbeFailure> {
        let material = self
            .store
            .load_existing(SERVICE_NAME)
            .map_err(|_| probe_failure(RsdProbeStage::Discovery))?;
        if material.paired_peer_id.is_none() {
            return Err(probe_failure(RsdProbeStage::Discovery));
        }
        let pairing_file = material.pairing_file;
        if pairing_file
            .alt_irk()
            .is_none_or(|alt_irk| alt_irk.len() != 16)
        {
            return Err(probe_failure(RsdProbeStage::Discovery));
        }

        let endpoints = discover_remote_pairing_endpoints(&pairing_file).await?;
        let (address, mut client) =
            connect_and_validate_remote_pairing(&endpoints, &pairing_file).await?;
        let listener_port = timeout(REMOTE_CONNECT_TIMEOUT, client.create_tcp_listener())
            .await
            .map_err(|_| probe_failure(RsdProbeStage::Tunnel))?
            .map_err(|_| probe_failure(RsdProbeStage::Tunnel))?;
        let listener_stream = timeout(
            REMOTE_CONNECT_TIMEOUT,
            TcpStream::connect(SocketAddr::new(address, listener_port)),
        )
        .await
        .map_err(|_| probe_failure(RsdProbeStage::Tunnel))?
        .map_err(|_| probe_failure(RsdProbeStage::Tunnel))?;
        let encryption_key = client.encryption_key().to_owned();
        let tunnel = timeout(
            REMOTE_CONNECT_TIMEOUT,
            connect_tls_psk_tunnel_native(listener_stream, &encryption_key),
        )
        .await
        .map_err(|_| probe_failure(RsdProbeStage::Tunnel))?
        .map_err(|_| probe_failure(RsdProbeStage::Tunnel))?;
        let tunnel_info = tunnel.info.clone();
        if tunnel_info.server_rsd_port == 0 {
            return Err(probe_failure(RsdProbeStage::Tunnel));
        }
        let host_ip = tunnel_info
            .client_address
            .parse::<IpAddr>()
            .map_err(|_| probe_failure(RsdProbeStage::Tunnel))?;
        let peer_ip = tunnel_info
            .server_address
            .parse::<IpAddr>()
            .map_err(|_| probe_failure(RsdProbeStage::Tunnel))?;
        let mut adapter = Adapter::new(Box::new(tunnel.into_inner()), host_ip, peer_ip);
        adapter.set_mss(usize::from(tunnel_info.mtu.saturating_sub(60)));
        let mut provider = adapter.to_async_handle();
        let rsd_stream = timeout(
            REMOTE_CONNECT_TIMEOUT,
            provider.connect(tunnel_info.server_rsd_port),
        )
        .await
        .map_err(|_| probe_failure(RsdProbeStage::RsdHandshake))?
        .map_err(|_| probe_failure(RsdProbeStage::RsdHandshake))?;
        let handshake = timeout(REMOTE_CONNECT_TIMEOUT, RsdHandshake::new(rsd_stream))
            .await
            .map_err(|_| probe_failure(RsdProbeStage::RsdHandshake))?
            .map_err(|_| probe_failure(RsdProbeStage::RsdHandshake))?;
        let app_port =
            core_device_appservice_port(&handshake).map_err(report_core_device_service_failure)?;
        let app_stream = run_core_device_service_operation(
            CoreDeviceServiceOperation::ServiceConnect,
            true,
            REMOTE_CONNECT_TIMEOUT,
            provider.connect_to_service_port(app_port),
        )
        .await
        .map_err(report_core_device_service_failure)?;
        let mut app_service = run_core_device_service_operation(
            CoreDeviceServiceOperation::ClientInit,
            true,
            REMOTE_CONNECT_TIMEOUT,
            AppServiceClient::<idevice::IdeviceSocket>::new(app_stream),
        )
        .await
        .map_err(report_core_device_service_failure)?;
        let _ = run_core_device_service_operation(
            CoreDeviceServiceOperation::ListApps,
            true,
            REMOTE_CONNECT_TIMEOUT,
            app_service.list_apps(false, false, false, false, false),
        )
        .await
        .map_err(report_core_device_service_failure)?;
        let _ = provider.close().await;
        Ok(())
    }

    #[allow(dead_code)]
    fn load_pairing_material(&self) -> Result<StoredPairingMaterial, PairingError> {
        self.store.load_or_create(SERVICE_NAME)
    }

    async fn run_pairing(
        &self,
        mut listeners: Vec<TcpListener>,
        id: Uuid,
        mut material: StoredPairingMaterial,
        resources: Arc<Mutex<Option<MdnsAdvertisement>>>,
    ) {
        let expires_at = match self.status(id).await {
            Ok(status) => status.expires_at,
            Err(_) => return,
        };
        let timeout_duration =
            Duration::from_secs(expires_at.saturating_sub(unix_seconds(SystemTime::now())));
        let accepted = timeout(timeout_duration, async {
            if listeners.len() == 1 {
                listeners[0].accept().await
            } else {
                let (first, second) = listeners.split_at_mut(1);
                tokio::select! {
                    result = first[0].accept() => result,
                    result = second[0].accept() => result,
                }
            }
        })
        .await;
        let (stream, _) = match accepted {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => {
                self.finish(
                    id,
                    PairingPhase::Expired,
                    "The wireless pairing session expired.",
                    Some(PairingFailure::from_display("tcp_accept", error)),
                    resources,
                )
                .await;
                return;
            }
            Err(_) => {
                self.finish(
                    id,
                    PairingPhase::Expired,
                    "The wireless pairing session expired.",
                    None,
                    resources,
                )
                .await;
                return;
            }
        };
        if !self.set_pairing_phase(id).await {
            return;
        }
        let mut host = PairableHost::new(
            RpPairingSocket::new_device(stream),
            material.host_info.clone(),
        );
        let handshake_timeout =
            Duration::from_secs(expires_at.saturating_sub(unix_seconds(SystemTime::now())));
        let service = self.clone();
        let result = timeout(
            handshake_timeout,
            host.accept(&mut material.pairing_file, move |setup_code| {
                let service = service.clone();
                async move {
                    service.set_setup_code(id, setup_code).await;
                }
            }),
        )
        .await;
        let peer = match result {
            Ok(Ok(peer)) => peer,
            Ok(Err(error)) => {
                self.finish(
                    id,
                    PairingPhase::Failed,
                    "The iPhone or iPad rejected wireless pairing.",
                    Some(PairingFailure::from_display("rppairing_accept", error)),
                    resources,
                )
                .await;
                return;
            }
            Err(_) => {
                self.finish(
                    id,
                    PairingPhase::Expired,
                    "The wireless pairing session expired.",
                    None,
                    resources,
                )
                .await;
                return;
            }
        };
        drop(host);
        let commitment_deadline = Instant::now()
            + Duration::from_secs(expires_at.saturating_sub(unix_seconds(SystemTime::now())));
        let commitment =
            commit_remote_pairing(&mut material.pairing_file, commitment_deadline).await;
        self.finalize_new_pairing(
            id,
            material,
            peer,
            resources,
            commitment_deadline,
            commitment,
        )
        .await;
    }

    async fn finalize_new_pairing(
        &self,
        id: Uuid,
        mut material: StoredPairingMaterial,
        peer: PeerDevice,
        resources: Arc<Mutex<Option<MdnsAdvertisement>>>,
        commitment_deadline: Instant,
        commitment: Result<(), PostPairCommitFailure>,
    ) {
        if let Err(failure) = commitment {
            tracing::warn!(
                session_id = %id,
                stage = failure.stage,
                result = "error",
                error_kind = failure.error_kind,
                "remote pairing post-pair commitment failed"
            );
            self.finish_if_active(
                id,
                PairingPhase::Failed,
                "Wireless pairing could not be completed.",
                None,
                resources,
            )
            .await;
            return;
        }

        let mut expired = false;
        let mut save_failure = None;
        let should_cleanup = {
            let mut current = self.session.lock().await;
            let Some(runtime) = current.as_mut() else {
                return;
            };
            if runtime.status.id != id || runtime.status.phase.is_terminal() {
                return;
            }
            if commitment_deadline
                .saturating_duration_since(Instant::now())
                .is_zero()
            {
                runtime.status.phase = PairingPhase::Failed;
                runtime.status.public_message = "Wireless pairing could not be completed.".into();
                runtime.status.setup_code = None;
                expired = true;
            } else {
                material.paired_peer_id = Some(fingerprint_peer(&peer.remotepairing_udid));
                match self.store.save(&material) {
                    Ok(()) => {
                        runtime.status.phase = PairingPhase::VerifyingTransport;
                        runtime.status.public_message =
                            "RemotePairing completed. Verifying trusted device transport.".into();
                        runtime.status.setup_code = None;
                    }
                    Err(error) => {
                        save_failure =
                            Some(PairingFailure::from_display("pairing_state_save", error));
                        runtime.status.phase = PairingPhase::Failed;
                        runtime.status.public_message =
                            "Wireless pairing completed but its state could not be saved.".into();
                        runtime.status.setup_code = None;
                    }
                }
            }
            true
        };
        if should_cleanup {
            resources.lock().await.take();
        }
        if expired {
            tracing::warn!(
                session_id = %id,
                stage = POST_PAIR_COMMIT_STAGE,
                result = "timeout",
                error_kind = "session_expired",
                "remote pairing post-pair commitment exceeded the pairing session"
            );
        }
        if let Some(failure) = save_failure {
            tracing::warn!(
                session_id = %id,
                stage = failure.stage,
                result = "error",
                "wireless pairing failed"
            );
        }
    }

    async fn finish_if_active(
        &self,
        id: Uuid,
        phase: PairingPhase,
        public_message: &str,
        failure: Option<PairingFailure>,
        resources: Arc<Mutex<Option<MdnsAdvertisement>>>,
    ) {
        if let Some(failure) = failure.as_ref() {
            tracing::warn!(
                session_id = %id,
                stage = failure.stage,
                result = "error",
                "wireless pairing failed"
            );
        }
        let should_cleanup = {
            let mut current = self.session.lock().await;
            let Some(runtime) = current.as_mut() else {
                return;
            };
            if runtime.status.id != id || runtime.status.phase.is_terminal() {
                return;
            }
            runtime.status.phase = phase;
            runtime.status.public_message = public_message.into();
            runtime.status.setup_code = None;
            true
        };
        if should_cleanup {
            resources.lock().await.take();
        }
    }

    async fn set_pairing_phase(&self, id: Uuid) -> bool {
        self.set_phase(
            id,
            PairingPhase::AwaitingCodeEntry,
            "The iPhone or iPad is completing wireless pairing.",
            None,
        )
        .await
        .is_ok()
    }

    async fn set_setup_code(&self, id: Uuid, setup_code: String) {
        let mut current = self.session.lock().await;
        if let Some(runtime) = current.as_mut().filter(|runtime| runtime.status.id == id) {
            runtime.status.public_message =
                "Enter the one-time pairing code shown for this session on the iPhone or iPad."
                    .into();
            runtime.status.setup_code = Some(setup_code);
        }
    }

    async fn set_phase(
        &self,
        id: Uuid,
        phase: PairingPhase,
        public_message: &str,
        setup_code: Option<String>,
    ) -> Result<(), PairingError> {
        let mut current = self.session.lock().await;
        let runtime = current.as_mut().ok_or(PairingError::NotFound)?;
        if runtime.status.id != id {
            return Err(PairingError::NotFound);
        }
        runtime.status.phase = phase;
        runtime.status.public_message = public_message.into();
        runtime.status.setup_code = setup_code;
        Ok(())
    }

    async fn finish(
        &self,
        id: Uuid,
        phase: PairingPhase,
        public_message: &str,
        failure: Option<PairingFailure>,
        resources: Arc<Mutex<Option<MdnsAdvertisement>>>,
    ) {
        if let Some(failure) = failure {
            tracing::warn!(
                session_id = %id,
                stage = failure.stage,
                result = "error",
                "wireless pairing failed"
            );
        }
        resources.lock().await.take();
        let _ = self.set_phase(id, phase, public_message, None).await;
    }
}

fn probe_failure(stage: RsdProbeStage) -> RsdProbeFailure {
    tracing::debug!(stage = stage.as_str(), "remote pairing RSD probe failed");
    RsdProbeFailure { stage }
}

fn core_device_appservice_port(handshake: &RsdHandshake) -> Result<u16, CoreDeviceServiceFailure> {
    handshake
        .services
        .get(CORE_DEVICE_APP_SERVICE_NAME)
        .map(|service| service.port)
        .ok_or_else(CoreDeviceServiceFailure::missing_service)
}

async fn run_core_device_service_operation<T>(
    operation: CoreDeviceServiceOperation,
    appservice_present: bool,
    timeout_duration: Duration,
    future: impl Future<Output = Result<T, idevice::IdeviceError>>,
) -> Result<T, CoreDeviceServiceFailure> {
    match timeout(timeout_duration, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(CoreDeviceServiceFailure::from_error(
            operation,
            appservice_present,
            &error,
        )),
        Err(_) => Err(CoreDeviceServiceFailure::timeout(
            operation,
            appservice_present,
        )),
    }
}

fn report_core_device_service_failure(failure: CoreDeviceServiceFailure) -> RsdProbeFailure {
    tracing::warn!(
        stage = RsdProbeStage::CoreDeviceService.as_str(),
        operation = failure.operation.as_str(),
        result = failure.result,
        error_kind = failure.error_kind,
        appservice_present = failure.appservice_present,
        "remote pairing CoreDevice service probe failed"
    );
    RsdProbeFailure {
        stage: RsdProbeStage::CoreDeviceService,
    }
}

#[cfg(test)]
fn post_pair_commit_failure(error_kind: &'static str) -> PostPairCommitFailure {
    PostPairCommitFailure::new(POST_PAIR_COMMIT_STAGE, error_kind)
}

fn post_pair_stage_failure(stage: &'static str, error_kind: &'static str) -> PostPairCommitFailure {
    PostPairCommitFailure::new(stage, error_kind)
}

async fn commit_remote_pairing(
    pairing_file: &mut RpPairingFile,
    deadline: Instant,
) -> Result<(), PostPairCommitFailure> {
    let discovery_deadline = std::cmp::min(deadline, Instant::now() + REMOTE_DISCOVERY_TIMEOUT);
    let endpoints =
        match discover_remote_pairing_endpoints_until(pairing_file, discovery_deadline).await {
            Ok(endpoints) => endpoints,
            Err(_) if deadline.saturating_duration_since(Instant::now()).is_zero() => {
                tracing::warn!(
                    stage = POST_PAIR_BOOTSTRAP_STAGE,
                    result = "timeout",
                    error_kind = "discovery_timeout",
                    "remote pairing commitment discovery timed out"
                );
                return Err(post_pair_stage_failure(
                    POST_PAIR_BOOTSTRAP_STAGE,
                    "discovery_timeout",
                ));
            }
            Err(_) => {
                tracing::warn!(
                    stage = POST_PAIR_BOOTSTRAP_STAGE,
                    result = "error",
                    error_kind = "discovery",
                    "remote pairing commitment discovery failed"
                );
                return Err(post_pair_stage_failure(
                    POST_PAIR_BOOTSTRAP_STAGE,
                    "discovery",
                ));
            }
        };
    commit_remote_pairing_endpoints(&endpoints, pairing_file, deadline).await
}

async fn commit_remote_pairing_endpoints(
    endpoints: &[RemotePairingEndpoint],
    pairing_file: &mut RpPairingFile,
    deadline: Instant,
) -> Result<(), PostPairCommitFailure> {
    let mut last_failure = post_pair_stage_failure(POST_PAIR_BOOTSTRAP_STAGE, "no_candidate");
    for (candidate_index, endpoint) in endpoints.iter().enumerate() {
        for (address_index, address) in endpoint.addresses.iter().enumerate() {
            let address_family = address_family(*address);
            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .min(REMOTE_CONNECT_TIMEOUT);
            if remaining.is_zero() {
                return Err(post_pair_stage_failure(
                    POST_PAIR_BOOTSTRAP_STAGE,
                    "session_expired",
                ));
            }
            let stream = match timeout(
                remaining,
                TcpStream::connect(SocketAddr::new(*address, endpoint.port)),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    last_failure =
                        post_pair_stage_failure(POST_PAIR_BOOTSTRAP_STAGE, io_error_kind(&error));
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = POST_PAIR_BOOTSTRAP_STAGE,
                        result = "tcp_connect_error",
                        error_kind = io_error_kind(&error),
                        "remote pairing bootstrap TCP connection failed"
                    );
                    continue;
                }
                Err(_) => {
                    last_failure =
                        post_pair_stage_failure(POST_PAIR_BOOTSTRAP_STAGE, "tcp_connect_timeout");
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = POST_PAIR_BOOTSTRAP_STAGE,
                        result = "tcp_connect_timeout",
                        "remote pairing bootstrap TCP connection timed out"
                    );
                    continue;
                }
            };

            let mut client = RemotePairingClient::new(RpPairingSocket::new(stream), SERVICE_NAME);
            if let Err(failure) = verify_established_pairing(
                &mut client,
                pairing_file,
                EstablishedPairingVerificationTiming::Deadline(deadline),
            )
            .await
            {
                last_failure =
                    post_pair_stage_failure(POST_PAIR_BOOTSTRAP_STAGE, failure.error_kind);
                if failure.error_kind == "session_expired" {
                    return Err(last_failure);
                }
                tracing::warn!(
                    candidate_index,
                    address_index,
                    address_family,
                    stage = POST_PAIR_BOOTSTRAP_STAGE,
                    operation = failure.stage.as_str(),
                    result = failure.result,
                    error_kind = failure.error_kind,
                    remote_pairing_subcode = ?failure.remote_pairing_subcode,
                    "remote pairing bootstrap verification failed"
                );
                continue;
            }
            tracing::info!(
                candidate_index,
                address_index,
                address_family,
                stage = POST_PAIR_BOOTSTRAP_STAGE,
                result = "success",
                "remote pairing bootstrap verification succeeded"
            );

            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .min(REMOTE_CONNECT_TIMEOUT);
            if remaining.is_zero() {
                return Err(post_pair_stage_failure(
                    POST_PAIR_TUNNEL_STAGE,
                    "session_expired",
                ));
            }
            let listener_port = match timeout(remaining, client.create_tcp_listener()).await {
                Ok(Ok(port)) => port,
                Ok(Err(error)) => {
                    last_failure =
                        post_pair_stage_failure(POST_PAIR_TUNNEL_STAGE, idevice_error_kind(&error));
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = POST_PAIR_TUNNEL_STAGE,
                        result = "error",
                        operation = "create_tcp_listener",
                        error_kind = idevice_error_kind(&error),
                        "remote pairing tunnel listener creation failed"
                    );
                    continue;
                }
                Err(_) => {
                    last_failure = post_pair_stage_failure(
                        POST_PAIR_TUNNEL_STAGE,
                        "create_tcp_listener_timeout",
                    );
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = POST_PAIR_TUNNEL_STAGE,
                        result = "timeout",
                        operation = "create_tcp_listener",
                        "remote pairing tunnel listener creation timed out"
                    );
                    continue;
                }
            };
            let encryption_key = client.encryption_key().to_owned();
            drop(client);

            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .min(REMOTE_CONNECT_TIMEOUT);
            if remaining.is_zero() {
                return Err(post_pair_stage_failure(
                    POST_PAIR_TUNNEL_STAGE,
                    "session_expired",
                ));
            }
            let listener_stream = match timeout(
                remaining,
                TcpStream::connect(SocketAddr::new(*address, listener_port)),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    last_failure =
                        post_pair_stage_failure(POST_PAIR_TUNNEL_STAGE, io_error_kind(&error));
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = POST_PAIR_TUNNEL_STAGE,
                        result = "tcp_connect_error",
                        operation = "tunnel_listener",
                        error_kind = io_error_kind(&error),
                        "remote pairing tunnel listener connection failed"
                    );
                    continue;
                }
                Err(_) => {
                    last_failure = post_pair_stage_failure(
                        POST_PAIR_TUNNEL_STAGE,
                        "tunnel_listener_connect_timeout",
                    );
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = POST_PAIR_TUNNEL_STAGE,
                        result = "timeout",
                        operation = "tunnel_listener",
                        "remote pairing tunnel listener connection timed out"
                    );
                    continue;
                }
            };

            let remaining = deadline
                .saturating_duration_since(Instant::now())
                .min(REMOTE_CONNECT_TIMEOUT);
            if remaining.is_zero() {
                return Err(post_pair_stage_failure(
                    POST_PAIR_TUNNEL_STAGE,
                    "session_expired",
                ));
            }
            let tunnel = match timeout(
                remaining,
                connect_tls_psk_tunnel_native(listener_stream, &encryption_key),
            )
            .await
            {
                Ok(Ok(tunnel)) => tunnel,
                Ok(Err(error)) => {
                    last_failure =
                        post_pair_stage_failure(POST_PAIR_TUNNEL_STAGE, idevice_error_kind(&error));
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = POST_PAIR_TUNNEL_STAGE,
                        result = "error",
                        operation = "connect_tls_psk_tunnel_native",
                        error_kind = idevice_error_kind(&error),
                        "remote pairing TLS/CDTunnel setup failed"
                    );
                    continue;
                }
                Err(_) => {
                    last_failure =
                        post_pair_stage_failure(POST_PAIR_TUNNEL_STAGE, "tunnel_timeout");
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = POST_PAIR_TUNNEL_STAGE,
                        result = "timeout",
                        operation = "connect_tls_psk_tunnel_native",
                        "remote pairing TLS/CDTunnel setup timed out"
                    );
                    continue;
                }
            };
            let tunnel_info = tunnel.info.clone();
            if tunnel_info.server_rsd_port == 0 {
                last_failure = post_pair_stage_failure(POST_PAIR_TUNNEL_STAGE, "missing_rsd_port");
                tracing::warn!(
                    candidate_index,
                    address_index,
                    address_family,
                    stage = POST_PAIR_TUNNEL_STAGE,
                    result = "error",
                    operation = "tunnel_info",
                    error_kind = "missing_rsd_port",
                    "remote pairing tunnel did not advertise an RSD port"
                );
                continue;
            }
            let host_ip = match tunnel_info.client_address.parse::<IpAddr>() {
                Ok(address) => address,
                Err(_) => {
                    last_failure =
                        post_pair_stage_failure(POST_PAIR_TUNNEL_STAGE, "invalid_host_address");
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = POST_PAIR_TUNNEL_STAGE,
                        result = "error",
                        operation = "tunnel_info",
                        error_kind = "invalid_host_address",
                        "remote pairing tunnel advertised an invalid host address"
                    );
                    continue;
                }
            };
            let peer_ip = match tunnel_info.server_address.parse::<IpAddr>() {
                Ok(address) => address,
                Err(_) => {
                    last_failure =
                        post_pair_stage_failure(POST_PAIR_TUNNEL_STAGE, "invalid_peer_address");
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = POST_PAIR_TUNNEL_STAGE,
                        result = "error",
                        operation = "tunnel_info",
                        error_kind = "invalid_peer_address",
                        "remote pairing tunnel advertised an invalid peer address"
                    );
                    continue;
                }
            };
            let mut adapter = Adapter::new(Box::new(tunnel.into_inner()), host_ip, peer_ip);
            adapter.set_mss(usize::from(tunnel_info.mtu.saturating_sub(60)));
            let commitment = async {
                let remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .min(REMOTE_CONNECT_TIMEOUT);
                if remaining.is_zero() {
                    return Err(post_pair_stage_failure(
                        POST_PAIR_RSD_STAGE,
                        "session_expired",
                    ));
                }
                let rsd_stream = match timeout(
                    remaining,
                    AdapterStream::connect(&mut adapter, tunnel_info.server_rsd_port),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_RSD_STAGE,
                            io_error_kind(&error),
                        ));
                    }
                    Err(_) => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_RSD_STAGE,
                            "rsd_connect_timeout",
                        ));
                    }
                };
                let remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .min(REMOTE_CONNECT_TIMEOUT);
                if remaining.is_zero() {
                    return Err(post_pair_stage_failure(
                        POST_PAIR_RSD_STAGE,
                        "session_expired",
                    ));
                }
                let handshake = match timeout(remaining, RsdHandshake::new(rsd_stream)).await {
                    Ok(Ok(handshake)) => handshake,
                    Ok(Err(error)) => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_RSD_STAGE,
                            idevice_error_kind(&error),
                        ));
                    }
                    Err(_) => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_RSD_STAGE,
                            "rsd_handshake_timeout",
                        ));
                    }
                };
                let tunnel_service_port = match handshake.services.get(TUNNEL_SERVICE_NAME) {
                    Some(service) => service.port,
                    None => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_TUNNEL_SERVICE_STAGE,
                            "service_not_found",
                        ));
                    }
                };
                drop(handshake);
                tracing::info!(
                    candidate_index,
                    address_index,
                    address_family,
                    stage = POST_PAIR_RSD_STAGE,
                    result = "success",
                    "remote pairing RSD handshake succeeded"
                );

                let remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .min(REMOTE_CONNECT_TIMEOUT);
                if remaining.is_zero() {
                    return Err(post_pair_stage_failure(
                        POST_PAIR_TUNNEL_SERVICE_STAGE,
                        "session_expired",
                    ));
                }
                let service_stream = match timeout(
                    remaining,
                    AdapterStream::connect(&mut adapter, tunnel_service_port),
                )
                .await
                {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_TUNNEL_SERVICE_STAGE,
                            io_error_kind(&error),
                        ));
                    }
                    Err(_) => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_TUNNEL_SERVICE_STAGE,
                            "service_connect_timeout",
                        ));
                    }
                };
                let remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .min(REMOTE_CONNECT_TIMEOUT);
                if remaining.is_zero() {
                    return Err(post_pair_stage_failure(
                        POST_PAIR_TUNNEL_SERVICE_STAGE,
                        "session_expired",
                    ));
                }
                let mut xpc = match timeout(remaining, RemoteXpcClient::new(service_stream)).await {
                    Ok(Ok(xpc)) => xpc,
                    Ok(Err(error)) => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_TUNNEL_SERVICE_STAGE,
                            idevice_error_kind(&error),
                        ));
                    }
                    Err(_) => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_TUNNEL_SERVICE_STAGE,
                            "remote_xpc_new_timeout",
                        ));
                    }
                };
                let remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .min(REMOTE_CONNECT_TIMEOUT);
                if remaining.is_zero() {
                    return Err(post_pair_stage_failure(
                        POST_PAIR_TUNNEL_SERVICE_STAGE,
                        "session_expired",
                    ));
                }
                match timeout(remaining, xpc.do_handshake()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_TUNNEL_SERVICE_STAGE,
                            idevice_error_kind(&error),
                        ));
                    }
                    Err(_) => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_TUNNEL_SERVICE_STAGE,
                            "remote_xpc_handshake_timeout",
                        ));
                    }
                }
                let remaining = deadline
                    .saturating_duration_since(Instant::now())
                    .min(REMOTE_CONNECT_TIMEOUT);
                if remaining.is_zero() {
                    return Err(post_pair_stage_failure(
                        POST_PAIR_TUNNEL_SERVICE_STAGE,
                        "session_expired",
                    ));
                }
                match timeout(remaining, xpc.recv_root()).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(error)) => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_TUNNEL_SERVICE_STAGE,
                            idevice_error_kind(&error),
                        ));
                    }
                    Err(_) => {
                        return Err(post_pair_stage_failure(
                            POST_PAIR_TUNNEL_SERVICE_STAGE,
                            "remote_xpc_root_timeout",
                        ));
                    }
                }
                tracing::info!(
                    candidate_index,
                    address_index,
                    address_family,
                    stage = POST_PAIR_TUNNEL_SERVICE_STAGE,
                    result = "success",
                    "remote pairing tunnel service RemoteXpc established"
                );

                let mut follow_up = RemotePairingClient::new(xpc, SERVICE_NAME);
                match verify_established_pairing(
                    &mut follow_up,
                    pairing_file,
                    EstablishedPairingVerificationTiming::Deadline(deadline),
                )
                .await
                {
                    Ok(()) => {
                        tracing::info!(
                            candidate_index,
                            address_index,
                            address_family,
                            stage = POST_PAIR_COMMIT_STAGE,
                            result = "success",
                            "remote pairing tunnel-service commitment succeeded"
                        );
                        Ok(())
                    }
                    Err(failure) => Err(post_pair_stage_failure(
                        POST_PAIR_COMMIT_STAGE,
                        failure.error_kind,
                    )),
                }
            }
            .await;
            match commitment {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last_failure = error;
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = last_failure.stage,
                        result = "error",
                        error_kind = last_failure.error_kind,
                        "remote pairing tunnel-service commitment failed"
                    );
                }
            }
        }
    }
    Err(last_failure)
}

#[derive(Debug, PartialEq, Eq)]
struct RemotePairingEndpoint {
    addresses: Vec<IpAddr>,
    port: u16,
}

fn authenticated_remote_pairing_endpoint(
    alt_irk: &[u8],
    identifier: &str,
    auth_tag: &str,
    mut addresses: Vec<IpAddr>,
    port: u16,
) -> Option<RemotePairingEndpoint> {
    if port == 0
        || addresses.is_empty()
        || !PeerDevice::validate_auth_tag(alt_irk, identifier, auth_tag)
    {
        return None;
    }
    addresses.sort_by_key(|address| (!address.is_ipv4(), address.to_string()));
    Some(RemotePairingEndpoint { addresses, port })
}

async fn discover_remote_pairing_endpoints(
    pairing_file: &RpPairingFile,
) -> Result<Vec<RemotePairingEndpoint>, RsdProbeFailure> {
    discover_remote_pairing_endpoints_until(pairing_file, Instant::now() + REMOTE_DISCOVERY_TIMEOUT)
        .await
}

async fn discover_remote_pairing_endpoints_until(
    pairing_file: &RpPairingFile,
    deadline: Instant,
) -> Result<Vec<RemotePairingEndpoint>, RsdProbeFailure> {
    let alt_irk = pairing_file
        .alt_irk()
        .ok_or_else(|| probe_failure(RsdProbeStage::Discovery))?;
    let daemon = ServiceDaemon::new().map_err(|_| probe_failure(RsdProbeStage::Discovery))?;
    let daemon = MdnsShutdownGuard::new(daemon);
    let receiver = match daemon.daemon.browse(REMOTE_PAIRING_SERVICE_TYPE) {
        Ok(receiver) => receiver,
        Err(_) => return Err(probe_failure(RsdProbeStage::Discovery)),
    };
    let mut endpoints = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let event = match timeout(remaining, receiver.recv_async()).await {
            Ok(Ok(event)) => event,
            Ok(Err(_)) | Err(_) => break,
        };
        if let ServiceEvent::ServiceResolved(info) = event {
            let Some(identifier) = info.get_property_val_str("identifier") else {
                continue;
            };
            let Some(auth_tag) = info.get_property_val_str("authTag") else {
                continue;
            };
            let addresses = info
                .get_addresses()
                .iter()
                .map(|address| address.to_ip_addr())
                .collect::<Vec<_>>();
            if let Some(endpoint) = authenticated_remote_pairing_endpoint(
                alt_irk,
                identifier,
                auth_tag,
                addresses,
                info.get_port(),
            ) && !endpoints.contains(&endpoint)
            {
                endpoints.push(endpoint);
            }
        }
    }
    if endpoints.is_empty() {
        Err(probe_failure(RsdProbeStage::Discovery))
    } else {
        Ok(endpoints)
    }
}

async fn connect_and_validate_remote_pairing(
    endpoints: &[RemotePairingEndpoint],
    pairing_file: &RpPairingFile,
) -> Result<(IpAddr, RemotePairingClient<RpPairingSocket<TcpStream>>), RsdProbeFailure> {
    connect_and_validate_remote_pairing_with_timeout(
        endpoints,
        pairing_file,
        REMOTE_CONNECT_TIMEOUT,
    )
    .await
}

async fn connect_and_validate_remote_pairing_with_timeout(
    endpoints: &[RemotePairingEndpoint],
    pairing_file: &RpPairingFile,
    timeout_duration: Duration,
) -> Result<(IpAddr, RemotePairingClient<RpPairingSocket<TcpStream>>), RsdProbeFailure> {
    for (candidate_index, endpoint) in endpoints.iter().enumerate() {
        for (address_index, address) in endpoint.addresses.iter().enumerate() {
            let address_family = address_family(*address);
            let stream = match timeout(
                timeout_duration,
                TcpStream::connect(SocketAddr::new(*address, endpoint.port)),
            )
            .await
            {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = "tcp_connect",
                        result = "tcp_connect_error",
                        error_kind = io_error_kind(&error),
                        os_error = ?error.raw_os_error(),
                        "remote pairing candidate TCP connection failed"
                    );
                    continue;
                }
                Err(_) => {
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = "tcp_connect",
                        result = "tcp_connect_timeout",
                        "remote pairing candidate TCP connection timed out"
                    );
                    continue;
                }
            };

            let mut client = RemotePairingClient::new(RpPairingSocket::new(stream), SERVICE_NAME);
            match verify_established_pairing(
                &mut client,
                pairing_file,
                EstablishedPairingVerificationTiming::PerStep(timeout_duration),
            )
            .await
            {
                Ok(()) => {
                    tracing::info!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = "validate_pairing",
                        result = "validate_pairing_success",
                        "remote pairing established verification succeeded"
                    );
                    return Ok((*address, client));
                }
                Err(failure) => {
                    tracing::warn!(
                        candidate_index,
                        address_index,
                        address_family,
                        stage = failure.stage.as_str(),
                        result = failure.result,
                        error_kind = failure.error_kind,
                        remote_pairing_subcode = ?failure.remote_pairing_subcode,
                        "remote pairing established verification failed"
                    );
                }
            }
        }
    }
    Err(probe_failure(RsdProbeStage::ValidatePairing))
}

fn address_family(address: IpAddr) -> &'static str {
    if address.is_ipv4() { "ipv4" } else { "ipv6" }
}

fn io_error_kind(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::ConnectionRefused => "connection_refused",
        std::io::ErrorKind::ConnectionReset => "connection_reset",
        std::io::ErrorKind::ConnectionAborted => "connection_aborted",
        std::io::ErrorKind::NotConnected => "not_connected",
        std::io::ErrorKind::AddrNotAvailable => "address_not_available",
        std::io::ErrorKind::TimedOut => "timed_out",
        std::io::ErrorKind::InvalidInput => "invalid_input",
        _ => "other",
    }
}

// UnexpectedResponse and PairingRejected can carry device text or payload-derived data.
// Keep diagnostics to safe variant categories and the library-defined RemotePairing subcode.
fn core_device_error_kind(error: &idevice::IdeviceError) -> &'static str {
    match error {
        idevice::IdeviceError::Socket(error) => io_error_kind(error),
        idevice::IdeviceError::ServiceNotFound => "service_not_found",
        idevice::IdeviceError::Xpc(_) => "xpc",
        idevice::IdeviceError::CoreDevice(_) => "core_device",
        _ => idevice_error_kind(error),
    }
}

fn idevice_error_kind(error: &idevice::IdeviceError) -> &'static str {
    match error {
        idevice::IdeviceError::Socket(_) => "socket",
        idevice::IdeviceError::Timeout => "timeout",
        idevice::IdeviceError::Plist(_) => "plist",
        idevice::IdeviceError::Utf8(_) | idevice::IdeviceError::Utf8Error => "utf8",
        idevice::IdeviceError::NotEnoughBytes(_, _) => "not_enough_bytes",
        idevice::IdeviceError::UnexpectedResponse(_) => "unexpected_response",
        idevice::IdeviceError::InternalError(_) => "internal_error",
        idevice::IdeviceError::SessionInactive => "session_inactive",
        idevice::IdeviceError::NoEstablishedConnection => "no_established_connection",
        idevice::IdeviceError::RemotePairing(error) => remote_pairing_error_kind(error),
        _ => "other",
    }
}

fn remote_pairing_error_kind(error: &RemotePairingError) -> &'static str {
    match error {
        RemotePairingError::UnknownTlv(_) => "remote_pairing_unknown_tlv",
        RemotePairingError::MalformedTlv => "remote_pairing_malformed_tlv",
        RemotePairingError::PairingRejected(_) => "remote_pairing_rejected",
        RemotePairingError::Base64DecodeError(_) => "remote_pairing_base64_decode",
        RemotePairingError::PairVerifyFailed => "remote_pairing_pair_verify_failed",
        RemotePairingError::SrpAuthFailed => "remote_pairing_srp_auth_failed",
        RemotePairingError::ChachaEncryption(_) => "remote_pairing_encryption",
        _ => "remote_pairing_other",
    }
}

fn remote_pairing_subcode(error: &idevice::IdeviceError) -> Option<i32> {
    match error {
        idevice::IdeviceError::RemotePairing(error) => Some(error.sub_code()),
        _ => None,
    }
}

fn session_expired(status: &PairingSessionStatus, now: SystemTime) -> bool {
    unix_seconds(now) >= status.expires_at
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn serialize_expiry<S>(seconds: &u64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let seconds = i64::try_from(*seconds).map_err(serde::ser::Error::custom)?;
    let timestamp =
        OffsetDateTime::from_unix_timestamp(seconds).map_err(serde::ser::Error::custom)?;
    let formatted = timestamp
        .format(&Rfc3339)
        .map_err(serde::ser::Error::custom)?;
    serializer.serialize_str(&formatted)
}

fn bind_listeners(addresses: &[IpAddr], port: u16) -> Result<Vec<TcpListener>, PairingError> {
    addresses
        .iter()
        .copied()
        .map(|ip| {
            let socket = std::net::TcpListener::bind(SocketAddr::new(ip, port))
                .map_err(|_| PairingError::Listener)?;
            socket
                .set_nonblocking(true)
                .map_err(|_| PairingError::Listener)?;
            TcpListener::from_std(socket).map_err(|_| PairingError::Listener)
        })
        .collect()
}

fn pairing_addresses(interface: Option<&str>) -> Result<Vec<IpAddr>, PairingError> {
    let interfaces = if_addrs::get_if_addrs().map_err(|_| PairingError::Configuration)?;
    let mut addresses = interfaces
        .into_iter()
        .filter(|entry| interface.is_none_or(|name| entry.name == name))
        .map(|entry| entry.ip())
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .filter(|ip| interface.is_some() || is_safe_default_address(ip))
        .collect::<Vec<_>>();
    addresses.sort_by_key(|ip| (!ip.is_ipv4(), ip.to_string()));
    addresses.dedup();
    let mut selected = Vec::with_capacity(2);
    for address in addresses {
        if selected
            .iter()
            .any(|chosen: &IpAddr| chosen.is_ipv4() == address.is_ipv4())
        {
            continue;
        }
        selected.push(address);
    }
    if selected.is_empty() {
        return Err(PairingError::Configuration);
    }
    Ok(selected)
}

fn is_safe_default_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_private() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_unicast_link_local(),
    }
}

async fn advertise(
    addresses: &[IpAddr],
    port: u16,
    host_info: &PairableHostInfo,
    pairing_file: &RpPairingFile,
    interface: Option<&str>,
) -> Result<MdnsAdvertisement, PairingError> {
    let properties = host_info.mdns_txt_records(pairing_file.identifier());
    let hostname = local_hostname();
    let mut service = ServiceInfo::new(
        PAIRABLE_HOST_SERVICE_TYPE,
        pairing_file.identifier(),
        &hostname,
        addresses,
        port,
        &properties[..],
    )
    .map_err(|_| PairingError::Advertisement)?;
    if let Some(interface) = interface {
        service.set_interfaces(vec![IfKind::Name(interface.to_owned())]);
    }
    let daemon = ServiceDaemon::new().map_err(|_| PairingError::Advertisement)?;
    daemon
        .set_service_name_len_max(MDNS_SERVICE_NAME_LIMIT)
        .map_err(|_| {
            let _ = daemon.shutdown();
            PairingError::Advertisement
        })?;
    let monitor = daemon.monitor().map_err(|_| {
        let _ = daemon.shutdown();
        PairingError::Advertisement
    })?;
    let fullname = service.get_fullname().to_owned();
    if daemon.register(service).is_err() {
        let _ = daemon.shutdown();
        return Err(PairingError::Advertisement);
    }
    let deadline = Instant::now() + MDNS_ANNOUNCE_TIMEOUT;
    let announced = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break false;
        }
        match timeout(remaining, monitor.recv_async()).await {
            Ok(Ok(DaemonEvent::Announce(name, _))) if name.eq_ignore_ascii_case(&fullname) => {
                break true;
            }
            Ok(Ok(DaemonEvent::Error(_))) | Ok(Err(_)) | Err(_) => break false,
            Ok(Ok(_)) => {}
        }
    };
    if !announced {
        let _ = daemon.shutdown();
        return Err(PairingError::Advertisement);
    }
    Ok(MdnsAdvertisement {
        daemon: Some(daemon),
        fullname,
    })
}

fn local_hostname() -> String {
    let raw = std::env::var("HOSTNAME").unwrap_or_else(|_| SERVICE_NAME.into());
    let sanitized = raw
        .trim()
        .trim_end_matches(".local")
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!(
        "{}.local.",
        if sanitized.is_empty() {
            "iphoneloadly"
        } else {
            &sanitized
        }
    )
}

struct MdnsAdvertisement {
    daemon: Option<ServiceDaemon>,
    fullname: String,
}

impl Drop for MdnsAdvertisement {
    fn drop(&mut self) {
        if let Some(daemon) = self.daemon.take() {
            let _ = daemon.unregister(&self.fullname);
            let _ = daemon.shutdown();
        }
    }
}

struct MdnsShutdownGuard {
    daemon: ServiceDaemon,
}

impl MdnsShutdownGuard {
    fn new(daemon: ServiceDaemon) -> Self {
        Self { daemon }
    }
}

impl Drop for MdnsShutdownGuard {
    fn drop(&mut self) {
        let _ = self.daemon.shutdown();
    }
}

struct PairingStore {
    state_dir: PathBuf,
}
struct StoredPairingMaterial {
    host_info: PairableHostInfo,
    pairing_file: RpPairingFile,
    paired_peer_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct EncryptedState {
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct PairingStatePayload {
    host_alt_irk: Vec<u8>,
    pairing_file: String,
    #[serde(default)]
    paired_peer_id: Option<String>,
}

impl PairingStore {
    fn new(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }

    fn load_or_create(&self, sending_host: &str) -> Result<StoredPairingMaterial, PairingError> {
        self.ensure_state_dir()?;
        let path = self.state_dir.join(STATE_FILE);
        if !path.exists() {
            let mut pairing_file = RpPairingFile::generate(sending_host);
            pairing_file.identifier = Uuid::now_v7().to_string();
            let mut host_info = PairableHostInfo::generate(sending_host, SERVICE_MODEL);
            host_info.identifier = pairing_file.identifier().to_owned();
            return Ok(StoredPairingMaterial {
                host_info,
                pairing_file,
                paired_peer_id: None,
            });
        }
        let key = self.load_or_create_key()?;
        set_private_permissions(&path, false);
        self.load_encrypted(&key, sending_host)
    }

    fn load_existing(&self, sending_host: &str) -> Result<StoredPairingMaterial, PairingError> {
        let path = self.state_dir.join(STATE_FILE);
        if !path.exists() {
            return Err(PairingError::Storage);
        }
        let key: [u8; 32] = fs::read(self.state_dir.join(KEY_FILE))
            .map_err(|_| PairingError::Storage)?
            .try_into()
            .map_err(|_| PairingError::CorruptedState)?;
        self.load_encrypted(&key, sending_host)
    }

    fn load_encrypted(
        &self,
        key: &[u8; 32],
        sending_host: &str,
    ) -> Result<StoredPairingMaterial, PairingError> {
        let path = self.state_dir.join(STATE_FILE);
        let encrypted = fs::read(&path).map_err(|_| PairingError::Storage)?;
        let record: EncryptedState =
            serde_json::from_slice(&encrypted).map_err(|_| PairingError::CorruptedState)?;
        let nonce = BASE64
            .decode(record.nonce)
            .map_err(|_| PairingError::CorruptedState)?;
        let ciphertext = BASE64
            .decode(record.ciphertext)
            .map_err(|_| PairingError::CorruptedState)?;
        if nonce.len() != 12 {
            return Err(PairingError::CorruptedState);
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PairingError::CorruptedState)?;
        let payload = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| PairingError::CorruptedState)?;
        let payload: PairingStatePayload =
            serde_json::from_slice(&payload).map_err(|_| PairingError::CorruptedState)?;
        let host_alt_irk: [u8; 16] = payload
            .host_alt_irk
            .try_into()
            .map_err(|_| PairingError::CorruptedState)?;
        let pairing_bytes = BASE64
            .decode(payload.pairing_file)
            .map_err(|_| PairingError::CorruptedState)?;
        let pairing_file =
            RpPairingFile::from_bytes(&pairing_bytes).map_err(|_| PairingError::CorruptedState)?;
        let mut host_info = PairableHostInfo::generate(sending_host, SERVICE_MODEL);
        host_info.identifier = pairing_file.identifier().to_owned();
        host_info.alt_irk = host_alt_irk;
        Ok(StoredPairingMaterial {
            host_info,
            pairing_file,
            paired_peer_id: payload.paired_peer_id,
        })
    }

    fn save(&self, material: &StoredPairingMaterial) -> Result<(), PairingError> {
        self.ensure_state_dir()?;
        let key = self.load_or_create_key()?;
        self.save_with_key(&key, material)
    }

    fn save_with_key(
        &self,
        key: &[u8; 32],
        material: &StoredPairingMaterial,
    ) -> Result<(), PairingError> {
        let nonce: [u8; 12] = rand::random();
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| PairingError::Storage)?;
        let payload = serde_json::to_vec(&PairingStatePayload {
            host_alt_irk: material.host_info.alt_irk.to_vec(),
            pairing_file: BASE64.encode(material.pairing_file.to_bytes()),
            paired_peer_id: material.paired_peer_id.clone(),
        })
        .map_err(|_| PairingError::Storage)?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), payload.as_ref())
            .map_err(|_| PairingError::Storage)?;
        let record = serde_json::to_vec(&EncryptedState {
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        })
        .map_err(|_| PairingError::Storage)?;
        let state_path = self.state_dir.join(STATE_FILE);
        let temporary_path = self.state_dir.join(format!("{STATE_FILE}.tmp"));
        fs::write(&temporary_path, record).map_err(|_| PairingError::Storage)?;
        set_private_permissions(&temporary_path, false);
        #[cfg(windows)]
        if state_path.exists() {
            fs::remove_file(&state_path).map_err(|_| PairingError::Storage)?;
        }
        fs::rename(&temporary_path, &state_path).map_err(|_| PairingError::Storage)?;
        set_private_permissions(&state_path, false);
        Ok(())
    }

    fn ensure_state_dir(&self) -> Result<(), PairingError> {
        fs::create_dir_all(&self.state_dir).map_err(|_| PairingError::Storage)?;
        set_private_permissions(&self.state_dir, true);
        Ok(())
    }

    fn load_or_create_key(&self) -> Result<[u8; 32], PairingError> {
        let path = self.state_dir.join(KEY_FILE);
        match fs::read(&path) {
            Ok(bytes) => bytes.try_into().map_err(|_| PairingError::CorruptedState),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let key: [u8; 32] = rand::random();
                fs::write(&path, key).map_err(|_| PairingError::Storage)?;
                set_private_permissions(&path, false);
                Ok(key)
            }
            Err(_) => Err(PairingError::Storage),
        }
    }
}

fn fingerprint_peer(identifier: &str) -> String {
    BASE64.encode(Sha256::digest(identifier.as_bytes()))
}

#[cfg(unix)]
fn set_private_permissions(path: &Path, directory: bool) {
    use std::os::unix::fs::PermissionsExt;
    let mode = if directory { 0o700 } else { 0o600 };
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &Path, _directory: bool) {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn temp_state_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("iphoneloadly-wireless-{name}-{}", Uuid::now_v7()))
    }

    fn test_peer_device() -> PeerDevice {
        PeerDevice {
            account_id: "test-account".into(),
            alt_irk: vec![0x11; 16],
            model: "iPhone17,1".into(),
            name: "Test iPhone".into(),
            remotepairing_udid: "test-peer".into(),
        }
    }

    fn test_commitment_deadline() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    async fn test_service_with_session(
        state_dir: PathBuf,
    ) -> (
        WirelessPairingService,
        Uuid,
        Arc<Mutex<Option<MdnsAdvertisement>>>,
    ) {
        let service = WirelessPairingService::new(WirelessPairingConfig {
            mode: WirelessPairingMode::Experimental,
            pairing_port: DEFAULT_PAIRING_PORT,
            interface: None,
            state_dir,
        });
        let id = Uuid::now_v7();
        let task = tokio::spawn(async {});
        let resources = Arc::new(Mutex::new(Some(MdnsAdvertisement {
            daemon: None,
            fullname: String::new(),
        })));
        *service.session.lock().await = Some(SessionRuntime {
            status: PairingSessionStatus {
                id,
                phase: PairingPhase::AwaitingCodeEntry,
                expires_at: unix_seconds(SystemTime::now() + SESSION_LIFETIME),
                public_message: String::new(),
                setup_code: Some("123456".into()),
            },
            cancel: task.abort_handle(),
            resources: resources.clone(),
        });
        (service, id, resources)
    }

    #[test]
    fn fresh_pairing_material_is_not_persisted_until_saved() {
        let dir = temp_state_dir("deferred-persistence");
        let store = PairingStore::new(dir.clone());
        let material = store
            .load_or_create(SERVICE_NAME)
            .expect("create in-memory pairing material");
        assert!(dir.exists());
        assert!(!dir.join(STATE_FILE).exists());
        assert!(!dir.join(KEY_FILE).exists());
        store.save(&material).expect("persist pairing material");
        assert!(dir.join(STATE_FILE).exists());
        assert!(dir.join(KEY_FILE).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_or_unknown_mode_is_off() {
        assert_eq!(WirelessPairingMode::parse(None), WirelessPairingMode::Off);
        assert_eq!(
            WirelessPairingMode::parse(Some("unknown")),
            WirelessPairingMode::Off
        );
        assert_eq!(
            WirelessPairingMode::parse(Some("experimental")),
            WirelessPairingMode::Experimental
        );
        assert_eq!(
            WirelessPairingMode::parse(Some("on")),
            WirelessPairingMode::On
        );
    }

    #[test]
    fn invalid_ports_are_rejected_without_binding() {
        assert!(matches!(
            validate_pairing_port(80),
            Err(ConfigError::InvalidPort)
        ));
    }

    #[test]
    fn pairable_host_service_type_fits_configured_mdns_limit() {
        let service_name = PAIRABLE_HOST_SERVICE_TYPE
            .strip_suffix("._tcp.local.")
            .and_then(|value| value.strip_prefix('_'))
            .expect("PairableHost service type has a valid DNS-SD suffix");
        assert!(service_name.len() <= MDNS_SERVICE_NAME_LIMIT as usize);
    }

    #[test]
    fn session_expiry_uses_controlled_time() {
        let now = UNIX_EPOCH + Duration::from_secs(1_000);
        let status = PairingSessionStatus {
            id: Uuid::now_v7(),
            phase: PairingPhase::AwaitingDevice,
            expires_at: 1_300,
            public_message: String::new(),
            setup_code: None,
        };
        assert!(!session_expired(&status, now + Duration::from_secs(299)));
        assert!(session_expired(&status, now + Duration::from_secs(300)));
    }
    #[tokio::test]
    async fn only_one_session_can_be_active() {
        let config = WirelessPairingConfig {
            mode: WirelessPairingMode::Experimental,
            pairing_port: DEFAULT_PAIRING_PORT,
            interface: None,
            state_dir: temp_state_dir("one"),
        };
        let service = WirelessPairingService::new(config);
        let task = tokio::spawn(async {});
        let id = Uuid::now_v7();
        *service.session.lock().await = Some(SessionRuntime {
            status: PairingSessionStatus {
                id,
                phase: PairingPhase::AwaitingDevice,
                expires_at: unix_seconds(SystemTime::now() + SESSION_LIFETIME),
                public_message: String::new(),
                setup_code: None,
            },
            cancel: task.abort_handle(),
            resources: Arc::new(Mutex::new(None)),
        });
        assert!(matches!(
            service.start_wireless().await,
            Err(PairingError::Busy)
        ));
        task.abort();
    }

    #[test]
    fn persistence_round_trip_preserves_verification_inputs_without_plaintext_secrets() {
        let dir = temp_state_dir("round-trip");
        let store = PairingStore::new(dir.clone());
        let mut material = store
            .load_or_create(SERVICE_NAME)
            .expect("create pairing state");
        material.pairing_file.alt_irk = Some(vec![0x42; 16]);
        let private_key = material.pairing_file.private_key_bytes();
        let public_key = material.pairing_file.public_key_bytes();
        store.save(&material).expect("persist pairing state");
        let reloaded = store
            .load_or_create(SERVICE_NAME)
            .expect("reload pairing state");
        assert_eq!(
            material.pairing_file.identifier(),
            reloaded.pairing_file.identifier()
        );
        assert_eq!(
            material.pairing_file.private_key_bytes(),
            reloaded.pairing_file.private_key_bytes()
        );
        assert_eq!(
            material.pairing_file.public_key_bytes(),
            reloaded.pairing_file.public_key_bytes()
        );
        assert_eq!(
            material.pairing_file.alt_irk(),
            reloaded.pairing_file.alt_irk()
        );
        assert_eq!(material.host_info.alt_irk, reloaded.host_info.alt_irk);
        let bytes = fs::read(dir.join(STATE_FILE)).expect("read encrypted state");
        assert!(
            !bytes
                .windows(private_key.len())
                .any(|window| window == private_key)
        );
        assert!(
            !bytes
                .windows(public_key.len())
                .any(|window| window == public_key)
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn persistence_files_are_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_state_dir("permissions");
        let store = PairingStore::new(dir.clone());
        let material = store
            .load_or_create(SERVICE_NAME)
            .expect("create private pairing state");
        store
            .save(&material)
            .expect("persist private pairing state");
        assert_eq!(
            fs::metadata(&dir)
                .expect("state directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(dir.join(STATE_FILE))
                .expect("state file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(dir.join(KEY_FILE))
                .expect("state key metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupted_state_fails_closed() {
        let dir = temp_state_dir("corrupt");
        let store = PairingStore::new(dir.clone());
        let material = store.load_or_create(SERVICE_NAME).expect("create state");
        store.save(&material).expect("persist state");
        fs::write(dir.join(STATE_FILE), b"not pairing state").expect("corrupt state");
        assert!(matches!(
            store.load_or_create(SERVICE_NAME),
            Err(PairingError::CorruptedState)
        ));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn pairing_does_not_enter_verifying_before_commitment() {
        let dir = temp_state_dir("commit-order");
        let (service, id, resources) = test_service_with_session(dir.clone()).await;
        let material = service
            .store
            .load_or_create(SERVICE_NAME)
            .expect("create pairing material");
        assert_eq!(
            service
                .status(id)
                .await
                .expect("pre-commit session status")
                .phase,
            PairingPhase::AwaitingCodeEntry
        );
        service
            .finalize_new_pairing(
                id,
                material,
                test_peer_device(),
                resources,
                test_commitment_deadline(),
                Ok(()),
            )
            .await;
        assert_eq!(
            service
                .status(id)
                .await
                .expect("final session status")
                .phase,
            PairingPhase::VerifyingTransport
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn successful_commitment_persists_final_pairing_state() {
        let dir = temp_state_dir("commit-success");
        let (service, id, resources) = test_service_with_session(dir.clone()).await;
        let material = service
            .store
            .load_or_create(SERVICE_NAME)
            .expect("create pairing material");
        let expected_peer_id = fingerprint_peer("test-peer");
        service
            .finalize_new_pairing(
                id,
                material,
                test_peer_device(),
                resources,
                test_commitment_deadline(),
                Ok(()),
            )
            .await;
        let saved = service
            .store
            .load_existing(SERVICE_NAME)
            .expect("load committed pairing state");
        assert_eq!(
            saved.paired_peer_id.as_deref(),
            Some(expected_peer_id.as_str())
        );
        assert_eq!(
            service
                .status(id)
                .await
                .expect("final session status")
                .phase,
            PairingPhase::VerifyingTransport
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn expired_commitment_does_not_persist_final_pairing_state() {
        let dir = temp_state_dir("commit-expired");
        let (service, id, resources) = test_service_with_session(dir.clone()).await;
        let material = service
            .store
            .load_or_create(SERVICE_NAME)
            .expect("create pairing material");
        service
            .finalize_new_pairing(
                id,
                material,
                test_peer_device(),
                resources,
                Instant::now() - Duration::from_secs(1),
                Ok(()),
            )
            .await;
        let status = service.status(id).await.expect("expired session status");
        assert_eq!(status.phase, PairingPhase::Failed);
        assert!(!dir.join(STATE_FILE).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn commitment_failure_prevents_verifying_transport_or_ready() {
        let dir = temp_state_dir("commit-failure");
        let (service, id, resources) = test_service_with_session(dir.clone()).await;
        let material = service
            .store
            .load_or_create(SERVICE_NAME)
            .expect("create pairing material");
        service
            .finalize_new_pairing(
                id,
                material,
                test_peer_device(),
                resources,
                test_commitment_deadline(),
                Err(post_pair_commit_failure("socket")),
            )
            .await;
        let status = service.status(id).await.expect("failed session status");
        assert_eq!(status.phase, PairingPhase::Failed);
        assert_ne!(status.phase, PairingPhase::VerifyingTransport);
        assert_ne!(status.phase, PairingPhase::Ready);
        assert!(!dir.join(STATE_FILE).exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn commitment_failure_preserves_previous_valid_state() {
        let dir = temp_state_dir("commit-preserve");
        let store = PairingStore::new(dir.clone());
        let previous = store
            .load_or_create(SERVICE_NAME)
            .expect("create previous pairing state");
        store
            .save(&previous)
            .expect("persist previous pairing state");
        let before = fs::read(dir.join(STATE_FILE)).expect("read previous state");
        let (service, id, resources) = test_service_with_session(dir.clone()).await;
        let material = service
            .store
            .load_or_create(SERVICE_NAME)
            .expect("load previous pairing state");
        service
            .finalize_new_pairing(
                id,
                material,
                test_peer_device(),
                resources,
                test_commitment_deadline(),
                Err(post_pair_commit_failure("socket")),
            )
            .await;
        let after = fs::read(dir.join(STATE_FILE)).expect("read preserved state");
        assert_eq!(after, before);
        assert_eq!(
            service
                .status(id)
                .await
                .expect("failed session status")
                .phase,
            PairingPhase::Failed
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn post_pair_commit_reuses_new_pairing_file() {
        let dir = temp_state_dir("commit-file-reuse");
        let (service, id, resources) = test_service_with_session(dir.clone()).await;
        let material = service
            .store
            .load_or_create(SERVICE_NAME)
            .expect("create pairing material");
        let expected_identifier = material.pairing_file.identifier().to_owned();
        let expected_private_key = material.pairing_file.private_key_bytes();
        service
            .finalize_new_pairing(
                id,
                material,
                test_peer_device(),
                resources,
                test_commitment_deadline(),
                Ok(()),
            )
            .await;
        let saved = service
            .store
            .load_existing(SERVICE_NAME)
            .expect("load committed pairing state");
        assert_eq!(saved.pairing_file.identifier(), expected_identifier);
        assert_eq!(saved.pairing_file.private_key_bytes(), expected_private_key);
        let _ = fs::remove_dir_all(dir);
    }
    #[tokio::test]
    async fn rsd_probe_does_not_create_wireless_state() {
        let dir = temp_state_dir("rsd-empty");
        let service = WirelessPairingService::new(WirelessPairingConfig {
            mode: WirelessPairingMode::Experimental,
            pairing_port: DEFAULT_PAIRING_PORT,
            interface: None,
            state_dir: dir.clone(),
        });

        let failure = service
            .probe_remote_pairing_rsd()
            .await
            .expect_err("empty pairing state must fail closed");
        assert_eq!(failure.stage, RsdProbeStage::Discovery);
        assert!(!dir.exists());
    }

    #[test]
    fn core_device_service_lookup_requires_exact_appservice_name() {
        let mut handshake = RsdHandshake {
            services: std::collections::HashMap::new(),
            protocol_version: 0,
            properties: std::collections::HashMap::new(),
            uuid: String::new(),
        };
        handshake.services.insert(
            format!("{CORE_DEVICE_APP_SERVICE_NAME}.unexpected"),
            idevice::services::rsd::RsdService {
                entitlement: String::new(),
                port: 62_078,
                uses_remote_xpc: true,
                features: None,
                service_version: None,
            },
        );

        let missing = core_device_appservice_port(&handshake)
            .expect_err("near-match must not satisfy exact AppService lookup");
        assert_eq!(missing.operation, CoreDeviceServiceOperation::ServiceLookup);
        assert_eq!(missing.operation.as_str(), "service_lookup");
        assert_eq!(missing.result, "missing");
        assert_eq!(missing.error_kind, "service_not_found");
        assert!(!missing.appservice_present);

        handshake.services.insert(
            CORE_DEVICE_APP_SERVICE_NAME.to_owned(),
            idevice::services::rsd::RsdService {
                entitlement: String::new(),
                port: 62_079,
                uses_remote_xpc: true,
                features: None,
                service_version: None,
            },
        );
        assert_eq!(
            core_device_appservice_port(&handshake).expect("exact AppService name"),
            62_079
        );
    }

    #[tokio::test]
    async fn core_device_service_failures_are_classified_and_secret_free() {
        let connect_timeout = run_core_device_service_operation(
            CoreDeviceServiceOperation::ServiceConnect,
            true,
            Duration::from_millis(1),
            std::future::pending::<Result<(), idevice::IdeviceError>>(),
        )
        .await
        .expect_err("pending service connection must time out");
        assert_eq!(
            connect_timeout.operation,
            CoreDeviceServiceOperation::ServiceConnect
        );
        assert_eq!(connect_timeout.operation.as_str(), "service_connect");
        assert_eq!(connect_timeout.result, "timeout");
        assert_eq!(connect_timeout.error_kind, "timeout");
        assert!(connect_timeout.appservice_present);

        let secret = "device-controlled-secret";
        let client_init = run_core_device_service_operation(
            CoreDeviceServiceOperation::ClientInit,
            true,
            Duration::from_secs(1),
            std::future::ready(Err::<(), _>(idevice::IdeviceError::UnexpectedResponse(
                secret.to_owned(),
            ))),
        )
        .await
        .expect_err("client initialization error must fail closed");
        assert_eq!(
            client_init.operation,
            CoreDeviceServiceOperation::ClientInit
        );
        assert_eq!(client_init.operation.as_str(), "client_init");
        assert_eq!(client_init.result, "error");
        assert_eq!(client_init.error_kind, "unexpected_response");

        let list_error: idevice::IdeviceError =
            idevice::services::core_device::CoreDeviceError::DeviceError(secret.to_owned()).into();
        let list_apps = run_core_device_service_operation(
            CoreDeviceServiceOperation::ListApps,
            true,
            Duration::from_secs(1),
            std::future::ready(Err::<(), _>(list_error)),
        )
        .await
        .expect_err("list_apps error must fail closed");
        assert_eq!(list_apps.operation, CoreDeviceServiceOperation::ListApps);
        assert_eq!(list_apps.operation.as_str(), "list_apps");
        assert_eq!(list_apps.result, "error");
        assert_eq!(list_apps.error_kind, "core_device");
        assert!(list_apps.appservice_present);

        let rendered = format!("{connect_timeout:?}{client_init:?}{list_apps:?}");
        assert!(!rendered.contains(secret));
        assert_eq!(
            report_core_device_service_failure(list_apps).stage,
            RsdProbeStage::CoreDeviceService
        );
    }

    #[test]
    fn valid_auth_tag_accepts_discovery_and_invalid_tag_is_rejected() {
        let alt_irk = BASE64
            .decode("Mgp6ZGPzXM2ku9br46vsiw==")
            .expect("decode authTag test altIRK");
        let addresses = vec!["192.0.2.1".parse().expect("parse test address")];
        let endpoint = authenticated_remote_pairing_endpoint(
            &alt_irk,
            "2BE6E510-0325-4365-923E-B14C6F57DB3A",
            "kXjlTr2l",
            addresses.clone(),
            52_345,
        )
        .expect("valid authTag should authenticate discovery");
        assert_eq!(endpoint.port, 52_345);
        assert_eq!(endpoint.addresses, addresses);
        assert!(
            authenticated_remote_pairing_endpoint(
                &alt_irk,
                "2BE6E510-0325-4365-923E-B14C6F57DB3A",
                "invalid",
                addresses,
                52_345,
            )
            .is_none()
        );
    }

    #[tokio::test]
    async fn tcp_failure_does_not_reach_validate_pairing() {
        let endpoint = RemotePairingEndpoint {
            addresses: vec!["127.0.0.1".parse().expect("parse loopback")],
            port: 0,
        };
        let pairing_file = RpPairingFile::generate(SERVICE_NAME);
        let failure = connect_and_validate_remote_pairing(&[endpoint], &pairing_file)
            .await
            .expect_err("unreachable endpoint must fail validation");
        assert_eq!(failure.stage, RsdProbeStage::ValidatePairing);
    }

    async fn read_pairing_frame(stream: &mut TcpStream) -> serde_json::Value {
        let mut magic = [0u8; 9];
        stream
            .read_exact(&mut magic)
            .await
            .expect("read frame magic");
        assert_eq!(magic, *b"RPPairing");
        let mut length = [0u8; 2];
        stream
            .read_exact(&mut length)
            .await
            .expect("read frame length");
        let mut payload = vec![0u8; u16::from_be_bytes(length) as usize];
        stream
            .read_exact(&mut payload)
            .await
            .expect("read frame payload");
        serde_json::from_slice(&payload).expect("decode pairing frame")
    }

    async fn write_pairing_frame(stream: &mut TcpStream, response: serde_json::Value) {
        let payload = serde_json::to_vec(&response).expect("serialize pairing response");
        stream
            .write_all(b"RPPairing")
            .await
            .expect("write frame magic");
        stream
            .write_all(&(payload.len() as u16).to_be_bytes())
            .await
            .expect("write frame length");
        stream
            .write_all(&payload)
            .await
            .expect("write frame payload");
        stream.flush().await.expect("flush pairing response");
    }

    fn assert_attempt_pair_verify_request(request: &serde_json::Value) {
        assert_eq!(request["originatedBy"], "host");
        assert_eq!(request["sequenceNumber"], 0);
        assert_eq!(
            request["message"]["plain"]["_0"]["request"]["_0"]["handshake"]["_0"]["hostOptions"]["attemptPairVerify"],
            true
        );
        assert_eq!(
            request["message"]["plain"]["_0"]["request"]["_0"]["handshake"]["_0"]["wireProtocolVersion"],
            19
        );
    }

    fn assert_validate_pairing_request(
        request: &serde_json::Value,
        sequence_number: u64,
        start_new_session: bool,
    ) {
        assert_eq!(request["originatedBy"], "host");
        assert_eq!(request["sequenceNumber"], sequence_number);
        let pairing_data = &request["message"]["plain"]["_0"]["event"]["_0"]["pairingData"]["_0"];
        assert_eq!(pairing_data["kind"], "verifyManualPairing");
        assert_eq!(pairing_data["startNewSession"], start_new_session);
        assert!(pairing_data["data"].as_str().is_some());
    }

    fn attempt_pair_verify_response() -> serde_json::Value {
        serde_json::json!({
            "message": {
                "plain": {
                    "_0": {
                        "response": {
                            "_1": {
                                "handshake": {
                                    "_0": {
                                        "wireProtocolVersion": 19
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "originatedBy": "device",
            "sequenceNumber": 0
        })
    }

    fn validation_response(tlv: Vec<u8>) -> serde_json::Value {
        serde_json::json!({
            "message": {
                "plain": {
                    "_0": {
                        "event": {
                            "_0": {
                                "pairingData": {
                                    "_0": {
                                        "data": BASE64.encode(tlv)
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "originatedBy": "device",
            "sequenceNumber": 0
        })
    }

    async fn serve_successful_established_verification(listener: TcpListener) -> Vec<&'static str> {
        let (mut stream, _) = listener
            .accept()
            .await
            .expect("accept verification connection");

        let attempt = read_pairing_frame(&mut stream).await;
        assert_attempt_pair_verify_request(&attempt);
        write_pairing_frame(&mut stream, attempt_pair_verify_response()).await;

        let validation_start = read_pairing_frame(&mut stream).await;
        assert_validate_pairing_request(&validation_start, 1, true);
        let mut peer_public_key = Vec::with_capacity(34);
        peer_public_key.extend([0x03, 32]);
        peer_public_key.extend([0u8; 32]);
        write_pairing_frame(&mut stream, validation_response(peer_public_key)).await;

        let validation_finish = read_pairing_frame(&mut stream).await;
        assert_validate_pairing_request(&validation_finish, 2, false);
        write_pairing_frame(&mut stream, validation_response(Vec::new())).await;

        vec![
            "attempt_pair_verify",
            "validate_pairing_start",
            "validate_pairing_finish",
        ]
    }

    async fn spawn_successful_verification_peer()
    -> (u16, tokio::task::JoinHandle<Vec<&'static str>>) {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind verification listener");
        let port = listener
            .local_addr()
            .expect("verification listener address")
            .port();
        let server_task =
            tokio::spawn(async move { serve_successful_established_verification(listener).await });
        (port, server_task)
    }

    async fn successful_fresh_sequence(pairing_file: &RpPairingFile) -> Vec<&'static str> {
        let (port, server_task) = spawn_successful_verification_peer().await;
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect fresh verification client");
        let mut client = RemotePairingClient::new(RpPairingSocket::new(stream), SERVICE_NAME);
        let result = verify_established_pairing(
            &mut client,
            pairing_file,
            EstablishedPairingVerificationTiming::Deadline(Instant::now() + Duration::from_secs(1)),
        )
        .await;
        assert!(result.is_ok());
        server_task.await.expect("fresh verification server task")
    }

    async fn successful_restart_sequence(pairing_file: &RpPairingFile) -> Vec<&'static str> {
        let (port, server_task) = spawn_successful_verification_peer().await;
        let endpoint = RemotePairingEndpoint {
            addresses: vec!["127.0.0.1".parse().expect("parse loopback")],
            port,
        };
        let result = connect_and_validate_remote_pairing_with_timeout(
            &[endpoint],
            pairing_file,
            Duration::from_secs(1),
        )
        .await;
        assert!(result.is_ok());
        server_task.await.expect("restart verification server task")
    }

    #[tokio::test]
    async fn attempt_rejection_prevents_validation_and_key_regeneration() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind rejection listener");
        let port = listener
            .local_addr()
            .expect("rejection listener address")
            .port();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept rejection connection");
            let attempt = read_pairing_frame(&mut stream).await;
            assert_attempt_pair_verify_request(&attempt);
            write_pairing_frame(
                &mut stream,
                serde_json::json!({
                    "message": {
                        "plain": {
                            "_0": {
                                "response": {}
                            }
                        }
                    },
                    "originatedBy": "device",
                    "sequenceNumber": 0
                }),
            )
            .await;
            let mut next_byte = [0u8; 1];
            match timeout(Duration::from_millis(100), stream.read(&mut next_byte)).await {
                Err(_) | Ok(Ok(0)) | Ok(Err(_)) => {}
                Ok(Ok(_)) => panic!("rejected prerequisite must not reach validation or tunneling"),
            }
        });
        let endpoint = RemotePairingEndpoint {
            addresses: vec!["127.0.0.1".parse().expect("parse loopback")],
            port,
        };
        let mut pairing_file = RpPairingFile::generate(SERVICE_NAME);
        pairing_file.alt_irk = Some(vec![0x11; 16]);
        let identifier = pairing_file.identifier().to_owned();
        let private_key = pairing_file.private_key_bytes();
        let public_key = pairing_file.public_key_bytes();
        let alt_irk = pairing_file.alt_irk().map(<[u8]>::to_vec);

        let failure = connect_and_validate_remote_pairing_with_timeout(
            &[endpoint],
            &pairing_file,
            Duration::from_secs(1),
        )
        .await
        .expect_err("rejected prerequisite must fail closed");

        server_task.await.expect("rejection server task");
        assert_eq!(failure.stage, RsdProbeStage::ValidatePairing);
        assert_eq!(pairing_file.identifier(), identifier);
        assert_eq!(pairing_file.private_key_bytes(), private_key);
        assert_eq!(pairing_file.public_key_bytes(), public_key);
        assert_eq!(pairing_file.alt_irk(), alt_irk.as_deref());
    }

    #[tokio::test]
    async fn validation_rejection_does_not_fallback_to_pairing_or_tunneling() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind validation rejection listener");
        let port = listener
            .local_addr()
            .expect("validation rejection listener address")
            .port();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("accept validation rejection connection");
            let attempt = read_pairing_frame(&mut stream).await;
            assert_attempt_pair_verify_request(&attempt);
            write_pairing_frame(&mut stream, attempt_pair_verify_response()).await;

            let validation = read_pairing_frame(&mut stream).await;
            assert_validate_pairing_request(&validation, 1, true);
            write_pairing_frame(&mut stream, validation_response(Vec::new())).await;

            let mut next_byte = [0u8; 1];
            match timeout(Duration::from_millis(100), stream.read(&mut next_byte)).await {
                Err(_) | Ok(Ok(0)) | Ok(Err(_)) => {}
                Ok(Ok(_)) => {
                    panic!("failed validation must not reach pairing fallback or tunneling")
                }
            }
        });
        let endpoint = RemotePairingEndpoint {
            addresses: vec!["127.0.0.1".parse().expect("parse loopback")],
            port,
        };
        let mut pairing_file = RpPairingFile::generate(SERVICE_NAME);
        pairing_file.alt_irk = Some(vec![0x44; 16]);
        let identifier = pairing_file.identifier().to_owned();
        let private_key = pairing_file.private_key_bytes();
        let public_key = pairing_file.public_key_bytes();
        let alt_irk = pairing_file.alt_irk().map(<[u8]>::to_vec);

        let failure = connect_and_validate_remote_pairing_with_timeout(
            &[endpoint],
            &pairing_file,
            Duration::from_secs(1),
        )
        .await
        .expect_err("failed validation must fail closed");

        server_task.await.expect("validation rejection server task");
        assert_eq!(failure.stage, RsdProbeStage::ValidatePairing);
        assert_eq!(pairing_file.identifier(), identifier);
        assert_eq!(pairing_file.private_key_bytes(), private_key);
        assert_eq!(pairing_file.public_key_bytes(), public_key);
        assert_eq!(pairing_file.alt_irk(), alt_irk.as_deref());
    }

    #[tokio::test]
    async fn attempt_timeout_prevents_validation_and_key_regeneration() {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind timeout listener");
        let port = listener
            .local_addr()
            .expect("timeout listener address")
            .port();
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept timeout connection");
            let attempt = read_pairing_frame(&mut stream).await;
            assert_attempt_pair_verify_request(&attempt);
            let mut next_byte = [0u8; 1];
            let read = timeout(Duration::from_millis(200), stream.read(&mut next_byte)).await;
            assert!(matches!(read, Ok(Ok(0)) | Ok(Err(_))));
        });
        let endpoint = RemotePairingEndpoint {
            addresses: vec!["127.0.0.1".parse().expect("parse loopback")],
            port,
        };
        let mut pairing_file = RpPairingFile::generate(SERVICE_NAME);
        pairing_file.alt_irk = Some(vec![0x22; 16]);
        let identifier = pairing_file.identifier().to_owned();
        let private_key = pairing_file.private_key_bytes();
        let public_key = pairing_file.public_key_bytes();
        let alt_irk = pairing_file.alt_irk().map(<[u8]>::to_vec);

        let failure = connect_and_validate_remote_pairing_with_timeout(
            &[endpoint],
            &pairing_file,
            Duration::from_millis(50),
        )
        .await
        .expect_err("silent prerequisite must time out");

        server_task.await.expect("timeout server task");
        assert_eq!(failure.stage, RsdProbeStage::ValidatePairing);
        assert_eq!(pairing_file.identifier(), identifier);
        assert_eq!(pairing_file.private_key_bytes(), private_key);
        assert_eq!(pairing_file.public_key_bytes(), public_key);
        assert_eq!(pairing_file.alt_irk(), alt_irk.as_deref());
    }

    #[tokio::test]
    async fn fresh_and_reloaded_pairing_use_identical_established_sequence() {
        let mut fresh = RpPairingFile::generate(SERVICE_NAME);
        fresh.alt_irk = Some(vec![0x33; 16]);
        let reloaded = RpPairingFile::from_bytes(&fresh.to_bytes()).expect("reload pairing file");
        assert_eq!(fresh.identifier(), reloaded.identifier());
        assert_eq!(fresh.private_key_bytes(), reloaded.private_key_bytes());
        assert_eq!(fresh.public_key_bytes(), reloaded.public_key_bytes());
        assert_eq!(fresh.alt_irk(), reloaded.alt_irk());

        let fresh_sequence = successful_fresh_sequence(&fresh).await;
        let reloaded_sequence = successful_restart_sequence(&reloaded).await;

        assert_eq!(
            fresh_sequence,
            vec![
                "attempt_pair_verify",
                "validate_pairing_start",
                "validate_pairing_finish"
            ]
        );
        assert_eq!(reloaded_sequence, fresh_sequence);
    }

    #[test]
    fn established_verification_diagnostics_exclude_device_error_text() {
        let secret = "device-supplied-secret-value";
        let error = idevice::IdeviceError::UnexpectedResponse(secret.to_owned());
        let failure = EstablishedPairingVerificationFailure::from_error(
            EstablishedPairingVerificationStage::AttemptPairVerify,
            &error,
        );
        let rendered = format!("{failure:?}");
        assert_eq!(failure.stage.as_str(), "attempt_pair_verify");
        assert_eq!(failure.result, "error");
        assert!(!rendered.contains(secret));
    }

    #[tokio::test]
    async fn every_commitment_stage_failure_blocks_persistence_and_transport() {
        for (name, stage) in [
            ("bootstrap", POST_PAIR_BOOTSTRAP_STAGE),
            ("tunnel", POST_PAIR_TUNNEL_STAGE),
            ("rsd", POST_PAIR_RSD_STAGE),
            ("tunnel-service", POST_PAIR_TUNNEL_SERVICE_STAGE),
            ("commit", POST_PAIR_COMMIT_STAGE),
        ] {
            let dir = temp_state_dir(name);
            let (service, id, resources) = test_service_with_session(dir.clone()).await;
            let material = service
                .store
                .load_or_create(SERVICE_NAME)
                .expect("create pairing material");
            service
                .finalize_new_pairing(
                    id,
                    material,
                    test_peer_device(),
                    resources,
                    test_commitment_deadline(),
                    Err(post_pair_stage_failure(stage, "test_failure")),
                )
                .await;
            let status = service.status(id).await.expect("failed session status");
            assert_eq!(status.phase, PairingPhase::Failed);
            assert_ne!(status.phase, PairingPhase::VerifyingTransport);
            assert_ne!(status.phase, PairingPhase::Ready);
            assert!(!dir.join(STATE_FILE).exists());
            assert!(!dir.join(KEY_FILE).exists());
            let _ = fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn validate_pairing_error_diagnostics_are_safe_categories() {
        let unexpected = idevice::IdeviceError::UnexpectedResponse(
            "protocol payload that must not be logged".into(),
        );
        assert_eq!(idevice_error_kind(&unexpected), "unexpected_response");
        assert_eq!(remote_pairing_subcode(&unexpected), None);

        let rejected = idevice::IdeviceError::RemotePairing(RemotePairingError::PairingRejected(
            "device detail".into(),
        ));
        assert_eq!(idevice_error_kind(&rejected), "remote_pairing_rejected");
        assert_eq!(remote_pairing_subcode(&rejected), Some(3));
        assert_eq!(address_family("127.0.0.1".parse().unwrap()), "ipv4");
    }

    #[test]
    fn terminal_phases_are_not_resumable() {
        for phase in [
            PairingPhase::Ready,
            PairingPhase::Failed,
            PairingPhase::Cancelled,
            PairingPhase::Expired,
        ] {
            assert!(phase.is_terminal());
        }
        assert!(!PairingPhase::AwaitingDevice.is_terminal());
        assert!(!PairingPhase::VerifyingTransport.is_terminal());
    }

    #[test]
    fn status_serialization_contains_no_pairing_material() {
        let status = PairingSessionStatus {
            id: Uuid::now_v7(),
            phase: PairingPhase::VerifyingTransport,
            expires_at: 1_700_000_000,
            public_message: "Verifying trusted device transport.".into(),
            setup_code: Some("123456".into()),
        };
        let encoded = serde_json::to_string(&status).expect("serialize status");
        assert!(encoded.contains("\"expiresAt\":\"2023-11-14T22:13:20Z\""));
        assert!(encoded.contains("\"setupCode\":\"123456\""));
        assert!(!encoded.contains("pairing_file"));
        assert!(!encoded.contains("private_key"));
        assert!(!encoded.contains("alt_irk"));
    }

    #[test]
    fn handshake_failure_detail_is_not_retained() {
        let secret = "unexpected pair-setup state: expected 3, got Some(4)";
        let failure = PairingFailure::from_display(
            "rppairing_accept",
            idevice::IdeviceError::UnexpectedResponse(secret.into()),
        );
        assert_eq!(failure.stage, "rppairing_accept");
        assert!(!format!("{failure:?}").contains(secret));

        let status = PairingSessionStatus {
            id: Uuid::now_v7(),
            phase: PairingPhase::Failed,
            expires_at: 1_700_000_000,
            public_message: "The iPhone or iPad rejected wireless pairing.".into(),
            setup_code: None,
        };
        let encoded = serde_json::to_string(&status).expect("serialize status");
        assert!(!encoded.contains(secret));
        assert!(!encoded.contains("rppairing_accept"));
    }
}
