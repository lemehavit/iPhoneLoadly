#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::{
    collections::VecDeque,
    fmt::Display,
    fs, io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use idevice::{
    IdeviceError, RemoteXpcClient, RsdService,
    provider::RsdProvider,
    remote_pairing::{
        PAIRABLE_HOST_SERVICE_TYPE, PairableHost, PairableHostInfo, PeerDevice,
        RemotePairingClient, RpPairingFile, RpPairingSocket, RpPairingSocketProvider,
        connect_tls_psk_tunnel_native, errors::RemotePairingError,
    },
    services::{
        afc::{
            AfcClient, MAGIC,
            errors::AfcError,
            opcode::{AfcFopenMode, AfcOpcode},
            packet::{AfcPacket, AfcPacketHeader},
        },
        core_device::AppServiceClient,
        installation_proxy::{InstallationProxyClient, InstallationProxyError},
        lockdown::LockdownClient,
        rsd::RsdHandshake,
    },
    tcp::{adapter::Adapter, handle::AdapterHandle, stream::AdapterStream},
};
use mdns_sd::{DaemonEvent, IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{
    io::AsyncReadExt,
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
const READ_ONLY_QUERY_TIMEOUT: Duration = Duration::from_secs(20);
const READ_ONLY_ENDPOINT_TIMEOUT: Duration = Duration::from_secs(60);
const POST_PAIR_BOOTSTRAP_STAGE: &str = "post_pair_bootstrap";
const POST_PAIR_TUNNEL_STAGE: &str = "post_pair_tunnel";
const POST_PAIR_RSD_STAGE: &str = "post_pair_rsd";
const POST_PAIR_TUNNEL_SERVICE_STAGE: &str = "post_pair_tunnel_service";
const POST_PAIR_COMMIT_STAGE: &str = "post_pair_commit";
const TUNNEL_SERVICE_NAME: &str = "com.apple.internal.dt.coredevice.untrusted.tunnelservice";
const CORE_DEVICE_APP_SERVICE_NAME: &str = "com.apple.coredevice.appservice";
const CORE_DEVICE_INFO_SERVICE_NAME: &str = "com.apple.coredevice.deviceinfo";
const MOBILE_IMAGE_MOUNTER_SERVICE_NAME: &str = "com.apple.mobile.mobile_image_mounter.shim.remote";
const INSTALLATION_PROXY_SERVICE_NAME: &str = "com.apple.mobile.installation_proxy.shim.remote";
const AFC_SERVICE_NAME: &str = "com.apple.afc.shim.remote";
const LOCKDOWN_REMOTE_TRUSTED_SERVICE_NAME: &str = "com.apple.mobile.lockdown.remote.trusted";
pub(crate) const SPIKE_DIAGNOSTICS_TARGET: &str = "iphoneloadly_api::spike_diagnostics";

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
pub(crate) enum RsdSessionCleanup {
    NotNeeded,
    Succeeded,
    Failed,
}

impl RsdSessionCleanup {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NotNeeded => "notNeeded",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsdProbeFailure {
    pub stage: RsdProbeStage,
    pub(crate) session_cleanup: RsdSessionCleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadOnlyProbeService {
    Afc,
    InstallationProxy,
}

impl ReadOnlyProbeService {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Afc => "afc",
            Self::InstallationProxy => "installationProxy",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReadOnlyProbeStage {
    Discovery,
    ValidatePairing,
    Tunnel,
    RsdHandshake,
    ServiceLookup,
    ServiceConnect,
    ClientInit,
    AfcQuery,
    AppLookup,
    Cleanup,
}
impl ReadOnlyProbeStage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::ValidatePairing => "validatePairing",
            Self::Tunnel => "tunnel",
            Self::RsdHandshake => "rsdHandshake",
            Self::ServiceLookup => "serviceLookup",
            Self::ServiceConnect => "serviceConnect",
            Self::ClientInit => "clientInit",
            Self::AfcQuery => "afcQuery",
            Self::AppLookup => "appLookup",
            Self::Cleanup => "cleanup",
        }
    }

    const fn operation(self) -> &'static str {
        match self {
            Self::Discovery | Self::ValidatePairing | Self::Tunnel | Self::RsdHandshake => "setup",
            Self::ServiceLookup => "service_lookup",
            Self::ServiceConnect => "service_connect",
            Self::ClientInit => "client_init",
            Self::AfcQuery => "afc_query",
            Self::AppLookup => "app_lookup",
            Self::Cleanup => "cleanup",
        }
    }
}

impl From<RsdProbeStage> for ReadOnlyProbeStage {
    fn from(stage: RsdProbeStage) -> Self {
        match stage {
            RsdProbeStage::Discovery => Self::Discovery,
            RsdProbeStage::ValidatePairing => Self::ValidatePairing,
            RsdProbeStage::Tunnel => Self::Tunnel,
            RsdProbeStage::RsdHandshake => Self::RsdHandshake,
            RsdProbeStage::CoreDeviceService => Self::ServiceConnect,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReadOnlyProbeFailure {
    pub(crate) stage: ReadOnlyProbeStage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RsdIdentityFailure {
    HandshakeIdentity,
    ServiceLookup,
    ServiceConnect,
    ClientInit,
    LockdownIdentity,
    DeviceName,
    IdentityMismatch,
}

impl RsdIdentityFailure {
    const fn kind(self) -> &'static str {
        match self {
            Self::HandshakeIdentity => "handshake_identity",
            Self::ServiceLookup => "lockdown_service_lookup",
            Self::ServiceConnect => "lockdown_service_connect",
            Self::ClientInit => "lockdown_client_init",
            Self::LockdownIdentity => "lockdown_identity",
            Self::DeviceName => "device_name",
            Self::IdentityMismatch => "identity_mismatch",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RsdInstallOutcome {
    NotStarted,
    Installed,
    NotInstalled,
    OutcomeUnknown,
}

impl RsdInstallOutcome {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "notStarted",
            Self::Installed => "installed",
            Self::NotInstalled => "notInstalled",
            Self::OutcomeUnknown => "outcomeUnknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RsdInstallStage {
    Discovery,
    ValidatePairing,
    Tunnel,
    RsdHandshake,
    Identity,
    AccountPreflight,
    Signing,
    AlreadyInstalled,
    Staging,
    Install,
    Verification,
    Cleanup,
    SessionCleanup,
    Complete,
}

impl RsdInstallStage {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::ValidatePairing => "validatePairing",
            Self::Tunnel => "tunnel",
            Self::RsdHandshake => "rsdHandshake",
            Self::Identity => "identity",
            Self::AccountPreflight => "accountPreflight",
            Self::Signing => "signing",
            Self::AlreadyInstalled => "alreadyInstalled",
            Self::Staging => "staging",
            Self::Install => "install",
            Self::Verification => "verification",
            Self::Cleanup => "cleanup",
            Self::SessionCleanup => "sessionCleanup",
            Self::Complete => "complete",
        }
    }
}

impl From<RsdProbeStage> for RsdInstallStage {
    fn from(value: RsdProbeStage) -> Self {
        match value {
            RsdProbeStage::Discovery => Self::Discovery,
            RsdProbeStage::ValidatePairing => Self::ValidatePairing,
            RsdProbeStage::Tunnel => Self::Tunnel,
            RsdProbeStage::RsdHandshake => Self::RsdHandshake,
            RsdProbeStage::CoreDeviceService => Self::RsdHandshake,
        }
    }
}

impl From<ReadOnlyProbeStage> for RsdInstallStage {
    fn from(value: ReadOnlyProbeStage) -> Self {
        match value {
            ReadOnlyProbeStage::Discovery => Self::Discovery,
            ReadOnlyProbeStage::ValidatePairing => Self::ValidatePairing,
            ReadOnlyProbeStage::Tunnel => Self::Tunnel,
            ReadOnlyProbeStage::RsdHandshake
            | ReadOnlyProbeStage::ServiceLookup
            | ReadOnlyProbeStage::ServiceConnect
            | ReadOnlyProbeStage::ClientInit => Self::RsdHandshake,
            ReadOnlyProbeStage::AfcQuery => Self::Staging,
            ReadOnlyProbeStage::AppLookup => Self::AlreadyInstalled,
            ReadOnlyProbeStage::Cleanup => Self::SessionCleanup,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RsdStagingCleanup {
    NotNeeded,

    Succeeded,
    Failed,
}

impl RsdStagingCleanup {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::NotNeeded => "notNeeded",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

pub(crate) struct RsdInstallReport {
    pub(crate) outcome: RsdInstallOutcome,
    pub(crate) stage: RsdInstallStage,
    pub(crate) cleanup: RsdStagingCleanup,
    pub(crate) session_cleanup: RsdSessionCleanup,
    pub(crate) install_command_count: u8,
    pub(crate) error_kind: &'static str,
    pub(crate) bundle_id: Option<String>,
    pub(crate) certificate_pressure: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedRsdServiceSummary {
    parsed_appservice_present: bool,
    parsed_deviceinfo_present: bool,
    parsed_untrusted_tunnelservice_present: bool,
    parsed_image_mounter_present: bool,
    parsed_installation_proxy_present: bool,
    parsed_afc_present: bool,
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
    #[cfg(test)]
    probe_open_attempts: Arc<AtomicUsize>,
}

trait ClosableRsdProvider {
    async fn close_provider(&mut self) -> Result<(), std::io::Error>;
}

impl ClosableRsdProvider for AdapterHandle {
    async fn close_provider(&mut self) -> Result<(), std::io::Error> {
        self.close().await?;
        match self.connect(0).await {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::NetworkUnreachable
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::other("RSD adapter accepted work after shutdown")),
        }
    }
}
struct RemoteRsdSession<P> {
    provider: Option<P>,
    handshake: Option<RsdHandshake>,
}

impl<P> RemoteRsdSession<P> {
    fn provider_mut(&mut self) -> &mut P {
        self.provider
            .as_mut()
            .expect("request-owned RSD provider is available until cleanup")
    }

    fn handshake(&self) -> &RsdHandshake {
        self.handshake
            .as_ref()
            .expect("request-owned RSD handshake completed before use")
    }
}

impl<P: ClosableRsdProvider> RemoteRsdSession<P> {
    async fn close(mut self) -> Result<(), io::Error> {
        match self.provider.take() {
            Some(mut provider) => provider.close_provider().await,
            None => Ok(()),
        }
    }
}

impl<P> Drop for RemoteRsdSession<P> {
    fn drop(&mut self) {
        drop(self.provider.take());
    }
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
            #[cfg(test)]
            probe_open_attempts: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[cfg(test)]
    pub(crate) fn probe_open_attempts(&self) -> usize {
        self.probe_open_attempts.load(Ordering::SeqCst)
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
        let mut session = RemoteRsdSession::open(self, None)
            .await
            .map_err(report_appservice_setup_failure)?;
        report_parsed_rsd_service_summary(parsed_rsd_service_summary(session.handshake()));
        let result = async {
            let app_port = core_device_appservice_port(session.handshake())
                .map_err(report_core_device_service_failure)?;
            let app_stream = run_core_device_service_operation(
                CoreDeviceServiceOperation::ServiceConnect,
                true,
                REMOTE_CONNECT_TIMEOUT,
                session.provider_mut().connect_to_service_port(app_port),
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
            Ok(())
        }
        .await;
        let _ = timeout(REMOTE_CONNECT_TIMEOUT, session.close()).await;
        result
    }

    pub(crate) async fn probe_remote_pairing_afc(&self) -> Result<(), ReadOnlyProbeFailure> {
        let service = ReadOnlyProbeService::Afc;
        let deadline = tokio::time::Instant::now() + READ_ONLY_ENDPOINT_TIMEOUT;
        let mut current_stage = ReadOnlyProbeStage::Discovery;
        let mut session = match tokio::time::timeout_at(
            deadline,
            RemoteRsdSession::open(self, Some(&mut current_stage)),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err(failure)) => {
                let stage = ReadOnlyProbeStage::from(failure.stage);
                return Err(read_only_probe_failure(
                    service,
                    stage,
                    "setup",
                    "error",
                    "unavailable",
                ));
            }
            Err(_) => {
                return Err(read_only_probe_failure(
                    service,
                    current_stage,
                    current_stage.operation(),
                    "timeout",
                    "timeout",
                ));
            }
        };

        current_stage = ReadOnlyProbeStage::ServiceLookup;
        let primary = match tokio::time::timeout_at(deadline, async {
            let service_port = exact_rsd_service_port(session.handshake(), AFC_SERVICE_NAME)
                .ok_or_else(|| {
                    read_only_probe_failure(
                        service,
                        current_stage,
                        "service_lookup",
                        "missing",
                        "service_not_found",
                    )
                })?;

            current_stage = ReadOnlyProbeStage::ServiceConnect;
            let stream = run_read_only_probe_step(
                service,
                current_stage,
                "service_connect",
                REMOTE_CONNECT_TIMEOUT,
                session.provider_mut().connect_to_service_port(service_port),
            )
            .await?;

            current_stage = ReadOnlyProbeStage::ClientInit;
            let mut client = run_read_only_probe_step(
                service,
                current_stage,
                "client_init",
                REMOTE_CONNECT_TIMEOUT,
                <AfcClient as RsdService>::from_stream(stream),
            )
            .await?;

            current_stage = ReadOnlyProbeStage::AfcQuery;
            let _ = run_read_only_probe_step(
                service,
                current_stage,
                "afc_query",
                READ_ONLY_QUERY_TIMEOUT,
                client.get_device_info(),
            )
            .await?;
            Ok(())
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(read_only_probe_failure(
                service,
                current_stage,
                current_stage.operation(),
                "timeout",
                "timeout",
            )),
        };

        complete_read_only_probe_with_timeout(
            service,
            primary,
            session,
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await
    }

    pub(crate) async fn probe_remote_pairing_installation_proxy(
        &self,
    ) -> Result<(), ReadOnlyProbeFailure> {
        let service = ReadOnlyProbeService::InstallationProxy;
        let deadline = tokio::time::Instant::now() + READ_ONLY_ENDPOINT_TIMEOUT;
        let mut current_stage = ReadOnlyProbeStage::Discovery;
        let mut session = match tokio::time::timeout_at(
            deadline,
            RemoteRsdSession::open(self, Some(&mut current_stage)),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err(failure)) => {
                let stage = ReadOnlyProbeStage::from(failure.stage);
                return Err(read_only_probe_failure(
                    service,
                    stage,
                    "setup",
                    "error",
                    "unavailable",
                ));
            }
            Err(_) => {
                return Err(read_only_probe_failure(
                    service,
                    current_stage,
                    current_stage.operation(),
                    "timeout",
                    "timeout",
                ));
            }
        };

        current_stage = ReadOnlyProbeStage::ServiceLookup;
        let primary = match tokio::time::timeout_at(deadline, async {
            let service_port =
                exact_rsd_service_port(session.handshake(), INSTALLATION_PROXY_SERVICE_NAME)
                    .ok_or_else(|| {
                        read_only_probe_failure(
                            service,
                            current_stage,
                            "service_lookup",
                            "missing",
                            "service_not_found",
                        )
                    })?;

            current_stage = ReadOnlyProbeStage::ServiceConnect;
            let stream = run_read_only_probe_step(
                service,
                current_stage,
                "service_connect",
                REMOTE_CONNECT_TIMEOUT,
                session.provider_mut().connect_to_service_port(service_port),
            )
            .await?;

            current_stage = ReadOnlyProbeStage::ClientInit;
            let mut client = run_read_only_probe_step(
                service,
                current_stage,
                "client_init",
                REMOTE_CONNECT_TIMEOUT,
                <InstallationProxyClient as RsdService>::from_stream(stream),
            )
            .await?;

            current_stage = ReadOnlyProbeStage::AppLookup;
            let _ = run_read_only_probe_step(
                service,
                current_stage,
                "app_lookup",
                READ_ONLY_QUERY_TIMEOUT,
                client.get_apps(Some("User"), None),
            )
            .await?;
            Ok(())
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(read_only_probe_failure(
                service,
                current_stage,
                current_stage.operation(),
                "timeout",
                "timeout",
            )),
        };

        complete_read_only_probe_with_timeout(
            service,
            primary,
            session,
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await
    }

    pub(crate) async fn install_remote_pairing_first_app(
        &self,
        signing: Arc<crate::signing::AppleSigningProvider>,
        ipa_path: PathBuf,
    ) -> RsdInstallReport {
        let deadline = tokio::time::Instant::now() + RSD_INSTALL_TIMEOUT;
        let work_deadline = install_work_deadline(deadline, tokio::time::Instant::now());
        let mut current_stage = ReadOnlyProbeStage::Discovery;
        let mut identity_session = match tokio::time::timeout_at(
            work_deadline,
            RemoteRsdSession::open(self, Some(&mut current_stage)),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err(failure)) => {
                let mut report = rsd_install_failure(
                    RsdInstallStage::from(failure.stage),
                    "session_open",
                    false,
                    None,
                );
                record_session_cleanup(&mut report, failure.session_cleanup);
                return report;
            }
            Err(_) => {
                let mut report = rsd_install_failure(
                    RsdInstallStage::from(current_stage),
                    "timeout",
                    false,
                    None,
                );
                if current_stage == ReadOnlyProbeStage::RsdHandshake {
                    record_session_cleanup(&mut report, RsdSessionCleanup::Failed);
                }
                return report;
            }
        };

        let identity_result =
            tokio::time::timeout_at(work_deadline, identity_session.verified_signing_identity())
                .await;
        let initial_session_cleanup = close_install_session(identity_session).await;
        let identity = match identity_result {
            Ok(Ok(identity)) => identity,
            Ok(Err(failure)) => {
                let mut report =
                    rsd_install_failure(RsdInstallStage::Identity, failure.kind(), false, None);
                record_session_cleanup(&mut report, initial_session_cleanup);
                return report;
            }
            Err(_) => {
                let mut report =
                    rsd_install_failure(RsdInstallStage::Identity, "timeout", false, None);
                record_session_cleanup(&mut report, initial_session_cleanup);
                return report;
            }
        };
        if initial_session_cleanup == RsdSessionCleanup::Failed {
            let mut report = rsd_install_failure(
                RsdInstallStage::SessionCleanup,
                "session_cleanup",
                false,
                None,
            );
            record_session_cleanup(&mut report, initial_session_cleanup);
            return report;
        }

        let signing_identity = identity.clone();
        let mut signing_task = tokio::spawn(async move {
            signing
                .preflight_and_sign_for_existing_device(&signing_identity, ipa_path)
                .await
        });
        let (preflight, artifact) =
            match tokio::time::timeout_at(work_deadline, &mut signing_task).await {
                Ok(Ok(Ok(result))) => result,
                Ok(Ok(Err(error))) => {
                    let (stage, error) = match error {
                        crate::signing::ExistingDeviceSigningError::Preflight(error) => {
                            (RsdInstallStage::AccountPreflight, error)
                        }
                        crate::signing::ExistingDeviceSigningError::Signing(error) => {
                            (RsdInstallStage::Signing, error)
                        }
                    };
                    let mut report =
                        rsd_install_failure(stage, signing_error_kind(&error), false, None);
                    record_session_cleanup(&mut report, initial_session_cleanup);
                    return report;
                }
                Ok(Err(_)) => {
                    let mut report =
                        rsd_install_failure(RsdInstallStage::Signing, "local_task", false, None);
                    record_session_cleanup(&mut report, initial_session_cleanup);
                    return report;
                }
                Err(_) => {
                    signing_task.abort();
                    drop(tokio::spawn(async move {
                        if let Ok(Ok((_, artifact))) = signing_task.await {
                            schedule_artifact_cleanup(artifact);
                        }
                    }));
                    let mut report =
                        rsd_install_failure(RsdInstallStage::Signing, "timeout", false, None);
                    record_session_cleanup(&mut report, initial_session_cleanup);
                    return report;
                }
            };
        let certificate_pressure = preflight
            .development_certificate_capacity
            .is_some_and(|capacity| preflight.development_certificate_count >= capacity)
            && !preflight.machine_certificate_present;
        let Some(artifact) = artifact else {
            let mut report = rsd_install_failure(
                RsdInstallStage::AccountPreflight,
                "device_registration_required",
                certificate_pressure,
                None,
            );
            record_session_cleanup(&mut report, initial_session_cleanup);
            return report;
        };
        let bundle_id = artifact.bundle_id().to_owned();
        let mut artifact_cleanup = Some(artifact);

        let mut current_stage = ReadOnlyProbeStage::Discovery;
        let mut session = match tokio::time::timeout_at(
            work_deadline,
            RemoteRsdSession::open(self, Some(&mut current_stage)),
        )
        .await
        {
            Ok(Ok(session)) => session,
            Ok(Err(failure)) => {
                let mut report = rsd_install_failure(
                    RsdInstallStage::from(failure.stage),
                    "session_open",
                    certificate_pressure,
                    Some(bundle_id),
                );
                record_session_cleanup(
                    &mut report,
                    merge_session_cleanup(initial_session_cleanup, failure.session_cleanup),
                );
                schedule_artifact_cleanup(artifact_cleanup.take());
                return report;
            }
            Err(_) => {
                let second_cleanup = if current_stage == ReadOnlyProbeStage::RsdHandshake {
                    RsdSessionCleanup::Failed
                } else {
                    RsdSessionCleanup::NotNeeded
                };
                let mut report = rsd_install_failure(
                    RsdInstallStage::from(current_stage),
                    "timeout",
                    certificate_pressure,
                    Some(bundle_id),
                );
                record_session_cleanup(
                    &mut report,
                    merge_session_cleanup(initial_session_cleanup, second_cleanup),
                );
                schedule_artifact_cleanup(artifact_cleanup.take());
                return report;
            }
        };

        let second_identity_error =
            match tokio::time::timeout_at(work_deadline, session.verified_signing_identity()).await
            {
                Ok(Ok(second_identity)) if second_identity == identity => None,
                Ok(Ok(_)) => Some("identity_changed"),
                Ok(Err(failure)) => Some(failure.kind()),
                Err(_) => Some("timeout"),
            };
        if let Some(error_kind) = second_identity_error {
            let second_cleanup = close_install_session(session).await;
            let mut report = rsd_install_failure(
                RsdInstallStage::Identity,
                error_kind,
                certificate_pressure,
                Some(bundle_id),
            );
            record_session_cleanup(
                &mut report,
                merge_session_cleanup(initial_session_cleanup, second_cleanup),
            );
            schedule_artifact_cleanup(artifact_cleanup.take());
            return report;
        }

        let mut report = execute_rsd_first_install(
            &mut session,
            bundle_id,
            certificate_pressure,
            deadline,
            &mut artifact_cleanup,
        )
        .await;
        let final_session_cleanup = close_install_session(session).await;
        record_session_cleanup(
            &mut report,
            merge_session_cleanup(initial_session_cleanup, final_session_cleanup),
        );
        schedule_artifact_cleanup(artifact_cleanup.take());
        report
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

const RSD_INSTALL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const RSD_INSTALL_CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
const RSD_INSTALL_SESSION_CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
const RSD_INSTALL_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(20);
const RSD_INSTALL_FILE_LIMIT: usize = 20_000;
const RSD_INSTALL_BYTE_LIMIT: u64 = 2 * 1024 * 1024 * 1024;
const RSD_INSTALL_TRANSFER_CHUNK: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadPlanFailure {
    SourceNotDirectory,
    SourceSymlink,
    UnsupportedFileType,
    NonUnicodePath,
    UnsafePath,
    TooManyEntries,
    TooManyBytes,
    LocalIo,
    Timeout,
}

impl UploadPlanFailure {
    const fn kind(self) -> &'static str {
        match self {
            Self::SourceNotDirectory => "source_not_directory",
            Self::SourceSymlink => "source_symlink",
            Self::UnsupportedFileType => "unsupported_file_type",
            Self::NonUnicodePath => "non_unicode_path",
            Self::UnsafePath => "unsafe_path",
            Self::TooManyEntries => "entry_limit",
            Self::TooManyBytes => "byte_limit",
            Self::LocalIo => "local_io",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume: u64,
    file: u64,
    version: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UploadEntryKind {
    Directory {
        identity: FileIdentity,
    },
    File {
        size: u64,
        identity: FileIdentity,
        digest: [u8; 32],
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UploadEntry {
    local_path: PathBuf,
    remote_relative_path: String,
    kind: UploadEntryKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SignedBundleUploadPlan {
    canonical_root: PathBuf,
    entries: Vec<UploadEntry>,
    byte_count: u64,
}

fn safe_remote_relative_path(path: &Path) -> Result<String, UploadPlanFailure> {
    let mut parts = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(UploadPlanFailure::UnsafePath);
        };
        let Some(component) = component.to_str() else {
            return Err(UploadPlanFailure::NonUnicodePath);
        };
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains('/')
            || component.contains('\\')
            || component.contains('\0')
        {
            return Err(UploadPlanFailure::UnsafePath);
        }
        parts.push(component);
    }
    if parts.is_empty() {
        return Err(UploadPlanFailure::UnsafePath);
    }
    Ok(parts.join("/"))
}

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Some(FileIdentity {
        volume: metadata.dev(),
        file: metadata.ino(),
        version: (metadata.mtime() as u64).rotate_left(32) ^ metadata.mtime_nsec() as u64,
    })
}

#[cfg(windows)]
fn file_identity(metadata: &fs::Metadata) -> Option<FileIdentity> {
    use std::os::windows::fs::MetadataExt;
    Some(FileIdentity {
        volume: metadata.creation_time(),
        file: metadata.file_attributes() as u64,
        version: metadata.last_write_time(),
    })
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_metadata: &fs::Metadata) -> Option<FileIdentity> {
    None
}

#[cfg(unix)]
fn harden_signed_path(path: &Path, directory: bool) -> Result<(), UploadPlanFailure> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if directory { 0o700 } else { 0o600 };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|_| UploadPlanFailure::LocalIo)
}

#[cfg(not(unix))]
fn harden_signed_path(_path: &Path, _directory: bool) -> Result<(), UploadPlanFailure> {
    Ok(())
}

fn ensure_canonical_descendant(
    path: &Path,
    canonical_root: &Path,
) -> Result<PathBuf, UploadPlanFailure> {
    let canonical_path = fs::canonicalize(path).map_err(|_| UploadPlanFailure::LocalIo)?;
    if canonical_path == canonical_root || canonical_path.starts_with(canonical_root) {
        Ok(canonical_path)
    } else {
        Err(UploadPlanFailure::UnsafePath)
    }
}

fn validate_upload_bounds(entry_count: usize, byte_count: u64) -> Result<(), UploadPlanFailure> {
    if entry_count > RSD_INSTALL_FILE_LIMIT {
        return Err(UploadPlanFailure::TooManyEntries);
    }
    if byte_count > RSD_INSTALL_BYTE_LIMIT {
        return Err(UploadPlanFailure::TooManyBytes);
    }
    Ok(())
}

fn hash_planned_file(
    path: &Path,
    size: u64,
    identity: FileIdentity,
    deadline: Option<Instant>,
) -> Result<[u8; 32], UploadPlanFailure> {
    ensure_plan_deadline(deadline)?;
    let mut file = fs::File::open(path).map_err(|_| UploadPlanFailure::LocalIo)?;
    let opened_metadata = file.metadata().map_err(|_| UploadPlanFailure::LocalIo)?;
    if !opened_metadata.is_file()
        || opened_metadata.len() != size
        || file_identity(&opened_metadata) != Some(identity)
    {
        return Err(UploadPlanFailure::LocalIo);
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; RSD_INSTALL_TRANSFER_CHUNK];
    loop {
        ensure_plan_deadline(deadline)?;
        let count =
            std::io::Read::read(&mut file, &mut buffer).map_err(|_| UploadPlanFailure::LocalIo)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    ensure_plan_deadline(deadline)?;
    let final_metadata = file.metadata().map_err(|_| UploadPlanFailure::LocalIo)?;
    if final_metadata.len() != size || file_identity(&final_metadata) != Some(identity) {
        return Err(UploadPlanFailure::LocalIo);
    }
    Ok(digest.finalize().into())
}

fn ensure_plan_deadline(deadline: Option<Instant>) -> Result<(), UploadPlanFailure> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        Err(UploadPlanFailure::Timeout)
    } else {
        Ok(())
    }
}

#[cfg(test)]
fn plan_signed_bundle(root: &Path) -> Result<SignedBundleUploadPlan, UploadPlanFailure> {
    plan_signed_bundle_until(root, None)
}

fn plan_signed_bundle_until(
    root: &Path,
    deadline: Option<Instant>,
) -> Result<SignedBundleUploadPlan, UploadPlanFailure> {
    ensure_plan_deadline(deadline)?;

    let root_metadata = fs::symlink_metadata(root).map_err(|_| UploadPlanFailure::LocalIo)?;
    if root_metadata.file_type().is_symlink() {
        return Err(UploadPlanFailure::SourceSymlink);
    }
    if !root_metadata.is_dir() {
        return Err(UploadPlanFailure::SourceNotDirectory);
    }
    harden_signed_path(root, true)?;
    let canonical_root = fs::canonicalize(root).map_err(|_| UploadPlanFailure::LocalIo)?;

    let mut pending = VecDeque::from([root.to_path_buf()]);
    let mut entries = Vec::new();
    let mut byte_count = 0_u64;
    while let Some(directory) = pending.pop_front() {
        ensure_plan_deadline(deadline)?;
        let directory_metadata =
            fs::symlink_metadata(&directory).map_err(|_| UploadPlanFailure::LocalIo)?;
        if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
            return Err(UploadPlanFailure::SourceSymlink);
        }
        harden_signed_path(&directory, true)?;
        ensure_canonical_descendant(&directory, &canonical_root)?;
        let children = fs::read_dir(&directory).map_err(|_| UploadPlanFailure::LocalIo)?;
        for child in children {
            ensure_plan_deadline(deadline)?;
            let child = child.map_err(|_| UploadPlanFailure::LocalIo)?;
            let path = child.path();
            let metadata = fs::symlink_metadata(&path).map_err(|_| UploadPlanFailure::LocalIo)?;
            if metadata.file_type().is_symlink() {
                return Err(UploadPlanFailure::SourceSymlink);
            }
            ensure_canonical_descendant(&path, &canonical_root)?;
            let relative = path
                .strip_prefix(root)
                .map_err(|_| UploadPlanFailure::UnsafePath)?;
            let remote_relative_path = safe_remote_relative_path(relative)?;
            let kind = if metadata.is_dir() {
                harden_signed_path(&path, true)?;
                let identity = file_identity(&metadata).ok_or(UploadPlanFailure::LocalIo)?;
                pending.push_back(path.clone());
                UploadEntryKind::Directory { identity }
            } else if metadata.is_file() {
                harden_signed_path(&path, false)?;
                let size = metadata.len();
                byte_count = byte_count
                    .checked_add(size)
                    .ok_or(UploadPlanFailure::TooManyBytes)?;
                validate_upload_bounds(entries.len(), byte_count)?;
                let identity = file_identity(&metadata).ok_or(UploadPlanFailure::LocalIo)?;
                let digest = hash_planned_file(&path, size, identity, deadline)?;
                UploadEntryKind::File {
                    size,
                    identity,
                    digest,
                }
            } else {
                return Err(UploadPlanFailure::UnsupportedFileType);
            };
            entries.push(UploadEntry {
                local_path: path,
                remote_relative_path,
                kind,
            });
            validate_upload_bounds(entries.len(), byte_count)?;
        }
    }
    ensure_plan_deadline(deadline)?;
    entries.sort_by(|left, right| left.remote_relative_path.cmp(&right.remote_relative_path));
    Ok(SignedBundleUploadPlan {
        canonical_root,
        entries,
        byte_count,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TaskStagingPath {
    root: String,
    app: String,
}

impl TaskStagingPath {
    fn new(task_id: Uuid) -> Self {
        let root = format!("PublicStaging/iphoneloadly-spike-{task_id}");
        let app = format!("{root}/Signed.app");
        Self { root, app }
    }

    fn is_exact_task_root(&self, candidate: &str) -> bool {
        candidate == self.root
            && candidate
                .strip_prefix("PublicStaging/iphoneloadly-spike-")
                .is_some_and(|suffix| Uuid::parse_str(suffix).is_ok())
    }
}

struct TaskAfcClient {
    inner: AfcClient,
    packet_number: u64,
}

impl TaskAfcClient {
    fn new(inner: AfcClient) -> Self {
        Self {
            inner,
            packet_number: 0,
        }
    }

    async fn request(
        &mut self,
        operation: AfcOpcode,
        header_payload: Vec<u8>,
        payload: Vec<u8>,
    ) -> Result<AfcPacket, IdeviceError> {
        let header_payload_len = AfcPacketHeader::LEN + header_payload.len() as u64;
        let packet = AfcPacket {
            header: AfcPacketHeader {
                magic: MAGIC,
                entire_len: header_payload_len + payload.len() as u64,
                header_payload_len,
                packet_num: self.packet_number,
                operation,
            },
            header_payload,
            payload,
        };
        self.packet_number = self.packet_number.wrapping_add(1);
        self.inner.send(packet).await?;
        self.inner.read().await
    }

    async fn path_request(
        &mut self,
        operation: AfcOpcode,
        path: &str,
    ) -> Result<AfcPacket, IdeviceError> {
        self.request(operation, path.as_bytes().to_vec(), Vec::new())
            .await
    }

    async fn path_exists(&mut self, path: &str) -> Result<bool, IdeviceError> {
        match self.path_request(AfcOpcode::GetFileInfo, path).await {
            Ok(_) => Ok(true),
            Err(IdeviceError::Afc(AfcError::ObjectNotFound)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    async fn is_directory(&mut self, path: &str) -> Result<bool, IdeviceError> {
        let response = self.path_request(AfcOpcode::GetFileInfo, path).await?;
        let fields: Vec<&[u8]> = response
            .payload
            .split(|byte| *byte == 0)
            .filter(|field| !field.is_empty())
            .collect();
        Ok(fields
            .as_chunks::<2>()
            .0
            .iter()
            .any(|pair| pair[0] == b"st_ifmt" && pair[1] == b"S_IFDIR"))
    }

    async fn make_directory(&mut self, path: &str) -> Result<(), IdeviceError> {
        self.path_request(AfcOpcode::MakeDir, path).await?;
        Ok(())
    }

    async fn remove_all(&mut self, path: &str) -> Result<(), IdeviceError> {
        self.path_request(AfcOpcode::RemovePathAndContents, path)
            .await?;
        Ok(())
    }

    async fn open_for_write(&mut self, path: &str) -> Result<u64, IdeviceError> {
        let mut header_payload = (AfcFopenMode::Wr as u64).to_le_bytes().to_vec();
        header_payload.extend_from_slice(path.as_bytes());
        let response = self
            .request(AfcOpcode::FileOpen, header_payload, Vec::new())
            .await?;
        let descriptor = response.header_payload.get(..8).ok_or_else(|| {
            IdeviceError::UnexpectedResponse("AFC FileOpen response was incomplete".into())
        })?;
        Ok(u64::from_le_bytes(descriptor.try_into().map_err(|_| {
            IdeviceError::UnexpectedResponse("AFC FileOpen descriptor was invalid".into())
        })?))
    }

    async fn write(&mut self, descriptor: u64, bytes: Vec<u8>) -> Result<(), IdeviceError> {
        self.request(AfcOpcode::Write, descriptor.to_le_bytes().to_vec(), bytes)
            .await?;
        Ok(())
    }

    async fn close(&mut self, descriptor: u64) -> Result<(), IdeviceError> {
        self.request(
            AfcOpcode::FileClose,
            descriptor.to_le_bytes().to_vec(),
            Vec::new(),
        )
        .await?;
        Ok(())
    }
}

impl RemoteRsdSession<AdapterHandle> {
    async fn open(
        service: &WirelessPairingService,
        mut progress: Option<&mut ReadOnlyProbeStage>,
    ) -> Result<Self, RsdProbeFailure> {
        #[cfg(test)]
        service.probe_open_attempts.fetch_add(1, Ordering::SeqCst);
        if let Some(progress) = progress.as_deref_mut() {
            *progress = ReadOnlyProbeStage::Discovery;
        }
        let material = service
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
        if let Some(progress) = progress.as_deref_mut() {
            *progress = ReadOnlyProbeStage::ValidatePairing;
        }
        let (address, mut client) =
            connect_and_validate_remote_pairing(&endpoints, &pairing_file).await?;
        if let Some(progress) = progress.as_deref_mut() {
            *progress = ReadOnlyProbeStage::Tunnel;
        }
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
        let mut session = Self {
            provider: Some(adapter.to_async_handle()),
            handshake: None,
        };
        if let Some(progress) = progress {
            *progress = ReadOnlyProbeStage::RsdHandshake;
        }

        let handshake_result = async {
            let rsd_stream = timeout(
                REMOTE_CONNECT_TIMEOUT,
                session.provider_mut().connect(tunnel_info.server_rsd_port),
            )
            .await
            .map_err(|_| probe_failure(RsdProbeStage::RsdHandshake))?
            .map_err(|_| probe_failure(RsdProbeStage::RsdHandshake))?;
            timeout(REMOTE_CONNECT_TIMEOUT, RsdHandshake::new(rsd_stream))
                .await
                .map_err(|_| probe_failure(RsdProbeStage::RsdHandshake))?
                .map_err(|_| probe_failure(RsdProbeStage::RsdHandshake))
        }
        .await;

        match handshake_result {
            Ok(handshake) => {
                session.handshake = Some(handshake);
                Ok(session)
            }
            Err(mut failure) => {
                failure.session_cleanup = if matches!(
                    timeout(RSD_INSTALL_SESSION_CLEANUP_TIMEOUT, session.close()).await,
                    Ok(Ok(()))
                ) {
                    RsdSessionCleanup::Succeeded
                } else {
                    RsdSessionCleanup::Failed
                };
                Err(failure)
            }
        }
    }

    async fn verified_signing_identity(
        &mut self,
    ) -> Result<crate::signing::SigningDeviceIdentity, RsdIdentityFailure> {
        let handshake_identity = self.handshake().properties.get("UniqueDeviceID").cloned();
        let lockdown_port =
            exact_rsd_service_port(self.handshake(), LOCKDOWN_REMOTE_TRUSTED_SERVICE_NAME)
                .ok_or(RsdIdentityFailure::ServiceLookup)?;
        let lockdown_stream = timeout(
            REMOTE_CONNECT_TIMEOUT,
            self.provider_mut().connect_to_service_port(lockdown_port),
        )
        .await
        .map_err(|_| RsdIdentityFailure::ServiceConnect)?
        .map_err(|_| RsdIdentityFailure::ServiceConnect)?;
        let mut lockdown = timeout(
            REMOTE_CONNECT_TIMEOUT,
            <LockdownClient as RsdService>::from_stream(lockdown_stream),
        )
        .await
        .map_err(|_| RsdIdentityFailure::ClientInit)?
        .map_err(|_| RsdIdentityFailure::ClientInit)?;
        let lockdown_identity = timeout(
            REMOTE_CONNECT_TIMEOUT,
            lockdown.get_value(Some("UniqueDeviceID"), None),
        )
        .await
        .map_err(|_| RsdIdentityFailure::LockdownIdentity)?
        .map_err(|_| RsdIdentityFailure::LockdownIdentity)?;
        let device_name = timeout(
            REMOTE_CONNECT_TIMEOUT,
            lockdown.get_value(Some("DeviceName"), None),
        )
        .await
        .map_err(|_| RsdIdentityFailure::DeviceName)?
        .map_err(|_| RsdIdentityFailure::DeviceName)?;
        validate_rsd_identity(
            handshake_identity.as_ref(),
            Some(&lockdown_identity),
            Some(&device_name),
        )
    }

    async fn task_afc_client(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<TaskAfcClient, ()> {
        let port = exact_rsd_service_port(self.handshake(), AFC_SERVICE_NAME).ok_or(())?;
        let stream =
            tokio::time::timeout_at(deadline, self.provider_mut().connect_to_service_port(port))
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
        let client =
            tokio::time::timeout_at(deadline, <AfcClient as RsdService>::from_stream(stream))
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
        Ok(TaskAfcClient::new(client))
    }

    async fn installation_proxy_client(
        &mut self,
        deadline: tokio::time::Instant,
    ) -> Result<InstallationProxyClient, ()> {
        let service_name = InstallationProxyClient::rsd_service_name();
        let port = exact_rsd_service_port(self.handshake(), service_name.as_ref()).ok_or(())?;
        let stream =
            tokio::time::timeout_at(deadline, self.provider_mut().connect_to_service_port(port))
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
        tokio::time::timeout_at(
            deadline,
            <InstallationProxyClient as RsdService>::from_stream(stream),
        )
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
    }
}

fn exact_rsd_service_port(handshake: &RsdHandshake, service_name: &str) -> Option<u16> {
    handshake
        .services
        .get(service_name)
        .and_then(|service| (service.port != 0).then_some(service.port))
}

fn validate_rsd_identity(
    handshake_identity: Option<&plist::Value>,
    lockdown_identity: Option<&plist::Value>,
    device_name: Option<&plist::Value>,
) -> Result<crate::signing::SigningDeviceIdentity, RsdIdentityFailure> {
    let handshake_identity = handshake_identity
        .and_then(plist::Value::as_string)
        .filter(|value| !value.trim().is_empty() && value.len() <= 256)
        .ok_or(RsdIdentityFailure::HandshakeIdentity)?;
    let lockdown_identity = lockdown_identity
        .and_then(plist::Value::as_string)
        .filter(|value| !value.trim().is_empty() && value.len() <= 256)
        .ok_or(RsdIdentityFailure::LockdownIdentity)?;
    if handshake_identity != lockdown_identity {
        return Err(RsdIdentityFailure::IdentityMismatch);
    }
    let device_name = device_name
        .and_then(plist::Value::as_string)
        .filter(|value| !value.trim().is_empty() && value.len() <= 256)
        .ok_or(RsdIdentityFailure::DeviceName)?;
    crate::signing::SigningDeviceIdentity::new(device_name.to_owned(), lockdown_identity.to_owned())
        .map_err(|_| RsdIdentityFailure::DeviceName)
}

#[derive(Debug, Clone, PartialEq)]
enum SpikeInstallMutation {
    Install {
        package_path: String,
        options: plist::Value,
    },
}

fn installation_proxy_install_mutation(staging_app: &str) -> SpikeInstallMutation {
    let mut options = plist::Dictionary::new();
    options.insert(
        "PackageType".into(),
        plist::Value::String("Developer".into()),
    );
    SpikeInstallMutation::Install {
        package_path: staging_app.to_owned(),
        options: plist::Value::Dictionary(options),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallCommandFailure {
    Definitive,
    PossiblyAccepted,
}

async fn installed_bundle_lookup(
    client: &mut InstallationProxyClient,
    bundle_id: &str,
    deadline: tokio::time::Instant,
) -> Result<bool, ()> {
    let applications = tokio::time::timeout_at(
        deadline,
        client.get_apps(None, Some(vec![bundle_id.to_owned()])),
    )
    .await
    .map_err(|_| ())?
    .map_err(|_| ())?;
    Ok(applications.contains_key(bundle_id))
}

async fn send_one_install_command(
    client: &mut InstallationProxyClient,
    staging_app: &str,
    deadline: tokio::time::Instant,
) -> Result<(), InstallCommandFailure> {
    let mutation = installation_proxy_install_mutation(staging_app);
    let result = match mutation {
        SpikeInstallMutation::Install {
            package_path,
            options,
        } => tokio::time::timeout_at(deadline, client.install(package_path, Some(options))).await,
    };
    match result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(IdeviceError::InstallationProxy(InstallationProxyError::OperationFailed(_)))) => {
            Err(InstallCommandFailure::Definitive)
        }
        Ok(Err(_)) | Err(_) => Err(InstallCommandFailure::PossiblyAccepted),
    }
}

fn outcome_after_install_failure(
    failure: InstallCommandFailure,
    lookup: Result<bool, ()>,
) -> RsdInstallOutcome {
    match (failure, lookup) {
        (_, Ok(true)) => RsdInstallOutcome::Installed,
        (InstallCommandFailure::Definitive, Ok(false) | Err(())) => RsdInstallOutcome::NotInstalled,
        (InstallCommandFailure::PossiblyAccepted, Ok(false) | Err(())) => {
            RsdInstallOutcome::OutcomeUnknown
        }
    }
}

fn outcome_after_install_result(
    install_result: Result<(), InstallCommandFailure>,
    lookup: Result<bool, ()>,
) -> RsdInstallOutcome {
    match install_result {
        Ok(()) => match lookup {
            Ok(true) => RsdInstallOutcome::Installed,
            Ok(false) => RsdInstallOutcome::NotInstalled,
            Err(()) => RsdInstallOutcome::OutcomeUnknown,
        },
        Err(failure) => outcome_after_install_failure(failure, lookup),
    }
}
async fn verified_install_outcome(
    install_result: Result<(), InstallCommandFailure>,
    lookup: impl Future<Output = Result<bool, ()>>,
) -> RsdInstallOutcome {
    outcome_after_install_result(install_result, lookup.await)
}

fn install_cleanup_reserve() -> Duration {
    RSD_INSTALL_CLEANUP_TIMEOUT
        .checked_add(RSD_INSTALL_SESSION_CLEANUP_TIMEOUT)
        .unwrap_or(Duration::MAX)
}

fn install_work_deadline(
    overall_deadline: tokio::time::Instant,
    work_start: tokio::time::Instant,
) -> tokio::time::Instant {
    overall_deadline
        .checked_sub(install_cleanup_reserve())
        .unwrap_or(work_start)
}

fn install_verification_deadline(
    overall_deadline: tokio::time::Instant,
    verification_start: tokio::time::Instant,
) -> tokio::time::Instant {
    let overall_verification_limit = install_work_deadline(overall_deadline, verification_start);
    let timeout_limit = verification_start
        .checked_add(RSD_INSTALL_VERIFICATION_TIMEOUT)
        .unwrap_or(overall_verification_limit);
    overall_verification_limit.min(timeout_limit)
}
fn record_session_cleanup(report: &mut RsdInstallReport, session_cleanup: RsdSessionCleanup) {
    report.session_cleanup = session_cleanup;
    if session_cleanup == RsdSessionCleanup::Failed && report.error_kind.is_empty() {
        report.stage = RsdInstallStage::SessionCleanup;
        report.error_kind = "session_cleanup";
    }
}
async fn close_install_session(session: RemoteRsdSession<AdapterHandle>) -> RsdSessionCleanup {
    if matches!(
        timeout(RSD_INSTALL_SESSION_CLEANUP_TIMEOUT, session.close()).await,
        Ok(Ok(()))
    ) {
        RsdSessionCleanup::Succeeded
    } else {
        RsdSessionCleanup::Failed
    }
}

fn merge_session_cleanup(first: RsdSessionCleanup, second: RsdSessionCleanup) -> RsdSessionCleanup {
    if first == RsdSessionCleanup::Failed || second == RsdSessionCleanup::Failed {
        RsdSessionCleanup::Failed
    } else if first == RsdSessionCleanup::Succeeded || second == RsdSessionCleanup::Succeeded {
        RsdSessionCleanup::Succeeded
    } else {
        RsdSessionCleanup::NotNeeded
    }
}

fn schedule_artifact_cleanup(artifact: Option<crate::signing::SignedAppArtifact>) {
    if let Some(artifact) = artifact {
        drop(tokio::task::spawn_blocking(move || drop(artifact)));
    }
}

fn install_error_kind(
    install_result: Result<(), InstallCommandFailure>,
    outcome: RsdInstallOutcome,
) -> &'static str {
    match (install_result, outcome) {
        (_, RsdInstallOutcome::Installed) => "",
        (Ok(()), RsdInstallOutcome::NotInstalled) => "install_not_verified",
        (_, RsdInstallOutcome::NotInstalled) => "install_rejected",
        (_, RsdInstallOutcome::OutcomeUnknown) => "install_result_ambiguous",
        (_, RsdInstallOutcome::NotStarted) => unreachable!("install command was sent"),
    }
}
fn open_verified_upload_file(
    path: &Path,
    canonical_root: &Path,
    size: u64,
    identity: FileIdentity,
) -> Result<fs::File, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "source_changed")?;
    ensure_canonical_descendant(path, canonical_root).map_err(|_| "source_changed")?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != size
        || file_identity(&metadata) != Some(identity)
    {
        return Err("source_changed");
    }
    let file = fs::File::open(path).map_err(|_| "source_changed")?;
    let opened_metadata = file.metadata().map_err(|_| "source_changed")?;
    if !opened_metadata.is_file()
        || opened_metadata.len() != size
        || file_identity(&opened_metadata) != Some(identity)
    {
        return Err("source_changed");
    }
    Ok(file)
}

async fn stage_signed_bundle(
    client: &mut TaskAfcClient,
    staging: &TaskStagingPath,
    plan: &SignedBundleUploadPlan,
    root_created: &mut bool,
) -> Result<(), &'static str> {
    if !client
        .is_directory("PublicStaging")
        .await
        .map_err(|_| "public_staging_query")?
    {
        return Err("public_staging_invalid");
    }
    if client
        .path_exists(&staging.root)
        .await
        .map_err(|_| "staging_precheck")?
    {
        return Err("staging_root_exists");
    }
    *root_created = true;
    client
        .make_directory(&staging.root)
        .await
        .map_err(|_| "staging_root_create")?;
    client
        .make_directory(&staging.app)
        .await
        .map_err(|_| "staging_app_create")?;

    for entry in &plan.entries {
        let remote_path = format!("{}/{}", staging.app, entry.remote_relative_path);
        match entry.kind {
            UploadEntryKind::Directory { identity } => {
                let metadata =
                    fs::symlink_metadata(&entry.local_path).map_err(|_| "source_changed")?;
                ensure_canonical_descendant(&entry.local_path, &plan.canonical_root)
                    .map_err(|_| "source_changed")?;
                if metadata.file_type().is_symlink()
                    || !metadata.is_dir()
                    || file_identity(&metadata) != Some(identity)
                {
                    return Err("source_changed");
                }
                client
                    .make_directory(&remote_path)
                    .await
                    .map_err(|_| "staging_directory_create")?;
            }
            UploadEntryKind::File {
                size,
                identity,
                digest,
            } => {
                let local_file = open_verified_upload_file(
                    &entry.local_path,
                    &plan.canonical_root,
                    size,
                    identity,
                )?;
                let descriptor = client
                    .open_for_write(&remote_path)
                    .await
                    .map_err(|_| "staging_file_open")?;
                let write_result = async {
                    let mut file = tokio::fs::File::from_std(local_file);
                    let mut written = 0_u64;
                    let mut actual_digest = Sha256::new();
                    let mut buffer = vec![0_u8; RSD_INSTALL_TRANSFER_CHUNK];
                    loop {
                        let count = file.read(&mut buffer).await.map_err(|_| "source_read")?;
                        if count == 0 {
                            break;
                        }
                        written = written.checked_add(count as u64).ok_or("source_changed")?;
                        if written > size {
                            return Err("source_changed");
                        }
                        actual_digest.update(&buffer[..count]);
                        client
                            .write(descriptor, buffer[..count].to_vec())
                            .await
                            .map_err(|_| "staging_file_write")?;
                    }
                    let final_metadata = file.metadata().await.map_err(|_| "source_changed")?;
                    if written != size
                        || final_metadata.len() != size
                        || file_identity(&final_metadata) != Some(identity)
                        || <[u8; 32]>::from(actual_digest.finalize()) != digest
                    {
                        return Err("source_changed");
                    }
                    Ok(())
                }
                .await;
                let close_result = client.close(descriptor).await;
                write_result?;
                close_result.map_err(|_| "staging_file_close")?;
            }
        }
    }
    Ok(())
}

async fn clean_exact_task_staging(
    session: &mut RemoteRsdSession<AdapterHandle>,
    staging: &TaskStagingPath,
    root_created: bool,
) -> RsdStagingCleanup {
    if !root_created {
        return RsdStagingCleanup::NotNeeded;
    }
    if !staging.is_exact_task_root(&staging.root) {
        return RsdStagingCleanup::Failed;
    }
    let deadline = tokio::time::Instant::now() + RSD_INSTALL_CLEANUP_TIMEOUT;
    let mut client = match session.task_afc_client(deadline).await {
        Ok(client) => client,
        Err(()) => return RsdStagingCleanup::Failed,
    };
    match tokio::time::timeout_at(deadline, client.remove_all(&staging.root)).await {
        Ok(Ok(())) => RsdStagingCleanup::Succeeded,
        Ok(Err(IdeviceError::Afc(AfcError::ObjectNotFound))) => RsdStagingCleanup::Succeeded,
        Ok(Err(_)) | Err(_) => RsdStagingCleanup::Failed,
    }
}

fn rsd_install_failure(
    stage: RsdInstallStage,
    error_kind: &'static str,
    certificate_pressure: bool,
    bundle_id: Option<String>,
) -> RsdInstallReport {
    RsdInstallReport {
        outcome: RsdInstallOutcome::NotStarted,
        stage,
        cleanup: RsdStagingCleanup::NotNeeded,
        session_cleanup: RsdSessionCleanup::NotNeeded,
        install_command_count: 0,
        error_kind,
        bundle_id,
        certificate_pressure,
    }
}

fn signing_error_kind(error: &crate::signing::SigningError) -> &'static str {
    match error {
        crate::signing::SigningError::NotReady => "signing_not_ready",
        crate::signing::SigningError::DeviceRegistrationRequired => "device_registration_required",
        crate::signing::SigningError::DeveloperTeamFailed => "account_preflight",
        crate::signing::SigningError::SignedMetadataFailed => "signed_metadata",
        _ => "signing_failed",
    }
}

async fn execute_rsd_first_install(
    session: &mut RemoteRsdSession<AdapterHandle>,
    bundle_id: String,
    certificate_pressure: bool,
    deadline: tokio::time::Instant,
    artifact_cleanup: &mut Option<crate::signing::SignedAppArtifact>,
) -> RsdInstallReport {
    let work_deadline = install_work_deadline(deadline, tokio::time::Instant::now());

    let mut installation_proxy = match session.installation_proxy_client(work_deadline).await {
        Ok(client) => client,
        Err(()) => {
            return rsd_install_failure(
                RsdInstallStage::AlreadyInstalled,
                "installation_proxy",
                certificate_pressure,
                Some(bundle_id),
            );
        }
    };
    match installed_bundle_lookup(&mut installation_proxy, &bundle_id, work_deadline).await {
        Ok(true) => {
            return rsd_install_failure(
                RsdInstallStage::AlreadyInstalled,
                "app_already_installed",
                certificate_pressure,
                Some(bundle_id),
            );
        }
        Ok(false) => {}
        Err(()) => {
            return rsd_install_failure(
                RsdInstallStage::AlreadyInstalled,
                "installed_app_lookup",
                certificate_pressure,
                Some(bundle_id),
            );
        }
    }
    drop(installation_proxy);

    let artifact = artifact_cleanup
        .take()
        .expect("signed artifact remains owned until cleanup");
    let planning_task = tokio::task::spawn_blocking(move || {
        let artifact_path = artifact.app_bundle_path().to_path_buf();
        let plan = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            plan_signed_bundle_until(&artifact_path, Some(work_deadline.into_std()))
        }))
        .unwrap_or(Err(UploadPlanFailure::LocalIo));
        (artifact, plan)
    });
    let plan = match tokio::time::timeout_at(work_deadline, planning_task).await {
        Ok(Ok((artifact, Ok(plan)))) => {
            *artifact_cleanup = Some(artifact);
            plan
        }
        Ok(Ok((artifact, Err(failure)))) => {
            *artifact_cleanup = Some(artifact);
            return rsd_install_failure(
                RsdInstallStage::Staging,
                failure.kind(),
                certificate_pressure,
                Some(bundle_id),
            );
        }
        Ok(Err(_)) => {
            return rsd_install_failure(
                RsdInstallStage::Staging,
                "local_task",
                certificate_pressure,
                Some(bundle_id),
            );
        }
        Err(_) => {
            return rsd_install_failure(
                RsdInstallStage::Staging,
                "timeout",
                certificate_pressure,
                Some(bundle_id),
            );
        }
    };
    let staging = TaskStagingPath::new(Uuid::new_v4());
    let mut afc = match session.task_afc_client(work_deadline).await {
        Ok(client) => client,
        Err(()) => {
            return rsd_install_failure(
                RsdInstallStage::Staging,
                "afc_service",
                certificate_pressure,
                Some(bundle_id),
            );
        }
    };
    let mut root_created = false;
    let staging_result = tokio::time::timeout_at(
        work_deadline,
        stage_signed_bundle(&mut afc, &staging, &plan, &mut root_created),
    )
    .await;
    drop(afc);

    let mut report = match staging_result {
        Ok(Ok(())) => {
            let install_window_start = tokio::time::Instant::now();
            let overall_verification_limit = install_work_deadline(deadline, install_window_start);
            let install_deadline = overall_verification_limit
                .checked_sub(RSD_INSTALL_VERIFICATION_TIMEOUT)
                .unwrap_or(overall_verification_limit);
            if tokio::time::Instant::now() >= install_deadline {
                let mut report = rsd_install_failure(
                    RsdInstallStage::Install,
                    "timeout",
                    certificate_pressure,
                    Some(bundle_id.clone()),
                );
                report.outcome = RsdInstallOutcome::NotInstalled;
                report.cleanup = clean_exact_task_staging(session, &staging, root_created).await;
                return report;
            }
            let mut client = match session.installation_proxy_client(install_deadline).await {
                Ok(client) => client,
                Err(()) => {
                    let mut report = rsd_install_failure(
                        RsdInstallStage::Install,
                        "installation_proxy",
                        certificate_pressure,
                        Some(bundle_id.clone()),
                    );
                    report.outcome = RsdInstallOutcome::NotInstalled;
                    report.cleanup =
                        clean_exact_task_staging(session, &staging, root_created).await;
                    return report;
                }
            };
            let install_result =
                send_one_install_command(&mut client, &staging.app, install_deadline).await;
            drop(client);

            let verification_deadline =
                install_verification_deadline(deadline, tokio::time::Instant::now());
            let outcome = verified_install_outcome(install_result, async {
                if tokio::time::Instant::now() >= verification_deadline {
                    return Err(());
                }
                match session
                    .installation_proxy_client(verification_deadline)
                    .await
                {
                    Ok(mut verification_client) => {
                        installed_bundle_lookup(
                            &mut verification_client,
                            &bundle_id,
                            verification_deadline,
                        )
                        .await
                    }
                    Err(()) => Err(()),
                }
            })
            .await;
            let (stage, error_kind) = match outcome {
                RsdInstallOutcome::Installed => (RsdInstallStage::Complete, ""),
                RsdInstallOutcome::NotInstalled | RsdInstallOutcome::OutcomeUnknown => (
                    RsdInstallStage::Verification,
                    install_error_kind(install_result, outcome),
                ),
                RsdInstallOutcome::NotStarted => unreachable!("install command was sent"),
            };
            RsdInstallReport {
                outcome,
                stage,
                cleanup: RsdStagingCleanup::NotNeeded,
                session_cleanup: RsdSessionCleanup::NotNeeded,
                install_command_count: 1,
                error_kind,
                bundle_id: Some(bundle_id.clone()),
                certificate_pressure,
            }
        }
        Ok(Err(error_kind)) => {
            let mut report = rsd_install_failure(
                RsdInstallStage::Staging,
                error_kind,
                certificate_pressure,
                Some(bundle_id.clone()),
            );
            report.outcome = RsdInstallOutcome::NotInstalled;
            report
        }
        Err(_) => {
            let mut report = rsd_install_failure(
                RsdInstallStage::Staging,
                "timeout",
                certificate_pressure,
                Some(bundle_id.clone()),
            );
            report.outcome = RsdInstallOutcome::NotInstalled;
            report
        }
    };

    report.cleanup = clean_exact_task_staging(session, &staging, root_created).await;
    if report.cleanup == RsdStagingCleanup::Failed && report.error_kind.is_empty() {
        report.stage = RsdInstallStage::Cleanup;
        report.error_kind = "staging_cleanup";
    }
    report
}

fn read_only_probe_failure(
    service: ReadOnlyProbeService,
    stage: ReadOnlyProbeStage,
    operation: &'static str,
    result: &'static str,
    error_kind: &'static str,
) -> ReadOnlyProbeFailure {
    tracing::warn!(
        target: "iphoneloadly_api::spike_diagnostics",
        transport = "rsd",
        service = service.as_str(),
        stage = stage.as_str(),
        operation,
        result,
        error_kind,
        "remote pairing read-only probe failed"
    );
    ReadOnlyProbeFailure { stage }
}

#[cfg(test)]
pub(crate) fn emit_spike_diagnostic_for_filter_test() {
    let _ = read_only_probe_failure(
        ReadOnlyProbeService::Afc,
        ReadOnlyProbeStage::ServiceLookup,
        "service_lookup",
        "missing",
        "service_not_found",
    );
}

async fn run_read_only_probe_step<T>(
    service: ReadOnlyProbeService,
    stage: ReadOnlyProbeStage,
    operation: &'static str,
    timeout_duration: Duration,
    future: impl Future<Output = Result<T, idevice::IdeviceError>>,
) -> Result<T, ReadOnlyProbeFailure> {
    match timeout(timeout_duration, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(read_only_probe_failure(
            service,
            stage,
            operation,
            "error",
            idevice_error_kind(&error),
        )),
        Err(_) => Err(read_only_probe_failure(
            service, stage, operation, "timeout", "timeout",
        )),
    }
}

async fn complete_read_only_probe_with_timeout<P: ClosableRsdProvider>(
    service: ReadOnlyProbeService,
    primary: Result<(), ReadOnlyProbeFailure>,
    session: RemoteRsdSession<P>,
    cleanup_timeout: Duration,
) -> Result<(), ReadOnlyProbeFailure> {
    let cleanup_failure = match timeout(cleanup_timeout, session.close()).await {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(read_only_probe_failure(
            service,
            ReadOnlyProbeStage::Cleanup,
            "cleanup",
            "error",
            io_error_kind(&error),
        )),
        Err(_) => Some(read_only_probe_failure(
            service,
            ReadOnlyProbeStage::Cleanup,
            "cleanup",
            "timeout",
            "timeout",
        )),
    };

    match primary {
        Err(failure) => Err(failure),
        Ok(()) => cleanup_failure.map_or(Ok(()), Err),
    }
}

fn probe_failure(stage: RsdProbeStage) -> RsdProbeFailure {
    RsdProbeFailure {
        stage,
        session_cleanup: RsdSessionCleanup::NotNeeded,
    }
}

fn report_appservice_setup_failure(failure: RsdProbeFailure) -> RsdProbeFailure {
    tracing::debug!(
        target: "iphoneloadly_api::spike_diagnostics",
        stage = failure.stage.as_str(),
        "remote pairing RSD probe failed"
    );
    failure
}

fn parsed_rsd_service_summary(handshake: &RsdHandshake) -> ParsedRsdServiceSummary {
    ParsedRsdServiceSummary {
        parsed_appservice_present: handshake
            .services
            .contains_key(CORE_DEVICE_APP_SERVICE_NAME),
        parsed_deviceinfo_present: handshake
            .services
            .contains_key(CORE_DEVICE_INFO_SERVICE_NAME),
        parsed_untrusted_tunnelservice_present: handshake
            .services
            .contains_key(TUNNEL_SERVICE_NAME),
        parsed_image_mounter_present: handshake
            .services
            .contains_key(MOBILE_IMAGE_MOUNTER_SERVICE_NAME),
        parsed_installation_proxy_present: handshake
            .services
            .contains_key(INSTALLATION_PROXY_SERVICE_NAME),
        parsed_afc_present: handshake.services.contains_key(AFC_SERVICE_NAME),
    }
}

fn report_parsed_rsd_service_summary(summary: ParsedRsdServiceSummary) {
    tracing::warn!(
        target: "iphoneloadly_api::spike_diagnostics",
        stage = RsdProbeStage::CoreDeviceService.as_str(),
        operation = "service_summary",
        result = "observed",
        source = "parsed_rsd_services",
        parsed_appservice_present = summary.parsed_appservice_present,
        parsed_deviceinfo_present = summary.parsed_deviceinfo_present,
        parsed_untrusted_tunnelservice_present = summary.parsed_untrusted_tunnelservice_present,
        parsed_image_mounter_present = summary.parsed_image_mounter_present,
        parsed_installation_proxy_present = summary.parsed_installation_proxy_present,
        parsed_afc_present = summary.parsed_afc_present,
        "remote pairing parsed RSD service summary"
    );
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
        target: "iphoneloadly_api::spike_diagnostics",
        stage = RsdProbeStage::CoreDeviceService.as_str(),
        operation = failure.operation.as_str(),
        result = failure.result,
        error_kind = failure.error_kind,
        appservice_present = failure.appservice_present,
        "remote pairing CoreDevice service probe failed"
    );
    RsdProbeFailure {
        stage: RsdProbeStage::CoreDeviceService,
        session_cleanup: RsdSessionCleanup::NotNeeded,
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
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::{
            Arc as StdArc, Mutex as StdMutex,
            atomic::{AtomicUsize, Ordering},
        },
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tracing::{
        Event, Subscriber,
        field::{Field, Visit},
    };
    use tracing_subscriber::{
        Layer,
        layer::{Context, SubscriberExt},
        registry::LookupSpan,
    };

    #[derive(Clone, Debug)]
    struct CapturedEvent {
        level: tracing::Level,
        target: String,
        fields: BTreeMap<String, String>,
    }

    impl Visit for CapturedEvent {
        fn record_bool(&mut self, field: &Field, value: bool) {
            self.fields
                .insert(field.name().to_owned(), value.to_string());
        }

        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .insert(field.name().to_owned(), value.to_owned());
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .insert(field.name().to_owned(), format!("{value:?}"));
        }
    }

    #[derive(Clone)]
    struct EventCapture {
        events: StdArc<StdMutex<Vec<CapturedEvent>>>,
    }

    impl<S> Layer<S> for EventCapture
    where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            let mut captured = CapturedEvent {
                level: *event.metadata().level(),
                target: event.metadata().target().to_owned(),
                fields: BTreeMap::new(),
            };
            event.record(&mut captured);
            self.events
                .lock()
                .expect("capture tracing event")
                .push(captured);
        }
    }

    fn capture_events<T>(run: impl FnOnce() -> T) -> (T, Vec<CapturedEvent>) {
        let events = StdArc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(EventCapture {
            events: events.clone(),
        });
        let result = tracing::subscriber::with_default(subscriber, run);
        let captured = events.lock().expect("read captured tracing events").clone();
        (result, captured)
    }

    #[test]
    fn rsd_identity_requires_matching_bounded_lockdown_values() {
        let handshake = plist::Value::String("device-identity".into());
        let lockdown = plist::Value::String("device-identity".into());
        let name = plist::Value::String("Test iPhone".into());
        assert!(validate_rsd_identity(Some(&handshake), Some(&lockdown), Some(&name)).is_ok());

        assert_eq!(
            validate_rsd_identity(None, Some(&lockdown), Some(&name)).err(),
            Some(RsdIdentityFailure::HandshakeIdentity)
        );
        assert_eq!(
            validate_rsd_identity(
                Some(&handshake),
                Some(&plist::Value::Integer(1_u64.into())),
                Some(&name),
            )
            .err(),
            Some(RsdIdentityFailure::LockdownIdentity)
        );
        assert_eq!(
            validate_rsd_identity(
                Some(&handshake),
                Some(&plist::Value::String("other-device".into())),
                Some(&name),
            )
            .err(),
            Some(RsdIdentityFailure::IdentityMismatch)
        );
        assert_eq!(
            validate_rsd_identity(
                Some(&handshake),
                Some(&lockdown),
                Some(&plist::Value::String(String::new())),
            )
            .err(),
            Some(RsdIdentityFailure::DeviceName)
        );
    }

    #[test]
    fn task_staging_path_is_fixed_unique_and_cleanup_scoped() {
        let first =
            TaskStagingPath::new(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap());
        let second =
            TaskStagingPath::new(Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap());
        assert_eq!(
            first.root,
            "PublicStaging/iphoneloadly-spike-00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(first.app, format!("{}/Signed.app", first.root));
        assert_ne!(first.root, second.root);
        assert!(first.is_exact_task_root(&first.root));
        assert!(!first.is_exact_task_root("PublicStaging"));
        assert!(!first.is_exact_task_root("PublicStaging/iphoneloadly-spike-../../escape"));
    }

    #[test]
    fn upload_paths_and_resource_bounds_reject_unsafe_or_oversized_trees() {
        assert_eq!(
            safe_remote_relative_path(Path::new("Frameworks/Library.dylib")).unwrap(),
            "Frameworks/Library.dylib"
        );
        assert_eq!(
            safe_remote_relative_path(Path::new("../escape")),
            Err(UploadPlanFailure::UnsafePath)
        );
        assert!(validate_upload_bounds(RSD_INSTALL_FILE_LIMIT, RSD_INSTALL_BYTE_LIMIT).is_ok());
        assert_eq!(
            validate_upload_bounds(RSD_INSTALL_FILE_LIMIT + 1, 0),
            Err(UploadPlanFailure::TooManyEntries)
        );
        assert_eq!(
            validate_upload_bounds(0, RSD_INSTALL_BYTE_LIMIT + 1),
            Err(UploadPlanFailure::TooManyBytes)
        );
    }
    #[test]
    fn upload_plan_honors_expired_deadline() {
        let root = temp_state_dir("upload-timeout").join("Signed.app");
        fs::create_dir_all(&root).expect("create signed tree");
        assert_eq!(
            plan_signed_bundle_until(&root, Some(Instant::now())),
            Err(UploadPlanFailure::Timeout)
        );
        fs::remove_dir_all(root.parent().expect("test root")).expect("remove upload test tree");
    }

    #[test]
    fn upload_plan_rejects_a_replaced_file_before_follow_open() {
        let root = temp_state_dir("upload-replacement").join("Signed.app");
        fs::create_dir_all(&root).expect("create signed tree");
        let executable = root.join("Executable");
        fs::write(&executable, b"original").expect("write original file");
        let plan = plan_signed_bundle(&root).expect("plan signed tree");
        let entry = plan
            .entries
            .iter()
            .find(|entry| entry.remote_relative_path == "Executable")
            .expect("planned executable");
        let UploadEntryKind::File { size, identity, .. } = entry.kind else {
            panic!("executable must be a file");
        };
        assert!(
            open_verified_upload_file(&entry.local_path, &plan.canonical_root, size, identity)
                .is_ok()
        );

        fs::rename(&executable, root.join("Original")).expect("move original");
        fs::write(&executable, b"replacement").expect("write replacement");
        assert_eq!(
            open_verified_upload_file(&entry.local_path, &plan.canonical_root, size, identity)
                .err(),
            Some("source_changed")
        );
        fs::remove_dir_all(root.parent().expect("test root")).expect("remove upload test tree");
    }

    #[cfg(unix)]
    #[test]
    fn upload_plan_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let root = temp_state_dir("upload-symlink").join("Signed.app");
        fs::create_dir_all(&root).expect("create signed tree");
        fs::write(root.join("Target"), b"target").expect("write target");
        symlink(root.join("Target"), root.join("Link")).expect("create symlink");
        assert_eq!(
            plan_signed_bundle(&root),
            Err(UploadPlanFailure::SourceSymlink)
        );
        fs::remove_dir_all(root.parent().expect("test root")).expect("remove upload test tree");
    }

    #[test]
    fn spike_install_mutation_is_install_only_and_developer_typed() {
        let mutation =
            installation_proxy_install_mutation("PublicStaging/iphoneloadly-spike-task/Signed.app");
        let SpikeInstallMutation::Install {
            package_path,
            options,
        } = mutation;
        assert_eq!(
            package_path,
            "PublicStaging/iphoneloadly-spike-task/Signed.app"
        );
        assert_eq!(
            options
                .as_dictionary()
                .and_then(|value| value.get("PackageType"))
                .and_then(plist::Value::as_string),
            Some("Developer")
        );
    }

    #[test]
    fn possible_install_acceptance_is_classified_without_retry() {
        assert_eq!(
            outcome_after_install_failure(InstallCommandFailure::PossiblyAccepted, Ok(true)),
            RsdInstallOutcome::Installed
        );
        assert_eq!(
            outcome_after_install_failure(InstallCommandFailure::PossiblyAccepted, Ok(false)),
            RsdInstallOutcome::OutcomeUnknown
        );
        assert_eq!(
            outcome_after_install_failure(InstallCommandFailure::PossiblyAccepted, Err(())),
            RsdInstallOutcome::OutcomeUnknown
        );
        assert_eq!(
            outcome_after_install_failure(InstallCommandFailure::Definitive, Ok(false)),
            RsdInstallOutcome::NotInstalled
        );
        let failure = rsd_install_failure(RsdInstallStage::Install, "send_failed", false, None);
        assert_eq!(failure.install_command_count, 0);
    }
    #[test]
    fn every_install_result_requires_exact_bundle_verification() {
        assert_eq!(
            outcome_after_install_result(Ok(()), Ok(true)),
            RsdInstallOutcome::Installed
        );
        assert_eq!(
            outcome_after_install_result(Ok(()), Ok(false)),
            RsdInstallOutcome::NotInstalled
        );
        assert_eq!(
            outcome_after_install_result(Ok(()), Err(())),
            RsdInstallOutcome::OutcomeUnknown
        );
        assert_eq!(
            outcome_after_install_result(Err(InstallCommandFailure::Definitive), Ok(true)),
            RsdInstallOutcome::Installed
        );
        assert_eq!(
            outcome_after_install_result(Err(InstallCommandFailure::PossiblyAccepted), Ok(true)),
            RsdInstallOutcome::Installed
        );
    }
    #[tokio::test]
    async fn successful_install_still_executes_exact_bundle_lookup() {
        let lookups = AtomicUsize::new(0);
        let outcome = verified_install_outcome(Ok(()), async {
            lookups.fetch_add(1, Ordering::SeqCst);
            Ok(false)
        })
        .await;
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
        assert_eq!(outcome, RsdInstallOutcome::NotInstalled);
    }

    #[test]
    fn post_install_verification_deadline_is_bounded_by_timeout_and_reserve() {
        let start = tokio::time::Instant::now();
        assert_eq!(install_cleanup_reserve(), Duration::from_secs(20));

        let bounded = install_verification_deadline(start + Duration::from_secs(60), start);
        assert_eq!(bounded, start + RSD_INSTALL_VERIFICATION_TIMEOUT);

        let reserve_limited = install_verification_deadline(start + Duration::from_secs(28), start);
        assert_eq!(reserve_limited, start + Duration::from_secs(8));

        let no_safe_window = install_verification_deadline(start + Duration::from_secs(15), start);
        assert!(no_safe_window < start);

        let delayed_start = start + Duration::from_secs(5);
        let delayed = install_verification_deadline(start + Duration::from_secs(60), delayed_start);
        assert_eq!(delayed, delayed_start + RSD_INSTALL_VERIFICATION_TIMEOUT);
    }

    #[test]
    fn session_cleanup_failure_preserves_staging_cleanup_diagnostic() {
        let mut report = RsdInstallReport {
            outcome: RsdInstallOutcome::Installed,
            stage: RsdInstallStage::Cleanup,
            cleanup: RsdStagingCleanup::Failed,
            session_cleanup: RsdSessionCleanup::NotNeeded,
            install_command_count: 1,
            error_kind: "staging_cleanup",
            bundle_id: Some("com.example.test".into()),
            certificate_pressure: false,
        };
        record_session_cleanup(&mut report, RsdSessionCleanup::Failed);
        assert_eq!(report.outcome, RsdInstallOutcome::Installed);
        assert_eq!(report.cleanup, RsdStagingCleanup::Failed);
        assert_eq!(report.session_cleanup, RsdSessionCleanup::Failed);
        assert_eq!(report.error_kind, "staging_cleanup");
    }
    #[test]
    fn multiple_session_cleanup_attempts_preserve_any_failure() {
        assert_eq!(
            merge_session_cleanup(RsdSessionCleanup::Succeeded, RsdSessionCleanup::NotNeeded,),
            RsdSessionCleanup::Succeeded
        );
        assert_eq!(
            merge_session_cleanup(RsdSessionCleanup::Succeeded, RsdSessionCleanup::Failed),
            RsdSessionCleanup::Failed
        );
        assert_eq!(
            merge_session_cleanup(RsdSessionCleanup::NotNeeded, RsdSessionCleanup::NotNeeded),
            RsdSessionCleanup::NotNeeded
        );
    }

    fn test_rsd_handshake() -> RsdHandshake {
        RsdHandshake {
            services: std::collections::HashMap::new(),
            protocol_version: 7,
            properties: std::collections::HashMap::new(),
            uuid: String::new(),
        }
    }

    fn test_rsd_service(
        entitlement: impl Into<String>,
        port: u16,
    ) -> idevice::services::rsd::RsdService {
        idevice::services::rsd::RsdService {
            entitlement: entitlement.into(),
            port,
            uses_remote_xpc: true,
            features: Some(vec!["sentinel-feature".into()]),
            service_version: Some(1),
        }
    }

    fn summary_values(summary: ParsedRsdServiceSummary) -> [bool; 6] {
        [
            summary.parsed_appservice_present,
            summary.parsed_deviceinfo_present,
            summary.parsed_untrusted_tunnelservice_present,
            summary.parsed_image_mounter_present,
            summary.parsed_installation_proxy_present,
            summary.parsed_afc_present,
        ]
    }

    async fn read_framed_plist(stream: &mut tokio::io::DuplexStream) -> plist::Dictionary {
        let length = stream.read_u32().await.expect("read plist length");
        let mut body = vec![0; length as usize];
        stream.read_exact(&mut body).await.expect("read plist body");
        plist::from_bytes::<plist::Value>(&body)
            .expect("parse plist")
            .into_dictionary()
            .expect("plist dictionary")
    }

    async fn write_framed_plist(stream: &mut tokio::io::DuplexStream, value: plist::Value) {
        let mut body = Vec::new();
        value
            .to_writer_xml(&mut body)
            .expect("serialize plist response");
        stream
            .write_all(&(body.len() as u32).to_be_bytes())
            .await
            .expect("write plist length");
        stream.write_all(&body).await.expect("write plist body");
    }

    async fn serve_rsd_checkin(stream: &mut tokio::io::DuplexStream) {
        let request = read_framed_plist(stream).await;
        assert_eq!(
            request.get("Request").and_then(plist::Value::as_string),
            Some("RSDCheckin")
        );
        assert_eq!(
            request
                .get("ProtocolVersion")
                .and_then(plist::Value::as_string),
            Some("2")
        );
        for request_name in ["RSDCheckin", "StartService"] {
            write_framed_plist(
                stream,
                plist::Value::Dictionary(
                    [(
                        "Request".to_owned(),
                        plist::Value::String(request_name.to_owned()),
                    )]
                    .into_iter()
                    .collect(),
                ),
            )
            .await;
        }
    }

    async fn assert_stream_closed_after_one_query(stream: &mut tokio::io::DuplexStream) {
        let mut extra = [0; 1];
        let read = timeout(Duration::from_secs(1), stream.read(&mut extra))
            .await
            .expect("client closes after one query")
            .expect("read post-query EOF");
        assert_eq!(read, 0, "probe sent more than one request");
    }

    async fn run_afc_fixture(
        response_payload: Option<Vec<u8>>,
    ) -> (Result<idevice::afc::DeviceInfo, idevice::IdeviceError>, u64) {
        let (client_stream, mut server_stream) = tokio::io::duplex(4096);
        let client = async move {
            let mut client =
                <AfcClient as RsdService>::from_stream(Box::new(client_stream)).await?;
            client.get_device_info().await
        };
        let server = async move {
            serve_rsd_checkin(&mut server_stream).await;
            let mut request = [0; idevice::afc::packet::AfcPacketHeader::LEN as usize];
            server_stream
                .read_exact(&mut request)
                .await
                .expect("read AFC request");
            let magic = u64::from_le_bytes(request[0..8].try_into().unwrap());
            let entire_len = u64::from_le_bytes(request[8..16].try_into().unwrap());
            let header_payload_len = u64::from_le_bytes(request[16..24].try_into().unwrap());
            let opcode = u64::from_le_bytes(request[32..40].try_into().unwrap());
            assert_eq!(magic, idevice::afc::MAGIC);
            assert_eq!(entire_len, idevice::afc::packet::AfcPacketHeader::LEN);
            assert_eq!(
                header_payload_len,
                idevice::afc::packet::AfcPacketHeader::LEN
            );

            if let Some(payload) = response_payload {
                let packet = idevice::afc::packet::AfcPacket {
                    header: idevice::afc::packet::AfcPacketHeader {
                        magic: idevice::afc::MAGIC,
                        entire_len: idevice::afc::packet::AfcPacketHeader::LEN
                            + payload.len() as u64,
                        header_payload_len: idevice::afc::packet::AfcPacketHeader::LEN,
                        packet_num: 0,
                        operation: idevice::afc::opcode::AfcOpcode::Data,
                    },
                    header_payload: Vec::new(),
                    payload,
                };
                server_stream
                    .write_all(&packet.serialize())
                    .await
                    .expect("write AFC response");
                assert_stream_closed_after_one_query(&mut server_stream).await;
            }
            opcode
        };
        let (result, opcode) = tokio::join!(client, server);
        (result, opcode)
    }

    enum PlistFixtureReply {
        Value(plist::Value),
        Incomplete,
    }

    async fn run_installation_proxy_fixture(
        reply: PlistFixtureReply,
    ) -> (
        Result<std::collections::HashMap<String, plist::Value>, idevice::IdeviceError>,
        plist::Dictionary,
    ) {
        let (client_stream, mut server_stream) = tokio::io::duplex(4096);
        let client = async move {
            let mut client =
                <InstallationProxyClient as RsdService>::from_stream(Box::new(client_stream))
                    .await?;
            client.get_apps(Some("User"), None).await
        };
        let server = async move {
            serve_rsd_checkin(&mut server_stream).await;
            let request = read_framed_plist(&mut server_stream).await;
            match reply {
                PlistFixtureReply::Value(value) => {
                    write_framed_plist(&mut server_stream, value).await;
                    assert_stream_closed_after_one_query(&mut server_stream).await;
                }
                PlistFixtureReply::Incomplete => {
                    server_stream
                        .write_all(&8_u32.to_be_bytes())
                        .await
                        .expect("write truncated plist length");
                    server_stream
                        .write_all(b"trunc")
                        .await
                        .expect("write truncated plist");
                }
            }
            request
        };
        tokio::join!(client, server)
    }

    #[derive(Clone, Copy)]
    enum TestCloseOutcome {
        Success,
        Error,
        Pending,
    }

    struct TestCloseProvider {
        outcome: TestCloseOutcome,
        close_calls: StdArc<AtomicUsize>,
        drops: StdArc<AtomicUsize>,
    }

    impl ClosableRsdProvider for TestCloseProvider {
        async fn close_provider(&mut self) -> Result<(), std::io::Error> {
            self.close_calls.fetch_add(1, Ordering::SeqCst);
            match self.outcome {
                TestCloseOutcome::Success => Ok(()),
                TestCloseOutcome::Error => Err(std::io::Error::other("synthetic close failure")),
                TestCloseOutcome::Pending => std::future::pending().await,
            }
        }
    }

    impl Drop for TestCloseProvider {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    fn test_remote_session(
        outcome: TestCloseOutcome,
        close_calls: StdArc<AtomicUsize>,
        drops: StdArc<AtomicUsize>,
    ) -> RemoteRsdSession<TestCloseProvider> {
        RemoteRsdSession {
            provider: Some(TestCloseProvider {
                outcome,
                close_calls,
                drops,
            }),
            handshake: None,
        }
    }

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
    fn parsed_rsd_service_summary_uses_only_six_exact_names() {
        let service_names = [
            CORE_DEVICE_APP_SERVICE_NAME,
            CORE_DEVICE_INFO_SERVICE_NAME,
            TUNNEL_SERVICE_NAME,
            MOBILE_IMAGE_MOUNTER_SERVICE_NAME,
            INSTALLATION_PROXY_SERVICE_NAME,
            AFC_SERVICE_NAME,
        ];

        let empty = test_rsd_handshake();
        assert_eq!(
            summary_values(parsed_rsd_service_summary(&empty)),
            [false; 6]
        );

        for (index, service_name) in service_names.iter().enumerate() {
            let mut handshake = test_rsd_handshake();
            handshake.services.insert(
                (*service_name).to_owned(),
                test_rsd_service("sentinel-entitlement", 62_000 + index as u16),
            );
            let mut expected = [false; 6];
            expected[index] = true;
            assert_eq!(
                summary_values(parsed_rsd_service_summary(&handshake)),
                expected,
                "incorrect projection for {service_name}"
            );
        }

        let mut all = test_rsd_handshake();
        for (index, service_name) in service_names.iter().enumerate() {
            all.services.insert(
                (*service_name).to_owned(),
                test_rsd_service("sentinel-entitlement", 62_100 + index as u16),
            );
        }
        assert_eq!(summary_values(parsed_rsd_service_summary(&all)), [true; 6]);

        let mut mixed = test_rsd_handshake();
        for index in [0, 2, 5] {
            mixed.services.insert(
                service_names[index].to_owned(),
                test_rsd_service("sentinel-entitlement", 62_200 + index as u16),
            );
        }
        mixed.services.insert(
            format!("{CORE_DEVICE_APP_SERVICE_NAME}.unexpected"),
            test_rsd_service("sentinel-entitlement", 62_300),
        );
        mixed.services.insert(
            "sentinel-unknown-service".into(),
            test_rsd_service("sentinel-entitlement", 62_301),
        );
        assert_eq!(
            summary_values(parsed_rsd_service_summary(&mixed)),
            [true, false, true, false, false, true]
        );

        let before = mixed.services.keys().cloned().collect::<BTreeSet<String>>();
        let _ = parsed_rsd_service_summary(&mixed);
        assert_eq!(
            mixed.services.keys().cloned().collect::<BTreeSet<String>>(),
            before
        );
    }

    #[test]
    fn parsed_rsd_service_summary_event_is_bounded_and_precedes_lookup_failure() {
        let mut handshake = test_rsd_handshake();
        handshake.uuid = "sentinel-peer-uuid".into();
        handshake.properties.insert(
            "sentinel-property-name".into(),
            plist::Value::String("sentinel-property-value".into()),
        );
        handshake.services.insert(
            "sentinel-unknown-service".into(),
            test_rsd_service("sentinel-entitlement", 62_345),
        );
        for (index, service_name) in [
            CORE_DEVICE_INFO_SERVICE_NAME,
            TUNNEL_SERVICE_NAME,
            AFC_SERVICE_NAME,
        ]
        .into_iter()
        .enumerate()
        {
            handshake.services.insert(
                service_name.to_owned(),
                test_rsd_service("sentinel-entitlement", 62_346 + index as u16),
            );
        }

        let (result, events) = capture_events(|| {
            report_parsed_rsd_service_summary(parsed_rsd_service_summary(&handshake));
            core_device_appservice_port(&handshake).map_err(report_core_device_service_failure)
        });

        assert_eq!(
            result
                .expect_err("missing AppService must still fail")
                .stage,
            RsdProbeStage::CoreDeviceService
        );
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].level, tracing::Level::WARN);
        let summary = &events[0].fields;
        assert_eq!(
            summary.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            [
                "message",
                "operation",
                "parsed_afc_present",
                "parsed_appservice_present",
                "parsed_deviceinfo_present",
                "parsed_image_mounter_present",
                "parsed_installation_proxy_present",
                "parsed_untrusted_tunnelservice_present",
                "result",
                "source",
                "stage",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            summary.get("message").map(String::as_str),
            Some("remote pairing parsed RSD service summary")
        );
        assert_eq!(
            summary.get("stage").map(String::as_str),
            Some("coreDeviceService")
        );
        assert_eq!(
            summary.get("operation").map(String::as_str),
            Some("service_summary")
        );
        assert_eq!(summary.get("result").map(String::as_str), Some("observed"));
        assert_eq!(
            summary.get("source").map(String::as_str),
            Some("parsed_rsd_services")
        );
        assert_eq!(events[0].target, "iphoneloadly_api::spike_diagnostics");
        for (field, expected) in [
            ("parsed_appservice_present", "false"),
            ("parsed_deviceinfo_present", "true"),
            ("parsed_untrusted_tunnelservice_present", "true"),
            ("parsed_image_mounter_present", "false"),
            ("parsed_installation_proxy_present", "false"),
            ("parsed_afc_present", "true"),
        ] {
            assert_eq!(summary.get(field).map(String::as_str), Some(expected));
        }
        let failure = &events[1];
        assert_eq!(failure.target, "iphoneloadly_api::spike_diagnostics");
        assert_eq!(
            failure
                .fields
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            [
                "appservice_present",
                "error_kind",
                "message",
                "operation",
                "result",
                "stage",
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            failure.fields.get("operation").map(String::as_str),
            Some("service_lookup")
        );

        let rendered = format!("{summary:?}");
        for sentinel in [
            "sentinel-peer-uuid",
            "sentinel-property-name",
            "sentinel-property-value",
            "sentinel-unknown-service",
            "sentinel-entitlement",
            "sentinel-feature",
            "62345",
        ] {
            assert!(!rendered.contains(sentinel), "event leaked {sentinel}");
        }
    }

    #[test]
    fn appservice_setup_reporter_only_changes_the_target() {
        let failure = RsdProbeFailure {
            stage: RsdProbeStage::Tunnel,
            session_cleanup: RsdSessionCleanup::NotNeeded,
        };
        let (reported, events) = capture_events(|| report_appservice_setup_failure(failure));
        assert_eq!(reported, failure);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].target, "iphoneloadly_api::spike_diagnostics");
        assert_eq!(
            events[0]
                .fields
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            ["message", "stage"].into_iter().collect()
        );
        assert_eq!(
            events[0].fields.get("stage").map(String::as_str),
            Some("tunnel")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_rsd_handshake_emits_no_service_summary() {
        let events = StdArc::new(StdMutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(EventCapture {
            events: events.clone(),
        });
        let guard = tracing::subscriber::set_default(subscriber);
        let (stream, peer) = tokio::io::duplex(64);
        drop(peer);

        assert!(RsdHandshake::new(stream).await.is_err());
        drop(guard);

        let captured = events.lock().expect("read captured tracing events");
        assert!(!captured.iter().any(|event| {
            event.fields.get("message").map(String::as_str)
                == Some("remote pairing parsed RSD service summary")
        }));
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
    #[test]
    fn read_only_service_lookup_requires_exact_nonzero_entries() {
        for (service_name, near_match) in [
            (AFC_SERVICE_NAME, "com.apple.afc.shim.remote.unexpected"),
            (
                INSTALLATION_PROXY_SERVICE_NAME,
                "com.apple.mobile.installation_proxy.shim.remote.unexpected",
            ),
        ] {
            let mut handshake = test_rsd_handshake();
            handshake
                .services
                .insert(near_match.to_owned(), test_rsd_service("", 62_000));
            assert_eq!(exact_rsd_service_port(&handshake, service_name), None);

            handshake
                .services
                .insert(service_name.to_owned(), test_rsd_service("", 0));
            assert_eq!(exact_rsd_service_port(&handshake, service_name), None);

            handshake
                .services
                .insert(service_name.to_owned(), test_rsd_service("", 62_001));
            assert_eq!(
                exact_rsd_service_port(&handshake, service_name),
                Some(62_001)
            );
        }
    }

    #[test]
    fn read_only_probe_stages_are_static_and_service_specific() {
        assert_eq!(
            [
                ReadOnlyProbeStage::Discovery.as_str(),
                ReadOnlyProbeStage::ValidatePairing.as_str(),
                ReadOnlyProbeStage::Tunnel.as_str(),
                ReadOnlyProbeStage::RsdHandshake.as_str(),
                ReadOnlyProbeStage::ServiceLookup.as_str(),
                ReadOnlyProbeStage::ServiceConnect.as_str(),
                ReadOnlyProbeStage::ClientInit.as_str(),
                ReadOnlyProbeStage::AfcQuery.as_str(),
                ReadOnlyProbeStage::AppLookup.as_str(),
                ReadOnlyProbeStage::Cleanup.as_str(),
            ],
            [
                "discovery",
                "validatePairing",
                "tunnel",
                "rsdHandshake",
                "serviceLookup",
                "serviceConnect",
                "clientInit",
                "afcQuery",
                "appLookup",
                "cleanup",
            ]
        );
    }
    #[test]
    fn read_only_probe_preserves_existing_setup_stages() {
        for (setup, read_only) in [
            (RsdProbeStage::Discovery, ReadOnlyProbeStage::Discovery),
            (
                RsdProbeStage::ValidatePairing,
                ReadOnlyProbeStage::ValidatePairing,
            ),
            (RsdProbeStage::Tunnel, ReadOnlyProbeStage::Tunnel),
            (
                RsdProbeStage::RsdHandshake,
                ReadOnlyProbeStage::RsdHandshake,
            ),
        ] {
            assert_eq!(ReadOnlyProbeStage::from(setup), read_only);
        }
    }

    #[tokio::test]
    async fn afc_probe_performs_only_get_device_info_and_validates_fields() {
        fn payload(fields: &[(&str, &str)]) -> Vec<u8> {
            let mut payload = Vec::new();
            for (key, value) in fields {
                payload.extend_from_slice(key.as_bytes());
                payload.push(0);
                payload.extend_from_slice(value.as_bytes());
                payload.push(0);
            }
            payload
        }

        let valid = payload(&[
            ("Model", "iPhone17,1"),
            ("FSTotalBytes", "1000"),
            ("FSFreeBytes", "500"),
            ("FSBlockSize", "4096"),
        ]);
        let (result, opcode) = run_afc_fixture(Some(valid)).await;
        assert!(result.is_ok());
        assert_eq!(opcode, idevice::afc::opcode::AfcOpcode::GetDevInfo as u64);

        let missing = payload(&[
            ("Model", "iPhone17,1"),
            ("FSTotalBytes", "1000"),
            ("FSFreeBytes", "500"),
        ]);
        assert!(run_afc_fixture(Some(missing)).await.0.is_err());

        let invalid = payload(&[
            ("Model", "iPhone17,1"),
            ("FSTotalBytes", "not-a-number"),
            ("FSFreeBytes", "500"),
            ("FSBlockSize", "4096"),
        ]);
        assert!(run_afc_fixture(Some(invalid)).await.0.is_err());
        assert!(run_afc_fixture(None).await.0.is_err());
    }

    #[tokio::test]
    async fn installation_proxy_probe_uses_user_lookup_and_accepts_empty_result() {
        fn response(lookup_result: plist::Value) -> plist::Value {
            plist::Value::Dictionary(
                [("LookupResult".to_owned(), lookup_result)]
                    .into_iter()
                    .collect(),
            )
        }

        let empty = response(plist::Value::Dictionary(plist::Dictionary::new()));
        let (result, request) =
            run_installation_proxy_fixture(PlistFixtureReply::Value(empty)).await;
        assert_eq!(result.expect("empty lookup result is valid").len(), 0);
        assert_eq!(
            request.get("Command").and_then(plist::Value::as_string),
            Some("Lookup")
        );
        let options = request
            .get("ClientOptions")
            .and_then(plist::Value::as_dictionary)
            .expect("lookup client options");
        assert_eq!(
            options
                .get("ApplicationType")
                .and_then(plist::Value::as_string),
            Some("User")
        );
        assert!(!options.contains_key("BundleIDs"));

        let nonempty = response(plist::Value::Dictionary(
            [(
                "com.example.application".to_owned(),
                plist::Value::Dictionary(plist::Dictionary::new()),
            )]
            .into_iter()
            .collect(),
        ));
        assert_eq!(
            run_installation_proxy_fixture(PlistFixtureReply::Value(nonempty))
                .await
                .0
                .expect("nonempty lookup result")
                .len(),
            1
        );

        let missing = plist::Value::Dictionary(plist::Dictionary::new());
        assert!(
            run_installation_proxy_fixture(PlistFixtureReply::Value(missing))
                .await
                .0
                .is_err()
        );
        let wrong_type = response(plist::Value::String("not-a-dictionary".into()));
        assert!(
            run_installation_proxy_fixture(PlistFixtureReply::Value(wrong_type))
                .await
                .0
                .is_err()
        );
        assert!(
            run_installation_proxy_fixture(PlistFixtureReply::Incomplete)
                .await
                .0
                .is_err()
        );
    }

    #[tokio::test]
    async fn read_only_step_timeouts_map_to_the_active_stage() {
        for (service, stage) in [
            (
                ReadOnlyProbeService::Afc,
                ReadOnlyProbeStage::ServiceConnect,
            ),
            (ReadOnlyProbeService::Afc, ReadOnlyProbeStage::ClientInit),
            (ReadOnlyProbeService::Afc, ReadOnlyProbeStage::AfcQuery),
            (
                ReadOnlyProbeService::InstallationProxy,
                ReadOnlyProbeStage::ServiceConnect,
            ),
            (
                ReadOnlyProbeService::InstallationProxy,
                ReadOnlyProbeStage::ClientInit,
            ),
            (
                ReadOnlyProbeService::InstallationProxy,
                ReadOnlyProbeStage::AppLookup,
            ),
        ] {
            let failure = run_read_only_probe_step(
                service,
                stage,
                stage.operation(),
                Duration::from_millis(1),
                std::future::pending::<Result<(), idevice::IdeviceError>>(),
            )
            .await
            .expect_err("pending operation must time out");
            assert_eq!(failure.stage, stage);
        }
    }

    #[tokio::test]
    async fn cleanup_is_bounded_and_preserves_primary_failures() {
        let close_calls = StdArc::new(AtomicUsize::new(0));
        let drops = StdArc::new(AtomicUsize::new(0));
        complete_read_only_probe_with_timeout(
            ReadOnlyProbeService::Afc,
            Ok(()),
            test_remote_session(
                TestCloseOutcome::Success,
                close_calls.clone(),
                drops.clone(),
            ),
            Duration::from_secs(1),
        )
        .await
        .expect("successful cleanup");
        assert_eq!(close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let cleanup_failure = complete_read_only_probe_with_timeout(
            ReadOnlyProbeService::Afc,
            Ok(()),
            test_remote_session(TestCloseOutcome::Error, close_calls.clone(), drops.clone()),
            Duration::from_secs(1),
        )
        .await
        .expect_err("cleanup failure must be public");
        assert_eq!(cleanup_failure.stage, ReadOnlyProbeStage::Cleanup);

        let primary = ReadOnlyProbeFailure {
            stage: ReadOnlyProbeStage::AfcQuery,
        };
        let preserved = complete_read_only_probe_with_timeout(
            ReadOnlyProbeService::Afc,
            Err(primary),
            test_remote_session(TestCloseOutcome::Error, close_calls.clone(), drops.clone()),
            Duration::from_secs(1),
        )
        .await
        .expect_err("primary failure must win");
        assert_eq!(preserved, primary);

        let deadline = tokio::time::Instant::now() + Duration::from_millis(1);
        let preserved_after_deadline = complete_read_only_probe_with_timeout(
            ReadOnlyProbeService::Afc,
            Err(primary),
            test_remote_session(
                TestCloseOutcome::Pending,
                close_calls.clone(),
                drops.clone(),
            ),
            deadline.saturating_duration_since(tokio::time::Instant::now()),
        )
        .await
        .expect_err("primary failure must survive cleanup deadline");
        assert_eq!(preserved_after_deadline, primary);

        let timeout_failure = complete_read_only_probe_with_timeout(
            ReadOnlyProbeService::InstallationProxy,
            Ok(()),
            test_remote_session(
                TestCloseOutcome::Pending,
                close_calls.clone(),
                drops.clone(),
            ),
            Duration::from_millis(1),
        )
        .await
        .expect_err("pending cleanup must time out");
        assert_eq!(timeout_failure.stage, ReadOnlyProbeStage::Cleanup);
        assert_eq!(close_calls.load(Ordering::SeqCst), 5);
        assert_eq!(drops.load(Ordering::SeqCst), 5);
    }

    #[tokio::test]
    async fn cancellation_drops_the_only_request_owned_provider() {
        let close_calls = StdArc::new(AtomicUsize::new(0));
        let drops = StdArc::new(AtomicUsize::new(0));
        let task = tokio::spawn(
            test_remote_session(
                TestCloseOutcome::Pending,
                close_calls.clone(),
                drops.clone(),
            )
            .close(),
        );
        tokio::task::yield_now().await;
        task.abort();
        let _ = task.await;
        assert_eq!(close_calls.load(Ordering::SeqCst), 1);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn approved_reporter_uses_only_bounded_static_fields() {
        let secret = "device-controlled-secret";
        let (_, events) = capture_events(|| {
            read_only_probe_failure(
                ReadOnlyProbeService::Afc,
                ReadOnlyProbeStage::ClientInit,
                "client_init",
                "error",
                "unexpected_response",
            )
        });
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].target, SPIKE_DIAGNOSTICS_TARGET);
        assert_eq!(
            events[0]
                .fields
                .keys()
                .map(String::as_str)
                .collect::<BTreeSet<_>>(),
            [
                "error_kind",
                "message",
                "operation",
                "result",
                "service",
                "stage",
                "transport",
            ]
            .into_iter()
            .collect()
        );
        assert!(!format!("{:?}", events[0]).contains(secret));
    }
}
