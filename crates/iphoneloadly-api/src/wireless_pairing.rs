use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use idevice::remote_pairing::{
    PAIRABLE_HOST_SERVICE_TYPE, PairableHost, PairableHostInfo, RpPairingFile, RpPairingSocket,
};
use mdns_sd::{IfKind, ServiceDaemon, ServiceInfo};
use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{net::TcpListener, sync::Mutex, task::AbortHandle, time::timeout};
use uuid::Uuid;

const DEFAULT_PAIRING_PORT: u16 = 52_345;
const SESSION_LIFETIME: Duration = Duration::from_secs(5 * 60);
const SERVICE_NAME: &str = "iPhoneLoadly";
const SERVICE_MODEL: &str = "Mac17,7";
const STATE_FILE: &str = "pairing-state.json";
const KEY_FILE: &str = "pairing-state.key";

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
}

struct SessionRuntime {
    status: PairingSessionStatus,
    cancel: AbortHandle,
    resources: Arc<Mutex<Option<MdnsAdvertisement>>>,
}

impl WirelessPairingService {
    pub fn new(config: WirelessPairingConfig) -> Self {
        Self {
            store: Arc::new(PairingStore::new(config.state_dir.clone())),
            config,
            session: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn start_wireless(&self) -> Result<PairingSessionStatus, PairingError> {
        if !self.config.mode.is_enabled() {
            return Err(PairingError::Disabled);
        }

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

        let material = self.store.load_or_create(SERVICE_NAME)?;
        let addresses = pairing_addresses(self.config.interface.as_deref())?;
        let listeners = bind_listeners(&addresses, self.config.pairing_port)?;
        let advertisement = advertise(
            &addresses,
            self.config.pairing_port,
            &material.host_info,
            &material.pairing_file,
            self.config.interface.as_deref(),
        )?;
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
        *current = Some(runtime);
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
            Ok(Err(_)) | Err(_) => {
                self.finish(
                    id,
                    PairingPhase::Expired,
                    "The wireless pairing session expired.",
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
            Ok(Err(_)) => {
                self.finish(
                    id,
                    PairingPhase::Failed,
                    "The iPhone or iPad rejected wireless pairing.",
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
                    resources,
                )
                .await;
                return;
            }
        };
        material.paired_peer_id = Some(fingerprint_peer(&peer.remotepairing_udid));
        if self.store.save(&material).is_err() {
            self.finish(
                id,
                PairingPhase::Failed,
                "Wireless pairing completed but its state could not be saved.",
                resources,
            )
            .await;
            return;
        }
        resources.lock().await.take();
        let _ = self
            .set_phase(
                id,
                PairingPhase::VerifyingTransport,
                "RemotePairing completed. Verifying trusted device transport.",
                None,
            )
            .await;
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
        resources: Arc<Mutex<Option<MdnsAdvertisement>>>,
    ) {
        resources.lock().await.take();
        let _ = self.set_phase(id, phase, public_message, None).await;
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

fn advertise(
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
    let fullname = service.get_fullname().to_owned();
    if daemon.register(service).is_err() {
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
        let key = self.load_or_create_key()?;
        let path = self.state_dir.join(STATE_FILE);
        if !path.exists() {
            let mut pairing_file = RpPairingFile::generate(sending_host);
            pairing_file.identifier = Uuid::now_v7().to_string();
            let mut host_info = PairableHostInfo::generate(sending_host, SERVICE_MODEL);
            host_info.identifier = pairing_file.identifier().to_owned();
            let material = StoredPairingMaterial {
                host_info,
                pairing_file,
                paired_peer_id: None,
            };
            self.save_with_key(&key, &material)?;
            return Ok(material);
        }
        set_private_permissions(&path, false);
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
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|_| PairingError::CorruptedState)?;
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

    fn temp_state_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("iphoneloadly-wireless-{name}-{}", Uuid::now_v7()))
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
    fn persistence_round_trip_is_encrypted_and_secret_free_on_disk() {
        let dir = temp_state_dir("round-trip");
        let store = PairingStore::new(dir.clone());
        let material = store
            .load_or_create(SERVICE_NAME)
            .expect("create pairing state");
        let secret = material.pairing_file.private_key_bytes();
        let reloaded = store
            .load_or_create(SERVICE_NAME)
            .expect("reload pairing state");
        assert_eq!(
            material.pairing_file.identifier(),
            reloaded.pairing_file.identifier()
        );
        assert_eq!(material.host_info.alt_irk, reloaded.host_info.alt_irk);
        store.save(&reloaded).expect("rewrite pairing state");
        let bytes = fs::read(dir.join(STATE_FILE)).expect("read encrypted state");
        assert!(!bytes.windows(secret.len()).any(|window| window == secret));
    }

    #[cfg(unix)]
    #[test]
    fn persistence_files_are_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_state_dir("permissions");
        PairingStore::new(dir.clone())
            .load_or_create(SERVICE_NAME)
            .expect("create private pairing state");
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
                .expect("key file metadata")
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
        store.load_or_create(SERVICE_NAME).expect("create state");
        fs::write(dir.join(STATE_FILE), b"not pairing state").expect("corrupt state");
        assert!(matches!(
            store.load_or_create(SERVICE_NAME),
            Err(PairingError::CorruptedState)
        ));
        let _ = fs::remove_dir_all(dir);
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
}
