mod github;
mod ipa;
mod jobs;
mod signing;
mod sources;
mod store;
mod update;
mod wireless_pairing;
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    path::{Path as StdPath, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse},
    routing::{delete, get, patch, post},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tracing_subscriber::{
    EnvFilter, Layer, filter::filter_fn, layer::SubscriberExt, util::SubscriberInitExt,
};
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) signing: Arc<signing::AppleSigningProvider>,
    pub(crate) devices: Arc<dyn DeviceTransport>,
    pub(crate) wireless_pairing: Arc<wireless_pairing::WirelessPairingService>,
    pub(crate) apps_dir: PathBuf,
    pub(crate) database: Arc<Mutex<rusqlite::Connection>>,
    pub(crate) app_mutation: Arc<tokio::sync::RwLock<()>>,
    pub(crate) spike_install_mutation: Arc<tokio::sync::Mutex<()>>,
    pub(crate) source_sync: Arc<tokio::sync::Mutex<()>>,
    pub(crate) github: Arc<github::GitHubClient>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceSummary {
    id: Uuid,
    display_name: String,
    product_type: String,
    ios_version: String,
    connection_type: ConnectionType,
    status: DeviceStatus,
    install_eligible: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstalledAppSummary {
    display_name: String,
    bundle_id: String,
    version: String,
}
#[derive(Debug, Clone, Serialize)]
struct AfcProbeResponse {
    transport: &'static str,
    afc: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RsdProbeSuccessResponse {
    transport: &'static str,
    remote_pairing: &'static str,
    rsd: &'static str,
    core_device: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RsdProbeFailureResponse {
    transport: &'static str,
    status: &'static str,
    stage: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ReadOnlyProbeSuccessResponse {
    transport: &'static str,
    service: &'static str,
    status: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ReadOnlyProbeFailureResponse {
    transport: &'static str,
    service: &'static str,
    status: &'static str,
    stage: &'static str,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SpikeRsdInstallRequest {
    app_id: Uuid,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SpikeRsdInstallResponse {
    transport: &'static str,
    outcome: &'static str,
    stage: &'static str,
    cleanup: &'static str,
    session_cleanup: &'static str,
    install_command_count: u8,
    error_kind: Option<&'static str>,
    bundle_id: Option<String>,
    certificate_pressure: bool,
}

const SPIKE_AFC_PROBE_PATH: &str = "/api/spike/devices/{id}/afc-probe";
const SPIKE_RSD_PROBE_PATH: &str = "/api/spike/remote-pairing/rsd-probe";

enum SpikeInstallExecution {
    AppNotFound,
    Report(wireless_pairing::RsdInstallReport),
}
const SPIKE_REMOTE_AFC_PROBE_PATH: &str = "/api/spike/remote-pairing/afc-probe";
const SPIKE_INSTALLATION_PROXY_PROBE_PATH: &str =
    "/api/spike/remote-pairing/installation-proxy-probe";
const SPIKE_RSD_INSTALL_PATH: &str = "/api/spike/remote-pairing/install";

fn spike_route_paths(spike_mode: bool) -> &'static [&'static str] {
    if spike_mode {
        &[
            SPIKE_AFC_PROBE_PATH,
            SPIKE_RSD_PROBE_PATH,
            SPIKE_REMOTE_AFC_PROBE_PATH,
            SPIKE_INSTALLATION_PROXY_PROBE_PATH,
            SPIKE_RSD_INSTALL_PATH,
        ]
    } else {
        &[]
    }
}

fn with_spike_routes(app: Router<AppState>, spike_mode: bool) -> Router<AppState> {
    if spike_route_paths(spike_mode).is_empty() {
        app
    } else {
        app.route(SPIKE_AFC_PROBE_PATH, get(spike_afc_probe))
            .route(SPIKE_RSD_PROBE_PATH, get(spike_remote_pairing_rsd_probe))
            .route(
                SPIKE_REMOTE_AFC_PROBE_PATH,
                get(spike_remote_pairing_afc_probe),
            )
            .route(
                SPIKE_INSTALLATION_PROXY_PROBE_PATH,
                get(spike_remote_pairing_installation_proxy_probe),
            )
            .route(
                SPIKE_RSD_INSTALL_PATH,
                post(spike_remote_pairing_install).layer(DefaultBodyLimit::max(1024)),
            )
    }
}

fn operator_env_filter(explicit: Option<&str>) -> EnvFilter {
    match explicit {
        Some(filter) => EnvFilter::new(filter),
        None => EnvFilter::from_default_env()
            .add_directive("idevice=info".parse().expect("static tracing directive")),
    }
}

// This cap governs configured tracing-subscriber output only. Direct writes and
// panics remain outside the subscriber boundary.
fn spike_target_allowed(spike_mode: bool, metadata: &tracing::Metadata<'_>) -> bool {
    !spike_mode || metadata.target() == wireless_pairing::SPIKE_DIAGNOSTICS_TARGET
}
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum ConnectionType {
    Network,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum DeviceStatus {
    Online,
}

/// Owns all Apple-account, 2FA, developer-resource, profile, and signing work.
/// Implementations must never persist an Apple password.
#[async_trait]
trait SigningProvider: Send + Sync {
    async fn readiness(&self) -> SigningReadiness;
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SigningReadiness {
    available: bool,
    message: &'static str,
}

/// Discovers and installs only through an already-trusted network transport.
#[async_trait]
trait DeviceTransport: Send + Sync {
    async fn list_network_devices(&self) -> Result<Vec<DeviceSummary>, TransportError>;
    async fn list_installed_apps(
        &self,
        device_id: Uuid,
    ) -> Result<Vec<InstalledAppSummary>, TransportError>;
    async fn probe_afc(&self, device_id: Uuid) -> Result<(), TransportError>;
    async fn install_ipa(
        &self,
        signing: &signing::AppleSigningProvider,
        device_id: Uuid,
        ipa_path: PathBuf,
        progress: Box<dyn Fn(u8) + Send + Sync>,
    ) -> Result<String, TransportError>;
}
#[derive(Debug, Error)]
enum TransportError {
    #[error("network device transport is not configured")]
    Unavailable,
    #[error("device installation failed")]
    DeviceInstallFailed,
    #[error("device information lookup failed")]
    DeviceInfoFailed,
    #[error("developer team lookup failed")]
    DeveloperTeamFailed,
    #[error("device registration failed")]
    DeviceRegistrationFailed,
    #[error("IPA signing failed")]
    IpaSigningFailed,
    #[error("signed IPA metadata validation failed")]
    SignedMetadataFailed,
}

#[async_trait]
impl SigningProvider for signing::AppleSigningProvider {
    async fn readiness(&self) -> SigningReadiness {
        if self.is_ready().await {
            SigningReadiness {
                available: true,
                message: "Apple signing session is active.",
            }
        } else if self.has_anisette_url() {
            SigningReadiness {
                available: false,
                message: "Sign in with Apple to enable signing.",
            }
        } else {
            SigningReadiness {
                available: false,
                message: "Configure a trusted anisette URL before signing in with Apple.",
            }
        }
    }
}

/// Resolves trusted Wi-Fi devices without retaining a DHCP address in
/// configuration or process memory. netmuxd is preferred; Bonjour plus a
/// pairing-record-validated TCP connection is the compatibility fallback.
struct NetmuxTransport {
    mux_socket: String,
    pairing_path: PathBuf,
}

#[async_trait]
impl DeviceTransport for NetmuxTransport {
    async fn list_network_devices(&self) -> Result<Vec<DeviceSummary>, TransportError> {
        Ok(self
            .reachable_network_devices()
            .await?
            .into_iter()
            .map(|(_, _, summary)| summary)
            .collect())
    }

    async fn install_ipa(
        &self,
        signing: &signing::AppleSigningProvider,
        device_id: Uuid,
        ipa_path: PathBuf,
        progress: Box<dyn Fn(u8) + Send + Sync>,
    ) -> Result<String, TransportError> {
        let (udid, address, _) = self
            .reachable_network_devices()
            .await?
            .into_iter()
            .find(|(udid, _, _)| device_id_for_udid(udid) == device_id)
            .ok_or(TransportError::Unavailable)?;
        let provider = self.provider_for(&udid, address)?;
        signing
            .install_ipa(&provider, ipa_path, progress)
            .await
            .map_err(|error| match error {
                signing::SigningError::DeviceInfoFailed => TransportError::DeviceInfoFailed,
                signing::SigningError::DeveloperTeamFailed => TransportError::DeveloperTeamFailed,
                signing::SigningError::DeviceRegistrationFailed => {
                    TransportError::DeviceRegistrationFailed
                }
                signing::SigningError::IpaSigningFailed => TransportError::IpaSigningFailed,
                signing::SigningError::SignedMetadataFailed => TransportError::SignedMetadataFailed,
                signing::SigningError::DeviceInstallFailed | signing::SigningError::NotReady => {
                    TransportError::DeviceInstallFailed
                }
                _ => TransportError::DeviceInstallFailed,
            })
    }

    async fn list_installed_apps(
        &self,
        device_id: Uuid,
    ) -> Result<Vec<InstalledAppSummary>, TransportError> {
        use idevice::{IdeviceService, services::installation_proxy::InstallationProxyClient};
        let (udid, address, _) = self
            .reachable_network_devices()
            .await?
            .into_iter()
            .find(|(udid, _, _)| device_id_for_udid(udid) == device_id)
            .ok_or(TransportError::Unavailable)?;
        let provider = self.provider_for(&udid, address)?;
        let mut client = tokio::time::timeout(
            Duration::from_secs(10),
            InstallationProxyClient::connect(&provider),
        )
        .await
        .map_err(|_| TransportError::Unavailable)?
        .map_err(|_| TransportError::Unavailable)?;
        let mut options = plist::Dictionary::new();
        options.insert(
            "ApplicationType".into(),
            plist::Value::String("User".into()),
        );
        let values = tokio::time::timeout(
            Duration::from_secs(20),
            client.browse(Some(plist::Value::Dictionary(options))),
        )
        .await
        .map_err(|_| TransportError::Unavailable)?
        .map_err(|_| TransportError::Unavailable)?;
        Ok(values
            .into_iter()
            .filter_map(|value| {
                let info = value.as_dictionary()?;
                let bundle_id = info.get("CFBundleIdentifier")?.as_string()?.to_owned();
                let display_name = info
                    .get("CFBundleDisplayName")
                    .or_else(|| info.get("CFBundleName"))
                    .and_then(|v| v.as_string())
                    .unwrap_or(&bundle_id)
                    .to_owned();
                let version = info
                    .get("CFBundleShortVersionString")
                    .or_else(|| info.get("CFBundleVersion"))
                    .and_then(|v| v.as_string())
                    .unwrap_or("—")
                    .to_owned();
                Some(InstalledAppSummary {
                    display_name,
                    bundle_id,
                    version,
                })
            })
            .collect())
    }

    async fn probe_afc(&self, device_id: Uuid) -> Result<(), TransportError> {
        use idevice::{IdeviceService, services::afc::AfcClient};

        let (udid, address, _) = self
            .reachable_network_devices()
            .await?
            .into_iter()
            .find(|(udid, _, _)| device_id_for_udid(udid) == device_id)
            .ok_or(TransportError::Unavailable)?;
        let provider = self.provider_for(&udid, address)?;
        let mut client =
            tokio::time::timeout(Duration::from_secs(10), AfcClient::connect(&provider))
                .await
                .map_err(|_| TransportError::Unavailable)?
                .map_err(|_| TransportError::Unavailable)?;
        tokio::time::timeout(Duration::from_secs(10), client.get_device_info())
            .await
            .map_err(|_| TransportError::Unavailable)?
            .map_err(|_| TransportError::Unavailable)?;
        Ok(())
    }
}

impl NetmuxTransport {
    async fn reachable_network_devices(
        &self,
    ) -> Result<Vec<(String, IpAddr, DeviceSummary)>, TransportError> {
        let mut reachable = self
            .reachable_candidates(self.netmux_network_devices().await.unwrap_or_default())
            .await;
        if reachable.is_empty() {
            let bonjour_candidates = self.bonjour_candidates().await?;
            reachable = self.reachable_candidates(bonjour_candidates).await;
        }
        if reachable.is_empty() {
            Err(TransportError::Unavailable)
        } else {
            Ok(reachable)
        }
    }

    async fn reachable_candidates(
        &self,
        candidates: Vec<(String, IpAddr)>,
    ) -> Vec<(String, IpAddr, DeviceSummary)> {
        let mut reachable = Vec::new();
        let mut attempted = HashSet::new();
        let mut identified_udids = HashSet::new();
        for (udid, address) in candidates {
            if identified_udids.contains(&udid) || !attempted.insert((udid.clone(), address)) {
                continue;
            }
            match self.describe_device(&udid, address).await {
                Ok(summary) => {
                    identified_udids.insert(udid.clone());
                    reachable.push((udid, address, summary));
                }
                Err(_) => {
                    tracing::debug!(device_id = %device_id_for_udid(&udid), "skipping unreachable or untrusted network device")
                }
            }
        }
        reachable
    }

    async fn netmux_network_devices(&self) -> Result<Vec<(String, IpAddr)>, TransportError> {
        #[cfg(not(unix))]
        {
            let _ = &self.mux_socket;
            Err(TransportError::Unavailable)
        }
        #[cfg(unix)]
        {
            use idevice::usbmuxd::{Connection, UsbmuxdAddr};

            let address = UsbmuxdAddr::UnixSocket(self.mux_socket.clone());
            let mut connection = tokio::time::timeout(Duration::from_secs(3), address.connect(0))
                .await
                .map_err(|_| TransportError::Unavailable)?
                .map_err(|_| TransportError::Unavailable)?;
            let devices = tokio::time::timeout(Duration::from_secs(3), connection.get_devices())
                .await
                .map_err(|_| TransportError::Unavailable)?
                .map_err(|_| TransportError::Unavailable)?;
            Ok(devices
                .into_iter()
                .filter_map(|device| match device.connection_type {
                    Connection::Network(address) => Some((device.udid, address)),
                    Connection::Usb | Connection::Unknown(_) => None,
                })
                .collect())
        }
    }

    async fn bonjour_candidates(&self) -> Result<Vec<(String, IpAddr)>, TransportError> {
        let addresses = tokio::task::spawn_blocking(discover_mobdev2_ipv4_addresses)
            .await
            .map_err(|_| TransportError::Unavailable)??;
        let udids = pairing_record_udids(&self.pairing_path)?;
        Ok(udids
            .into_iter()
            .flat_map(|udid| {
                addresses
                    .iter()
                    .copied()
                    .map(move |address| (udid.clone(), address))
            })
            .collect())
    }

    fn provider_for(
        &self,
        udid: &str,
        address: IpAddr,
    ) -> Result<idevice::provider::TcpProvider, TransportError> {
        use idevice::pairing_file::PairingFile;

        let pairing_path = pairing_record_path(&self.pairing_path, udid);
        let pairing_file =
            PairingFile::read_from_file(pairing_path).map_err(|_| TransportError::Unavailable)?;
        Ok(idevice::provider::TcpProvider {
            addr: address,
            scope_id: None,
            pairing_file,
            label: "iPhoneLoadly".into(),
        })
    }

    async fn describe_device(
        &self,
        udid: &str,
        address: IpAddr,
    ) -> Result<DeviceSummary, TransportError> {
        use idevice::IdeviceService;
        use idevice::services::lockdown::LockdownClient;

        let provider = self.provider_for(udid, address)?;
        let pairing_file = provider.pairing_file.clone();
        let mut client =
            tokio::time::timeout(Duration::from_secs(5), LockdownClient::connect(&provider))
                .await
                .map_err(|_| TransportError::Unavailable)?
                .map_err(|_| TransportError::Unavailable)?;
        tokio::time::timeout(Duration::from_secs(5), client.start_session(&pairing_file))
            .await
            .map_err(|_| TransportError::Unavailable)?
            .map_err(|_| TransportError::Unavailable)?;
        let device_name = tokio::time::timeout(
            Duration::from_secs(3),
            client.get_value(Some("DeviceName"), None),
        )
        .await
        .map_err(|_| TransportError::Unavailable)?
        .map_err(|_| TransportError::Unavailable)?;
        let product_type = tokio::time::timeout(
            Duration::from_secs(3),
            client.get_value(Some("ProductType"), None),
        )
        .await
        .map_err(|_| TransportError::Unavailable)?
        .map_err(|_| TransportError::Unavailable)?;
        let ios_version = tokio::time::timeout(
            Duration::from_secs(3),
            client.get_value(Some("ProductVersion"), None),
        )
        .await
        .map_err(|_| TransportError::Unavailable)?
        .map_err(|_| TransportError::Unavailable)?;
        Ok(DeviceSummary {
            id: device_id_for_udid(udid),
            display_name: device_name.as_string().unwrap_or("iPhone").to_owned(),
            product_type: product_type.as_string().unwrap_or("unknown").to_owned(),
            ios_version: ios_version.as_string().unwrap_or("unknown").to_owned(),
            connection_type: ConnectionType::Network,
            status: DeviceStatus::Online,
            install_eligible: true,
        })
    }
}

fn pairing_record_path(pairing_dir: &StdPath, udid: &str) -> PathBuf {
    pairing_dir.join(format!("{udid}.plist"))
}

fn pairing_record_udids(pairing_dir: &StdPath) -> Result<Vec<String>, TransportError> {
    let entries = std::fs::read_dir(pairing_dir).map_err(|_| TransportError::Unavailable)?;
    Ok(entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter_map(|name| name.strip_suffix(".plist").map(str::to_owned))
        .filter(|udid| udid != "SystemConfiguration")
        .collect())
}

fn discover_mobdev2_ipv4_addresses() -> Result<Vec<IpAddr>, TransportError> {
    use mdns_sd::{ServiceDaemon, ServiceEvent};

    let daemon = ServiceDaemon::new().map_err(|_| TransportError::Unavailable)?;
    let receiver = daemon
        .browse("_apple-mobdev2._tcp.local.")
        .map_err(|_| TransportError::Unavailable)?;
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut addresses = HashSet::new();
    while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
        let Ok(event) = receiver.recv_timeout(remaining) else {
            break;
        };
        if let ServiceEvent::ServiceResolved(service) = event {
            addresses.extend(
                service
                    .get_addresses()
                    .iter()
                    .filter(|address| address.is_ipv4())
                    .map(|address| address.to_ip_addr()),
            );
        }
    }
    drop(receiver);
    let _ = daemon.stop_browse("_apple-mobdev2._tcp.local.");
    let _ = daemon.shutdown();
    if addresses.is_empty() {
        Err(TransportError::Unavailable)
    } else {
        Ok(addresses.into_iter().collect())
    }
}

/// The browser and SQLite use an internal UUID. Apple UDIDs remain private and
/// are only used in memory to resolve the currently announced network device.
fn device_id_for_udid(udid: &str) -> Uuid {
    let digest = Sha256::digest(udid.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::{
        AfcProbeResponse, AppState, DeviceSummary, DeviceTransport, InstalledAppSummary,
        ReadOnlyProbeFailureResponse, ReadOnlyProbeSuccessResponse, Router,
        RsdProbeFailureResponse, RsdProbeSuccessResponse, SPIKE_INSTALLATION_PROXY_PROBE_PATH,
        SPIKE_REMOTE_AFC_PROBE_PATH, SPIKE_RSD_INSTALL_PATH, SPIKE_RSD_PROBE_PATH,
        StartAppleLoginRequest, StatusCode, TransportError, device_id_for_udid, install_job_json,
        managed_app, operator_env_filter, spike_route_paths, spike_target_allowed,
        with_spike_routes,
    };
    use crate::{
        github, signing, store,
        store::{ManagedAppIdentity, StoredJob},
        wireless_pairing,
    };
    use async_trait::async_trait;
    use std::{
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    };
    use tracing::{
        Event, Subscriber,
        field::{Field, Visit},
    };
    use tracing_subscriber::{
        Layer,
        filter::filter_fn,
        layer::{Context, SubscriberExt},
        registry::LookupSpan,
    };
    use uuid::Uuid;

    #[derive(Clone, Debug)]
    struct CapturedEvent {
        target: String,
        fields: Vec<(String, String)>,
    }

    impl Visit for CapturedEvent {
        fn record_str(&mut self, field: &Field, value: &str) {
            self.fields
                .push((field.name().to_owned(), value.to_owned()));
        }

        fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
            self.fields
                .push((field.name().to_owned(), format!("{value:?}")));
        }
    }

    #[derive(Clone)]
    struct EventCapture {
        events: Arc<Mutex<Vec<CapturedEvent>>>,
    }

    impl<S> Layer<S> for EventCapture
    where
        S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    {
        fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
            let mut captured = CapturedEvent {
                target: event.metadata().target().to_owned(),
                fields: Vec::new(),
            };
            event.record(&mut captured);
            self.events.lock().expect("capture event").push(captured);
        }
    }

    fn capture_tracing(spike_mode: bool, run: impl FnOnce()) -> Vec<CapturedEvent> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(
            EventCapture {
                events: events.clone(),
            }
            .with_filter(operator_env_filter(Some("trace,idevice=trace")))
            .with_filter(filter_fn(move |metadata| {
                spike_target_allowed(spike_mode, metadata)
            })),
        );
        tracing::subscriber::with_default(subscriber, run);
        events.lock().expect("read captured events").clone()
    }

    fn emit_hostile_filter_sentinels() {
        tracing::debug!(target: "idevice", sentinel = "idevice_debug");
        tracing::error!(target: "idevice", sentinel = "idevice_error");
        tracing::warn!(
            target: "idevice::services::afc",
            sentinel = "idevice_afc_warn"
        );
        tracing::debug!(
            target: "idevice::services::afc::packet",
            sentinel = "idevice_afc_packet_debug"
        );
        tracing::error!(
            target: "idevice::remote_pairing::sentinel",
            sentinel = "idevice_other"
        );
        tracing::error!(target: "jktcp", sentinel = "jktcp_root");
        tracing::trace!(target: "jktcp::adapter", sentinel = "jktcp_adapter");
        tracing::error!(target: "jktcp::other", sentinel = "jktcp_other");
        tracing::error!(
            target: "revision4_dependency_sentinel",
            sentinel = "dependency_error"
        );
        tracing::error!(
            target: "iphoneloadly_api",
            sentinel = "default_application"
        );
        tracing::error!(
            target: "iphoneloadly_api::wireless_pairing",
            sentinel = "wireless_application"
        );
        tracing::error!(
            target: "iphoneloadly_api::spike_diagnostics::child",
            sentinel = "approved_target_descendant"
        );
        wireless_pairing::emit_spike_diagnostic_for_filter_test();
    }

    struct RejectingTransport;

    #[async_trait]
    impl DeviceTransport for RejectingTransport {
        async fn list_network_devices(&self) -> Result<Vec<DeviceSummary>, TransportError> {
            panic!("read-only RSD probe must not use classic device discovery")
        }

        async fn list_installed_apps(
            &self,
            _device_id: Uuid,
        ) -> Result<Vec<InstalledAppSummary>, TransportError> {
            panic!("read-only RSD probe must not use classic app lookup")
        }

        async fn probe_afc(&self, _device_id: Uuid) -> Result<(), TransportError> {
            panic!("read-only RSD probe must not use classic AFC")
        }

        async fn install_ipa(
            &self,
            _signing: &signing::AppleSigningProvider,
            _device_id: Uuid,
            _ipa_path: PathBuf,
            _progress: Box<dyn Fn(u8) + Send + Sync>,
        ) -> Result<String, TransportError> {
            panic!("read-only RSD probe must not install")
        }
    }

    fn route_test_state(root: &Path) -> (AppState, Arc<wireless_pairing::WirelessPairingService>) {
        std::fs::create_dir_all(root).expect("create route test directory");
        let database =
            store::initialize(&root.join("route-test.db")).expect("initialize route test database");
        let wireless_pairing = Arc::new(wireless_pairing::WirelessPairingService::new(
            wireless_pairing::WirelessPairingConfig {
                mode: wireless_pairing::WirelessPairingMode::Experimental,
                pairing_port: 52_345,
                interface: None,
                state_dir: root.join("wireless-pairing"),
            },
        ));
        (
            AppState {
                signing: signing::AppleSigningProvider::new(None, root.join("signing")),
                devices: Arc::new(RejectingTransport),
                wireless_pairing: wireless_pairing.clone(),
                apps_dir: root.join("apps"),
                database: Arc::new(Mutex::new(database)),
                app_mutation: Arc::new(tokio::sync::RwLock::new(())),
                spike_install_mutation: Arc::new(tokio::sync::Mutex::new(())),
                source_sync: Arc::new(tokio::sync::Mutex::new(())),
                github: Arc::new(
                    github::GitHubClient::new(env!("CARGO_PKG_VERSION"))
                        .expect("create route test GitHub client"),
                ),
            },
            wireless_pairing,
        )
    }

    async fn exercise_probe_routes(
        spike_mode: bool,
    ) -> (Vec<(StatusCode, serde_json::Value)>, usize) {
        let root =
            std::env::temp_dir().join(format!("iphoneloadly-read-only-routes-{}", Uuid::now_v7()));
        let (state, wireless_pairing) = route_test_state(&root);
        let app = with_spike_routes(Router::new(), spike_mode).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind route test listener");
        let address = listener.local_addr().expect("route test listener address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve route test router");
        });

        let client = reqwest::Client::new();
        let mut responses = Vec::new();
        for path in [
            SPIKE_REMOTE_AFC_PROBE_PATH,
            SPIKE_INSTALLATION_PROXY_PROBE_PATH,
        ] {
            let response = client
                .get(format!("http://{address}{path}"))
                .send()
                .await
                .expect("request read-only probe route");
            let status = response.status();
            let body = response.text().await.expect("read probe response body");
            let json = if body.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::from_str(&body).expect("parse probe response")
            };
            responses.push((status, json));
        }
        let open_attempts = wireless_pairing.probe_open_attempts();
        server.abort();
        let _ = server.await;
        let _ = std::fs::remove_dir_all(root);
        (responses, open_attempts)
    }

    #[test]
    fn device_id_is_stable_for_non_uuid_apple_udids() {
        let first = device_id_for_udid("00008110-001A2B3C00000000");
        assert_eq!(first, device_id_for_udid("00008110-001A2B3C00000000"));
        assert_ne!(first, device_id_for_udid("00008110-001A2B3C00000001"));
    }

    #[test]
    fn afc_probe_response_contains_only_non_secret_status() {
        let value = serde_json::to_value(AfcProbeResponse {
            transport: "lockdown",
            afc: "ok",
        })
        .expect("serialize AFC probe response");
        assert_eq!(
            value,
            serde_json::json!({
                "transport": "lockdown",
                "afc": "ok",
            })
        );
    }

    #[test]
    fn rsd_probe_success_response_is_non_secret() {
        let value = serde_json::to_value(RsdProbeSuccessResponse {
            transport: "rsdCoreDevice",
            remote_pairing: "ok",
            rsd: "ok",
            core_device: "ok",
        })
        .expect("serialize RSD probe response");
        assert_eq!(
            value,
            serde_json::json!({
                "transport": "rsdCoreDevice",
                "remotePairing": "ok",
                "rsd": "ok",
                "coreDevice": "ok",
            })
        );
        let encoded = value.to_string();
        for secret_name in [
            "pairingFile",
            "privateKey",
            "altIrk",
            "authTag",
            "encryptionKey",
            "identifier",
        ] {
            assert!(
                !encoded.contains(secret_name),
                "response leaked {secret_name}"
            );
        }
    }
    #[test]
    fn rsd_probe_failure_response_is_non_secret() {
        for stage in ["validatePairing", "coreDeviceService"] {
            let value = serde_json::to_value(RsdProbeFailureResponse {
                transport: "rsdCoreDevice",
                status: "unavailable",
                stage,
            })
            .expect("serialize RSD probe failure response");
            assert_eq!(
                value,
                serde_json::json!({
                    "transport": "rsdCoreDevice",
                    "status": "unavailable",
                    "stage": stage,
                })
            );
            let encoded = value.to_string();
            assert!(!encoded.contains("auth"));
            assert!(!encoded.contains("key"));
            assert!(!encoded.contains("secret"));
        }
    }

    #[test]
    fn read_only_probe_responses_are_bounded() {
        for service in ["afc", "installationProxy"] {
            let success = serde_json::to_value(ReadOnlyProbeSuccessResponse {
                transport: "rsd",
                service,
                status: "ok",
            })
            .expect("serialize read-only probe success");
            assert_eq!(
                success,
                serde_json::json!({
                    "transport": "rsd",
                    "service": service,
                    "status": "ok",
                })
            );

            for stage in [
                "discovery",
                "validatePairing",
                "tunnel",
                "rsdHandshake",
                "serviceLookup",
                "serviceConnect",
                "clientInit",
                if service == "afc" {
                    "afcQuery"
                } else {
                    "appLookup"
                },
                "cleanup",
            ] {
                let failure = serde_json::to_value(ReadOnlyProbeFailureResponse {
                    transport: "rsd",
                    service,
                    status: "unavailable",
                    stage,
                })
                .expect("serialize read-only probe failure");
                assert_eq!(
                    failure,
                    serde_json::json!({
                        "transport": "rsd",
                        "service": service,
                        "status": "unavailable",
                        "stage": stage,
                    })
                );
                let encoded = failure.to_string();
                for sentinel in [
                    "device-controlled-secret",
                    "00008110-001A2B3C00000000",
                    "127.0.0.1",
                    "62000",
                    "/private/var/mobile",
                ] {
                    assert!(!encoded.contains(sentinel));
                }
            }
        }
    }

    #[test]
    fn rsd_probe_routes_are_registered_only_in_spike_mode() {
        for path in [
            SPIKE_RSD_PROBE_PATH,
            SPIKE_REMOTE_AFC_PROBE_PATH,
            SPIKE_INSTALLATION_PROXY_PROBE_PATH,
            SPIKE_RSD_INSTALL_PATH,
        ] {
            assert!(!spike_route_paths(false).contains(&path));
            assert!(spike_route_paths(true).contains(&path));
        }
    }

    #[tokio::test]
    async fn read_only_probe_routes_are_spike_only_and_use_fresh_wireless_sessions() {
        let (active, open_attempts) = exercise_probe_routes(true).await;
        assert_eq!(open_attempts, 2);
        assert_eq!(
            active,
            vec![
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({
                        "transport": "rsd",
                        "service": "afc",
                        "status": "unavailable",
                        "stage": "discovery",
                    }),
                ),
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    serde_json::json!({
                        "transport": "rsd",
                        "service": "installationProxy",
                        "status": "unavailable",
                        "stage": "discovery",
                    }),
                ),
            ]
        );

        let (inactive, open_attempts) = exercise_probe_routes(false).await;
        assert_eq!(open_attempts, 0);
        assert_eq!(
            inactive
                .into_iter()
                .map(|(status, _)| status)
                .collect::<Vec<_>>(),
            [StatusCode::NOT_FOUND, StatusCode::NOT_FOUND]
        );
    }

    #[tokio::test]
    async fn install_route_is_guarded_spike_only_and_resolves_server_app_id() {
        let root =
            std::env::temp_dir().join(format!("iphoneloadly-install-route-{}", Uuid::now_v7()));
        let (state, wireless_pairing) = route_test_state(&root);
        let install_admission = state.spike_install_mutation.clone();
        let app_id = Uuid::now_v7();
        let ipa_path = root.join("selected.ipa");
        std::fs::write(&ipa_path, b"server-selected-ipa").expect("write server app");
        store::insert_app(
            &state.database.lock().expect("lock database"),
            app_id,
            "test-hash",
            &ipa_path.to_string_lossy(),
            19,
            "com.example.selected",
            "Selected",
            Some("1"),
        )
        .expect("insert server app");
        let app = with_spike_routes(Router::new(), true).with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind install route listener");
        let address = listener.local_addr().expect("install route address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve install route router");
        });
        let client = reqwest::Client::new();
        let url = format!("http://{address}{SPIKE_RSD_INSTALL_PATH}");

        let missing_action = client
            .post(&url)
            .json(&serde_json::json!({"appId": app_id}))
            .send()
            .await
            .expect("request without action header");
        assert_eq!(missing_action.status(), StatusCode::BAD_REQUEST);

        let oversized = client
            .post(&url)
            .header("content-type", "application/json")
            .header("x-iphoneloadly-action", "1")
            .body(vec![b'x'; 1025])
            .send()
            .await
            .expect("request oversized install body");
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let arbitrary_path = client
            .post(&url)
            .header("x-iphoneloadly-action", "1")
            .json(&serde_json::json!({
                "appId": app_id,
                "ipaPath": "C:\\untrusted\\arbitrary.ipa"
            }))
            .send()
            .await
            .expect("request arbitrary path");
        assert_eq!(arbitrary_path.status(), StatusCode::BAD_REQUEST);

        let unknown_app = client
            .post(&url)
            .header("x-iphoneloadly-action", "1")
            .json(&serde_json::json!({"appId": Uuid::now_v7()}))
            .send()
            .await
            .expect("request unknown app");
        assert_eq!(unknown_app.status(), StatusCode::NOT_FOUND);

        let single_flight = install_admission
            .clone()
            .try_lock_owned()
            .expect("reserve install single-flight");
        let busy = client
            .post(&url)
            .header("x-iphoneloadly-action", "1")
            .json(&serde_json::json!({"appId": app_id}))
            .send()
            .await
            .expect("request busy install route");
        assert_eq!(busy.status(), StatusCode::CONFLICT);
        drop(single_flight);

        let selected_app = client
            .post(&url)
            .header("x-iphoneloadly-action", "1")
            .json(&serde_json::json!({"appId": app_id}))
            .send()
            .await
            .expect("request selected server app");
        assert_eq!(selected_app.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            selected_app
                .json::<serde_json::Value>()
                .await
                .expect("parse selected app response"),
            serde_json::json!({
                "transport": "rsd",
                "outcome": "notStarted",
                "stage": "discovery",
                "cleanup": "notNeeded",
                "sessionCleanup": "notNeeded",
                "installCommandCount": 0,
                "errorKind": "session_open",
                "bundleId": null,
                "certificatePressure": false,
            })
        );
        assert_eq!(wireless_pairing.probe_open_attempts(), 1);
        server.abort();
        let _ = server.await;

        let (inactive_state, inactive_wireless_pairing) = route_test_state(&root.join("inactive"));
        let inactive_app = with_spike_routes(Router::new(), false).with_state(inactive_state);
        let inactive_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind inactive install route listener");
        let inactive_address = inactive_listener
            .local_addr()
            .expect("inactive install route address");
        let inactive_server = tokio::spawn(async move {
            axum::serve(inactive_listener, inactive_app)
                .await
                .expect("serve inactive install router");
        });
        let inactive_response = client
            .post(format!("http://{inactive_address}{SPIKE_RSD_INSTALL_PATH}"))
            .header("x-iphoneloadly-action", "1")
            .json(&serde_json::json!({"appId": app_id}))
            .send()
            .await
            .expect("request inactive install route");
        assert_eq!(inactive_response.status(), StatusCode::NOT_FOUND);
        assert_eq!(inactive_wireless_pairing.probe_open_attempts(), 0);
        inactive_server.abort();
        let _ = inactive_server.await;
        std::fs::remove_dir_all(root).expect("remove install route root");
    }

    #[test]
    fn spike_subscriber_hard_filter_denies_every_nonapproved_target() {
        let events = capture_tracing(true, emit_hostile_filter_sentinels);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].target, wireless_pairing::SPIKE_DIAGNOSTICS_TARGET);
        assert!(events[0].fields.iter().any(|(name, value)| {
            name == "message" && value.contains("remote pairing read-only probe failed")
        }));
    }

    #[test]
    fn non_spike_subscriber_preserves_every_hostile_operator_enabled_event() {
        let events = capture_tracing(false, emit_hostile_filter_sentinels);
        let sentinels = events
            .iter()
            .flat_map(|event| event.fields.iter())
            .filter(|(name, _)| name == "sentinel")
            .map(|(_, value)| value.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            sentinels,
            [
                "approved_target_descendant",
                "dependency_error",
                "idevice_afc_packet_debug",
                "idevice_afc_warn",
                "idevice_debug",
                "idevice_error",
                "idevice_other",
                "jktcp_adapter",
                "jktcp_other",
                "jktcp_root",
                "wireless_application",
                "default_application",
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn login_request_reads_browser_save_credentials_field() {
        let request: StartAppleLoginRequest = serde_json::from_str(
            r#"{"email":"person@example.test","password":"secret","saveCredentials":true}"#,
        )
        .expect("deserialize browser login request");
        assert!(request.save_credentials);
    }

    #[test]
    fn managed_apps_require_service_install_history() {
        let identities = vec![
            ManagedAppIdentity {
                installed_bundle_id: Some("com.example.current.TEAM123".into()),
                source_bundle_id: Some("com.example.current".into()),
            },
            ManagedAppIdentity {
                installed_bundle_id: None,
                source_bundle_id: Some("com.example.legacy".into()),
            },
        ];

        assert!(managed_app("com.example.current.TEAM123", &identities));
        assert!(!managed_app("com.example.current.OTHERTEAM", &identities));
        assert!(managed_app("com.example.legacy.OLDTEAM", &identities));
        assert!(!managed_app(
            "com.example.legacymalicious.OLDTEAM",
            &identities
        ));
        assert!(!managed_app("com.apple.Pages", &identities));
    }

    #[test]
    fn install_job_json_preserves_live_progress_and_safe_fields() {
        let id = Uuid::now_v7();
        let app_id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        let value = install_job_json(StoredJob {
            id,
            app_id,
            device_id,
            phase: "signing".into(),
            progress_percent: Some(18),
            device_label: "Test iPhone".into(),
            created_at: "2026-08-28T12:00:00Z".into(),
            completed_at: None,
            failure_code: None,
            app_display_name: "Example".into(),
            app_version: Some("1.2.3".into()),
        });

        assert_eq!(value["id"], id.to_string());
        assert_eq!(value["appId"], app_id.to_string());
        assert_eq!(value["deviceId"], device_id.to_string());
        assert_eq!(value["deviceLabel"], "Test iPhone");
        assert_eq!(value["progressPercent"], 18);
        assert_eq!(value["appDisplayName"], "Example");
        assert_eq!(value["appVersion"], "1.2.3");
        assert_eq!(value["createdAt"], "2026-08-28T12:00:00Z");
        assert!(value["completedAt"].is_null());
        assert_eq!(value["publicMessage"], "Signing the IPA.");
    }
    fn install_report(
        outcome: wireless_pairing::RsdInstallOutcome,
        cleanup: wireless_pairing::RsdStagingCleanup,
        error_kind: &'static str,
    ) -> wireless_pairing::RsdInstallReport {
        wireless_pairing::RsdInstallReport {
            outcome,
            stage: wireless_pairing::RsdInstallStage::Complete,
            cleanup,
            session_cleanup: wireless_pairing::RsdSessionCleanup::NotNeeded,
            install_command_count: 1,
            error_kind,
            bundle_id: Some("com.example.test".into()),
            certificate_pressure: false,
        }
    }

    #[test]
    fn verified_installed_status_is_success_despite_ancillary_cleanup_errors() {
        for (cleanup, error_kind) in [
            (
                wireless_pairing::RsdStagingCleanup::Failed,
                "staging_cleanup",
            ),
            (
                wireless_pairing::RsdStagingCleanup::Succeeded,
                "session_cleanup",
            ),
        ] {
            let report = install_report(
                wireless_pairing::RsdInstallOutcome::Installed,
                cleanup,
                error_kind,
            );
            assert_eq!(super::spike_install_status(&report), StatusCode::OK);
        }
    }
    #[test]
    fn verified_install_preserves_both_cleanup_failures() {
        let mut report = install_report(
            wireless_pairing::RsdInstallOutcome::Installed,
            wireless_pairing::RsdStagingCleanup::Failed,
            "staging_cleanup",
        );
        report.session_cleanup = wireless_pairing::RsdSessionCleanup::Failed;
        assert_eq!(super::spike_install_status(&report), StatusCode::OK);

        let response =
            serde_json::to_value(super::spike_install_response(report)).expect("serialize report");
        assert_eq!(response["cleanup"], "failed");
        assert_eq!(response["sessionCleanup"], "failed");
        assert_eq!(response["errorKind"], "staging_cleanup");
    }

    #[test]
    fn unverified_install_outcomes_remain_failure_class_statuses() {
        for outcome in [
            wireless_pairing::RsdInstallOutcome::NotInstalled,
            wireless_pairing::RsdInstallOutcome::OutcomeUnknown,
        ] {
            let report =
                install_report(outcome, wireless_pairing::RsdStagingCleanup::NotNeeded, "");
            assert_eq!(
                super::spike_install_status(&report),
                StatusCode::BAD_GATEWAY
            );
        }
        let report = install_report(
            wireless_pairing::RsdInstallOutcome::NotStarted,
            wireless_pairing::RsdStagingCleanup::NotNeeded,
            "",
        );
        assert_eq!(
            super::spike_install_status(&report),
            StatusCode::SERVICE_UNAVAILABLE
        );
        let report = install_report(
            wireless_pairing::RsdInstallOutcome::NotStarted,
            wireless_pairing::RsdStagingCleanup::NotNeeded,
            "app_already_installed",
        );
        assert_eq!(super::spike_install_status(&report), StatusCode::CONFLICT);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    status: &'static str,
    version: &'static str,
    signing: SigningReadiness,
}

async fn healthz(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
        signing: state.signing.readiness().await,
    })
}

async fn dashboard() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}
async fn list_apps(State(state): State<AppState>) -> impl IntoResponse {
    match state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|database| store::list_apps(&database).map_err(|_| ()))
    {
        Ok(apps) => Json(serde_json::json!(
            apps.into_iter()
                .map(|app| serde_json::json!({
                    "id": app.id,
                    "displayName": app.display_name,
                    "appVersion": app.app_version,
                    "bundleId": app.bundle_id,
                    "sha256": app.sha256,
                    "sizeBytes": app.size_bytes,
                }))
                .collect::<Vec<_>>()
        )),
        Err(_) => Json(serde_json::json!({"message":"Unable to list uploaded IPAs."})),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct StartAppleLoginRequest {
    email: String,
    password: String,
    #[serde(default)]
    save_credentials: bool,
}

#[derive(Serialize)]
struct CertificateRecoveryResponse {
    message: &'static str,
}

async fn request_certificate_recovery(
    State(state): State<AppState>,
) -> (StatusCode, Json<CertificateRecoveryResponse>) {
    state.signing.request_certificate_recovery();
    (
        StatusCode::ACCEPTED,
        Json(CertificateRecoveryResponse {
            message: "Certificate recovery is armed for one new Apple sign-in. Sign in again; if Apple reports a certificate limit, iPhoneLoadly will revoke one older development certificate and continue.",
        }),
    )
}

async fn start_apple_login(
    State(state): State<AppState>,
    Json(request): Json<StartAppleLoginRequest>,
) -> impl IntoResponse {
    if request.email.trim().is_empty() || request.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message":"Email and password are required."})),
        )
            .into_response();
    }
    if request.save_credentials
        && state
            .signing
            .save_credentials(&request.email, &request.password)
            .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to save encrypted credentials."})),
        )
            .into_response();
    }
    match state.signing.begin_login(request.email, request.password).await {
        Ok(status) => {
            if request.save_credentials {
                state.signing.set_saved_login_id(status.id).await;
            }
            (StatusCode::ACCEPTED, Json(status)).into_response()
        }
        Err(signing::SigningError::MissingAnisetteUrl) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"message":"Configure IPHONELOADLY_ANISETTE_URL with a trusted anisette service before signing in."})),
        ).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"message":"Unable to start Apple sign-in."}))).into_response(),
    }
}

async fn saved_apple_login(State(state): State<AppState>) -> impl IntoResponse {
    match state.signing.saved_login_status().await {
        Ok(Some(status)) => (
            StatusCode::OK,
            Json(serde_json::json!({"saved":true,"login":status})),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::OK,
            Json(serde_json::json!({"saved":state.signing.has_saved_credentials()})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to read saved sign-in state."})),
        )
            .into_response(),
    }
}

async fn delete_saved_apple_login(State(state): State<AppState>) -> impl IntoResponse {
    match state.signing.delete_saved_credentials() {
        Ok(()) => {
            state.signing.clear_saved_login_id().await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to remove saved credentials."})),
        )
            .into_response(),
    }
}

async fn get_apple_login(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match state.signing.login_status(id).await {
        Ok(status) => (StatusCode::OK, Json(status)).into_response(),
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"Apple login session was not found."})),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TwoFactorRequest {
    action: String,
    code: Option<String>,
    number_id: Option<u32>,
}

async fn submit_apple_two_factor(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<TwoFactorRequest>,
) -> impl IntoResponse {
    match state.signing.submit_two_factor(id, &request.action, request.code, request.number_id).await {
        Ok(()) => (StatusCode::ACCEPTED, Json(serde_json::json!({"message":"Two-factor response accepted."}))).into_response(),
        Err(signing::SigningError::UnknownSession) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"message":"Apple login session was not found."}))).into_response(),
        Err(signing::SigningError::NoTwoFactorChallenge) => (StatusCode::CONFLICT, Json(serde_json::json!({"message":"Apple is not currently requesting a two-factor response."}))).into_response(),
        Err(_) => (StatusCode::BAD_REQUEST, Json(serde_json::json!({"message":"Invalid two-factor response."}))).into_response(),
    }
}

async fn list_devices(State(state): State<AppState>) -> impl IntoResponse {
    match state.devices.list_network_devices().await {
        Ok(devices) => (StatusCode::OK, Json(devices)).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "message": "Wi-Fi device discovery is unavailable. Check netmuxd and the dedicated mux socket."
            })),
        )
            .into_response(),
    }
}

async fn rescan_devices(State(state): State<AppState>) -> impl IntoResponse {
    list_devices(State(state)).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreatePairingSessionRequest {
    mode: String,
}

async fn create_pairing_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreatePairingSessionRequest>,
) -> impl IntoResponse {
    if request.mode != "wireless" {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"message":"Only wireless pairing is available in this spike."}),
            ),
        )
            .into_response();
    }
    if !sources::action_allowed(&headers) {
        return sources::action_required();
    }
    match state.wireless_pairing.start_wireless().await {
        Ok(status) => (StatusCode::ACCEPTED, Json(status)).into_response(),
        Err(wireless_pairing::PairingError::Disabled) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"Wireless pairing is disabled."})),
        )
            .into_response(),
        Err(wireless_pairing::PairingError::Busy) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"message":"A wireless pairing session is already active."})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"message":"Unable to start wireless pairing."})),
        )
            .into_response(),
    }
}

async fn get_pairing_session(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.wireless_pairing.status(id).await {
        Ok(status) => (StatusCode::OK, Json(status)).into_response(),
        Err(wireless_pairing::PairingError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"Wireless pairing session was not found."})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"message":"Unable to read wireless pairing status."})),
        )
            .into_response(),
    }
}

async fn cancel_pairing_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if !sources::action_allowed(&headers) {
        return sources::action_required();
    }
    match state.wireless_pairing.cancel(id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(wireless_pairing::PairingError::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"Wireless pairing session was not found."})),
        )
            .into_response(),
        Err(wireless_pairing::PairingError::Terminal) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"message":"Wireless pairing session is already finished."})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"message":"Unable to cancel wireless pairing."})),
        )
            .into_response(),
    }
}

async fn list_device_apps(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let identities = match state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|database| store::managed_app_identities(&database, id).map_err(|_| ()))
    {
        Ok(identities) => identities,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"message":"Unable to read managed app history."})),
            )
                .into_response();
        }
    };
    match state.devices.list_installed_apps(id).await {
        Ok(mut apps) => {
            apps.retain(|app| managed_app(&app.bundle_id, &identities));
            apps.sort_by(|a, b| a.display_name.cmp(&b.display_name));
            (StatusCode::OK, Json(apps)).into_response()
        }
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"message":"The selected trusted iPhone is not reachable over Wi-Fi."}))).into_response(),
    }
}

async fn spike_afc_probe(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    match state.devices.probe_afc(id).await {
        Ok(()) => (
            StatusCode::OK,
            Json(AfcProbeResponse {
                transport: "lockdown",
                afc: "ok",
            }),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(AfcProbeResponse {
                transport: "lockdown",
                afc: "unavailable",
            }),
        )
            .into_response(),
    }
}

async fn spike_remote_pairing_rsd_probe(State(state): State<AppState>) -> impl IntoResponse {
    match state.wireless_pairing.probe_remote_pairing_rsd().await {
        Ok(()) => (
            StatusCode::OK,
            Json(RsdProbeSuccessResponse {
                transport: "rsdCoreDevice",
                remote_pairing: "ok",
                rsd: "ok",
                core_device: "ok",
            }),
        )
            .into_response(),
        Err(failure) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(RsdProbeFailureResponse {
                transport: "rsdCoreDevice",
                status: "unavailable",
                stage: failure.stage.as_str(),
            }),
        )
            .into_response(),
    }
}

async fn spike_remote_pairing_afc_probe(State(state): State<AppState>) -> impl IntoResponse {
    match state.wireless_pairing.probe_remote_pairing_afc().await {
        Ok(()) => (
            StatusCode::OK,
            Json(ReadOnlyProbeSuccessResponse {
                transport: "rsd",
                service: "afc",
                status: "ok",
            }),
        )
            .into_response(),
        Err(failure) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadOnlyProbeFailureResponse {
                transport: "rsd",
                service: "afc",
                status: "unavailable",
                stage: failure.stage.as_str(),
            }),
        )
            .into_response(),
    }
}

async fn spike_remote_pairing_installation_proxy_probe(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state
        .wireless_pairing
        .probe_remote_pairing_installation_proxy()
        .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(ReadOnlyProbeSuccessResponse {
                transport: "rsd",
                service: "installationProxy",
                status: "ok",
            }),
        )
            .into_response(),
        Err(failure) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadOnlyProbeFailureResponse {
                transport: "rsd",
                service: "installationProxy",
                status: "unavailable",
                stage: failure.stage.as_str(),
            }),
        )
            .into_response(),
    }
}

async fn run_spike_remote_pairing_install(
    state: AppState,
    app_id: Uuid,
    _single_flight: tokio::sync::OwnedMutexGuard<()>,
) -> SpikeInstallExecution {
    let _mutation = state.app_mutation.read().await;
    let ipa_path = state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|database| store::app_path(&database, app_id).map_err(|_| ()))
        .ok()
        .flatten()
        .map(PathBuf::from)
        .filter(|path| path.is_file());
    let Some(ipa_path) = ipa_path else {
        return SpikeInstallExecution::AppNotFound;
    };
    SpikeInstallExecution::Report(
        state
            .wireless_pairing
            .install_remote_pairing_first_app(state.signing.clone(), ipa_path)
            .await,
    )
}
fn spike_install_status(report: &wireless_pairing::RsdInstallReport) -> StatusCode {
    if report.outcome == wireless_pairing::RsdInstallOutcome::Installed {
        StatusCode::OK
    } else if matches!(
        report.error_kind,
        "device_registration_required" | "app_already_installed" | "signing_not_ready"
    ) {
        StatusCode::CONFLICT
    } else if report.outcome == wireless_pairing::RsdInstallOutcome::NotStarted {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_GATEWAY
    }
}
fn spike_install_response(report: wireless_pairing::RsdInstallReport) -> SpikeRsdInstallResponse {
    SpikeRsdInstallResponse {
        transport: "rsd",
        outcome: report.outcome.as_str(),
        stage: report.stage.as_str(),
        cleanup: report.cleanup.as_str(),
        session_cleanup: report.session_cleanup.as_str(),
        install_command_count: report.install_command_count,
        error_kind: (!report.error_kind.is_empty()).then_some(report.error_kind),
        bundle_id: report.bundle_id,
        certificate_pressure: report.certificate_pressure,
    }
}

async fn spike_remote_pairing_install(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if !sources::action_allowed(&headers) {
        return sources::action_required();
    }
    if body.len() > 1024 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message":"Invalid installation request."})),
        )
            .into_response();
    }
    let request: SpikeRsdInstallRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message":"Invalid installation request."})),
            )
                .into_response();
        }
    };
    let single_flight = match state.spike_install_mutation.clone().try_lock_owned() {
        Ok(single_flight) => single_flight,
        Err(_) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"message":"An RSD installation is already in progress."})),
            )
                .into_response();
        }
    };
    let execution = match tokio::spawn(run_spike_remote_pairing_install(
        state,
        request.app_id,
        single_flight,
    ))
    .await
    {
        Ok(execution) => execution,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"message":"Installation request failed."})),
            )
                .into_response();
        }
    };
    let report = match execution {
        SpikeInstallExecution::AppNotFound => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"message":"Uploaded IPA was not found."})),
            )
                .into_response();
        }
        SpikeInstallExecution::Report(report) => report,
    };
    let status = spike_install_status(&report);
    let result = if report.error_kind.is_empty() {
        "ok"
    } else {
        "error"
    };
    tracing::warn!(
        target: wireless_pairing::SPIKE_DIAGNOSTICS_TARGET,
        transport = "rsd",
        stage = report.stage.as_str(),
        result,
        error_kind = report.error_kind,
        install_command_count = report.install_command_count,
        cleanup = report.cleanup.as_str(),
        session_cleanup = report.session_cleanup.as_str(),
        certificate_pressure = report.certificate_pressure,
        "remote pairing first-install spike completed"
    );
    (status, Json(spike_install_response(report))).into_response()
}

async fn list_managed_installations(State(state): State<AppState>) -> impl IntoResponse {
    match state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|database| store::list_managed_installations(&database).map_err(|_| ()))
    {
        Ok(items) => Json(serde_json::json!(
            items
                .into_iter()
                .map(|item| serde_json::json!({
                    "appId": item.app_id,
                    "deviceId": item.device_id,
                    "appDisplayName": item.app_display_name,
                    "appVersion": item.app_version,
                    "deviceLabel": item.device_label
                }))
                .collect::<Vec<_>>()
        ))
        .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to read managed installations."})),
        )
            .into_response(),
    }
}

async fn forget_managed_installation(
    State(state): State<AppState>,
    Path((device_id, app_id)): Path<(Uuid, Uuid)>,
) -> impl IntoResponse {
    match state.database.lock().map_err(|_| ()).and_then(|database| {
        store::forget_managed_installation(&database, app_id, device_id).map_err(|_| ())
    }) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::CONFLICT, Json(serde_json::json!({"message":"This installation has an active job and cannot be removed from management yet."}))).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"message":"Unable to remove the installation from management."}))).into_response(),
    }
}

fn managed_app(bundle_id: &str, identities: &[store::ManagedAppIdentity]) -> bool {
    identities.iter().any(|identity| {
        if let Some(installed_bundle_id) = &identity.installed_bundle_id {
            return installed_bundle_id == bundle_id;
        }
        identity.source_bundle_id.as_ref().is_some_and(|source| {
            bundle_id == source
                || bundle_id
                    .strip_prefix(source)
                    .is_some_and(|suffix| suffix.starts_with('.'))
        })
    })
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateInstallJobRequest {
    app_id: Uuid,
    device_id: Uuid,
}

async fn create_install_job(
    State(state): State<AppState>,
    Json(request): Json<CreateInstallJobRequest>,
) -> impl IntoResponse {
    if !state.signing.is_ready().await {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"message":"Apple signing is not ready. Sign in before creating an installation job."})),
        ).into_response();
    }
    let devices = match state.devices.list_network_devices().await {
        Ok(devices) => devices,
        Err(_) => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                serde_json::json!({"message":"Wi-Fi device discovery is unavailable. Check netmuxd and try again."}),
            ),
        )
            .into_response(),
    };
    let Some(device) = devices.iter().find(|device| device.id == request.device_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"The requested iPhone was not found on the trusted Wi-Fi transport."})),
        ).into_response();
    };

    let _mutation = state.app_mutation.read().await;
    let id = Uuid::now_v7();
    let ipa_path = state.database.lock().map_err(|_| ()).and_then(|database| {
        let path = store::app_path(&database, request.app_id).map_err(|_| ())?;
        let path = path.ok_or(())?;
        store::insert_job(
            &database,
            id,
            request.app_id,
            request.device_id,
            &device.display_name,
        )
        .map_err(|_| ())?;
        Ok::<_, ()>(PathBuf::from(path))
    });
    let Ok(ipa_path) = ipa_path else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"Uploaded IPA was not found."})),
        )
            .into_response();
    };
    tokio::spawn(run_install_job(
        state.clone(),
        id,
        request.app_id,
        request.device_id,
        ipa_path,
    ));
    let job = jobs::InstallJob {
        id,
        phase: jobs::JobPhase::Queued,
        progress_percent: None,
        public_message: format!(
            "Signing and installation job queued for app {}.",
            request.app_id
        ),
    };
    (StatusCode::ACCEPTED, Json(job)).into_response()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RefreshResponse {
    queued: usize,
}

async fn trigger_refresh(State(state): State<AppState>) -> impl IntoResponse {
    let _mutation = state.app_mutation.read().await;
    if !state.signing.is_ready().await {
        return (StatusCode::CONFLICT, Json(serde_json::json!({"message":"Apple signing is not ready. Sign in before refreshing apps."}))).into_response();
    }
    let devices = match state.devices.list_network_devices().await {
        Ok(devices) => devices,
        Err(_) => return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                serde_json::json!({"message":"Wi-Fi device discovery is unavailable. Check netmuxd and try again."}),
            ),
        )
            .into_response(),
    };
    let targets = match state.database.lock().map_err(|_| ()).and_then(|database| {
        let after_days = store::refresh_after_days(&database).map_err(|_| ())?;
        store::refresh_due_targets(&database, after_days).map_err(|_| ())
    }) {
        Ok(targets) => targets,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"message":"Unable to read refresh targets."})),
            )
                .into_response();
        }
    };
    let mut queued = 0;
    for (app_id, device_id, ipa_path) in targets {
        if !devices.iter().any(|device| device.id == device_id) {
            continue;
        }
        let id = Uuid::now_v7();
        let inserted = state.database.lock().map_err(|_| ()).and_then(|database| {
            if store::active_job_exists(&database, app_id, device_id).map_err(|_| ())? {
                return Ok(false);
            }
            let device_label = devices
                .iter()
                .find(|device| device.id == device_id)
                .map(|device| device.display_name.as_str())
                .unwrap_or("Trusted iPhone");
            store::insert_job(&database, id, app_id, device_id, device_label).map_err(|_| ())?;
            Ok(true)
        });
        if matches!(inserted, Ok(true)) {
            queued += 1;
            tokio::spawn(run_install_job(
                state.clone(),
                id,
                app_id,
                device_id,
                PathBuf::from(ipa_path),
            ));
        }
    }
    (StatusCode::ACCEPTED, Json(RefreshResponse { queued })).into_response()
}
async fn run_install_job(
    state: AppState,
    id: Uuid,
    app_id: Uuid,
    device_id: Uuid,
    ipa_path: PathBuf,
) {
    set_job_status(&state.database, id, "connecting", Some(0));
    set_job_status(&state.database, id, "signing", Some(1));
    let progress_database = state.database.clone();
    let result = state
        .devices
        .install_ipa(
            &state.signing,
            device_id,
            ipa_path,
            Box::new(move |progress| {
                let phase = if progress >= 40 {
                    "transferring"
                } else {
                    "signing"
                };
                set_job_status(&progress_database, id, phase, Some(progress));
            }),
        )
        .await;
    match result {
        Ok(bundle_id) => {
            if let Ok(connection) = state.database.lock() {
                let _ = store::set_job_installed_bundle_id(&connection, id, &bundle_id);
                let _ = store::restore_managed_installation(&connection, app_id, device_id);
            }
            set_job_status(&state.database, id, "succeeded", Some(100));
        }
        Err(error) => {
            tracing::warn!(job_id = %id, error = %error, "IPA installation failed");
            set_job_failure(
                &state.database,
                id,
                match error {
                    TransportError::Unavailable => "iphone_unavailable",
                    TransportError::DeviceInfoFailed => "device_info_failed",
                    TransportError::DeveloperTeamFailed => "developer_team_failed",
                    TransportError::DeviceRegistrationFailed => "device_registration_failed",
                    TransportError::IpaSigningFailed => "ipa_signing_failed",
                    TransportError::SignedMetadataFailed => "signed_metadata_failed",
                    TransportError::DeviceInstallFailed => "device_install_failed",
                },
            );
            set_job_status(&state.database, id, "failed", None);
        }
    }
}

fn set_job_status(
    database: &Arc<Mutex<rusqlite::Connection>>,
    id: Uuid,
    phase: &str,
    progress_percent: Option<u8>,
) {
    if let Ok(connection) = database.lock() {
        let _ = store::update_job_status(&connection, id, phase, progress_percent);
    }
}

fn set_job_failure(database: &Arc<Mutex<rusqlite::Connection>>, id: Uuid, failure_code: &str) {
    if let Ok(connection) = database.lock() {
        let _ = store::set_job_failure(&connection, id, failure_code);
    }
}

fn job_message(phase: &str, failure_code: Option<&str>) -> &'static str {
    if phase == "failed" {
        return match failure_code.unwrap_or("installation_failed") {
            "iphone_unavailable" => "The selected trusted iPhone is not reachable over Wi-Fi.",
            "device_info_failed" => {
                "Could not read the selected iPhone information over the trusted Wi-Fi connection."
            }
            "developer_team_failed" => "Apple developer team information could not be prepared.",
            "device_registration_failed" => {
                "The iPhone could not be registered for this signing session."
            }
            "ipa_signing_failed" => "The IPA could not be signed.",
            "signed_metadata_failed" => "The signed IPA metadata could not be validated.",
            "device_install_failed" => {
                "Signing completed, but transfer/installation on the iPhone failed. Keep the phone unlocked, reachable, and check free storage."
            }
            _ => "Installation failed.",
        };
    }
    match phase {
        "queued" => "Installation job is queued.",
        "connecting" => "Connecting to the trusted iPhone over Wi-Fi.",
        "signing" => "Signing the IPA.",
        "transferring" | "installing" => "Transferring and installing the IPA on the iPhone.",
        "succeeded" => "IPA was signed and installed.",
        _ => "Installation job status is unavailable.",
    }
}
fn install_job_json(job: store::StoredJob) -> serde_json::Value {
    let public_message = job_message(&job.phase, job.failure_code.as_deref());
    serde_json::json!({
        "id": job.id,
        "appId": job.app_id,
        "deviceId": job.device_id,
        "deviceLabel": job.device_label,
        "phase": job.phase,
        "progressPercent": job.progress_percent,
        "appDisplayName": job.app_display_name,
        "appVersion": job.app_version,
        "createdAt": job.created_at,
        "completedAt": job.completed_at,
        "failureCode": job.failure_code,
        "publicMessage": public_message
    })
}

async fn get_install_job(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    let job = state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|database| store::find_job(&database, id).map_err(|_| ()));
    match job {
        Ok(Some(job)) => (StatusCode::OK, Json(install_job_json(job))).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"Installation job was not found."})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to read installation job."})),
        )
            .into_response(),
    }
}

async fn list_install_jobs(State(state): State<AppState>) -> impl IntoResponse {
    match state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|database| store::list_recent_jobs(&database, 20).map_err(|_| ()))
    {
        Ok(jobs) => Json(serde_json::json!(
            jobs.into_iter().map(install_job_json).collect::<Vec<_>>()
        )),
        Err(_) => Json(serde_json::json!({"message":"Unable to read installation history."})),
    }
}

async fn refresh_attention(State(state): State<AppState>) -> impl IntoResponse {
    match state.database.lock().map_err(|_| ()).and_then(|database| {
        let after_days = store::refresh_after_days(&database).map_err(|_| ())?;
        let items = store::refresh_attention(&database, after_days).map_err(|_| ())?;
        Ok((after_days, items))
    }) {
        Ok((after_days, items)) => Json(serde_json::json!({
            "afterDays": after_days,
            "items": items
                .into_iter()
                .map(|item| serde_json::json!({
                    "appId": item.app_id,
                    "deviceLabel": item.device_label,
                    "ageHours": item.age_hours,
                    "retryFailed": item.retry_failed,
                }))
                .collect::<Vec<_>>()
        })),
        Err(_) => Json(serde_json::json!({"message":"Unable to read refresh warnings."})),
    }
}

#[derive(Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RefreshSettings {
    after_days: u8,
}

async fn get_refresh_settings(State(state): State<AppState>) -> impl IntoResponse {
    match state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|database| store::refresh_after_days(&database).map_err(|_| ()))
    {
        Ok(after_days) => (StatusCode::OK, Json(RefreshSettings { after_days })).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to read refresh settings."})),
        )
            .into_response(),
    }
}

async fn update_refresh_settings(
    State(state): State<AppState>,
    Json(settings): Json<RefreshSettings>,
) -> impl IntoResponse {
    if !(store::MIN_REFRESH_AFTER_DAYS..=store::MAX_REFRESH_AFTER_DAYS)
        .contains(&settings.after_days)
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(
                serde_json::json!({"message":"Automatic refresh must be between day 1 and day 6."}),
            ),
        )
            .into_response();
    }
    match state.database.lock().map_err(|_| ()).and_then(|database| {
        store::set_refresh_after_days(&database, settings.after_days).map_err(|_| ())
    }) {
        Ok(()) => (StatusCode::OK, Json(settings)).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to save refresh settings."})),
        )
            .into_response(),
    }
}

async fn installation_validity(State(state): State<AppState>) -> impl IntoResponse {
    match state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|database| store::installation_validity(&database).map_err(|_| ()))
    {
        Ok(items) => Json(serde_json::json!(
            items
                .into_iter()
                .map(|item| serde_json::json!({
                    "appId": item.app_id,
                    "deviceLabel": item.device_label,
                    "remainingDays": item.remaining_days,
                    "completedAt": item.completed_at,
                }))
                .collect::<Vec<_>>()
        )),
        Err(_) => Json(serde_json::json!({"message":"Unable to read IPA validity."})),
    }
}

async fn delete_ipa(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    let _mutation = state.app_mutation.write().await;
    let deletion = state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|database| store::mark_app_deleted(&database, id).map_err(|_| ()));
    match deletion {
        Ok(store::AppDeletion::Ready { storage_path }) => {
            if tokio::fs::remove_file(&storage_path).await.is_ok() {
                (StatusCode::NO_CONTENT, ()).into_response()
            } else {
                if let Ok(database) = state.database.lock() {
                    let _ = store::restore_app(&database, id);
                }
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message":"Unable to remove the IPA file from server storage."})),
                )
                    .into_response()
            }
        }
        Ok(store::AppDeletion::ActiveJob) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"message":"This IPA cannot be removed while an installation or refresh job is active."})),
        )
            .into_response(),
        Ok(store::AppDeletion::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"Uploaded IPA was not found."})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to remove the IPA."})),
        )
            .into_response(),
    }
}

fn validate_display_name(value: &str) -> Result<String, &'static str> {
    let value = value.trim();
    if value.chars().count() > 120 || value.chars().any(|character| character.is_ascii_control()) {
        return Err(
            "Display name must be at most 120 characters and contain no control characters.",
        );
    }
    Ok(value.to_owned())
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RenameAppRequest {
    display_name: String,
}

async fn rename_app(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(request): Json<RenameAppRequest>,
) -> impl IntoResponse {
    let Ok(display_name) = validate_display_name(&request.display_name) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message":"Invalid display name."})),
        )
            .into_response();
    };
    if display_name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message":"Display name cannot be empty when renaming."})),
        )
            .into_response();
    }
    match state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|database| store::rename_app(&database, id, &display_name).map_err(|_| ()))
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"Uploaded IPA was not found."})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to rename the IPA."})),
        )
            .into_response(),
    }
}

async fn upload_ipa(State(state): State<AppState>, mut multipart: Multipart) -> impl IntoResponse {
    let id = Uuid::now_v7();
    let temporary = state.apps_dir.join(format!(".{id}.upload"));
    let final_path = state.apps_dir.join(format!("{id}.ipa"));
    let Ok(mut output) = tokio::fs::File::create(&temporary).await else {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to store IPA upload."})),
        )
            .into_response();
    };
    let mut display_name = None;
    let mut file_seen = false;
    let mut written = 0_u64;
    while let Ok(Some(mut field)) = multipart.next_field().await {
        let Some(name) = field.name() else {
            let _ = tokio::fs::remove_file(&temporary).await;
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message":"Invalid multipart field."})),
            )
                .into_response();
        };
        match name {
            "displayName" if display_name.is_none() => {
                let Ok(value) = field.text().await else {
                    let _ = tokio::fs::remove_file(&temporary).await;
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"message":"Invalid display name."})),
                    )
                        .into_response();
                };
                let Ok(value) = validate_display_name(&value) else {
                    let _ = tokio::fs::remove_file(&temporary).await;
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({"message":"Invalid display name."})),
                    )
                        .into_response();
                };
                display_name = Some(value);
            }
            "file" if !file_seen => {
                file_seen = true;
                loop {
                    let chunk = match field.chunk().await {
                        Ok(Some(chunk)) => chunk,
                        Ok(None) => break,
                        Err(_) => {
                            let _ = tokio::fs::remove_file(&temporary).await;
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({"message":"Unable to read IPA upload."})),
                            )
                                .into_response();
                        }
                    };
                    written = written.saturating_add(chunk.len() as u64);
                    if written > ipa::MAX_COMPRESSED_BYTES {
                        let _ = tokio::fs::remove_file(&temporary).await;
                        return (StatusCode::PAYLOAD_TOO_LARGE, Json(serde_json::json!({"message":"IPA exceeds the 2 GiB upload limit."}))).into_response();
                    }
                    if output.write_all(&chunk).await.is_err() {
                        let _ = tokio::fs::remove_file(&temporary).await;
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(serde_json::json!({"message":"Unable to store IPA upload."})),
                        )
                            .into_response();
                    }
                }
            }
            _ => {
                let _ = tokio::fs::remove_file(&temporary).await;
                return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"message":"Expected one file field and at most one display name field."}))).into_response();
            }
        }
    }
    if !file_seen {
        let _ = tokio::fs::remove_file(&temporary).await;
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message":"Expected an IPA file field."})),
        )
            .into_response();
    }
    if output.flush().await.is_err() || output.sync_all().await.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to store IPA upload."})),
        )
            .into_response();
    }
    drop(output);
    match ipa::inspect_ipa(&temporary) {
        Ok(metadata) => {
            let display_name = display_name
                .filter(|value| !value.is_empty())
                .unwrap_or(metadata.display_name.clone());
            if tokio::fs::rename(&temporary, &final_path).await.is_err() {
                let _ = tokio::fs::remove_file(&temporary).await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message":"Unable to finalize IPA upload."})),
                )
                    .into_response();
            }
            let inserted = state.database.lock().map_err(|_| ()).and_then(|database| {
                store::insert_app(
                    &database,
                    id,
                    &metadata.sha256,
                    &final_path.to_string_lossy(),
                    metadata.size_bytes,
                    &metadata.bundle_id,
                    &display_name,
                    metadata.app_version.as_deref(),
                )
                .map_err(|_| ())
            });
            if inserted.is_err() {
                let _ = tokio::fs::remove_file(&final_path).await;
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"message":"Unable to record IPA upload."})),
                )
                    .into_response();
            }
            (StatusCode::CREATED, Json(serde_json::json!({"id":id,"displayName":display_name,"appVersion":metadata.app_version,"sha256":metadata.sha256,"sizeBytes":metadata.size_bytes}))).into_response()
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(&temporary).await;
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message":"IPA was rejected.","code":error.to_string()})),
            )
                .into_response()
        }
    }
}

#[tokio::main]
async fn main() {
    let spike_mode = std::env::args().any(|argument| argument == "--wireless-pairing-spike");

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install rustls AWS-LC crypto provider");

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_filter(operator_env_filter(None))
                .with_filter(filter_fn(move |metadata| {
                    spike_target_allowed(spike_mode, metadata)
                })),
        )
        .init();
    let data_dir = if spike_mode {
        std::env::var("IPHONELOADLY_SPIKE_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("spike-data"))
    } else {
        PathBuf::from("data")
    };
    std::fs::create_dir_all(&data_dir).expect("create API data directory");

    let database_path = data_dir.join("iphoneloadly.db");
    let database = store::initialize(&database_path).expect("initialize SQLite store");
    for (id, path) in store::apps_missing_bundle_id(&database).unwrap_or_default() {
        match ipa::bundle_identifier(StdPath::new(&path)) {
            Ok(bundle_id) => {
                if let Err(error) = store::set_app_bundle_id(&database, id, &bundle_id) {
                    tracing::warn!(app_id = %id, error = %error, "unable to migrate IPA bundle identifier");
                }
            }
            Err(error) => {
                tracing::warn!(app_id = %id, error = %error, "unable to inspect existing IPA during migration");
            }
        }
    }
    let mux_socket = std::env::var("IPHONELOADLY_MUX_SOCKET")
        .unwrap_or_else(|_| "/run/iphoneloadly/mux.sock".into());
    let pairing_dir =
        std::env::var("IPHONELOADLY_PAIRING_DIR").unwrap_or_else(|_| "/var/lib/lockdown".into());
    let devices: Arc<dyn DeviceTransport> = Arc::new(NetmuxTransport {
        mux_socket,
        pairing_path: pairing_dir.into(),
    });
    let wireless_pairing_config = match wireless_pairing::WirelessPairingConfig::from_env(
        data_dir.join("wireless-pairing"),
    ) {
        Ok(mut config) => {
            if !spike_mode && matches!(config.mode, wireless_pairing::WirelessPairingMode::On) {
                tracing::warn!("wireless pairing on-mode is restricted to the disposable spike");
                config.mode = wireless_pairing::WirelessPairingMode::Off;
            }
            config
        }
        Err(_) => {
            tracing::warn!("invalid wireless pairing configuration; feature disabled");
            wireless_pairing::WirelessPairingConfig::disabled(data_dir.join("wireless-pairing"))
        }
    };
    let wireless_pairing = Arc::new(wireless_pairing::WirelessPairingService::new(
        wireless_pairing_config,
    ));
    let github =
        github::GitHubClient::new(env!("CARGO_PKG_VERSION")).expect("create GitHub client");
    let state = AppState {
        signing: signing::AppleSigningProvider::new(
            std::env::var("IPHONELOADLY_ANISETTE_URL").ok(),
            data_dir.join("signing"),
        ),
        devices,
        wireless_pairing,
        apps_dir: data_dir.join("apps"),
        database: Arc::new(Mutex::new(database)),
        app_mutation: Arc::new(tokio::sync::RwLock::new(())),
        spike_install_mutation: Arc::new(tokio::sync::Mutex::new(())),
        source_sync: Arc::new(tokio::sync::Mutex::new(())),
        github: Arc::new(github),
    };
    tokio::fs::create_dir_all(&state.apps_dir)
        .await
        .expect("create app storage");
    if let Err(error) = state.signing.restore_saved_login().await {
        tracing::warn!(error = %error, "unable to restore saved Apple sign-in");
    }
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/healthz", get(healthz))
        .route("/api/signing/sessions", post(start_apple_login))
        .route(
            "/api/signing/saved-session",
            get(saved_apple_login).delete(delete_saved_apple_login),
        )
        .route(
            "/api/signing/certificate-recovery",
            post(request_certificate_recovery),
        )
        .route("/api/signing/sessions/{id}", get(get_apple_login))
        .route(
            "/api/signing/sessions/{id}/two-factor",
            post(submit_apple_two_factor),
        )
        .route("/api/devices", get(list_devices))
        .route("/api/devices/{id}/apps", get(list_device_apps))
        .route("/api/devices/rescan", post(rescan_devices))
        .route("/api/pairing-sessions", post(create_pairing_session))
        .route(
            "/api/pairing-sessions/{id}",
            get(get_pairing_session).delete(cancel_pairing_session),
        )
        .route(
            "/api/managed-installations",
            get(list_managed_installations),
        )
        .route(
            "/api/devices/{device_id}/managed-apps/{app_id}",
            delete(forget_managed_installation),
        )
        .route("/api/sources/preview", post(sources::preview))
        .route("/api/sources", get(sources::list).post(sources::create))
        .route(
            "/api/sources/{id}",
            axum::routing::put(sources::update).delete(sources::remove),
        )
        .route("/api/sources/{id}/check", post(sources::check))
        .route("/api/sources/{id}/download", post(sources::download))
        .route(
            "/api/sources/{id}/automation",
            axum::routing::put(sources::automation),
        )
        .route("/api/sources/sync", post(sources::sync))
        .route("/api/update", get(update::info).post(update::request))
        .route("/api/update/status", get(update::status))
        .route("/api/apps", get(list_apps).post(upload_ipa))
        .route("/api/apps/{id}", patch(rename_app).delete(delete_ipa))
        .route("/api/install-jobs", post(create_install_job))
        .route("/api/install-jobs", get(list_install_jobs))
        .route("/api/install-jobs/{id}", get(get_install_job))
        .route("/api/refresh", post(trigger_refresh))
        .route("/api/refresh-attention", get(refresh_attention))
        .route(
            "/api/settings/refresh",
            get(get_refresh_settings).put(update_refresh_settings),
        )
        .route("/api/installation-validity", get(installation_validity));
    let app = with_spike_routes(app, spike_mode);
    let app = app
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024 * 1024usize))
        .with_state(state);
    let address: SocketAddr = if spike_mode {
        std::env::var("IPHONELOADLY_SPIKE_API_ADDRESS").unwrap_or_else(|_| "127.0.0.1:18080".into())
    } else {
        "127.0.0.1:8080".into()
    }
    .parse()
    .expect("valid API socket address");
    if spike_mode && !address.ip().is_loopback() {
        panic!("wireless pairing spike API must bind to loopback");
    }
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("bind API listener");
    tracing::info!(%address, spike_mode, "iPhoneLoadly API listening");
    axum::serve(listener, app).await.expect("serve API");
}
