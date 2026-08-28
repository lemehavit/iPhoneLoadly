mod github;
mod ipa;
mod jobs;
mod signing;
mod sources;
mod store;
mod update;
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
    extract::{DefaultBodyLimit, Multipart, Path, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{delete, get, patch, post},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) signing: Arc<signing::AppleSigningProvider>,
    pub(crate) devices: Arc<dyn DeviceTransport>,
    pub(crate) apps_dir: PathBuf,
    pub(crate) database: Arc<Mutex<rusqlite::Connection>>,
    pub(crate) app_mutation: Arc<tokio::sync::RwLock<()>>,
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
    use super::{StartAppleLoginRequest, device_id_for_udid, managed_app};
    use crate::store::ManagedAppIdentity;

    #[test]
    fn device_id_is_stable_for_non_uuid_apple_udids() {
        let first = device_id_for_udid("00008110-001A2B3C00000000");
        assert_eq!(first, device_id_for_udid("00008110-001A2B3C00000000"));
        assert_ne!(first, device_id_for_udid("00008110-001A2B3C00000001"));
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

async fn get_install_job(State(state): State<AppState>, Path(id): Path<Uuid>) -> impl IntoResponse {
    let job = state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|database| store::find_job(&database, id).map_err(|_| ()));
    match job {
        Ok(Some(job)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "id": job.id,
                "appId": job.app_id,
                "deviceId": job.device_id,
                "phase": job.phase,
                "appDisplayName": job.app_display_name,
                "appVersion": job.app_version,
                "failureCode": job.failure_code,
                "publicMessage": job_message(&job.phase, job.failure_code.as_deref())
            })),
        )
            .into_response(),
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
            jobs.into_iter()
                .map(|job| serde_json::json!({
                    "id": job.id,
                    "appId": job.app_id,
                    "deviceLabel": job.device_label,
                    "phase": job.phase,
                    "appDisplayName": job.app_display_name,
                    "appVersion": job.app_version,
                    "progressPercent": job.progress_percent,
                    "createdAt": job.created_at,
                    "completedAt": job.completed_at,
                    "failureCode": job.failure_code,
                    "publicMessage": job_message(&job.phase, job.failure_code.as_deref())
                }))
                .collect::<Vec<_>>()
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
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("install rustls AWS-LC crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let data_dir = PathBuf::from("data");
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
    let github =
        github::GitHubClient::new(env!("CARGO_PKG_VERSION")).expect("create GitHub client");
    let state = AppState {
        signing: signing::AppleSigningProvider::new(
            std::env::var("IPHONELOADLY_ANISETTE_URL").ok(),
            data_dir.join("signing"),
        ),
        devices,
        apps_dir: data_dir.join("apps"),
        database: Arc::new(Mutex::new(database)),
        app_mutation: Arc::new(tokio::sync::RwLock::new(())),
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
        .route("/api/installation-validity", get(installation_validity))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024 * 1024usize))
        .with_state(state);

    let address: SocketAddr = "127.0.0.1:8080".parse().expect("static socket address");
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("bind API listener");
    tracing::info!(%address, "iPhoneLoadly API listening");
    axum::serve(listener, app).await.expect("serve API");
}
