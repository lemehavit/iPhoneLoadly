mod ipa;
mod jobs;
mod signing;
mod store;

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
    routing::{get, post},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    signing: Arc<signing::AppleSigningProvider>,
    devices: Arc<dyn DeviceTransport>,
    apps_dir: PathBuf,
    database: Arc<Mutex<rusqlite::Connection>>,
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
    async fn install_ipa(
        &self,
        signing: &signing::AppleSigningProvider,
        device_id: Uuid,
        ipa_path: PathBuf,
    ) -> Result<(), TransportError>;
}

#[derive(Debug, Error)]
enum TransportError {
    #[error("network device transport is not configured")]
    Unavailable,
    #[error("IPA installation could not be completed")]
    InstallFailed,
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
    ) -> Result<(), TransportError> {
        let (udid, address, _) = self
            .reachable_network_devices()
            .await?
            .into_iter()
            .find(|(udid, _, _)| device_id_for_udid(udid) == device_id)
            .ok_or(TransportError::Unavailable)?;
        let provider = self.provider_for(&udid, address)?;
        signing
            .install_ipa(&provider, ipa_path)
            .await
            .map_err(|_| TransportError::InstallFailed)
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
            return Err(TransportError::Unavailable);
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
    use super::device_id_for_udid;

    #[test]
    fn device_id_is_stable_for_non_uuid_apple_udids() {
        let first = device_id_for_udid("00008110-001A2B3C00000000");
        assert_eq!(first, device_id_for_udid("00008110-001A2B3C00000000"));
        assert_ne!(first, device_id_for_udid("00008110-001A2B3C00000001"));
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HealthResponse {
    status: &'static str,
    signing: SigningReadiness,
}

async fn healthz(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
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
                    "sha256": app.sha256,
                    "sizeBytes": app.size_bytes,
                }))
                .collect::<Vec<_>>()
        )),
        Err(_) => Json(serde_json::json!({"message":"Unable to list uploaded IPAs."})),
    }
}

#[derive(serde::Deserialize)]
struct StartAppleLoginRequest {
    email: String,
    password: String,
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
    match state.signing.begin_login(request.email, request.password).await {
        Ok(status) => (StatusCode::ACCEPTED, Json(status)).into_response(),
        Err(signing::SigningError::MissingAnisetteUrl) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"message":"Configure IPHONELOADLY_ANISETTE_URL with a trusted anisette service before signing in."})),
        ).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"message":"Unable to start Apple sign-in."}))).into_response(),
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
    if !devices.iter().any(|device| device.id == request.device_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"The requested iPhone was not found on the trusted Wi-Fi transport."})),
        ).into_response();
    }

    let id = Uuid::now_v7();
    let ipa_path = state.database.lock().map_err(|_| ()).and_then(|database| {
        let path = store::app_path(&database, request.app_id).map_err(|_| ())?;
        let path = path.ok_or(())?;
        store::insert_job(&database, id, request.app_id, request.device_id).map_err(|_| ())?;
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
    let targets = match state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|database| store::refresh_due_targets(&database).map_err(|_| ()))
    {
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
            store::insert_job(&database, id, app_id, device_id).map_err(|_| ())?;
            Ok(true)
        });
        if matches!(inserted, Ok(true)) {
            queued += 1;
            tokio::spawn(run_install_job(
                state.clone(),
                id,
                device_id,
                PathBuf::from(ipa_path),
            ));
        }
    }
    (StatusCode::ACCEPTED, Json(RefreshResponse { queued })).into_response()
}

async fn run_install_job(state: AppState, id: Uuid, device_id: Uuid, ipa_path: PathBuf) {
    set_job_phase(&state.database, id, "connecting");
    set_job_phase(&state.database, id, "installing");
    let result = state
        .devices
        .install_ipa(&state.signing, device_id, ipa_path)
        .await;
    if result.is_err() {
        tracing::warn!(job_id = %id, "IPA installation failed");
    }
    set_job_phase(
        &state.database,
        id,
        if result.is_ok() {
            "succeeded"
        } else {
            "failed"
        },
    );
}

fn set_job_phase(database: &Arc<Mutex<rusqlite::Connection>>, id: Uuid, phase: &str) {
    if let Ok(connection) = database.lock() {
        let _ = store::update_job_phase(&connection, id, phase);
    }
}

fn job_message(phase: &str) -> &'static str {
    match phase {
        "queued" => "Installation job is queued.",
        "connecting" => "Connecting to the trusted iPhone over Wi-Fi.",
        "installing" => "Signing and installing the IPA.",
        "succeeded" => "IPA was signed and installed.",
        "failed" => "Installation failed. Check the server logs for redacted diagnostics.",
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
                "publicMessage": job_message(&job.phase)
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

async fn upload_ipa(State(state): State<AppState>, mut multipart: Multipart) -> impl IntoResponse {
    let Some(mut field) = multipart.next_field().await.ok().flatten() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message":"Expected an IPA file field."})),
        )
            .into_response();
    };
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
    let mut written = 0_u64;
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
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({"message":"IPA exceeds the 2 GiB upload limit."})),
            )
                .into_response();
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
    if output.flush().await.is_err() || output.sync_all().await.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to store IPA upload."})),
        )
            .into_response();
    }
    drop(output);
    let inspected = ipa::inspect_ipa(&temporary);
    match inspected {
        Ok(metadata) => {
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
            (StatusCode::CREATED, Json(serde_json::json!({"id":id,"sha256":metadata.sha256,"sizeBytes":metadata.size_bytes}))).into_response()
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

    let database_path = PathBuf::from("data/iphoneloadly.db");
    let database = store::initialize(&database_path).expect("initialize SQLite store");
    let mux_socket = std::env::var("IPHONELOADLY_MUX_SOCKET")
        .unwrap_or_else(|_| "/run/iphoneloadly/mux.sock".into());
    let pairing_dir =
        std::env::var("IPHONELOADLY_PAIRING_DIR").unwrap_or_else(|_| "/var/lib/lockdown".into());
    let devices: Arc<dyn DeviceTransport> = Arc::new(NetmuxTransport {
        mux_socket,
        pairing_path: pairing_dir.into(),
    });
    let state = AppState {
        signing: signing::AppleSigningProvider::new(
            std::env::var("IPHONELOADLY_ANISETTE_URL").ok(),
        ),
        devices,
        apps_dir: PathBuf::from("data/apps"),
        database: Arc::new(Mutex::new(database)),
    };
    tokio::fs::create_dir_all(&state.apps_dir)
        .await
        .expect("create app storage");
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/healthz", get(healthz))
        .route("/api/signing/sessions", post(start_apple_login))
        .route("/api/signing/sessions/{id}", get(get_apple_login))
        .route(
            "/api/signing/sessions/{id}/two-factor",
            post(submit_apple_two_factor),
        )
        .route("/api/devices", get(list_devices))
        .route("/api/devices/rescan", post(rescan_devices))
        .route("/api/apps", get(list_apps).post(upload_ipa))
        .route("/api/install-jobs", post(create_install_job))
        .route("/api/install-jobs/{id}", get(get_install_job))
        .route("/api/refresh", post(trigger_refresh))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024 * 1024usize))
        .with_state(state);

    let address: SocketAddr = "127.0.0.1:8080".parse().expect("static socket address");
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .expect("bind API listener");
    tracing::info!(%address, "iPhoneLoadly API listening");
    axum::serve(listener, app).await.expect("serve API");
}
