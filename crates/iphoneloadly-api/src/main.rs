mod ipa;
mod jobs;
mod signing;
mod store;

use std::{net::{IpAddr, SocketAddr}, path::PathBuf, sync::{Arc, Mutex}};

use async_trait::async_trait;
use axum::{extract::{DefaultBodyLimit, Multipart, Path, State}, http::StatusCode, response::{Html, IntoResponse}, routing::{get, post}, Json, Router};
use serde::Serialize;
use thiserror::Error;
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
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
enum ConnectionType {
    Network,
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
    async fn install_ipa(&self, signing: &signing::AppleSigningProvider, ipa_path: PathBuf) -> Result<(), TransportError>;
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
            SigningReadiness { available: true, message: "Apple signing session is active." }
        } else if self.has_anisette_url() {
            SigningReadiness { available: false, message: "Sign in with Apple to enable signing." }
        } else {
            SigningReadiness { available: false, message: "Configure a trusted anisette URL before signing in with Apple." }
        }
    }
}

struct UnconfiguredTransport;

struct ConfiguredNetworkTransport {
    device: DeviceSummary,
}

struct DirectTcpTransport {
    id: Uuid,
    address: IpAddr,
    pairing_path: PathBuf,
}

#[async_trait]
impl DeviceTransport for UnconfiguredTransport {
    async fn list_network_devices(&self) -> Result<Vec<DeviceSummary>, TransportError> {
        Err(TransportError::Unavailable)
    }

    async fn install_ipa(&self, _: &signing::AppleSigningProvider, _: PathBuf) -> Result<(), TransportError> {
        Err(TransportError::Unavailable)
    }
}

#[async_trait]
impl DeviceTransport for ConfiguredNetworkTransport {
    async fn list_network_devices(&self) -> Result<Vec<DeviceSummary>, TransportError> {
        Ok(vec![self.device.clone()])
    }

    async fn install_ipa(&self, _: &signing::AppleSigningProvider, _: PathBuf) -> Result<(), TransportError> {
        Err(TransportError::Unavailable)
    }
}

#[async_trait]
impl DeviceTransport for DirectTcpTransport {
    async fn list_network_devices(&self) -> Result<Vec<DeviceSummary>, TransportError> {
        use idevice::pairing_file::PairingFile;
        use idevice::provider::TcpProvider;
        use idevice::IdeviceService;
        use idevice::services::lockdown::LockdownClient;

        let pairing_file = PairingFile::read_from_file(&self.pairing_path).map_err(|_| TransportError::Unavailable)?;
        let provider = TcpProvider {
            addr: self.address,
            scope_id: None,
            pairing_file: pairing_file.clone(),
            label: "iPhoneLoadly".into(),
        };
        let mut client = LockdownClient::connect(&provider).await.map_err(|_| TransportError::Unavailable)?;
        client.start_session(&pairing_file).await.map_err(|_| TransportError::Unavailable)?;
        let device_name = client.get_value(Some("DeviceName"), None).await.map_err(|_| TransportError::Unavailable)?;
        let product_type = client.get_value(Some("ProductType"), None).await.map_err(|_| TransportError::Unavailable)?;
        let ios_version = client.get_value(Some("ProductVersion"), None).await.map_err(|_| TransportError::Unavailable)?;
        Ok(vec![DeviceSummary {
            id: self.id,
            display_name: device_name.as_string().unwrap_or("iPhone").to_owned(),
            product_type: product_type.as_string().unwrap_or("unknown").to_owned(),
            ios_version: ios_version.as_string().unwrap_or("unknown").to_owned(),
            connection_type: ConnectionType::Network,
        }])
    }

    async fn install_ipa(&self, signing: &signing::AppleSigningProvider, ipa_path: PathBuf) -> Result<(), TransportError> {
        use idevice::pairing_file::PairingFile;
        use idevice::provider::TcpProvider;

        let pairing_file = PairingFile::read_from_file(&self.pairing_path).map_err(|_| TransportError::Unavailable)?;
        let provider = TcpProvider {
            addr: self.address,
            scope_id: None,
            pairing_file,
            label: "iPhoneLoadly".into(),
        };
        signing.install_ipa(&provider, ipa_path).await.map_err(|_| TransportError::InstallFailed)
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
    match state.database.lock().map_err(|_| ()).and_then(|database| store::list_apps(&database).map_err(|_| ())) {
        Ok(apps) => Json(serde_json::json!(apps.into_iter().map(|app| serde_json::json!({
            "id": app.id,
            "sha256": app.sha256,
            "sizeBytes": app.size_bytes,
        })).collect::<Vec<_>>())),
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
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"message":"Email and password are required."}))).into_response();
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

async fn get_apple_login(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    match state.signing.login_status(id).await {
        Ok(status) => (StatusCode::OK, Json(status)).into_response(),
        Err(_) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"message":"Apple login session was not found."}))).into_response(),
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
                "message": "Wi-Fi device transport is not configured yet."
            })),
        )
            .into_response(),
    }
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
            Json(serde_json::json!({"message":"The configured iPhone is not reachable over Wi-Fi."})),
        ).into_response(),
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
        return (StatusCode::NOT_FOUND, Json(serde_json::json!({"message":"Uploaded IPA was not found."}))).into_response();
    };
    tokio::spawn(run_install_job(state.clone(), id, ipa_path));
    let job = jobs::InstallJob {
        id,
        phase: jobs::JobPhase::Queued,
        progress_percent: None,
        public_message: format!("Signing and installation job queued for app {}.", request.app_id),
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
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"message":"The configured iPhone is not reachable over Wi-Fi."}))).into_response(),
    };
    let targets = match state.database.lock().map_err(|_| ()).and_then(|database| store::refresh_due_targets(&database).map_err(|_| ())) {
        Ok(targets) => targets,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"message":"Unable to read refresh targets."}))).into_response(),
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
            tokio::spawn(run_install_job(state.clone(), id, PathBuf::from(ipa_path)));
        }
    }
    (StatusCode::ACCEPTED, Json(RefreshResponse { queued })).into_response()
}

async fn run_install_job(state: AppState, id: Uuid, ipa_path: PathBuf) {
    set_job_phase(&state.database, id, "connecting");
    set_job_phase(&state.database, id, "installing");
    let result = state.devices.install_ipa(&state.signing, ipa_path).await;
    if result.is_err() {
        tracing::warn!(job_id = %id, "IPA installation failed");
    }
    set_job_phase(&state.database, id, if result.is_ok() { "succeeded" } else { "failed" });
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

async fn get_install_job(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let job = state.database.lock().map_err(|_| ()).and_then(|database| {
        store::find_job(&database, id).map_err(|_| ())
    });
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
        ).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"Installation job was not found."})),
        ).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to read installation job."})),
        ).into_response(),
    }
}

async fn upload_ipa(State(state): State<AppState>, mut multipart: Multipart) -> impl IntoResponse {
    let Some(field) = multipart.next_field().await.ok().flatten() else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"message":"Expected an IPA file field."}))).into_response();
    };
    let id = Uuid::now_v7();
    let temporary = state.apps_dir.join(format!(".{id}.upload"));
    let final_path = state.apps_dir.join(format!("{id}.ipa"));
    let Ok(bytes) = field.bytes().await else {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"message":"Unable to read IPA upload."}))).into_response();
    };
    if tokio::fs::write(&temporary, bytes).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"message":"Unable to store IPA upload."}))).into_response();
    }
    let inspected = ipa::inspect_ipa(&temporary);
    match inspected {
        Ok(metadata) => {
            if tokio::fs::rename(&temporary, &final_path).await.is_err() {
                let _ = tokio::fs::remove_file(&temporary).await;
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"message":"Unable to finalize IPA upload."}))).into_response();
            }
            let inserted = state.database.lock().map_err(|_| ()).and_then(|database| {
                store::insert_app(&database, id, &metadata.sha256, &final_path.to_string_lossy(), metadata.size_bytes).map_err(|_| ())
            });
            if inserted.is_err() {
                let _ = tokio::fs::remove_file(&final_path).await;
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"message":"Unable to record IPA upload."}))).into_response();
            }
            (StatusCode::CREATED, Json(serde_json::json!({"id":id,"sha256":metadata.sha256,"sizeBytes":metadata.size_bytes}))).into_response()
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(&temporary).await;
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({"message":"IPA was rejected.","code":error.to_string()}))).into_response()
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
    let devices: Arc<dyn DeviceTransport> = match (
        std::env::var("IPHONELOADLY_DEVICE_ID"),
        std::env::var("IPHONELOADLY_DEVICE_IP"),
        std::env::var("IPHONELOADLY_PAIRING_FILE"),
    ) {
        (Ok(id), Ok(address), Ok(pairing_path)) => match (Uuid::parse_str(&id), address.parse::<IpAddr>()) {
            (Ok(id), Ok(address)) => Arc::new(DirectTcpTransport { id, address, pairing_path: pairing_path.into() }),
            _ => Arc::new(UnconfiguredTransport),
        },
        _ => match (
        std::env::var("IPHONELOADLY_DEVICE_ID"),
        std::env::var("IPHONELOADLY_DEVICE_NAME"),
        std::env::var("IPHONELOADLY_DEVICE_PRODUCT"),
        std::env::var("IPHONELOADLY_DEVICE_IOS_VERSION"),
    ) {
        (Ok(id), Ok(display_name), Ok(product_type), Ok(ios_version)) => match Uuid::parse_str(&id) {
            Ok(id) => Arc::new(ConfiguredNetworkTransport {
            device: DeviceSummary { id, display_name, product_type, ios_version, connection_type: ConnectionType::Network },
        }),
            Err(_) => Arc::new(UnconfiguredTransport),
        },
        _ => Arc::new(UnconfiguredTransport),
    },
};
    let state = AppState {
        signing: signing::AppleSigningProvider::new(std::env::var("IPHONELOADLY_ANISETTE_URL").ok()),
        devices,
        apps_dir: PathBuf::from("data/apps"),
        database: Arc::new(Mutex::new(database)),
    };
    tokio::fs::create_dir_all(&state.apps_dir).await.expect("create app storage");
    let app = Router::new()
        .route("/", get(dashboard))
        .route("/healthz", get(healthz))
        .route("/api/signing/sessions", post(start_apple_login))
        .route("/api/signing/sessions/{id}", get(get_apple_login))
        .route("/api/signing/sessions/{id}/two-factor", post(submit_apple_two_factor))
        .route("/api/devices", get(list_devices))
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
