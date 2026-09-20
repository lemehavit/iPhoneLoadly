use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use idevice::provider::TcpProvider;
use isideload::{
    SideloadError,
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{
        certificates::CertificatesApi, developer_session::DeveloperSession, devices::DevicesApi,
    },
    sideload::{
        SideloaderBuilder, builder::MaxCertsBehavior, install::install_app as install_signed_app,
        sideloader::Sideloader,
    },
    util::{device::IdeviceInfo, fs_storage::FsStorage, storage::InMemoryStorage},
};
use rootcause::Report;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{Mutex, Notify};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum LoginPhase {
    Authenticating,
    AwaitingTwoFactor,
    Ready,
    Failed,
}
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthDiagnosticStage {
    AnisetteInit,
    AppleAccountLogin,
    AppleAccountLoginTimeout,
    DeveloperSession,
}

impl AuthDiagnosticStage {
    fn as_str(&self) -> &'static str {
        match self {
            Self::AnisetteInit => "ANISSETTE_INIT",
            Self::AppleAccountLogin => "APPLE_ACCOUNT_LOGIN",
            Self::AppleAccountLoginTimeout => "APPLE_ACCOUNT_LOGIN_TIMEOUT",
            Self::DeveloperSession => "DEVELOPER_SESSION",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthNetworkClass {
    AppleAuth,
    Http,
    Network,
    Timeout,
    Unknown,
}

impl AuthNetworkClass {
    fn as_str(&self) -> &'static str {
        match self {
            Self::AppleAuth => "APPLE_AUTH",
            Self::Http => "HTTP",
            Self::Network => "NETWORK",
            Self::Timeout => "TIMEOUT",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthFailureDiagnostic {
    #[serde(rename = "AUTH_STAGE")]
    pub auth_stage: AuthDiagnosticStage,
    #[serde(rename = "HTTP_STATUS", skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(rename = "APPLE_AUTH_CODE", skip_serializing_if = "Option::is_none")]
    pub apple_auth_code: Option<i64>,
    #[serde(rename = "NETWORK_CLASS")]
    pub network_class: AuthNetworkClass,
    #[serde(rename = "TIMEOUT")]
    pub timeout: bool,
}

impl AuthFailureDiagnostic {
    fn unknown(auth_stage: AuthDiagnosticStage) -> Self {
        Self {
            auth_stage,
            http_status: None,
            apple_auth_code: None,
            network_class: AuthNetworkClass::Unknown,
            timeout: false,
        }
    }

    fn timeout(auth_stage: AuthDiagnosticStage) -> Self {
        Self {
            auth_stage,
            http_status: None,
            apple_auth_code: None,
            network_class: AuthNetworkClass::Timeout,
            timeout: true,
        }
    }

    fn from_report(auth_stage: AuthDiagnosticStage, report: &Report) -> Self {
        let mut diagnostic = Self::unknown(auth_stage);
        for context in report.as_ref().iter_reports() {
            if let Some(error) = context.downcast_current_context::<SideloadError>() {
                if let SideloadError::AuthWithMessage(code, _) = error {
                    diagnostic.apple_auth_code = Some(*code);
                    diagnostic.network_class = AuthNetworkClass::AppleAuth;
                    diagnostic.timeout = false;
                    return diagnostic;
                }
            }

            if let Some(error) = context.downcast_current_context::<reqwest_013::Error>() {
                if let Some(status) = error.status() {
                    diagnostic.http_status = Some(status.as_u16());
                    diagnostic.network_class = AuthNetworkClass::Http;
                } else if error.is_timeout() && diagnostic.http_status.is_none() {
                    diagnostic.network_class = AuthNetworkClass::Timeout;
                    diagnostic.timeout = true;
                } else if diagnostic.http_status.is_none() && !diagnostic.timeout {
                    diagnostic.network_class = AuthNetworkClass::Network;
                }
            }
        }
        diagnostic
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStatus {
    pub id: Uuid,
    pub phase: LoginPhase,
    pub two_factor: Option<TwoFactorCallbackParams>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<AuthFailureDiagnostic>,
}

fn log_auth_failure(diagnostic: &AuthFailureDiagnostic) {
    match (diagnostic.http_status, diagnostic.apple_auth_code) {
        (Some(http_status), Some(apple_auth_code)) => tracing::warn!(
            AUTH_STAGE = diagnostic.auth_stage.as_str(),
            HTTP_STATUS = http_status,
            APPLE_AUTH_CODE = apple_auth_code,
            NETWORK_CLASS = diagnostic.network_class.as_str(),
            TIMEOUT = diagnostic.timeout,
            "Apple authentication failed"
        ),
        (Some(http_status), None) => tracing::warn!(
            AUTH_STAGE = diagnostic.auth_stage.as_str(),
            HTTP_STATUS = http_status,
            NETWORK_CLASS = diagnostic.network_class.as_str(),
            TIMEOUT = diagnostic.timeout,
            "Apple authentication failed"
        ),
        (None, Some(apple_auth_code)) => tracing::warn!(
            AUTH_STAGE = diagnostic.auth_stage.as_str(),
            APPLE_AUTH_CODE = apple_auth_code,
            NETWORK_CLASS = diagnostic.network_class.as_str(),
            TIMEOUT = diagnostic.timeout,
            "Apple authentication failed"
        ),
        (None, None) => tracing::warn!(
            AUTH_STAGE = diagnostic.auth_stage.as_str(),
            NETWORK_CLASS = diagnostic.network_class.as_str(),
            TIMEOUT = diagnostic.timeout,
            "Apple authentication failed"
        ),
    }
}

struct LoginAttempt {
    id: Uuid,
    state: Mutex<LoginStatus>,
    response: Mutex<Option<TwoFactorCallbackResponse>>,
    response_ready: Notify,
}

impl LoginAttempt {
    fn new(id: Uuid) -> Self {
        Self {
            id,
            state: Mutex::new(LoginStatus {
                id,
                phase: LoginPhase::Authenticating,
                two_factor: None,
                message: "Authenticating with Apple.".into(),
                diagnostic: None,
            }),
            response: Mutex::new(None),
            response_ready: Notify::new(),
        }
    }

    async fn status(&self) -> LoginStatus {
        self.state.lock().await.clone()
    }

    async fn authenticating(&self, message: &str) {
        let mut state = self.state.lock().await;
        state.phase = LoginPhase::Authenticating;
        state.two_factor = None;
        state.diagnostic = None;
        state.message = message.into();
    }

    async fn wait_for_two_factor(
        &self,
        params: TwoFactorCallbackParams,
    ) -> TwoFactorCallbackResponse {
        {
            let mut state = self.state.lock().await;
            *state = LoginStatus {
                id: self.id,
                phase: LoginPhase::AwaitingTwoFactor,
                two_factor: Some(params),
                message: "Apple requires a two-factor authentication response.".into(),
                diagnostic: None,
            };
        }

        loop {
            if let Some(response) = self.response.lock().await.take() {
                return response;
            }
            self.response_ready.notified().await;
        }
    }

    async fn submit(&self, response: TwoFactorCallbackResponse) -> Result<(), SigningError> {
        if !matches!(self.state.lock().await.phase, LoginPhase::AwaitingTwoFactor) {
            return Err(SigningError::NoTwoFactorChallenge);
        }
        *self.response.lock().await = Some(response);
        self.response_ready.notify_one();
        Ok(())
    }

    async fn ready(&self) {
        *self.state.lock().await = LoginStatus {
            id: self.id,
            phase: LoginPhase::Ready,
            two_factor: None,
            message: "Apple signing session is ready.".into(),
            diagnostic: None,
        };
    }

    async fn failed(&self, diagnostic: AuthFailureDiagnostic) {
        log_auth_failure(&diagnostic);
        *self.state.lock().await = LoginStatus {
            id: self.id,
            phase: LoginPhase::Failed,
            two_factor: None,
            message: "Apple authentication failed. Check the server logs for redacted diagnostics."
                .into(),
            diagnostic: Some(diagnostic),
        };
    }
}

pub struct AppleSigningProvider {
    anisette_url: Option<String>,
    signing_storage_path: PathBuf,
    sideloader: Mutex<Option<Sideloader>>,
    attempts: Mutex<HashMap<Uuid, Arc<LoginAttempt>>>,
    certificate_recovery_requested: AtomicBool,
    saved_login_id: Mutex<Option<Uuid>>,
}

#[derive(Serialize, Deserialize)]
struct SavedCredentials {
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedCredentials {
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("Apple login session was not found")]
    UnknownSession,
    #[error("Apple is not currently requesting a two-factor response")]
    NoTwoFactorChallenge,
    #[error("two-factor action is invalid")]
    InvalidTwoFactorAction,
    #[error("a trusted anisette URL must be configured before Apple sign-in")]
    MissingAnisetteUrl,
    #[error("Apple signing session is not ready")]
    NotReady,
    #[error("device information lookup failed")]
    DeviceInfoFailed,
    #[error("developer team lookup failed")]
    DeveloperTeamFailed,
    #[error("device registration requires explicit authorization")]
    DeviceRegistrationRequired,
    #[error("device registration failed")]
    DeviceRegistrationFailed,
    #[error("IPA signing failed")]
    IpaSigningFailed,
    #[error("signed IPA metadata validation failed")]
    SignedMetadataFailed,
    #[error("device installation failed")]
    DeviceInstallFailed,
    #[error("encrypted credential storage failed")]
    CredentialStorage,
}
pub enum ExistingDeviceSigningError {
    Preflight(SigningError),
    Signing(SigningError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningDeviceIdentity {
    name: String,
    udid: String,
}

impl SigningDeviceIdentity {
    pub fn new(name: String, udid: String) -> Result<Self, SigningError> {
        if name.trim().is_empty() || udid.trim().is_empty() || name.len() > 256 || udid.len() > 256
        {
            return Err(SigningError::DeviceInfoFailed);
        }
        Ok(Self { name, udid })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRegistrationState {
    AlreadyPresent,
    NewRequired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceRegistrationPolicy {
    RequireExisting,
    Ensure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppleAccountPreflight {
    pub device_registration: DeviceRegistrationState,
    pub development_certificate_count: usize,
    pub development_certificate_capacity: Option<usize>,
    pub machine_certificate_present: bool,
}

pub struct SignedAppArtifact {
    app_bundle_path: Option<PathBuf>,
    cleanup_root: Option<PathBuf>,
    extraction_root: Option<PathBuf>,
    bundle_id: String,
}

impl SignedAppArtifact {
    pub fn app_bundle_path(&self) -> &Path {
        self.app_bundle_path
            .as_deref()
            .expect("owned signed app path is present until drop")
    }

    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }
}

impl Drop for SignedAppArtifact {
    fn drop(&mut self) {
        self.app_bundle_path.take();
        if let Some(path) = self.cleanup_root.take() {
            remove_signed_artifact_path(&path);
        }
        if let Some(path) = self.extraction_root.take() {
            remove_signed_artifact_path(&path);
        }
    }
}
struct SideloadInput {
    path: PathBuf,
}

impl SideloadInput {
    fn for_ipa(ipa_path: &Path) -> Result<Self, SigningError> {
        let parent = ipa_path.parent().ok_or(SigningError::IpaSigningFailed)?;
        let path = parent.join(format!(".iphoneloadly-signing-{}.ipa", Uuid::now_v7()));
        std::fs::hard_link(ipa_path, &path).map_err(|_| SigningError::IpaSigningFailed)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SideloadInput {
    fn drop(&mut self) {
        remove_signed_artifact_path(&self.path);
    }
}

struct SideloadExtractionCleanup {
    path: Option<PathBuf>,
}

impl SideloadExtractionCleanup {
    fn for_ipa(ipa_path: &Path) -> Result<Self, SigningError> {
        let file_name = ipa_path
            .file_name()
            .ok_or(SigningError::IpaSigningFailed)?
            .to_string_lossy();
        Ok(Self {
            path: Some(std::env::temp_dir().join(format!("{file_name}_extracted"))),
        })
    }

    fn into_path(mut self) -> PathBuf {
        self.path
            .take()
            .expect("extraction root remains owned until artifact transfer")
    }
}

impl Drop for SideloadExtractionCleanup {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            remove_signed_artifact_path(&path);
        }
    }
}

#[cfg(unix)]
fn restrict_signed_artifact_path(path: &Path, directory: bool) -> Result<(), SigningError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if directory { 0o700 } else { 0o600 };
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|_| SigningError::SignedMetadataFailed)?;
    let actual = std::fs::metadata(path)
        .map_err(|_| SigningError::SignedMetadataFailed)?
        .permissions()
        .mode()
        & 0o777;
    (actual == mode)
        .then_some(())
        .ok_or(SigningError::SignedMetadataFailed)
}

#[cfg(not(unix))]
fn restrict_signed_artifact_path(_path: &Path, _directory: bool) -> Result<(), SigningError> {
    Ok(())
}

fn remove_signed_artifact_path(path: &Path) {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() || metadata.is_file() {
        let _ = std::fs::remove_file(path);
    } else if metadata.is_dir() {
        let _ = std::fs::remove_dir_all(path);
    }
}

#[cfg(unix)]
fn quarantine_signed_app(
    source: &Path,
    artifact_storage: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf), SigningError> {
    use std::os::unix::fs::MetadataExt;

    let source_parent = source.parent().ok_or(SigningError::SignedMetadataFailed)?;
    let parent_metadata =
        std::fs::symlink_metadata(source_parent).map_err(|_| SigningError::SignedMetadataFailed)?;
    let trusted_metadata = std::fs::symlink_metadata(artifact_storage)
        .map_err(|_| SigningError::SignedMetadataFailed)?;
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != trusted_metadata.uid()
    {
        return Err(SigningError::SignedMetadataFailed);
    }
    restrict_signed_artifact_path(source_parent, true)?;
    let canonical_parent =
        std::fs::canonicalize(source_parent).map_err(|_| SigningError::SignedMetadataFailed)?;
    let quarantine = source_parent.join(format!(".iphoneloadly-owned-{}", Uuid::now_v7()));
    std::fs::create_dir(&quarantine).map_err(|_| SigningError::SignedMetadataFailed)?;
    restrict_signed_artifact_path(&quarantine, true)?;
    let canonical_quarantine =
        std::fs::canonicalize(&quarantine).map_err(|_| SigningError::SignedMetadataFailed)?;
    if canonical_quarantine.parent() != Some(canonical_parent.as_path()) {
        remove_signed_artifact_path(&quarantine);
        return Err(SigningError::SignedMetadataFailed);
    }
    let owned_path = quarantine.join("Signed.app");
    if std::fs::rename(source, &owned_path).is_err() {
        remove_signed_artifact_path(&quarantine);
        return Err(SigningError::SignedMetadataFailed);
    }
    Ok((owned_path, quarantine, canonical_quarantine))
}

#[cfg(not(unix))]
fn quarantine_signed_app(
    _source: &Path,
    _artifact_storage: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf), SigningError> {
    Err(SigningError::SignedMetadataFailed)
}

fn validate_private_signed_tree(root: &Path) -> Result<(), SigningError> {
    const MAX_ENTRIES: usize = 20_000;
    const MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

    let canonical_root =
        std::fs::canonicalize(root).map_err(|_| SigningError::SignedMetadataFailed)?;
    let mut pending = VecDeque::from([root.to_path_buf()]);
    let mut entries = 0_usize;
    let mut bytes = 0_u64;
    while let Some(directory) = pending.pop_front() {
        for entry in std::fs::read_dir(directory).map_err(|_| SigningError::SignedMetadataFailed)? {
            let entry = entry.map_err(|_| SigningError::SignedMetadataFailed)?;
            entries = entries
                .checked_add(1)
                .filter(|count| *count <= MAX_ENTRIES)
                .ok_or(SigningError::SignedMetadataFailed)?;
            let path = entry.path();
            let metadata =
                std::fs::symlink_metadata(&path).map_err(|_| SigningError::SignedMetadataFailed)?;
            if metadata.file_type().is_symlink() {
                return Err(SigningError::SignedMetadataFailed);
            }
            let canonical_path =
                std::fs::canonicalize(&path).map_err(|_| SigningError::SignedMetadataFailed)?;
            if !canonical_path.starts_with(&canonical_root) {
                return Err(SigningError::SignedMetadataFailed);
            }
            if metadata.is_dir() {
                pending.push_back(path);
            } else if metadata.is_file() {
                bytes = bytes
                    .checked_add(metadata.len())
                    .filter(|total| *total <= MAX_BYTES)
                    .ok_or(SigningError::SignedMetadataFailed)?;
            } else {
                return Err(SigningError::SignedMetadataFailed);
            }
        }
    }
    Ok(())
}

fn snapshot_signed_app_inner(
    source: &Path,
    artifact_storage: &Path,
    force_source_quarantine: bool,
) -> Result<SignedAppArtifact, SigningError> {
    let source_metadata =
        std::fs::symlink_metadata(source).map_err(|_| SigningError::SignedMetadataFailed)?;
    if source_metadata.file_type().is_symlink() || !source_metadata.is_dir() {
        return Err(SigningError::SignedMetadataFailed);
    }
    std::fs::create_dir_all(artifact_storage).map_err(|_| SigningError::SignedMetadataFailed)?;
    let storage_metadata = std::fs::symlink_metadata(artifact_storage)
        .map_err(|_| SigningError::SignedMetadataFailed)?;
    if storage_metadata.file_type().is_symlink() || !storage_metadata.is_dir() {
        return Err(SigningError::SignedMetadataFailed);
    }
    restrict_signed_artifact_path(artifact_storage, true)?;
    let canonical_storage =
        std::fs::canonicalize(artifact_storage).map_err(|_| SigningError::SignedMetadataFailed)?;
    let direct_owned_path =
        artifact_storage.join(format!("iphoneloadly-signed-{}.app", Uuid::now_v7()));
    let direct_move = if force_source_quarantine {
        Err(std::io::Error::from(std::io::ErrorKind::CrossesDevices))
    } else {
        std::fs::rename(source, &direct_owned_path)
    };
    let (owned_path, cleanup_root, expected_parent) = match direct_move {
        Ok(()) => (
            direct_owned_path.clone(),
            direct_owned_path,
            canonical_storage,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::CrossesDevices => {
            match quarantine_signed_app(source, artifact_storage) {
                Ok((owned_path, cleanup_root, expected_parent)) => {
                    (owned_path, cleanup_root, expected_parent)
                }
                Err(error) => {
                    remove_signed_artifact_path(source);
                    return Err(error);
                }
            }
        }
        Err(_) => {
            remove_signed_artifact_path(source);
            return Err(SigningError::SignedMetadataFailed);
        }
    };

    let snapshot_result = (|| {
        let owned_metadata = std::fs::symlink_metadata(&owned_path)
            .map_err(|_| SigningError::SignedMetadataFailed)?;
        if owned_metadata.file_type().is_symlink() || !owned_metadata.is_dir() {
            return Err(SigningError::SignedMetadataFailed);
        }
        restrict_signed_artifact_path(&owned_path, true)?;
        let canonical_owned =
            std::fs::canonicalize(&owned_path).map_err(|_| SigningError::SignedMetadataFailed)?;
        if canonical_owned.parent() != Some(expected_parent.as_path()) {
            return Err(SigningError::SignedMetadataFailed);
        }
        validate_private_signed_tree(&owned_path)?;
        let info_path = owned_path.join("Info.plist");
        let info_metadata = std::fs::symlink_metadata(&info_path)
            .map_err(|_| SigningError::SignedMetadataFailed)?;
        if info_metadata.file_type().is_symlink() || !info_metadata.is_file() {
            return Err(SigningError::SignedMetadataFailed);
        }
        let signed_info =
            plist::Value::from_file(info_path).map_err(|_| SigningError::SignedMetadataFailed)?;
        let bundle_id = signed_info
            .as_dictionary()
            .and_then(|info| info.get("CFBundleIdentifier"))
            .and_then(plist::Value::as_string)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .map(str::to_owned)
            .ok_or(SigningError::SignedMetadataFailed)?;
        Ok(SignedAppArtifact {
            app_bundle_path: Some(owned_path.clone()),
            cleanup_root: Some(cleanup_root.clone()),
            extraction_root: None,
            bundle_id,
        })
    })();
    if snapshot_result.is_err() {
        remove_signed_artifact_path(&cleanup_root);
    }
    snapshot_result
}

fn snapshot_signed_app(
    source: &Path,
    artifact_storage: &Path,
) -> Result<SignedAppArtifact, SigningError> {
    snapshot_signed_app_inner(source, artifact_storage, false)
}

impl AppleSigningProvider {
    pub fn new(anisette_url: Option<String>, signing_storage_path: PathBuf) -> Arc<Self> {
        Arc::new(Self {
            anisette_url: anisette_url.filter(|url| !url.trim().is_empty()),
            signing_storage_path,
            sideloader: Mutex::new(None),
            attempts: Mutex::new(HashMap::new()),
            certificate_recovery_requested: AtomicBool::new(false),
            saved_login_id: Mutex::new(None),
        })
    }

    pub async fn is_ready(&self) -> bool {
        self.sideloader.lock().await.is_some()
    }

    pub fn has_anisette_url(&self) -> bool {
        self.anisette_url.is_some()
    }

    fn credentials_path(&self) -> PathBuf {
        self.signing_storage_path.join("saved-credentials.json")
    }

    fn credentials_key_path(&self) -> PathBuf {
        self.signing_storage_path.join("credentials.key")
    }

    fn credential_key(&self) -> Result<[u8; 32], SigningError> {
        std::fs::create_dir_all(&self.signing_storage_path)
            .map_err(|_| SigningError::CredentialStorage)?;
        let path = self.credentials_key_path();
        if let Ok(bytes) = std::fs::read(&path) {
            return bytes
                .try_into()
                .map_err(|_| SigningError::CredentialStorage);
        }
        let key: [u8; 32] = rand::random();
        std::fs::write(&path, key).map_err(|_| SigningError::CredentialStorage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(key)
    }

    pub fn save_credentials(&self, email: &str, password: &str) -> Result<(), SigningError> {
        let key = self.credential_key()?;
        let nonce: [u8; 12] = rand::random();
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|_| SigningError::CredentialStorage)?;
        let plaintext = serde_json::to_vec(&SavedCredentials {
            email: email.into(),
            password: password.into(),
        })
        .map_err(|_| SigningError::CredentialStorage)?;
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
            .map_err(|_| SigningError::CredentialStorage)?;
        let record = serde_json::to_vec(&EncryptedCredentials {
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        })
        .map_err(|_| SigningError::CredentialStorage)?;
        let path = self.credentials_path();
        std::fs::write(&path, record).map_err(|_| SigningError::CredentialStorage)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn delete_saved_credentials(&self) -> Result<(), SigningError> {
        match std::fs::remove_file(self.credentials_path()) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(SigningError::CredentialStorage),
        }
    }

    pub async fn clear_saved_login_id(&self) {
        *self.saved_login_id.lock().await = None;
    }

    pub fn has_saved_credentials(&self) -> bool {
        self.credentials_path().is_file()
    }

    pub async fn set_saved_login_id(&self, id: Uuid) {
        *self.saved_login_id.lock().await = Some(id);
    }

    pub async fn restore_saved_login(
        self: &Arc<Self>,
    ) -> Result<Option<LoginStatus>, SigningError> {
        let record = match std::fs::read(self.credentials_path()) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(SigningError::CredentialStorage),
        };
        let encrypted: EncryptedCredentials =
            serde_json::from_slice(&record).map_err(|_| SigningError::CredentialStorage)?;
        let nonce = BASE64
            .decode(encrypted.nonce)
            .map_err(|_| SigningError::CredentialStorage)?;
        if nonce.len() != 12 {
            return Err(SigningError::CredentialStorage);
        }
        let ciphertext = BASE64
            .decode(encrypted.ciphertext)
            .map_err(|_| SigningError::CredentialStorage)?;
        let cipher = Aes256Gcm::new_from_slice(&self.credential_key()?)
            .map_err(|_| SigningError::CredentialStorage)?;
        let plaintext = cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|_| SigningError::CredentialStorage)?;
        let saved: SavedCredentials =
            serde_json::from_slice(&plaintext).map_err(|_| SigningError::CredentialStorage)?;
        let status = self.begin_login(saved.email, saved.password).await?;
        *self.saved_login_id.lock().await = Some(status.id);
        Ok(Some(status))
    }

    pub async fn saved_login_status(&self) -> Result<Option<LoginStatus>, SigningError> {
        let Some(id) = *self.saved_login_id.lock().await else {
            return Ok(None);
        };
        self.login_status(id).await.map(Some)
    }

    /// Arms one subsequent interactive login to revoke an older development
    /// certificate only if Apple rejects a new certificate for hitting its
    /// certificate limit. This never makes an Apple request by itself.
    pub fn request_certificate_recovery(&self) {
        self.certificate_recovery_requested
            .store(true, Ordering::Release);
    }

    pub async fn begin_login(
        self: &Arc<Self>,
        email: String,
        password: String,
    ) -> Result<LoginStatus, SigningError> {
        let anisette_url = self
            .anisette_url
            .clone()
            .ok_or(SigningError::MissingAnisetteUrl)?;
        let revoke_old_certificate = self
            .certificate_recovery_requested
            .swap(false, Ordering::AcqRel);
        let id = Uuid::now_v7();
        let attempt = Arc::new(LoginAttempt::new(id));
        self.attempts.lock().await.insert(id, attempt.clone());

        let provider = self.clone();
        let background_attempt = attempt.clone();
        tokio::spawn(async move {
            background_attempt
                .authenticating("Preparing the local anisette provider.")
                .await;
            let anisette = match RemoteV3AnisetteProvider::new(
                &anisette_url,
                Box::new(InMemoryStorage::new()),
                "0".into(),
            ) {
                Ok(provider) => provider,
                Err(_) => {
                    background_attempt
                        .failed(AuthFailureDiagnostic::unknown(
                            AuthDiagnosticStage::AnisetteInit,
                        ))
                        .await;
                    return;
                }
            };
            let callback_attempt = background_attempt.clone();
            background_attempt
                .authenticating("Contacting Apple through the local anisette provider.")
                .await;
            let result = tokio::time::timeout(
                // Apple may require a user-entered two-factor code. Give the
                // user enough time to retrieve and submit it before timing out.
                Duration::from_secs(5 * 60),
                AppleAccount::builder(&email)
                    .anisette_provider(anisette)
                    .login(&password, move |params| {
                        let callback_attempt = callback_attempt.clone();
                        async move { Ok(callback_attempt.wait_for_two_factor(params).await) }
                    }),
            )
            .await;
            let mut account = match result {
                Ok(Ok(account)) => account,
                Ok(Err(error)) => {
                    background_attempt
                        .failed(AuthFailureDiagnostic::from_report(
                            AuthDiagnosticStage::AppleAccountLogin,
                            &error,
                        ))
                        .await;
                    return;
                }
                Err(_) => {
                    background_attempt
                        .failed(AuthFailureDiagnostic::timeout(
                            AuthDiagnosticStage::AppleAccountLoginTimeout,
                        ))
                        .await;
                    return;
                }
            };
            let developer_session = match DeveloperSession::from_account(&mut account).await {
                Ok(session) => session,
                Err(error) => {
                    background_attempt
                        .failed(AuthFailureDiagnostic::from_report(
                            AuthDiagnosticStage::DeveloperSession,
                            &error,
                        ))
                        .await;
                    return;
                }
            };
            let sideloader = SideloaderBuilder::new(developer_session, email)
                .machine_name("iPhoneLoadly".into())
                // Reusing this root-only service state lets isideload find the
                // matching Apple development certificate after a new login.
                .storage(Box::new(FsStorage::new(
                    provider.signing_storage_path.clone(),
                )))
                .max_certs_behavior(if revoke_old_certificate {
                    MaxCertsBehavior::Revoke
                } else {
                    MaxCertsBehavior::Error
                })
                .build();
            *provider.sideloader.lock().await = Some(sideloader);
            background_attempt.ready().await;
        });

        Ok(attempt.status().await)
    }

    pub async fn login_status(&self, id: Uuid) -> Result<LoginStatus, SigningError> {
        let attempt = self.attempts.lock().await.get(&id).cloned();
        let attempt = attempt.ok_or(SigningError::UnknownSession)?;
        Ok(attempt.status().await)
    }
    async fn account_preflight_with_sideloader(
        sideloader: &mut Sideloader,
        identity: &SigningDeviceIdentity,
    ) -> Result<AppleAccountPreflight, SigningError> {
        let team = sideloader
            .get_team()
            .await
            .map_err(|_| SigningError::DeveloperTeamFailed)?;
        let devices = sideloader
            .get_dev_session()
            .list_devices(&team, None)
            .await
            .map_err(|_| SigningError::DeveloperTeamFailed)?;
        let device_registration = if devices
            .iter()
            .any(|device| device.device_number == identity.udid)
        {
            DeviceRegistrationState::AlreadyPresent
        } else {
            DeviceRegistrationState::NewRequired
        };
        let certificates = sideloader
            .get_dev_session()
            .list_ios_certs(&team)
            .await
            .map_err(|_| SigningError::DeveloperTeamFailed)?;
        let development_certificate_capacity = certificates
            .iter()
            .filter_map(|certificate| {
                certificate
                    .certificate_type
                    .as_ref()
                    .and_then(|certificate_type| certificate_type.max_active_certs)
            })
            .filter_map(|capacity| usize::try_from(capacity).ok())
            .max();
        let active_certificates = certificates.iter().filter(|certificate| {
            certificate.serial_number.is_some() && certificate.status.as_deref() != Some("Revoked")
        });
        let development_certificate_count = active_certificates.clone().count();
        let machine_certificate_present = active_certificates
            .into_iter()
            .any(|certificate| certificate.machine_name.as_deref() == Some("iPhoneLoadly"));
        Ok(AppleAccountPreflight {
            device_registration,
            development_certificate_count,
            development_certificate_capacity,
            machine_certificate_present,
        })
    }

    async fn sign_for_device_with_sideloader(
        &self,
        sideloader: &mut Sideloader,
        identity: &SigningDeviceIdentity,
        ipa_path: PathBuf,
        registration_policy: DeviceRegistrationPolicy,
        progress: impl Fn(u8) + Send + Sync + 'static,
    ) -> Result<SignedAppArtifact, SigningError> {
        let team = sideloader
            .get_team()
            .await
            .map_err(|_| SigningError::DeveloperTeamFailed)?;
        match registration_policy {
            DeviceRegistrationPolicy::RequireExisting => {
                let devices = sideloader
                    .get_dev_session()
                    .list_devices(&team, None)
                    .await
                    .map_err(|_| SigningError::DeveloperTeamFailed)?;
                if !devices
                    .iter()
                    .any(|device| device.device_number == identity.udid)
                {
                    return Err(SigningError::DeviceRegistrationRequired);
                }
            }
            DeviceRegistrationPolicy::Ensure => {
                sideloader
                    .get_dev_session()
                    .ensure_device_registered(&team, &identity.name, &identity.udid, None)
                    .await
                    .map_err(|_| SigningError::DeviceRegistrationFailed)?;
            }
        }
        let sideload_input = SideloadInput::for_ipa(&ipa_path)?;
        let extraction_cleanup = SideloadExtractionCleanup::for_ipa(sideload_input.path())?;
        let progress = Arc::new(progress);
        let signing_progress = progress.clone();
        let (signed_app_path, _) = sideloader
            .sign_app(
                sideload_input.path().to_path_buf(),
                Some(team),
                false,
                Some(move |value: f32| {
                    signing_progress((value.clamp(0.0, 1.0) * 40.0) as u8);
                    async {}
                }),
            )
            .await
            .map_err(|_| SigningError::IpaSigningFailed)?;
        let mut artifact = snapshot_signed_app(
            &signed_app_path,
            &self.signing_storage_path.join("signed-artifacts"),
        )?;
        artifact.extraction_root = Some(extraction_cleanup.into_path());
        progress(40);
        Ok(artifact)
    }

    pub async fn preflight_and_sign_for_existing_device(
        &self,
        identity: &SigningDeviceIdentity,
        ipa_path: PathBuf,
    ) -> Result<(AppleAccountPreflight, Option<SignedAppArtifact>), ExistingDeviceSigningError>
    {
        if !ipa_path.is_file() {
            return Err(ExistingDeviceSigningError::Signing(
                SigningError::IpaSigningFailed,
            ));
        }
        let mut sideloader = self.sideloader.lock().await;
        let sideloader = sideloader
            .as_mut()
            .ok_or(ExistingDeviceSigningError::Preflight(
                SigningError::NotReady,
            ))?;
        let preflight = Self::account_preflight_with_sideloader(sideloader, identity)
            .await
            .map_err(ExistingDeviceSigningError::Preflight)?;
        if preflight.device_registration == DeviceRegistrationState::NewRequired {
            return Ok((preflight, None));
        }
        let artifact = self
            .sign_for_device_with_sideloader(
                sideloader,
                identity,
                ipa_path,
                DeviceRegistrationPolicy::RequireExisting,
                |_| {},
            )
            .await
            .map_err(ExistingDeviceSigningError::Signing)?;
        Ok((preflight, Some(artifact)))
    }
    pub async fn sign_for_device(
        &self,
        identity: &SigningDeviceIdentity,
        ipa_path: PathBuf,
        registration_policy: DeviceRegistrationPolicy,
        progress: impl Fn(u8) + Send + Sync + 'static,
    ) -> Result<SignedAppArtifact, SigningError> {
        if !ipa_path.is_file() {
            return Err(SigningError::IpaSigningFailed);
        }
        let mut sideloader = self.sideloader.lock().await;
        let sideloader = sideloader.as_mut().ok_or(SigningError::NotReady)?;
        self.sign_for_device_with_sideloader(
            sideloader,
            identity,
            ipa_path,
            registration_policy,
            progress,
        )
        .await
    }

    pub async fn install_ipa(
        &self,
        provider: &TcpProvider,
        ipa_path: PathBuf,
        progress: impl Fn(u8) + Send + Sync + 'static,
    ) -> Result<String, SigningError> {
        let device = IdeviceInfo::from_device(provider)
            .await
            .map_err(|_| SigningError::DeviceInfoFailed)?;
        let identity = SigningDeviceIdentity::new(device.name, device.udid)?;
        let progress = Arc::new(progress);
        let signing_progress = progress.clone();
        let artifact = self
            .sign_for_device(
                &identity,
                ipa_path,
                DeviceRegistrationPolicy::Ensure,
                move |value| signing_progress(value),
            )
            .await?;
        let installed_bundle_id = artifact.bundle_id().to_owned();
        let install_progress = progress.clone();
        install_signed_app(provider, artifact.app_bundle_path(), move |value| {
            let percent = 40 + ((value.min(100) * 60) / 100) as u8;
            install_progress(percent);
        })
        .await
        .map_err(|_| SigningError::DeviceInstallFailed)?;
        Ok(installed_bundle_id)
    }

    pub async fn submit_two_factor(
        &self,
        id: Uuid,
        action: &str,
        code: Option<String>,
        number_id: Option<u32>,
    ) -> Result<(), SigningError> {
        let response = match action {
            "submitCode" => TwoFactorCallbackResponse::SubmitCode(
                code.filter(|code| !code.trim().is_empty())
                    .ok_or(SigningError::InvalidTwoFactorAction)?,
            ),
            "sendSms" => TwoFactorCallbackResponse::SendSms(
                number_id.ok_or(SigningError::InvalidTwoFactorAction)?,
            ),
            "sendToDevices" => TwoFactorCallbackResponse::SendToDevices,
            "resendCode" => TwoFactorCallbackResponse::ResendCode,
            "abort" => TwoFactorCallbackResponse::Abort,
            _ => return Err(SigningError::InvalidTwoFactorAction),
        };
        let attempt = self.attempts.lock().await.get(&id).cloned();
        attempt
            .ok_or(SigningError::UnknownSession)?
            .submit(response)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_directory(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("iphoneloadly-signing-{name}-{}", Uuid::now_v7()))
    }
    #[test]
    fn sideload_inputs_use_unique_hardlinks_and_cleanup_independently() {
        let root = temp_directory("sideload-input");
        std::fs::create_dir_all(&root).expect("create input root");
        let source = root.join("source.ipa");
        std::fs::write(&source, b"ipa").expect("write source IPA");

        let first = SideloadInput::for_ipa(&source).expect("create first hardlink");
        let second = SideloadInput::for_ipa(&source).expect("create second hardlink");
        assert_ne!(first.path(), second.path());
        assert_eq!(std::fs::read(first.path()).expect("read first"), b"ipa");
        assert_eq!(std::fs::read(second.path()).expect("read second"), b"ipa");
        let first_extraction =
            SideloadExtractionCleanup::for_ipa(first.path()).expect("first extraction root");
        let second_extraction =
            SideloadExtractionCleanup::for_ipa(second.path()).expect("second extraction root");
        assert_ne!(
            first_extraction.path.as_ref(),
            second_extraction.path.as_ref()
        );

        let first_path = first.path().to_path_buf();
        let second_path = second.path().to_path_buf();
        drop(first);
        assert!(!first_path.exists());
        assert!(second_path.is_file());
        assert!(source.is_file());
        drop(second);
        assert!(!second_path.exists());
        assert!(source.is_file());
        std::fs::remove_dir_all(root).expect("remove input root");
    }

    #[test]
    fn sideloader_extraction_guard_removes_untransferred_root() {
        let ipa_path = temp_directory("extraction-guard").with_extension("ipa");
        let guard = SideloadExtractionCleanup::for_ipa(&ipa_path).expect("derive extraction root");
        let extraction_root = guard.path.as_ref().expect("owned extraction root").clone();
        std::fs::create_dir_all(&extraction_root).expect("create extraction root");
        std::fs::write(extraction_root.join("extra.bin"), b"extra").expect("write extracted extra");

        drop(guard);
        assert!(!extraction_root.exists());
    }

    #[test]
    fn signed_artifact_owns_unique_bundle_and_removes_only_it_on_drop() {
        let root = temp_directory("owned-artifact");
        let source = root.join("Signed.app");
        std::fs::create_dir_all(&source).expect("create signed app");
        std::fs::write(
            source.join("Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.signed</string>
</dict></plist>"#,
        )
        .expect("write signed metadata");

        let mut artifact =
            snapshot_signed_app(&source, &root.join("storage")).expect("own signed app");
        let owned = artifact.app_bundle_path().to_path_buf();
        assert_eq!(artifact.bundle_id(), "com.example.signed");
        assert!(!source.exists());
        assert!(owned.is_dir());
        assert_eq!(owned.parent(), Some(root.join("storage").as_path()));
        let extraction_root = root.join("ipa-extracted");
        std::fs::create_dir_all(&extraction_root).expect("create extraction root");
        std::fs::write(extraction_root.join("extra.bin"), b"extra").expect("write extracted extra");
        artifact.extraction_root = Some(extraction_root.clone());
        assert!(extraction_root.is_dir());

        drop(artifact);
        assert!(!owned.exists());
        assert!(!extraction_root.exists());
        assert!(root.join("storage").is_dir());
        assert!(root.is_dir());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn cross_device_fallback_owns_and_cleans_the_source_filesystem_quarantine() {
        let root = temp_directory("quarantine-artifact");
        let source_parent = root.join("Payload");
        let source = source_parent.join("Signed.app");
        std::fs::create_dir_all(&source).expect("create signed app");
        std::fs::write(
            source.join("Info.plist"),
            br#"<plist><dict>
<key>CFBundleIdentifier</key><string>com.example.quarantined</string>
</dict></plist>"#,
        )
        .expect("write signed metadata");

        let artifact = snapshot_signed_app_inner(&source, &root.join("storage"), true)
            .expect("own signed app through quarantine");
        let owned = artifact.app_bundle_path().to_path_buf();
        let quarantine = owned.parent().expect("quarantine parent").to_path_buf();
        assert_eq!(artifact.bundle_id(), "com.example.quarantined");
        assert_eq!(quarantine.parent(), Some(source_parent.as_path()));
        assert!(!source.exists());

        drop(artifact);
        assert!(!quarantine.exists());
        assert!(source_parent.is_dir());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(not(unix))]
    #[test]
    fn unsupported_cross_device_fallback_fails_closed() {
        let root = temp_directory("unsupported-quarantine-artifact");
        let source = root.join("Payload").join("Signed.app");
        std::fs::create_dir_all(&source).expect("create signed app");
        std::fs::write(
            source.join("Info.plist"),
            br#"<plist><dict>
<key>CFBundleIdentifier</key><string>com.example.unsupported</string>
</dict></plist>"#,
        )
        .expect("write signed metadata");

        assert!(snapshot_signed_app_inner(&source, &root.join("storage"), true).is_err());
        assert!(!source.exists());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn cross_device_fallback_cleans_quarantine_after_post_move_validation_failure() {
        let root = temp_directory("invalid-quarantine-artifact");
        let source_parent = root.join("Payload");
        let source = source_parent.join("Signed.app");
        std::fs::create_dir_all(&source).expect("create signed app");

        assert!(snapshot_signed_app_inner(&source, &root.join("storage"), true).is_err());
        assert!(!source.exists());
        assert!(
            std::fs::read_dir(&source_parent)
                .expect("read source parent")
                .next()
                .is_none()
        );
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[test]
    fn invalid_signed_metadata_removes_the_unowned_source_bundle() {
        let root = temp_directory("invalid-artifact");
        let source = root.join("Signed.app");
        std::fs::create_dir_all(&source).expect("create signed app");

        assert!(snapshot_signed_app(&source, &root.join("storage")).is_err());
        assert!(!source.exists());
        assert!(root.is_dir());
        std::fs::remove_dir_all(root).expect("remove test root");
    }

    #[cfg(unix)]
    #[test]
    fn signed_snapshot_rejects_descendant_symlinks_before_metadata_read() {
        use std::os::unix::fs::symlink;

        let root = temp_directory("symlink-artifact");
        let source = root.join("Signed.app");
        let outside = root.join("outside.plist");
        std::fs::create_dir_all(&source).expect("create signed app");
        std::fs::write(
            &outside,
            br#"<plist><dict><key>CFBundleIdentifier</key><string>outside</string></dict></plist>"#,
        )
        .expect("write outside metadata");
        symlink(&outside, source.join("Info.plist")).expect("link outside metadata");

        assert!(snapshot_signed_app(&source, &root.join("storage")).is_err());
        assert!(!source.exists());
        assert!(outside.is_file());
        std::fs::remove_dir_all(root).expect("remove test root");
    }
    #[test]
    fn auth_diagnostic_redacts_typed_apple_auth_messages() {
        let report = Report::new(SideloadError::AuthWithMessage(
            -22406,
            "sensitive Apple response text".into(),
        ))
        .into_dynamic();
        let diagnostic =
            AuthFailureDiagnostic::from_report(AuthDiagnosticStage::AppleAccountLogin, &report);
        let serialized = serde_json::to_string(&diagnostic).expect("serialize diagnostic");

        assert_eq!(diagnostic.apple_auth_code, Some(-22406));
        assert_eq!(diagnostic.network_class, AuthNetworkClass::AppleAuth);
        assert!(serialized.contains("\"APPLE_AUTH_CODE\":-22406"));
        assert!(!serialized.contains("sensitive Apple response text"));
    }

    #[tokio::test]
    async fn auth_diagnostic_captures_http_status_without_response_data() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind local test listener");
        let address = listener.local_addr().expect("read local test address");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept test request");
            let mut request = [0_u8; 1024];
            stream.read(&mut request).await.expect("read test request");
            stream
                .write_all(
                    b"HTTP/1.1 503 Service Unavailable\r\n\
                      Content-Length: 0\r\n\
                      Connection: close\r\n\
                      \r\n",
                )
                .await
                .expect("write test response");
        });

        let error = reqwest_013::Client::new()
            .get(format!("http://{address}"))
            .send()
            .await
            .expect("receive test response")
            .error_for_status()
            .expect_err("convert test status to error");
        let report = Report::new(error).into_dynamic();
        let diagnostic =
            AuthFailureDiagnostic::from_report(AuthDiagnosticStage::AppleAccountLogin, &report);

        assert_eq!(diagnostic.http_status, Some(503));
        assert_eq!(diagnostic.network_class, AuthNetworkClass::Http);
        assert!(!diagnostic.timeout);
        server.await.expect("join test server");
    }

    #[test]
    fn failed_login_status_serializes_only_bounded_diagnostic_fields() {
        let status = LoginStatus {
            id: Uuid::now_v7(),
            phase: LoginPhase::Failed,
            two_factor: None,
            message: "Apple authentication failed.".into(),
            diagnostic: Some(AuthFailureDiagnostic {
                auth_stage: AuthDiagnosticStage::AppleAccountLogin,
                http_status: Some(503),
                apple_auth_code: Some(-22406),
                network_class: AuthNetworkClass::Http,
                timeout: false,
            }),
        };
        let value = serde_json::to_value(status).expect("serialize failed login status");
        let diagnostic = value["diagnostic"].as_object().expect("diagnostic object");

        assert_eq!(diagnostic.len(), 5);
        assert_eq!(diagnostic["AUTH_STAGE"], "APPLE_ACCOUNT_LOGIN");
        assert_eq!(diagnostic["HTTP_STATUS"], 503);
        assert_eq!(diagnostic["APPLE_AUTH_CODE"], -22406);
        assert_eq!(diagnostic["NETWORK_CLASS"], "HTTP");
        assert_eq!(diagnostic["TIMEOUT"], false);
        assert!(!diagnostic.contains_key("id"));
    }

    #[test]
    fn successful_login_status_omits_diagnostic() {
        let status = LoginStatus {
            id: Uuid::now_v7(),
            phase: LoginPhase::Ready,
            two_factor: None,
            message: "Apple signing session is ready.".into(),
            diagnostic: None,
        };
        let serialized = serde_json::to_string(&status).expect("serialize login status");

        assert!(!serialized.contains("diagnostic"));
        assert!(!serialized.contains("AUTH_STAGE"));
    }
}
