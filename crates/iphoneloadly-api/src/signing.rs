use std::{
    collections::HashMap,
    path::PathBuf,
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
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{developer_session::DeveloperSession, devices::DevicesApi},
    sideload::{
        SideloaderBuilder, builder::MaxCertsBehavior, install::install_app as install_signed_app,
        sideloader::Sideloader,
    },
    util::{device::IdeviceInfo, fs_storage::FsStorage, storage::InMemoryStorage},
};
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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginStatus {
    pub id: Uuid,
    pub phase: LoginPhase,
    pub two_factor: Option<TwoFactorCallbackParams>,
    pub message: String,
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
        };
    }

    async fn failed(&self, error: impl std::fmt::Display) {
        *self.state.lock().await = LoginStatus {
            id: self.id,
            phase: LoginPhase::Failed,
            two_factor: None,
            message: "Apple authentication failed. Check the server logs for redacted diagnostics."
                .into(),
        };
        tracing::warn!(login_id = %self.id, error = %error, "Apple authentication failed");
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
    #[error("IPA installation failed")]
    InstallFailed,
    #[error("encrypted credential storage failed")]
    CredentialStorage,
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
                Err(error) => {
                    background_attempt.failed(error).await;
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
                    background_attempt.failed(error).await;
                    return;
                }
                Err(_) => {
                    background_attempt
                        .failed("Apple authentication timed out after 90 seconds")
                        .await;
                    return;
                }
            };
            let developer_session = match DeveloperSession::from_account(&mut account).await {
                Ok(session) => session,
                Err(error) => {
                    background_attempt.failed(error).await;
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

    pub async fn install_ipa(
        &self,
        provider: &TcpProvider,
        ipa_path: std::path::PathBuf,
        progress: impl Fn(u8) + Send + Sync + 'static,
    ) -> Result<String, SigningError> {
        let mut sideloader = self.sideloader.lock().await;
        let sideloader = sideloader.as_mut().ok_or(SigningError::NotReady)?;
        let progress = Arc::new(progress);
        let device = IdeviceInfo::from_device(provider)
            .await
            .map_err(|_| SigningError::InstallFailed)?;
        let team = sideloader
            .get_team()
            .await
            .map_err(|_| SigningError::InstallFailed)?;
        sideloader
            .get_dev_session()
            .ensure_device_registered(&team, &device.name, &device.udid, None)
            .await
            .map_err(|_| SigningError::InstallFailed)?;

        let signing_progress = progress.clone();
        let (signed_app_path, _) = sideloader
            .sign_app(
                ipa_path,
                Some(team),
                false,
                Some(move |value: f32| {
                    signing_progress((value.clamp(0.0, 1.0) * 40.0) as u8);
                    async {}
                }),
            )
            .await
            .map_err(|_| SigningError::InstallFailed)?;
        let signed_info = plist::Value::from_file(signed_app_path.join("Info.plist"))
            .map_err(|_| SigningError::InstallFailed)?;
        let installed_bundle_id = signed_info
            .as_dictionary()
            .and_then(|info| info.get("CFBundleIdentifier"))
            .and_then(plist::Value::as_string)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or(SigningError::InstallFailed)?;

        // The upstream installer reports actual AFC-upload and installation
        // percentages. Reserve the final 60% of the job for those values.
        progress(40);
        let install_progress = progress.clone();
        install_signed_app(provider, &signed_app_path, move |value| {
            let percent = 40 + ((value.min(100) * 60) / 100) as u8;
            install_progress(percent);
        })
        .await
        .map_err(|_| SigningError::InstallFailed)?;
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
