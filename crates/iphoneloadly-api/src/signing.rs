use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use idevice::provider::TcpProvider;
use isideload::{
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::developer_session::DeveloperSession,
    sideload::{SideloaderBuilder, builder::MaxCertsBehavior, sideloader::Sideloader},
    util::storage::InMemoryStorage,
};
use serde::Serialize;
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

#[derive(Default)]
pub struct AppleSigningProvider {
    anisette_url: Option<String>,
    sideloader: Mutex<Option<Sideloader>>,
    attempts: Mutex<HashMap<Uuid, Arc<LoginAttempt>>>,
    certificate_recovery_requested: AtomicBool,
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
}

impl AppleSigningProvider {
    pub fn new(anisette_url: Option<String>) -> Arc<Self> {
        Arc::new(Self {
            anisette_url: anisette_url.filter(|url| !url.trim().is_empty()),
            sideloader: Mutex::new(None),
            attempts: Mutex::new(HashMap::new()),
            certificate_recovery_requested: AtomicBool::new(false),
        })
    }

    pub async fn is_ready(&self) -> bool {
        self.sideloader.lock().await.is_some()
    }

    pub fn has_anisette_url(&self) -> bool {
        self.anisette_url.is_some()
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
                .storage(Box::new(InMemoryStorage::new()))
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
    ) -> Result<(), SigningError> {
        let mut sideloader = self.sideloader.lock().await;
        let sideloader = sideloader.as_mut().ok_or(SigningError::NotReady)?;
        sideloader
            .install_app(
                provider,
                ipa_path,
                false,
                Some(move |signing_progress: f32| {
                    // `isideload` reports signing progress, then performs the
                    // device transfer internally without exposing per-byte
                    // callbacks. Reserve the latter half for that visible
                    // transfer/installation phase rather than inventing it.
                    progress((signing_progress.clamp(0.0, 1.0) * 50.0) as u8);
                    async {}
                }),
            )
            .await
            .map_err(|_| SigningError::InstallFailed)?;
        Ok(())
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
