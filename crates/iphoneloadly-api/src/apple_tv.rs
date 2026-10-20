//! Apple TV support: PIN pairing from the dashboard and the HTTP routes for it.
//!
//! An Apple TV is paired as a client: it advertises
//! `_remotepairing-manual-pairing._tcp` while "Remote App and Devices" is open,
//! iPhoneLoadly connects, and the user types the PIN the TV shows. The pairing
//! is stored by its own [`WirelessPairingService`], so install, app listing and
//! refresh reuse the same RSD path as the iPhone.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, oneshot};
use uuid::Uuid;

use crate::{
    AppState, sources,
    wireless_pairing::{
        ManualPairingTarget, WirelessPairingService, discover_manual_pairing_targets,
    },
};

// Same window as the iPhone's RSD discovery; a fresh mDNS daemon needs time
// to start, query and collect SRV, TXT and address records.
const DISCOVERY_DURATION: Duration = Duration::from_secs(10);
const SESSION_LIFETIME: Duration = Duration::from_secs(5 * 60);
const VERIFY_TIMEOUT: Duration = Duration::from_secs(60);

pub(crate) fn enabled(value: Option<String>) -> bool {
    value.as_deref().map(str::trim) == Some("on")
}

pub(crate) struct AppleTv {
    pub(crate) service: Arc<WirelessPairingService>,
    targets: Mutex<Vec<ManualPairingTarget>>,
    session: Arc<Mutex<Option<Session>>>,
}

struct Session {
    status: PairingStatus,
    pin: Option<oneshot::Sender<String>>,
    task: tokio::task::AbortHandle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum PairingPhase {
    Connecting,
    AwaitingPin,
    Verifying,
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
pub(crate) struct PairingStatus {
    id: Uuid,
    phase: PairingPhase,
    device_name: String,
    expires_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure_code: Option<&'static str>,
    /// False when pairing was saved but the Apple TV could not yet be reached
    /// over its trusted connection.
    verified: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum PairingError {
    UnknownTarget,
    Busy,
    NotFound,
    Terminal,
    NotAwaitingPin,
}

impl AppleTv {
    pub(crate) fn new(service: Arc<WirelessPairingService>) -> Self {
        Self {
            service,
            targets: Mutex::new(Vec::new()),
            session: Arc::new(Mutex::new(None)),
        }
    }

    async fn discover(&self) -> Result<Vec<ManualPairingTarget>, ()> {
        let targets = discover_manual_pairing_targets(DISCOVERY_DURATION).await?;
        *self.targets.lock().await = targets.clone();
        Ok(targets)
    }

    /// Starts pairing with a target from the last discovery. Addresses come
    /// from the server's own mDNS result, never from the request.
    async fn start(&self, identifier: &str) -> Result<PairingStatus, PairingError> {
        let mut target = self
            .targets
            .lock()
            .await
            .iter()
            .find(|target| target.identifier == identifier)
            .cloned();
        if target.is_none() {
            target = self.discover().await.ok().and_then(|targets| {
                targets
                    .into_iter()
                    .find(|target| target.identifier == identifier)
            });
        }
        let target = target.ok_or(PairingError::UnknownTarget)?;

        let mut current = self.session.lock().await;
        if let Some(session) = current.as_mut() {
            expire_if_due(session);
            if !session.status.phase.is_terminal() {
                return Err(PairingError::Busy);
            }
        }
        let id = Uuid::now_v7();
        let status = PairingStatus {
            id,
            phase: PairingPhase::Connecting,
            device_name: target.name.clone(),
            expires_at: unix_seconds(SystemTime::now() + SESSION_LIFETIME),
            failure_code: None,
            verified: false,
        };
        let (pin_sender, pin_receiver) = oneshot::channel();
        let task = tokio::spawn(run_pairing(
            self.service.clone(),
            self.session.clone(),
            id,
            target,
            pin_receiver,
        ));
        *current = Some(Session {
            status: status.clone(),
            pin: Some(pin_sender),
            task: task.abort_handle(),
        });
        Ok(status)
    }

    async fn status(&self, id: Uuid) -> Result<PairingStatus, PairingError> {
        let mut current = self.session.lock().await;
        let session = current
            .as_mut()
            .filter(|session| session.status.id == id)
            .ok_or(PairingError::NotFound)?;
        expire_if_due(session);
        Ok(session.status.clone())
    }

    async fn submit_pin(&self, id: Uuid, pin: String) -> Result<PairingStatus, PairingError> {
        let mut current = self.session.lock().await;
        let session = current
            .as_mut()
            .filter(|session| session.status.id == id)
            .ok_or(PairingError::NotFound)?;
        expire_if_due(session);
        if session.status.phase != PairingPhase::AwaitingPin {
            return Err(PairingError::NotAwaitingPin);
        }
        let sender = session.pin.take().ok_or(PairingError::NotAwaitingPin)?;
        if sender.send(pin).is_err() {
            return Err(PairingError::Terminal);
        }
        session.status.phase = PairingPhase::Verifying;
        Ok(session.status.clone())
    }

    async fn cancel(&self, id: Uuid) -> Result<(), PairingError> {
        let mut current = self.session.lock().await;
        let session = current
            .as_mut()
            .filter(|session| session.status.id == id)
            .ok_or(PairingError::NotFound)?;
        if session.status.phase.is_terminal() {
            return Err(PairingError::Terminal);
        }
        session.task.abort();
        session.pin.take();
        session.status.phase = PairingPhase::Cancelled;
        Ok(())
    }
}

fn expire_if_due(session: &mut Session) {
    if !session.status.phase.is_terminal()
        && unix_seconds(SystemTime::now()) >= session.status.expires_at
    {
        session.task.abort();
        session.pin.take();
        session.status.phase = PairingPhase::Expired;
    }
}

async fn run_pairing(
    service: Arc<WirelessPairingService>,
    session: Arc<Mutex<Option<Session>>>,
    id: Uuid,
    target: ManualPairingTarget,
    pin_receiver: oneshot::Receiver<String>,
) {
    let pin_receiver = Arc::new(Mutex::new(Some(pin_receiver)));
    let pin_session = session.clone();
    let result = service
        .pair_with_pin(&target, move || {
            let pin_receiver = pin_receiver.clone();
            let session = pin_session.clone();
            async move {
                set_phase(&session, id, PairingPhase::AwaitingPin, None).await;
                let receiver = pin_receiver.lock().await.take();
                match receiver {
                    Some(receiver) => receiver.await.unwrap_or_default(),
                    None => String::new(),
                }
            }
        })
        .await;
    if let Err(failure) = result {
        tracing::warn!(
            stage = "apple_tv_pairing",
            failure = failure.as_str(),
            "Apple TV pairing failed"
        );
        set_phase(&session, id, PairingPhase::Failed, Some(failure.as_str())).await;
        return;
    }
    set_phase(&session, id, PairingPhase::Verifying, None).await;
    let identity = tokio::time::timeout(VERIFY_TIMEOUT, service.remote_pairing_device_identity())
        .await
        .ok()
        .flatten();
    let mut current = session.lock().await;
    if let Some(session) = current
        .as_mut()
        .filter(|session| session.status.id == id && !session.status.phase.is_terminal())
    {
        session.status.phase = PairingPhase::Ready;
        session.status.verified = identity.is_some();
        if let Some(identity) = identity {
            session.status.device_name = identity.name().to_owned();
            if !identity.is_apple_tv() {
                tracing::warn!("device paired through the Apple TV flow is not an Apple TV");
            }
        }
    }
}

async fn set_phase(
    session: &Mutex<Option<Session>>,
    id: Uuid,
    phase: PairingPhase,
    failure_code: Option<&'static str>,
) {
    let mut current = session.lock().await;
    if let Some(session) = current
        .as_mut()
        .filter(|session| session.status.id == id && !session.status.phase.is_terminal())
    {
        // A PIN submitted before the TV asked for it already moved the phase on.
        if phase == PairingPhase::AwaitingPin && session.pin.is_none() {
            return;
        }
        session.status.phase = phase;
        session.status.failure_code = failure_code;
        if phase.is_terminal() {
            session.pin.take();
        }
    }
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn valid_pin(pin: &str) -> bool {
    pin.len() == 6 && pin.bytes().all(|byte| byte.is_ascii_digit())
}

fn message(status: StatusCode, text: &str) -> axum::response::Response {
    (status, Json(serde_json::json!({ "message": text }))).into_response()
}

fn disabled() -> axum::response::Response {
    message(StatusCode::NOT_FOUND, "Apple TV support is not enabled.")
}

fn pairing_error(error: PairingError) -> axum::response::Response {
    match error {
        PairingError::UnknownTarget => message(
            StatusCode::NOT_FOUND,
            "The Apple TV was not found. Open Remote App and Devices on it and search again.",
        ),
        PairingError::Busy => message(
            StatusCode::CONFLICT,
            "An Apple TV pairing is already in progress.",
        ),
        PairingError::NotFound => message(
            StatusCode::NOT_FOUND,
            "Apple TV pairing session was not found.",
        ),
        PairingError::Terminal => message(
            StatusCode::CONFLICT,
            "Apple TV pairing session is already finished.",
        ),
        PairingError::NotAwaitingPin => message(
            StatusCode::CONFLICT,
            "The Apple TV is not waiting for a PIN.",
        ),
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OverviewResponse {
    enabled: bool,
    paired: bool,
}

pub(crate) async fn overview(State(state): State<AppState>) -> impl IntoResponse {
    let paired = state
        .apple_tv
        .as_ref()
        .is_some_and(|apple_tv| apple_tv.service.has_stored_pairing());
    Json(OverviewResponse {
        enabled: state.apple_tv.is_some(),
        paired,
    })
}

pub(crate) async fn discover(State(state): State<AppState>) -> impl IntoResponse {
    let Some(apple_tv) = state.apple_tv.as_ref() else {
        return disabled();
    };
    match apple_tv.discover().await {
        Ok(targets) => (StatusCode::OK, Json(targets)).into_response(),
        Err(()) => message(
            StatusCode::SERVICE_UNAVAILABLE,
            "Apple TV discovery is unavailable on this host.",
        ),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StartPairingRequest {
    identifier: String,
}

pub(crate) async fn start_pairing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<StartPairingRequest>,
) -> impl IntoResponse {
    let Some(apple_tv) = state.apple_tv.as_ref() else {
        return disabled();
    };
    if !sources::action_allowed(&headers) {
        return sources::action_required();
    }
    match apple_tv.start(request.identifier.trim()).await {
        Ok(status) => (StatusCode::ACCEPTED, Json(status)).into_response(),
        Err(error) => pairing_error(error),
    }
}

pub(crate) async fn pairing_status(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let Some(apple_tv) = state.apple_tv.as_ref() else {
        return disabled();
    };
    match apple_tv.status(id).await {
        Ok(status) => (StatusCode::OK, Json(status)).into_response(),
        Err(error) => pairing_error(error),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PinRequest {
    pin: String,
}

pub(crate) async fn submit_pin(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<PinRequest>,
) -> impl IntoResponse {
    let Some(apple_tv) = state.apple_tv.as_ref() else {
        return disabled();
    };
    if !sources::action_allowed(&headers) {
        return sources::action_required();
    }
    let pin = request.pin.trim().to_owned();
    if !valid_pin(&pin) {
        return message(StatusCode::BAD_REQUEST, "The PIN must be six digits.");
    }
    match apple_tv.submit_pin(id, pin).await {
        Ok(status) => (StatusCode::ACCEPTED, Json(status)).into_response(),
        Err(error) => pairing_error(error),
    }
}

pub(crate) async fn cancel_pairing(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let Some(apple_tv) = state.apple_tv.as_ref() else {
        return disabled();
    };
    if !sources::action_allowed(&headers) {
        return sources::action_required();
    }
    match apple_tv.cancel(id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => pairing_error(error),
    }
}

pub(crate) async fn forget(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(apple_tv) = state.apple_tv.as_ref() else {
        return disabled();
    };
    if !sources::action_allowed(&headers) {
        return sources::action_required();
    }
    match apple_tv.service.forget_pairing().await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => message(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The Apple TV pairing could not be removed.",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apple_tv_requires_explicit_on() {
        assert!(enabled(Some("on".into())));
        assert!(enabled(Some(" on\n".into())));
        assert!(!enabled(None));
        assert!(!enabled(Some("ON".into())));
        assert!(!enabled(Some("1".into())));
    }

    #[test]
    fn pin_must_be_six_digits() {
        assert!(valid_pin("012345"));
        assert!(!valid_pin("12345"));
        assert!(!valid_pin("1234567"));
        assert!(!valid_pin("12a456"));
        assert!(!valid_pin(""));
    }

    fn test_service() -> Arc<WirelessPairingService> {
        let directory = std::env::temp_dir().join(format!("iphoneloadly-atv-{}", Uuid::now_v7()));
        Arc::new(WirelessPairingService::new(
            crate::wireless_pairing::WirelessPairingConfig::disabled(directory),
        ))
    }

    #[tokio::test]
    async fn unknown_session_and_pin_before_prompt_are_rejected() {
        let apple_tv = AppleTv::new(test_service());
        assert_eq!(
            apple_tv.status(Uuid::now_v7()).await.unwrap_err(),
            PairingError::NotFound
        );

        let (sender, _receiver) = oneshot::channel();
        let task = tokio::spawn(async {});
        let id = Uuid::now_v7();
        *apple_tv.session.lock().await = Some(Session {
            status: PairingStatus {
                id,
                phase: PairingPhase::Connecting,
                device_name: "Living Room".into(),
                expires_at: unix_seconds(SystemTime::now() + SESSION_LIFETIME),
                failure_code: None,
                verified: false,
            },
            pin: Some(sender),
            task: task.abort_handle(),
        });
        assert_eq!(
            apple_tv.submit_pin(id, "123456".into()).await.unwrap_err(),
            PairingError::NotAwaitingPin
        );

        set_phase(&apple_tv.session, id, PairingPhase::AwaitingPin, None).await;
        let status = apple_tv.submit_pin(id, "123456".into()).await.unwrap();
        assert_eq!(status.phase, PairingPhase::Verifying);
        assert_eq!(
            apple_tv.submit_pin(id, "123456".into()).await.unwrap_err(),
            PairingError::NotAwaitingPin
        );
    }

    #[tokio::test]
    async fn expired_session_reports_expired() {
        let apple_tv = AppleTv::new(test_service());
        let (sender, _receiver) = oneshot::channel();
        let task = tokio::spawn(async {});
        let id = Uuid::now_v7();
        *apple_tv.session.lock().await = Some(Session {
            status: PairingStatus {
                id,
                phase: PairingPhase::AwaitingPin,
                device_name: "Living Room".into(),
                expires_at: 0,
                failure_code: None,
                verified: false,
            },
            pin: Some(sender),
            task: task.abort_handle(),
        });
        assert_eq!(
            apple_tv.status(id).await.unwrap().phase,
            PairingPhase::Expired
        );
    }

    #[test]
    fn failure_codes_are_stable() {
        assert_eq!(
            crate::wireless_pairing::ManualPairingFailure::WrongPin.as_str(),
            "wrong_pin"
        );
    }
}
