//! Persistable job-state vocabulary. Database storage follows in the next increment.

use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobPhase {
    Queued,
    AuthenticatingApple,
    AwaitingTwoFactorCode,
    Provisioning,
    Signing,
    Connecting,
    Staging,
    Installing,
    Verifying,
    CleaningUp,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallJob {
    pub id: Uuid,
    pub phase: JobPhase,
    pub progress_percent: Option<u8>,
    pub public_message: String,
}
