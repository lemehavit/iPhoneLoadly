//! API-only job-state values.
//!
//! Version 0.1 persists installation progress as strings in SQLite so a job can
//! report its current transport phase after a restart. `Queued` is the only
//! typed value constructed by the asynchronous job-creation response; the
//! persisted phase is returned by the job-status endpoint.

use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobPhase {
    Queued,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallJob {
    pub id: Uuid,
    pub phase: JobPhase,
    pub progress_percent: Option<u8>,
    pub public_message: String,
}
