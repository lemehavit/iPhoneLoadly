#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use semver::Version;
use serde::Serialize;

use crate::{AppState, github};

const REQUEST_PATH: &str = "/run/iphoneloadly/update-request.json";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateInfo {
    pub current_version: String,
    pub latest_version: Option<String>,
    pub available: bool,
    pub release_tag: Option<String>,
    pub prerelease: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct UpdateRequest {
    target_version: String,
    expected_archive_sha256: String,
    created_at: String,
}

fn release_archive(version: &str) -> String {
    format!("iphoneloadly-v{version}-linux-amd64.tar.gz")
}

pub async fn info(State(state): State<AppState>) -> impl IntoResponse {
    let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("package version is valid");
    let repository = github::official_repository();
    let releases = match state.github.releases(&repository).await {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::OK,
                Json(UpdateInfo {
                    current_version: current.to_string(),
                    latest_version: None,
                    available: false,
                    release_tag: None,
                    prerelease: false,
                    message: "The official GitHub release information is temporarily unavailable."
                        .into(),
                }),
            )
                .into_response();
        }
    };
    let mut candidate = None;
    for release in releases
        .into_iter()
        .filter(|release| !release.draft && (!release.prerelease || !current.pre.is_empty()))
    {
        let Ok(version) = github::official_version(&release.tag_name) else {
            continue;
        };
        if version <= current {
            continue;
        }
        let archive = release
            .assets
            .iter()
            .find(|asset| asset.name == release_archive(&version.to_string()));
        let checksum = release.assets.iter().find(|asset| {
            asset.name == format!("{}.sha256", release_archive(&version.to_string()))
        });
        if archive
            .and_then(|asset| asset.digest.as_deref())
            .is_some_and(|digest| {
                digest.strip_prefix("sha256:").is_some_and(|value| {
                    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
                })
            })
            && checksum.is_some()
            && (candidate
                .as_ref()
                .is_none_or(|(old, _): &(Version, _)| version > *old))
        {
            candidate = Some((version, release));
        }
    }
    let Some((version, release)) = candidate else {
        return (
            StatusCode::OK,
            Json(UpdateInfo {
                current_version: current.to_string(),
                latest_version: None,
                available: false,
                release_tag: None,
                prerelease: false,
                message: "iPhoneLoadly is up to date.".into(),
            }),
        )
            .into_response();
    };
    (
        StatusCode::OK,
        Json(UpdateInfo {
            current_version: current.to_string(),
            latest_version: Some(version.to_string()),
            available: true,
            release_tag: Some(release.tag_name),
            prerelease: release.prerelease,
            message: "A verified official iPhoneLoadly update is available.".into(),
        }),
    )
        .into_response()
}

pub async fn request(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if headers
        .get("x-iphoneloadly-action")
        .and_then(|value| value.to_str().ok())
        != Some("1")
        || headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_none_or(|value| !value.starts_with("application/json"))
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"message":"JSON action header required."})),
        )
            .into_response();
    }
    let Ok(_sync_guard) = state.source_sync.try_lock() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"message":"Source synchronization is active; try the update again later."})),
        )
            .into_response();
    };
    let active_install = state
        .database
        .lock()
        .ok()
        .and_then(|database| {
            database
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM jobs
                         WHERE phase IN ('queued', 'connecting', 'signing', 'transferring', 'installing')
                    )",
                    [],
                    |row| row.get::<_, bool>(0),
                )
                .ok()
        })
        .unwrap_or(true);
    if active_install {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"message":"An installation is active; wait before updating iPhoneLoadly."})),
        )
            .into_response();
    }
    let current = Version::parse(env!("CARGO_PKG_VERSION")).expect("package version is valid");
    let repository = github::official_repository();
    let releases = match state.github.releases(&repository).await {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"message":"Unable to resolve the official update."})),
            )
                .into_response();
        }
    };
    let mut candidate: Option<(Version, String)> = None;
    for release in releases
        .into_iter()
        .filter(|release| !release.draft && (!release.prerelease || !current.pre.is_empty()))
    {
        let Ok(version) = github::official_version(&release.tag_name) else {
            continue;
        };
        if version <= current {
            continue;
        }
        let archive_name = release_archive(&version.to_string());
        let Some(archive) = release
            .assets
            .iter()
            .find(|asset| asset.name == archive_name)
        else {
            continue;
        };
        let Some(digest) = archive
            .digest
            .as_deref()
            .and_then(|value| value.strip_prefix("sha256:"))
        else {
            continue;
        };
        if digest.len() == 64
            && digest
                .chars()
                .all(|character| character.is_ascii_hexdigit())
            && release
                .assets
                .iter()
                .any(|asset| asset.name == format!("{archive_name}.sha256"))
        {
            if candidate.as_ref().is_some_and(|(old, _)| *old >= version) {
                continue;
            }
            candidate = Some((version, digest.to_owned()));
        }
    }
    let Some((version, digest)) = candidate else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"message":"No newer verified official release is available."})),
        )
            .into_response();
    };
    let (version_string, digest) = (version.to_string(), digest);
    let request = UpdateRequest {
        target_version: version_string.clone(),
        expected_archive_sha256: digest,
        created_at: chrono_like_now(),
    };
    let path = PathBuf::from(REQUEST_PATH);
    if tokio::fs::try_exists(&path).await.unwrap_or(false) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"message":"An update is already requested or running."})),
        )
            .into_response();
    }
    if let Some(parent) = path.parent()
        && tokio::fs::create_dir_all(parent).await.is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to prepare the updater request."})),
        )
            .into_response();
    }
    let temporary = path.with_extension("json.tmp");
    let bytes = match serde_json::to_vec(&request) {
        Ok(value) => value,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"message":"Unable to serialize the updater request."})),
            )
                .into_response();
        }
    };
    if tokio::fs::write(&temporary, bytes).await.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to queue the updater request."})),
        )
            .into_response();
    }
    #[cfg(unix)]
    if tokio::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))
        .await
        .is_err()
    {
        let _ = tokio::fs::remove_file(&temporary).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to secure the updater request."})),
        )
            .into_response();
    }
    if tokio::fs::rename(&temporary, &path).await.is_err() {
        let _ = tokio::fs::remove_file(&temporary).await;
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to queue the updater request."})),
        )
            .into_response();
    }
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({"status":"requested","targetVersion":version_string})),
    )
        .into_response()
}

pub async fn status() -> impl IntoResponse {
    let path = PathBuf::from("/var/lib/iphoneloadly/data/update-status.json");
    match tokio::fs::read_to_string(path).await {
        Ok(value) => (
            StatusCode::OK,
            axum::response::Json(
                serde_json::from_str::<serde_json::Value>(&value)
                    .unwrap_or_else(|_| serde_json::json!({"status":"unknown"})),
            ),
        )
            .into_response(),
        Err(_) => (StatusCode::OK, Json(serde_json::json!({"status":"idle"}))).into_response(),
    }
}

fn chrono_like_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs().to_string())
        .unwrap_or_else(|_| "0".into())
}
