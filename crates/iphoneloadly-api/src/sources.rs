use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::Deserialize;
use std::path::PathBuf;
use uuid::Uuid;

use crate::{
    AppState,
    github::{self, GitHubError},
    store,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceConfig {
    pub repository: String,
    pub asset_pattern: String,
    #[serde(default)]
    pub include_prereleases: bool,
    pub app_id: Option<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct PreviewRequest {
    #[serde(flatten)]
    pub config: SourceConfig,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AutomationRequest {
    pub enabled: bool,
    #[serde(default)]
    pub acknowledged_security_warning: bool,
}
fn action_allowed(headers: &HeaderMap) -> bool {
    headers
        .get("x-iphoneloadly-action")
        .and_then(|value| value.to_str().ok())
        == Some("1")
        && headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/json"))
}

fn action_required() -> axum::response::Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"message":"JSON action header required."})),
    )
        .into_response()
}

fn github_error_code(error: &GitHubError) -> &'static str {
    match error {
        GitHubError::InvalidRepository => "invalid_repository",
        GitHubError::InvalidPattern => "invalid_asset_pattern",
        GitHubError::Http(status)
            if *status == StatusCode::FORBIDDEN || *status == StatusCode::TOO_MANY_REQUESTS =>
        {
            "github_rate_limited"
        }
        GitHubError::Http(_) => "github_unavailable",
        GitHubError::NoMatchingAsset => "no_ipa_asset",
        GitHubError::AmbiguousAsset => "ambiguous_asset",
        GitHubError::TooLarge => "asset_too_large",
        GitHubError::InvalidDownloadUrl => "invalid_download_url",
        GitHubError::InvalidResponse | GitHubError::InvalidVersion => "github_unavailable",
    }
}

fn record_source_error(state: &AppState, id: Uuid, error: &GitHubError) {
    if let Ok(database) = state.database.lock() {
        let _ = store::record_source_check(
            &database,
            id,
            None,
            None,
            None,
            None,
            None,
            "error",
            Some(github_error_code(error)),
        );
    }
}

fn error_response(error: GitHubError) -> axum::response::Response {
    let code = github_error_code(&error);
    let status = if matches!(code, "invalid_repository" | "invalid_asset_pattern") {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::BAD_GATEWAY
    };
    (
        status,
        Json(serde_json::json!({"code":code,"message":code_message(code)})),
    )
        .into_response()
}

fn code_message(code: &str) -> &'static str {
    match code {
        "ambiguous_asset" => {
            "The asset pattern matches more than one IPA; refine it before downloading."
        }
        "no_ipa_asset" => "No eligible IPA asset matches this source pattern.",
        "github_rate_limited" => "GitHub rate-limited this request; try again later.",
        "asset_too_large" => "The selected IPA exceeds the upload size limit.",
        "invalid_repository" => "Only public canonical GitHub repositories are supported.",
        "invalid_asset_pattern" => "The IPA asset pattern is invalid.",
        _ => "The GitHub source could not be processed.",
    }
}

fn source_json(source: store::GitHubSource) -> serde_json::Value {
    serde_json::json!({
        "id": source.id,
        "appId": source.app_id,
        "repository": format!("{}/{}", source.owner, source.repo),
        "assetPattern": source.asset_pattern,
        "includePrereleases": source.include_prereleases,
        "autoDownload": source.auto_download,
        "autoAcknowledgedAt": source.auto_acknowledged_at,
        "lastCheckedAt": source.last_checked_at,
        "lastReleaseId": source.last_release_id,
        "lastReleaseTag": source.last_release_tag,
        "lastAssetId": source.last_asset_id,
        "lastAssetName": source.last_asset_name,
        "lastDownloadSha256": source.last_download_sha256,
        "lastStatus": source.last_status,
        "lastErrorCode": source.last_error_code,
        "createdAt": source.created_at,
        "updatedAt": source.updated_at
    })
}

pub async fn list(State(state): State<AppState>) -> impl IntoResponse {
    match state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|db| store::list_github_sources(&db).map_err(|_| ()))
    {
        Ok(sources) => {
            Json(sources.into_iter().map(source_json).collect::<Vec<_>>()).into_response()
        }
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to list GitHub sources."})),
        )
            .into_response(),
    }
}

pub async fn preview(
    State(state): State<AppState>,
    Json(request): Json<PreviewRequest>,
) -> impl IntoResponse {
    let repository = match github::parse_public_repository(&request.config.repository) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let release = match state
        .github
        .latest_release(&repository, request.config.include_prereleases)
        .await
    {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let assets = release
        .assets
        .iter()
        .filter(|asset| asset.name.to_ascii_lowercase().ends_with(".ipa"))
        .map(|asset| serde_json::json!({"id":asset.id,"name":asset.name,"size":asset.size}))
        .collect::<Vec<_>>();
    let matching = github::match_ipa_asset(&release, &request.config.asset_pattern)
        .ok()
        .map(|asset| asset.id);
    (StatusCode::OK, Json(serde_json::json!({"repository":format!("{}/{}",repository.owner,repository.repo),"release":{"id":release.id,"tag":release.tag_name,"name":release.name,"prerelease":release.prerelease},"assets":assets,"matchingAssetId":matching}))).into_response()
}

pub async fn create(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SourceConfig>,
) -> impl IntoResponse {
    if !action_allowed(&headers) {
        return action_required();
    }
    let repository = match github::parse_public_repository(&request.repository) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    if let Err(error) = github::validate_asset_pattern(&request.asset_pattern) {
        return error_response(error);
    }
    if let Some(app_id) = request.app_id {
        let exists = state
            .database
            .lock()
            .ok()
            .and_then(|db| store::find_app(&db, app_id).ok())
            .flatten()
            .is_some();
        if !exists {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"message":"The linked IPA was not found."})),
            )
                .into_response();
        }
    }
    let id = Uuid::now_v7();
    let result = state.database.lock().map_err(|_| ()).and_then(|db| {
        store::insert_github_source(
            &db,
            id,
            request.app_id,
            &repository.owner,
            &repository.repo,
            &request.asset_pattern,
            request.include_prereleases,
        )
        .map_err(|_| ())
    });
    match result {
        Ok(()) => (StatusCode::CREATED, Json(serde_json::json!({"id":id}))).into_response(),
        Err(_) => (StatusCode::CONFLICT, Json(serde_json::json!({"code":"source_exists","message":"This source configuration already exists."}))).into_response(),
    }
}

pub async fn update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<SourceConfig>,
) -> impl IntoResponse {
    if !action_allowed(&headers) {
        return action_required();
    }
    if let Some(app_id) = request.app_id
        && state
            .database
            .lock()
            .ok()
            .and_then(|db| store::find_app(&db, app_id).ok())
            .flatten()
            .is_none()
    {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"The linked IPA was not found."})),
        )
            .into_response();
    }
    let repository = match github::parse_public_repository(&request.repository) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    if let Err(error) = github::validate_asset_pattern(&request.asset_pattern) {
        return error_response(error);
    }
    let result = state.database.lock().map_err(|_| ()).and_then(|db| {
        store::update_github_source(
            &db,
            id,
            request.app_id,
            &repository.owner,
            &repository.repo,
            &request.asset_pattern,
            request.include_prereleases,
        )
        .map_err(|_| ())
    });
    match result {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"GitHub source was not found."})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"message":"Unable to update GitHub source."})),
        )
            .into_response(),
    }
}

pub async fn remove(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if !action_allowed(&headers) {
        return action_required();
    }
    match state
        .database
        .lock()
        .map_err(|_| ())
        .and_then(|db| store::delete_github_source(&db, id).map_err(|_| ()))
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"GitHub source was not found."})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to remove GitHub source."})),
        )
            .into_response(),
    }
}

fn source_check_status(
    last_release_id: Option<i64>,
    last_asset_id: Option<i64>,
    last_status: Option<&str>,
    release_id: i64,
    asset_id: i64,
) -> &'static str {
    let same_asset = last_release_id == Some(release_id) && last_asset_id == Some(asset_id);
    if same_asset
        && matches!(
            last_status,
            Some("downloaded") | Some("unchanged") | Some("up_to_date")
        )
    {
        "up_to_date"
    } else {
        "update_available"
    }
}

pub async fn check(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if !action_allowed(&headers) {
        return action_required();
    }
    let source = match state
        .database
        .lock()
        .ok()
        .and_then(|db| store::find_github_source(&db, id).ok())
        .flatten()
    {
        Some(source) => source,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"message":"GitHub source was not found."})),
            )
                .into_response();
        }
    };
    let repository = github::RepositoryRef {
        owner: source.owner.clone(),
        repo: source.repo.clone(),
    };
    let release = match state
        .github
        .latest_release(&repository, source.include_prereleases)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            record_source_error(&state, id, &error);
            return error_response(error);
        }
    };
    let asset = match github::match_ipa_asset(&release, &source.asset_pattern) {
        Ok(value) => value,
        Err(error) => {
            record_source_error(&state, id, &error);
            return error_response(error);
        }
    };
    let status = source_check_status(
        source.last_release_id,
        source.last_asset_id,
        source.last_status.as_deref(),
        release.id,
        asset.id,
    );
    let current = status == "up_to_date";
    if let Ok(db) = state.database.lock() {
        let _ = store::record_source_check(
            &db,
            id,
            Some(release.id),
            Some(&release.tag_name),
            Some(asset.id),
            Some(&asset.name),
            source.last_download_sha256.as_deref(),
            status,
            None,
        );
    }
    (StatusCode::OK, Json(serde_json::json!({"current":current,"updateAvailable":!current,"releaseTag":release.tag_name,"assetName":asset.name,"assetSize":asset.size}))).into_response()
}

pub async fn download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    if !action_allowed(&headers) {
        return action_required();
    }
    let source = match state
        .database
        .lock()
        .ok()
        .and_then(|db| store::find_github_source(&db, id).ok())
        .flatten()
    {
        Some(source) => source,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"message":"GitHub source was not found."})),
            )
                .into_response();
        }
    };
    let repository = github::RepositoryRef {
        owner: source.owner.clone(),
        repo: source.repo.clone(),
    };
    let release = match state
        .github
        .latest_release(&repository, source.include_prereleases)
        .await
    {
        Ok(value) => value,
        Err(error) => {
            record_source_error(&state, id, &error);
            return error_response(error);
        }
    };
    let asset = match github::match_ipa_asset(&release, &source.asset_pattern) {
        Ok(value) => value,
        Err(error) => {
            record_source_error(&state, id, &error);
            return error_response(error);
        }
    };
    let temporary = state
        .apps_dir
        .join(format!(".source-{id}-{}.upload", Uuid::now_v7()));
    if let Err(error) = state
        .github
        .download_asset(&repository, &release, asset, &temporary)
        .await
    {
        let _ = tokio::fs::remove_file(&temporary).await;
        record_source_error(&state, id, &error);
        return error_response(error);
    }
    let metadata = match crate::ipa::inspect_ipa(&temporary) {
        Ok(value) => value,
        Err(_) => {
            let _ = tokio::fs::remove_file(&temporary).await;
            let _ = state.database.lock().ok().and_then(|db| {
                store::record_source_check(
                    &db,
                    id,
                    Some(release.id),
                    Some(&release.tag_name),
                    Some(asset.id),
                    Some(&asset.name),
                    None,
                    "error",
                    Some("invalid_ipa"),
                )
                .ok()
            });
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"code":"invalid_ipa","message":"The downloaded release asset is not a valid IPA."}))).into_response();
        }
    };
    let _mutation = state.app_mutation.write().await;
    let mut finalized_path: Option<PathBuf> = None;
    let result = state.database.lock().map_err(|_| ()).and_then(|mut db| {
        let Some(current_source) = store::find_github_source(&db, id).map_err(|_| ())? else {
            return Err(());
        };
        if current_source.app_id != source.app_id
            || current_source.owner != source.owner
            || current_source.repo != source.repo
            || current_source.asset_pattern != source.asset_pattern
            || current_source.include_prereleases != source.include_prereleases
        {
            return Err(());
        }
        if let Some(app_id) = source.app_id {
            let app = store::find_app(&db, app_id).map_err(|_| ())?.ok_or(())?;
            if store::active_job_exists_for_app(&db, app_id).map_err(|_| ())? {
                return Err(());
            }
            if app.bundle_id.as_deref() != Some(&metadata.bundle_id) {
                return Err(());
            }
            if app.sha256 == metadata.sha256 {
                let _ = std::fs::remove_file(&temporary);
                store::record_source_check(
                    &db,
                    id,
                    Some(release.id),
                    Some(&release.tag_name),
                    Some(asset.id),
                    Some(&asset.name),
                    Some(&metadata.sha256),
                    "unchanged",
                    None,
                )
                .map_err(|_| ())?;
                return Ok((String::new(), true));
            }
            let final_path = state.apps_dir.join(format!(
                "{}-{}.ipa",
                app_id,
                &metadata.sha256[..12.min(metadata.sha256.len())]
            ));
            std::fs::rename(&temporary, &final_path).map_err(|_| ())?;
            finalized_path = Some(final_path.clone());
            store::replace_app_from_source(
                &mut db,
                app_id,
                id,
                &metadata.sha256,
                &final_path.to_string_lossy(),
                metadata.size_bytes,
                &metadata.bundle_id,
                metadata.app_version.as_deref(),
                release.id,
                &release.tag_name,
                asset.id,
                &asset.name,
            )
            .map_err(|_| ())?;
            Ok((app.storage_path, false))
        } else {
            let app_id = Uuid::now_v7();
            let final_path = state.apps_dir.join(format!("{app_id}.ipa"));
            std::fs::rename(&temporary, &final_path).map_err(|_| ())?;
            finalized_path = Some(final_path.clone());
            store::insert_app(
                &db,
                app_id,
                &metadata.sha256,
                &final_path.to_string_lossy(),
                metadata.size_bytes,
                &metadata.bundle_id,
                &metadata.display_name,
                metadata.app_version.as_deref(),
            )
            .map_err(|_| ())?;
            store::link_github_source_app(&db, id, app_id).map_err(|_| ())?;
            store::record_source_check(
                &db,
                id,
                Some(release.id),
                Some(&release.tag_name),
                Some(asset.id),
                Some(&asset.name),
                Some(&metadata.sha256),
                "downloaded",
                None,
            )
            .map_err(|_| ())?;
            Ok((final_path.to_string_lossy().to_string(), false))
        }
    });
    match result {
        Ok((old_path, unchanged)) => {
            if !old_path.is_empty()
                && let Err(error) = tokio::fs::remove_file(&old_path).await
            {
                tracing::warn!(
                    path = %old_path,
                    error = %error,
                    "unable to remove replaced IPA orphan"
                );
            }
            let status = if unchanged {
                StatusCode::ALREADY_REPORTED
            } else {
                StatusCode::OK
            };
            (status, Json(serde_json::json!({"status":if unchanged {"unchanged"} else {"downloaded"},"releaseTag":release.tag_name,"assetName":asset.name,"sha256":metadata.sha256}))).into_response()
        }
        Err(_) => {
            let _ = tokio::fs::remove_file(&temporary).await;
            if let Some(path) = finalized_path {
                let _ = tokio::fs::remove_file(path).await;
            }
            (StatusCode::CONFLICT, Json(serde_json::json!({"code":"source_download_failed","message":"The source could not replace the server IPA; it may have an active job or bundle mismatch."}))).into_response()
        }
    }
}

pub async fn automation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(request): Json<AutomationRequest>,
) -> impl IntoResponse {
    if !action_allowed(&headers) {
        return action_required();
    }
    if request.enabled && !request.acknowledged_security_warning {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"code":"security_acknowledgement_required","message":"Read and acknowledge the source security warning before enabling automatic downloads."}))).into_response();
    }
    match state.database.lock().map_err(|_| ()).and_then(|db| {
        store::set_source_automation(
            &db,
            id,
            request.enabled,
            request.acknowledged_security_warning,
        )
        .map_err(|_| ())
    }) {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"message":"GitHub source was not found."})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message":"Unable to update source automation."})),
        )
            .into_response(),
    }
}

pub async fn sync(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if !action_allowed(&headers) {
        return action_required();
    }
    let Ok(_sync_guard) = state.source_sync.try_lock() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"message":"Source synchronization is already running."})),
        )
            .into_response();
    };
    let ids = state
        .database
        .lock()
        .ok()
        .and_then(|db| store::list_github_sources(&db).ok())
        .unwrap_or_default()
        .into_iter()
        .filter(|source| source.auto_download)
        .map(|source| source.id)
        .collect::<Vec<_>>();
    let mut updated = 0;
    let mut unchanged = 0;
    let mut failed = 0;
    for id in ids {
        match download(State(state.clone()), headers.clone(), Path(id))
            .await
            .into_response()
            .status()
        {
            StatusCode::ALREADY_REPORTED => unchanged += 1,
            status if status.is_success() => updated += 1,
            _ => failed += 1,
        }
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({"checked":updated + unchanged + failed,"updated":updated,"failed":failed,"unchanged":unchanged,"skipped":0})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::source_check_status;

    #[test]
    fn repeated_checks_keep_pending_release_available_until_downloaded() {
        assert_eq!(
            source_check_status(None, None, None, 1, 10),
            "update_available"
        );
        assert_eq!(
            source_check_status(Some(1), Some(10), Some("downloaded"), 2, 20),
            "update_available"
        );
        assert_eq!(
            source_check_status(Some(2), Some(20), Some("update_available"), 2, 20),
            "update_available"
        );
        assert_eq!(
            source_check_status(Some(2), Some(20), Some("downloaded"), 2, 20),
            "up_to_date"
        );
        assert_eq!(
            source_check_status(Some(2), Some(20), Some("unchanged"), 2, 20),
            "up_to_date"
        );
    }
}
