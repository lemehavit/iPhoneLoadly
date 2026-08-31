const DASHBOARD: &str = include_str!("../src/dashboard.html");

fn occurrences(needle: &str) -> usize {
    DASHBOARD.match_indices(needle).count()
}

#[test]
fn dashboard_keeps_the_app_shell_accessibility_contract() {
    assert!(DASHBOARD.contains("viewport-fit=cover"));
    assert!(DASHBOARD.contains("prefers-reduced-motion"));
    assert!(DASHBOARD.contains("aria-live=\"polite\""));
    assert!(DASHBOARD.contains("aria-current=\"page\""));
    assert!(DASHBOARD.contains("[hidden] { display:none !important; }"));
    assert!(DASHBOARD.contains("data-view-target"));
    for view in ["overview", "apps", "install", "activity", "settings"] {
        assert!(DASHBOARD.contains(&format!("data-view=\"{view}\"")));
    }
}

#[test]
fn dashboard_preserves_legacy_targets_without_unpairing() {
    for target in [
        "overview",
        "signing",
        "upload-card",
        "sources-card",
        "install-card",
        "history-card",
        "managed-card",
    ] {
        assert!(DASHBOARD.contains(target));
    }
    assert!(!DASHBOARD.contains("Unpair"));
    assert!(!DASHBOARD.contains("unpair"));
}

#[test]
fn dashboard_has_one_canonical_handler_for_each_refactored_flow() {
    assert_eq!(occurrences("async function upload("), 1);
    assert_eq!(occurrences("async function loadSources("), 1);
    assert_eq!(occurrences("function renderHistory("), 1);
    assert!(!DASHBOARD.contains("enhanceAlpha3"));
    assert!(!DASHBOARD.contains("setTimeout(enhance"));
}

#[test]
fn dashboard_uses_application_dialogs_and_local_assets() {
    assert!(DASHBOARD.contains("<dialog"));
    assert!(DASHBOARD.contains("function openConfirmation("));
    assert!(!DASHBOARD.contains("confirm("));
    assert!(!DASHBOARD.contains("prompt("));
    assert!(!DASHBOARD.contains("https://cdn."));
    assert!(!DASHBOARD.contains("fonts.googleapis.com"));
    assert!(!DASHBOARD.contains("cdnjs.cloudflare.com"));
}

#[test]
fn overview_has_one_wifi_status_and_keeps_device_controls() {
    assert_eq!(occurrences("function renderDevices("), 1);
    assert!(DASHBOARD.contains("statusNode('ok',t('online'"));
    assert!(DASHBOARD.contains("byId('devices-status').hidden=true"));
    assert!(!DASHBOARD.contains("setStatus('devices-status','ok'"));
    assert!(DASHBOARD.contains("id=\"rescan-overview\""));
    assert!(DASHBOARD.contains("id=\"overview-device\""));
}

#[test]
fn settings_keeps_one_update_card_and_manual_feedback() {
    assert!(DASHBOARD.contains("id=\"update-summary\" class=\"status info\""));
    assert!(DASHBOARD.contains("id=\"update-status\" class=\"status inline-status info\" hidden"));
    assert!(DASHBOARD.contains("async function checkOfficialUpdate(manual=true)"));
    assert!(DASHBOARD.contains("checkOfficialUpdate(false)"));
    assert!(DASHBOARD.contains("t('checkedJustNow')"));
    assert!(DASHBOARD.contains("officialUpdateDetail(info)"));
    assert!(DASHBOARD.contains("const inline=box.classList.contains('inline-status')"));
}

#[test]
fn activity_and_source_views_use_version_aware_data_refresh() {
    assert!(
        DASHBOARD.contains("const version=job.appVersion?`${t('version')} ${job.appVersion}`:''")
    );
    assert!(DASHBOARD.contains("function sourceVersionDetail("));
    assert!(DASHBOARD.contains("function sourceVersionComparison("));
    assert!(DASHBOARD.contains("t('currentVersion')"));
    assert!(DASHBOARD.contains("t('githubVersion')"));
    assert!(DASHBOARD.contains("await loadApps();const sourcesRefreshed=await loadSources()"));
    assert!(DASHBOARD.contains("sourceDownloadedRefreshFailed"));
    assert!(DASHBOARD.contains("sourceAppsRefreshFailed"));
    assert!(DASHBOARD.contains("sourceStatusRefreshFailed"));
    assert!(DASHBOARD.contains("id=\"source-status\""));
    assert!(!DASHBOARD.contains("location.reload"));
}

#[test]
fn new_dashboard_copy_is_localized_in_both_languages() {
    for key in [
        "checkedJustNow",
        "githubVersion",
        "newVersionAvailable",
        "noNewerVersion",
        "sourceDownloadedRefreshFailed",
        "sourceRefreshFailed",
        "sourceAppsRefreshFailed",
        "sourceStatusRefreshFailed",
    ] {
        assert!(DASHBOARD.contains(&format!("tr.sv.{key}")));
        assert!(DASHBOARD.contains(&format!("tr.en.{key}")));
    }
}
