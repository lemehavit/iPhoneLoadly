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
