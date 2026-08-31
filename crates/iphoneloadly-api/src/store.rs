use std::path::Path;

use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

pub const DEFAULT_REFRESH_AFTER_DAYS: u8 = 6;
pub const MIN_REFRESH_AFTER_DAYS: u8 = 1;
pub const MAX_REFRESH_AFTER_DAYS: u8 = 6;

pub struct StoredJob {
    pub id: Uuid,
    pub app_id: Uuid,
    pub device_id: Uuid,
    pub phase: String,
    pub progress_percent: Option<u8>,
    pub device_label: String,
    pub created_at: String,
    pub completed_at: Option<String>,
    pub failure_code: Option<String>,
    pub app_display_name: String,
    pub app_version: Option<String>,
}

pub struct StoredApp {
    pub id: Uuid,
    pub sha256: String,
    pub size_bytes: u64,
    pub display_name: String,
    pub app_version: Option<String>,
    pub bundle_id: Option<String>,
    pub storage_path: String,
}

#[derive(Debug, Clone)]
pub struct ManagedInstallation {
    pub app_id: Uuid,
    pub device_id: Uuid,
    pub app_display_name: String,
    pub app_version: Option<String>,
    pub device_label: String,
}

#[derive(Debug, Clone)]
pub struct GitHubSource {
    pub id: Uuid,
    pub app_id: Option<Uuid>,
    pub owner: String,
    pub repo: String,
    pub asset_pattern: String,
    pub include_prereleases: bool,
    pub auto_download: bool,
    pub auto_acknowledged_at: Option<String>,
    pub last_checked_at: Option<String>,
    pub last_release_id: Option<i64>,
    pub last_release_tag: Option<String>,
    pub last_asset_id: Option<i64>,
    pub last_asset_name: Option<String>,
    pub last_download_sha256: Option<String>,
    pub last_status: Option<String>,
    pub last_error_code: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}
pub struct ManagedAppIdentity {
    pub installed_bundle_id: Option<String>,
    pub source_bundle_id: Option<String>,
}

pub struct RefreshAttention {
    pub app_id: Uuid,
    pub device_label: String,
    pub age_hours: i64,
    pub retry_failed: bool,
}

pub struct InstallationValidity {
    pub app_id: Uuid,
    pub device_label: String,
    pub remaining_days: i64,
    pub completed_at: String,
}
pub fn initialize(path: &Path) -> rusqlite::Result<Connection> {
    let connection = Connection::open(path)?;
    connection.execute_batch(
        "
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS apps (
            id TEXT PRIMARY KEY,
            sha256 TEXT NOT NULL UNIQUE,
            storage_path TEXT NOT NULL UNIQUE,
            size_bytes INTEGER NOT NULL,
            uploaded_at TEXT NOT NULL,
            deleted_at TEXT,
            bundle_id TEXT,
            display_name TEXT,
            app_version TEXT
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            app_id TEXT NOT NULL REFERENCES apps(id),
            device_id TEXT NOT NULL,
            phase TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT,
            progress_percent INTEGER,
            device_label TEXT NOT NULL DEFAULT 'Trusted iPhone',
            failure_code TEXT,
            installed_bundle_id TEXT,
            app_display_name TEXT,
            app_version TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS unmanaged_installations (
            app_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            removed_at TEXT NOT NULL,
            PRIMARY KEY (app_id, device_id)
        );
        CREATE TABLE IF NOT EXISTS github_sources (
            id TEXT PRIMARY KEY,
            app_id TEXT UNIQUE,
            owner TEXT NOT NULL,
            repo TEXT NOT NULL,
            asset_pattern TEXT NOT NULL,
            include_prereleases INTEGER NOT NULL DEFAULT 0,
            auto_download INTEGER NOT NULL DEFAULT 0,
            auto_acknowledged_at TEXT,
            last_checked_at TEXT,
            last_release_id INTEGER,
            last_release_tag TEXT,
            last_asset_id INTEGER,
            last_asset_name TEXT,
            last_download_sha256 TEXT,
            last_status TEXT,
            last_error_code TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (app_id) REFERENCES apps(id)
        );
        CREATE UNIQUE INDEX IF NOT EXISTS github_sources_identity
            ON github_sources(owner, repo, asset_pattern);
        ",
    )?;
    let app_columns = table_columns(&connection, "apps")?;
    if !app_columns.iter().any(|name| name == "deleted_at") {
        connection.execute_batch("ALTER TABLE apps ADD COLUMN deleted_at TEXT;")?;
    }
    if !app_columns.iter().any(|name| name == "bundle_id") {
        connection.execute_batch("ALTER TABLE apps ADD COLUMN bundle_id TEXT;")?;
    }
    if !app_columns.iter().any(|name| name == "display_name") {
        connection.execute_batch("ALTER TABLE apps ADD COLUMN display_name TEXT;")?;
    }
    if !app_columns.iter().any(|name| name == "app_version") {
        connection.execute_batch("ALTER TABLE apps ADD COLUMN app_version TEXT;")?;
    }
    let job_columns = table_columns(&connection, "jobs")?;
    if !job_columns.iter().any(|name| name == "completed_at") {
        connection.execute_batch("ALTER TABLE jobs ADD COLUMN completed_at TEXT;")?;
    }
    if !job_columns.iter().any(|name| name == "progress_percent") {
        connection.execute_batch("ALTER TABLE jobs ADD COLUMN progress_percent INTEGER;")?;
    }
    if !job_columns.iter().any(|name| name == "device_label") {
        connection.execute_batch(
            "ALTER TABLE jobs ADD COLUMN device_label TEXT NOT NULL DEFAULT 'Trusted iPhone';",
        )?;
    }
    if !job_columns.iter().any(|name| name == "failure_code") {
        connection.execute_batch("ALTER TABLE jobs ADD COLUMN failure_code TEXT;")?;
    }
    if !job_columns.iter().any(|name| name == "installed_bundle_id") {
        connection.execute_batch("ALTER TABLE jobs ADD COLUMN installed_bundle_id TEXT;")?;
    }
    if !job_columns.iter().any(|name| name == "app_display_name") {
        connection.execute_batch("ALTER TABLE jobs ADD COLUMN app_display_name TEXT;")?;
    }
    if !job_columns.iter().any(|name| name == "app_version") {
        connection.execute_batch("ALTER TABLE jobs ADD COLUMN app_version TEXT;")?;
    }
    connection.execute_batch(
        "UPDATE apps SET display_name = COALESCE(NULLIF(display_name, ''), bundle_id, substr(id, 1, 8))
         WHERE display_name IS NULL OR display_name = '';
         UPDATE jobs SET completed_at = created_at
         WHERE phase = 'succeeded' AND completed_at IS NULL;
         UPDATE jobs SET app_display_name = (
             SELECT display_name FROM apps WHERE apps.id = jobs.app_id
         ) WHERE app_display_name IS NULL OR app_display_name = '';
         UPDATE jobs SET app_version = (
             SELECT app_version FROM apps WHERE apps.id = jobs.app_id
         ) WHERE app_version IS NULL;",
    )?;
    Ok(connection)
}

fn table_columns(connection: &Connection, table: &str) -> rusqlite::Result<Vec<String>> {
    let mut columns = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    columns
        .query_map([], |row| row.get::<_, String>(1))?
        .collect()
}

#[allow(clippy::too_many_arguments)]
pub fn insert_app(
    connection: &Connection,
    id: Uuid,
    sha256: &str,
    storage_path: &str,
    size_bytes: u64,
    bundle_id: &str,
    display_name: &str,
    app_version: Option<&str>,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO apps (id, sha256, storage_path, size_bytes, uploaded_at, bundle_id, display_name, app_version)
         VALUES (?1, ?2, ?3, ?4, datetime('now'), ?5, ?6, ?7)",
        rusqlite::params![
            id.to_string(),
            sha256,
            storage_path,
            size_bytes as i64,
            bundle_id,
            display_name,
            app_version
        ],
    )?;
    Ok(())
}
pub fn apps_missing_bundle_id(connection: &Connection) -> rusqlite::Result<Vec<(Uuid, String)>> {
    let mut statement = connection.prepare(
        "SELECT id, storage_path FROM apps WHERE bundle_id IS NULL AND deleted_at IS NULL",
    )?;
    statement
        .query_map([], |row| {
            let id: String = row.get(0)?;
            Ok((
                Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                row.get(1)?,
            ))
        })?
        .collect()
}

pub fn app_path(connection: &Connection, id: Uuid) -> rusqlite::Result<Option<String>> {
    connection
        .query_row(
            "SELECT storage_path FROM apps WHERE id = ?1 AND deleted_at IS NULL",
            [id.to_string()],
            |row| row.get(0),
        )
        .optional()
}

pub fn set_app_bundle_id(
    connection: &Connection,
    id: Uuid,
    bundle_id: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE apps SET bundle_id = ?1 WHERE id = ?2",
        (bundle_id, id.to_string()),
    )?;
    Ok(())
}

pub fn managed_app_identities(
    connection: &Connection,
    device_id: Uuid,
) -> rusqlite::Result<Vec<ManagedAppIdentity>> {
    let mut statement = connection.prepare(
        "SELECT DISTINCT jobs.installed_bundle_id, apps.bundle_id
         FROM jobs JOIN apps ON apps.id = jobs.app_id
         WHERE jobs.device_id = ?1 AND jobs.phase = 'succeeded'
           AND NOT EXISTS (
               SELECT 1 FROM unmanaged_installations u
               WHERE u.app_id = jobs.app_id AND u.device_id = jobs.device_id
           )
           AND (
                jobs.installed_bundle_id IS NOT NULL
                OR NOT EXISTS (
                    SELECT 1 FROM jobs AS exact
                    WHERE exact.app_id = jobs.app_id
                      AND exact.device_id = jobs.device_id
                      AND exact.phase = 'succeeded'
                      AND exact.installed_bundle_id IS NOT NULL
                )
           )",
    )?;
    statement
        .query_map([device_id.to_string()], |row| {
            Ok(ManagedAppIdentity {
                installed_bundle_id: row.get(0)?,
                source_bundle_id: row.get(1)?,
            })
        })?
        .collect()
}

pub fn list_apps(connection: &Connection) -> rusqlite::Result<Vec<StoredApp>> {
    let mut statement = connection.prepare(
        "SELECT id, sha256, size_bytes, display_name, app_version, bundle_id, storage_path
         FROM apps WHERE deleted_at IS NULL ORDER BY uploaded_at DESC",
    )?;
    statement
        .query_map([], |row| {
            let id: String = row.get(0)?;
            Ok(StoredApp {
                id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                sha256: row.get(1)?,
                size_bytes: row.get::<_, i64>(2)? as u64,
                display_name: row
                    .get::<_, Option<String>>(3)?
                    .unwrap_or_else(|| id.clone()),
                app_version: row.get(4)?,
                bundle_id: row.get(5)?,
                storage_path: row.get(6)?,
            })
        })?
        .collect()
}

pub fn refresh_after_days(connection: &Connection) -> rusqlite::Result<u8> {
    let mut statement =
        connection.prepare("SELECT value FROM settings WHERE key = 'refresh_after_days'")?;
    let mut rows = statement.query([])?;
    let Some(row) = rows.next()? else {
        return Ok(DEFAULT_REFRESH_AFTER_DAYS);
    };
    let value: String = row.get(0)?;
    Ok(value
        .parse::<u8>()
        .ok()
        .filter(|days| (MIN_REFRESH_AFTER_DAYS..=MAX_REFRESH_AFTER_DAYS).contains(days))
        .unwrap_or(DEFAULT_REFRESH_AFTER_DAYS))
}

pub fn set_refresh_after_days(connection: &Connection, after_days: u8) -> rusqlite::Result<()> {
    if !(MIN_REFRESH_AFTER_DAYS..=MAX_REFRESH_AFTER_DAYS).contains(&after_days) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    connection.execute(
        "INSERT INTO settings (key, value) VALUES ('refresh_after_days', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [after_days.to_string()],
    )?;
    Ok(())
}

pub fn refresh_due_targets(
    connection: &Connection,
    after_days: u8,
) -> rusqlite::Result<Vec<(Uuid, Uuid, String)>> {
    let mut statement = connection.prepare(
        "SELECT jobs.app_id, jobs.device_id, apps.storage_path
         FROM jobs JOIN apps ON apps.id = jobs.app_id
         WHERE jobs.phase = 'succeeded' AND apps.deleted_at IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM unmanaged_installations u
               WHERE u.app_id = jobs.app_id AND u.device_id = jobs.device_id
           )
           AND jobs.completed_at = (
                SELECT MAX(latest.completed_at) FROM jobs AS latest
                WHERE latest.app_id = jobs.app_id
                  AND latest.device_id = jobs.device_id
                  AND latest.phase = 'succeeded'
           )
           AND (julianday('now') - julianday(jobs.completed_at)) >= ?1",
    )?;
    statement
        .query_map([i64::from(after_days)], |row| {
            let app_id: String = row.get(0)?;
            let device_id: String = row.get(1)?;
            Ok((
                Uuid::parse_str(&app_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                Uuid::parse_str(&device_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                row.get(2)?,
            ))
        })?
        .collect()
}

pub fn refresh_attention(
    connection: &Connection,
    after_days: u8,
) -> rusqlite::Result<Vec<RefreshAttention>> {
    let attention_after_hours = i64::from(after_days.saturating_sub(1)) * 24;
    let mut statement = connection.prepare(
        "SELECT jobs.app_id, jobs.device_label,
                CAST((julianday('now') - julianday(jobs.completed_at)) * 24 AS INTEGER),
                EXISTS(
                    SELECT 1 FROM jobs AS failed
                    WHERE failed.app_id = jobs.app_id AND failed.device_id = jobs.device_id
                      AND failed.phase = 'failed' AND failed.created_at > jobs.completed_at
                )
         FROM jobs
         JOIN apps ON apps.id = jobs.app_id
         WHERE jobs.phase = 'succeeded' AND apps.deleted_at IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM unmanaged_installations u
               WHERE u.app_id = jobs.app_id AND u.device_id = jobs.device_id
           )
           AND jobs.completed_at = (
                SELECT MAX(latest.completed_at) FROM jobs AS latest
                WHERE latest.app_id = jobs.app_id AND latest.device_id = jobs.device_id
                  AND latest.phase = 'succeeded'
           )
           AND (julianday('now') - julianday(jobs.completed_at)) * 24 >= ?1",
    )?;
    statement
        .query_map([attention_after_hours], |row| {
            let app_id: String = row.get(0)?;
            Ok(RefreshAttention {
                app_id: Uuid::parse_str(&app_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                device_label: row.get(1)?,
                age_hours: row.get(2)?,
                retry_failed: row.get(3)?,
            })
        })?
        .collect()
}

pub fn installation_validity(
    connection: &Connection,
) -> rusqlite::Result<Vec<InstallationValidity>> {
    let mut statement = connection.prepare(
        "SELECT jobs.app_id, jobs.device_label,
                MAX(0, CAST((168 - ((julianday('now') - julianday(jobs.completed_at)) * 24) + 23) / 24 AS INTEGER)),
                jobs.completed_at
         FROM jobs JOIN apps ON apps.id = jobs.app_id
         WHERE jobs.phase = 'succeeded' AND apps.deleted_at IS NULL
           AND NOT EXISTS (
               SELECT 1 FROM unmanaged_installations u
               WHERE u.app_id = jobs.app_id AND u.device_id = jobs.device_id
           )
           AND jobs.completed_at = (
                SELECT MAX(latest.completed_at) FROM jobs AS latest
                WHERE latest.app_id = jobs.app_id AND latest.device_id = jobs.device_id
                  AND latest.phase = 'succeeded'
           )
         ORDER BY jobs.completed_at DESC",
    )?;
    statement
        .query_map([], |row| {
            let app_id: String = row.get(0)?;
            Ok(InstallationValidity {
                app_id: Uuid::parse_str(&app_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                device_label: row.get(1)?,
                remaining_days: row.get(2)?,
                completed_at: row.get(3)?,
            })
        })?
        .collect()
}

pub fn active_job_exists(
    connection: &Connection,
    app_id: Uuid,
    device_id: Uuid,
) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM jobs
            WHERE app_id = ?1 AND device_id = ?2
              AND phase IN ('queued', 'connecting', 'signing', 'transferring', 'installing')
        )",
        (app_id.to_string(), device_id.to_string()),
        |row| row.get(0),
    )
}

pub fn insert_job(
    connection: &Connection,
    id: Uuid,
    app_id: Uuid,
    device_id: Uuid,
    device_label: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO jobs (
             id, app_id, device_id, device_label, phase, created_at,
             app_display_name, app_version
         )
         SELECT ?1, id, ?3, ?4, 'queued', datetime('now'), display_name, app_version
         FROM apps WHERE id = ?2 AND deleted_at IS NULL",
        rusqlite::params![
            id.to_string(),
            app_id.to_string(),
            device_id.to_string(),
            device_label
        ],
    )?;
    Ok(())
}

pub fn find_job(connection: &Connection, id: Uuid) -> rusqlite::Result<Option<StoredJob>> {
    let mut statement = connection.prepare(
        "SELECT id, app_id, device_id, phase, progress_percent, device_label,
                created_at, completed_at, failure_code, app_display_name, app_version
         FROM jobs WHERE id = ?1",
    )?;
    let mut rows = statement.query([id.to_string()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let id: String = row.get(0)?;
    let app_id: String = row.get(1)?;
    let device_id: String = row.get(2)?;
    Ok(Some(StoredJob {
        id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        app_id: Uuid::parse_str(&app_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        device_id: Uuid::parse_str(&device_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        phase: row.get(3)?,
        progress_percent: row.get::<_, Option<i64>>(4)?.map(|value| value as u8),
        device_label: row.get(5)?,
        created_at: row.get(6)?,
        completed_at: row.get(7)?,
        failure_code: row.get(8)?,
        app_display_name: row
            .get::<_, Option<String>>(9)?
            .unwrap_or_else(|| app_id.clone()),
        app_version: row.get(10)?,
    }))
}

pub fn list_recent_jobs(connection: &Connection, limit: usize) -> rusqlite::Result<Vec<StoredJob>> {
    let mut statement = connection.prepare(
        "SELECT id, app_id, device_id, phase, progress_percent, device_label,
                created_at, completed_at, failure_code, app_display_name, app_version
         FROM jobs ORDER BY created_at DESC LIMIT ?1",
    )?;
    statement
        .query_map([limit as i64], |row| {
            let id: String = row.get(0)?;
            let app_id: String = row.get(1)?;
            let device_id: String = row.get(2)?;
            Ok(StoredJob {
                id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                app_id: Uuid::parse_str(&app_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                device_id: Uuid::parse_str(&device_id)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                phase: row.get(3)?,
                progress_percent: row.get::<_, Option<i64>>(4)?.map(|value| value as u8),
                device_label: row.get(5)?,
                created_at: row.get(6)?,
                completed_at: row.get(7)?,
                failure_code: row.get(8)?,
                app_display_name: row
                    .get::<_, Option<String>>(9)?
                    .unwrap_or_else(|| app_id.clone()),
                app_version: row.get(10)?,
            })
        })?
        .collect()
}

pub fn update_job_status(
    connection: &Connection,
    id: Uuid,
    phase: &str,
    progress_percent: Option<u8>,
) -> rusqlite::Result<()> {
    if matches!(phase, "succeeded" | "failed") {
        connection.execute(
            "UPDATE jobs SET phase = ?1, progress_percent = ?2, completed_at = datetime('now') WHERE id = ?3",
            (phase, progress_percent.map(i64::from), id.to_string()),
        )?;
    } else {
        connection.execute(
            "UPDATE jobs SET phase = ?1, progress_percent = ?2 WHERE id = ?3",
            (phase, progress_percent.map(i64::from), id.to_string()),
        )?;
    }
    Ok(())
}

pub fn set_job_failure(
    connection: &Connection,
    id: Uuid,
    failure_code: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE jobs SET failure_code = ?1 WHERE id = ?2",
        (failure_code, id.to_string()),
    )?;
    Ok(())
}

pub fn set_job_installed_bundle_id(
    connection: &Connection,
    id: Uuid,
    bundle_id: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE jobs SET installed_bundle_id = ?1 WHERE id = ?2",
        (bundle_id, id.to_string()),
    )?;
    Ok(())
}

pub enum AppDeletion {
    Ready { storage_path: String },
    ActiveJob,
    NotFound,
}

pub fn mark_app_deleted(connection: &Connection, id: Uuid) -> rusqlite::Result<AppDeletion> {
    let Some(path) = app_path(connection, id)? else {
        return Ok(AppDeletion::NotFound);
    };
    if connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM jobs WHERE app_id = ?1 AND phase IN ('queued', 'connecting', 'signing', 'transferring', 'installing'))",
        [id.to_string()],
        |row| row.get::<_, bool>(0),
    )? {
        return Ok(AppDeletion::ActiveJob);
    }
    connection.execute(
        "UPDATE apps SET deleted_at = datetime('now') WHERE id = ?1 AND deleted_at IS NULL",
        [id.to_string()],
    )?;
    connection.execute(
        "UPDATE github_sources
         SET auto_download = 0, auto_acknowledged_at = NULL, updated_at = datetime('now')
         WHERE app_id = ?1",
        [id.to_string()],
    )?;
    Ok(AppDeletion::Ready { storage_path: path })
}

pub fn restore_app(connection: &Connection, id: Uuid) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE apps SET deleted_at = NULL WHERE id = ?1",
        [id.to_string()],
    )?;
    Ok(())
}

pub fn rename_app(connection: &Connection, id: Uuid, display_name: &str) -> rusqlite::Result<bool> {
    Ok(connection.execute(
        "UPDATE apps SET display_name = ?1 WHERE id = ?2 AND deleted_at IS NULL",
        (display_name, id.to_string()),
    )? == 1)
}

pub fn find_app(connection: &Connection, id: Uuid) -> rusqlite::Result<Option<StoredApp>> {
    let mut statement = connection.prepare(
        "SELECT id, sha256, size_bytes, display_name, app_version, bundle_id, storage_path
         FROM apps WHERE id = ?1",
    )?;
    let mut rows = statement.query([id.to_string()])?;
    let Some(row) = rows.next()? else {
        return Ok(None);
    };
    let id_text: String = row.get(0)?;
    Ok(Some(StoredApp {
        id: Uuid::parse_str(&id_text).map_err(|_| rusqlite::Error::InvalidQuery)?,
        sha256: row.get(1)?,
        size_bytes: row.get::<_, i64>(2)? as u64,
        display_name: row
            .get::<_, Option<String>>(3)?
            .unwrap_or_else(|| id_text.clone()),
        app_version: row.get(4)?,
        bundle_id: row.get(5)?,
        storage_path: row.get(6)?,
    }))
}

pub fn forget_managed_installation(
    connection: &Connection,
    app_id: Uuid,
    device_id: Uuid,
) -> rusqlite::Result<bool> {
    if active_job_exists(connection, app_id, device_id)? {
        return Ok(false);
    }
    connection.execute(
        "INSERT INTO unmanaged_installations (app_id, device_id, removed_at)
         VALUES (?1, ?2, datetime('now'))
         ON CONFLICT(app_id, device_id) DO UPDATE SET removed_at = excluded.removed_at",
        (app_id.to_string(), device_id.to_string()),
    )?;
    Ok(true)
}

pub fn restore_managed_installation(
    connection: &Connection,
    app_id: Uuid,
    device_id: Uuid,
) -> rusqlite::Result<()> {
    connection.execute(
        "DELETE FROM unmanaged_installations WHERE app_id = ?1 AND device_id = ?2",
        (app_id.to_string(), device_id.to_string()),
    )?;
    Ok(())
}

pub fn list_managed_installations(
    connection: &Connection,
) -> rusqlite::Result<Vec<ManagedInstallation>> {
    let mut statement = connection.prepare(
        "SELECT jobs.app_id, jobs.device_id, COALESCE(apps.display_name, apps.bundle_id, apps.id),
                apps.app_version, jobs.device_label
         FROM jobs JOIN apps ON apps.id = jobs.app_id
         WHERE jobs.phase = 'succeeded' AND apps.deleted_at IS NULL
           AND jobs.completed_at = (
               SELECT MAX(latest.completed_at) FROM jobs AS latest
               WHERE latest.app_id = jobs.app_id AND latest.device_id = jobs.device_id
                 AND latest.phase = 'succeeded'
           )
           AND NOT EXISTS (
               SELECT 1 FROM unmanaged_installations u
               WHERE u.app_id = jobs.app_id AND u.device_id = jobs.device_id
           )
         ORDER BY jobs.device_label, apps.display_name",
    )?;
    statement
        .query_map([], |row| {
            let app_id: String = row.get(0)?;
            let device_id: String = row.get(1)?;
            Ok(ManagedInstallation {
                app_id: Uuid::parse_str(&app_id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                device_id: Uuid::parse_str(&device_id)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                app_display_name: row.get(2)?,
                app_version: row.get(3)?,
                device_label: row.get(4)?,
            })
        })?
        .collect()
}

pub fn active_job_exists_for_app(connection: &Connection, app_id: Uuid) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM jobs
            WHERE app_id = ?1
              AND phase IN ('queued', 'connecting', 'signing', 'transferring', 'installing')
        )",
        [app_id.to_string()],
        |row| row.get(0),
    )
}

const SOURCE_SELECT: &str = "SELECT id, app_id, owner, repo, asset_pattern, include_prereleases,
    auto_download, auto_acknowledged_at, last_checked_at, last_release_id, last_release_tag,
    last_asset_id, last_asset_name, last_download_sha256, last_status, last_error_code,
    created_at, updated_at FROM github_sources";

fn source_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GitHubSource> {
    let id: String = row.get(0)?;
    let app_id: Option<String> = row.get(1)?;
    Ok(GitHubSource {
        id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
        app_id: app_id
            .map(|value| Uuid::parse_str(&value).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()?,
        owner: row.get(2)?,
        repo: row.get(3)?,
        asset_pattern: row.get(4)?,
        include_prereleases: row.get::<_, i64>(5)? != 0,
        auto_download: row.get::<_, i64>(6)? != 0,
        auto_acknowledged_at: row.get(7)?,
        last_checked_at: row.get(8)?,
        last_release_id: row.get(9)?,
        last_release_tag: row.get(10)?,
        last_asset_id: row.get(11)?,
        last_asset_name: row.get(12)?,
        last_download_sha256: row.get(13)?,
        last_status: row.get(14)?,
        last_error_code: row.get(15)?,
        created_at: row.get(16)?,
        updated_at: row.get(17)?,
    })
}

pub fn insert_github_source(
    connection: &Connection,
    id: Uuid,
    app_id: Option<Uuid>,
    owner: &str,
    repo: &str,
    asset_pattern: &str,
    include_prereleases: bool,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO github_sources
         (id, app_id, owner, repo, asset_pattern, include_prereleases, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, datetime('now'), datetime('now'))",
        rusqlite::params![
            id.to_string(),
            app_id.map(|value| value.to_string()),
            owner,
            repo,
            asset_pattern,
            i64::from(include_prereleases)
        ],
    )?;
    Ok(())
}

pub fn update_github_source(
    connection: &Connection,
    id: Uuid,
    app_id: Option<Uuid>,
    owner: &str,
    repo: &str,
    asset_pattern: &str,
    include_prereleases: bool,
) -> rusqlite::Result<bool> {
    Ok(connection.execute(
        "UPDATE github_sources SET app_id = ?1, owner = ?2, repo = ?3, asset_pattern = ?4,
             include_prereleases = ?5, auto_download = 0, auto_acknowledged_at = NULL,
             updated_at = datetime('now') WHERE id = ?6",
        rusqlite::params![
            app_id.map(|value| value.to_string()),
            owner,
            repo,
            asset_pattern,
            i64::from(include_prereleases),
            id.to_string()
        ],
    )? == 1)
}

pub fn delete_github_source(connection: &Connection, id: Uuid) -> rusqlite::Result<bool> {
    Ok(connection.execute("DELETE FROM github_sources WHERE id = ?1", [id.to_string()])? == 1)
}

pub fn link_github_source_app(
    connection: &Connection,
    source_id: Uuid,
    app_id: Uuid,
) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE github_sources SET app_id = ?1, updated_at = datetime('now') WHERE id = ?2",
        (app_id.to_string(), source_id.to_string()),
    )?;
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub fn replace_app_from_source(
    connection: &mut Connection,
    app_id: Uuid,
    source_id: Uuid,
    sha256: &str,
    storage_path: &str,
    size_bytes: u64,
    bundle_id: &str,
    app_version: Option<&str>,
    release_id: i64,
    release_tag: &str,
    asset_id: i64,
    asset_name: &str,
) -> rusqlite::Result<()> {
    let transaction = connection.transaction()?;
    transaction.execute(
        "UPDATE apps SET sha256 = ?1, storage_path = ?2, size_bytes = ?3,
         bundle_id = ?4, app_version = ?5, deleted_at = NULL WHERE id = ?6",
        rusqlite::params![
            sha256,
            storage_path,
            size_bytes as i64,
            bundle_id,
            app_version,
            app_id.to_string()
        ],
    )?;
    transaction.execute(
        "UPDATE github_sources SET last_checked_at = datetime('now'), last_release_id = ?1,
         last_release_tag = ?2, last_asset_id = ?3, last_asset_name = ?4,
         last_download_sha256 = ?5, last_status = 'downloaded', last_error_code = NULL,
         updated_at = datetime('now') WHERE id = ?6",
        rusqlite::params![
            release_id,
            release_tag,
            asset_id,
            asset_name,
            sha256,
            source_id.to_string()
        ],
    )?;
    transaction.commit()
}

pub fn list_github_sources(connection: &Connection) -> rusqlite::Result<Vec<GitHubSource>> {
    let mut statement = connection.prepare(&format!("{SOURCE_SELECT} ORDER BY created_at DESC"))?;
    statement.query_map([], source_from_row)?.collect()
}

pub fn find_github_source(
    connection: &Connection,
    id: Uuid,
) -> rusqlite::Result<Option<GitHubSource>> {
    let mut statement = connection.prepare(&format!("{SOURCE_SELECT} WHERE id = ?1"))?;
    let mut rows = statement.query([id.to_string()])?;
    rows.next()?.map(source_from_row).transpose()
}

pub fn set_source_automation(
    connection: &Connection,
    id: Uuid,
    enabled: bool,
    acknowledged: bool,
) -> rusqlite::Result<bool> {
    if enabled && !acknowledged {
        return Ok(false);
    }
    Ok(connection.execute(
        "UPDATE github_sources
         SET auto_download = ?1,
             auto_acknowledged_at = CASE WHEN ?1 = 1 THEN datetime('now') ELSE NULL END,
             updated_at = datetime('now') WHERE id = ?2",
        rusqlite::params![i64::from(enabled), id.to_string()],
    )? == 1)
}

#[allow(clippy::too_many_arguments)]
pub fn record_source_check(
    connection: &Connection,
    id: Uuid,
    release_id: Option<i64>,
    release_tag: Option<&str>,
    asset_id: Option<i64>,
    asset_name: Option<&str>,
    sha256: Option<&str>,
    status: &str,
    error_code: Option<&str>,
) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE github_sources SET last_checked_at = datetime('now'), last_release_id = ?1,
         last_release_tag = ?2, last_asset_id = ?3, last_asset_name = ?4,
         last_download_sha256 = ?5, last_status = ?6, last_error_code = ?7,
         updated_at = datetime('now') WHERE id = ?8",
        rusqlite::params![
            release_id,
            release_tag,
            asset_id,
            asset_name,
            sha256,
            status,
            error_code,
            id.to_string()
        ],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_REFRESH_AFTER_DAYS, find_job, forget_managed_installation, initialize, insert_app,
        insert_job, list_managed_installations, managed_app_identities, refresh_after_days,
        refresh_due_targets, restore_managed_installation, set_refresh_after_days,
    };
    use rusqlite::Connection;
    use uuid::Uuid;

    #[test]
    fn initialize_adds_managed_app_columns_to_existing_database() {
        let path =
            std::env::temp_dir().join(format!("iphoneloadly-migration-{}.db", Uuid::now_v7()));
        let legacy = Connection::open(&path).expect("create legacy database");
        legacy
            .execute_batch(
                "CREATE TABLE apps (
                    id TEXT PRIMARY KEY, sha256 TEXT NOT NULL UNIQUE,
                    storage_path TEXT NOT NULL UNIQUE, size_bytes INTEGER NOT NULL,
                    uploaded_at TEXT NOT NULL, deleted_at TEXT
                );
                CREATE TABLE jobs (
                    id TEXT PRIMARY KEY, app_id TEXT NOT NULL, device_id TEXT NOT NULL,
                    phase TEXT NOT NULL, created_at TEXT NOT NULL, completed_at TEXT,
                    progress_percent INTEGER, device_label TEXT NOT NULL,
                    failure_code TEXT
                );",
            )
            .expect("create legacy schema");
        drop(legacy);

        let migrated = initialize(&path).expect("migrate database");
        let app_columns: Vec<String> = migrated
            .prepare("PRAGMA table_info(apps)")
            .expect("read app columns")
            .query_map([], |row| row.get(1))
            .expect("query app columns")
            .collect::<rusqlite::Result<_>>()
            .expect("collect app columns");
        let job_columns: Vec<String> = migrated
            .prepare("PRAGMA table_info(jobs)")
            .expect("read job columns")
            .query_map([], |row| row.get(1))
            .expect("query job columns")
            .collect::<rusqlite::Result<_>>()
            .expect("collect job columns");
        assert!(app_columns.iter().any(|column| column == "bundle_id"));
        assert!(
            job_columns
                .iter()
                .any(|column| column == "installed_bundle_id")
        );

        let app_id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        migrated
            .execute(
                "INSERT INTO apps (id, sha256, storage_path, size_bytes, uploaded_at, bundle_id)
                 VALUES (?1, 'hash', 'app.ipa', 1, datetime('now'), 'com.example.app')",
                [app_id.to_string()],
            )
            .expect("insert migrated app");
        migrated
            .execute(
                "INSERT INTO jobs (id, app_id, device_id, phase, created_at, device_label)
                 VALUES (?1, ?2, ?3, 'succeeded', datetime('now'), 'iPhone')",
                (
                    Uuid::now_v7().to_string(),
                    app_id.to_string(),
                    device_id.to_string(),
                ),
            )
            .expect("insert legacy installation");
        let legacy_identities =
            managed_app_identities(&migrated, device_id).expect("read legacy identity");
        assert_eq!(legacy_identities.len(), 1);
        assert!(legacy_identities[0].installed_bundle_id.is_none());

        migrated
            .execute(
                "INSERT INTO jobs (
                    id, app_id, device_id, phase, created_at, device_label, installed_bundle_id
                 ) VALUES (?1, ?2, ?3, 'succeeded', datetime('now'), 'iPhone', ?4)",
                (
                    Uuid::now_v7().to_string(),
                    app_id.to_string(),
                    device_id.to_string(),
                    "com.example.app.TEAM",
                ),
            )
            .expect("insert exact installation");
        let exact_identities =
            managed_app_identities(&migrated, device_id).expect("read exact identity");
        assert_eq!(exact_identities.len(), 1);
        assert_eq!(
            exact_identities[0].installed_bundle_id.as_deref(),
            Some("com.example.app.TEAM")
        );
        drop(migrated);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[test]
    fn refresh_day_setting_persists_and_controls_due_targets() {
        let path =
            std::env::temp_dir().join(format!("iphoneloadly-settings-{}.db", Uuid::now_v7()));
        let connection = initialize(&path).expect("initialize database");
        assert_eq!(
            refresh_after_days(&connection).expect("read default refresh day"),
            DEFAULT_REFRESH_AFTER_DAYS
        );

        set_refresh_after_days(&connection, 4).expect("save refresh day");
        assert_eq!(
            refresh_after_days(&connection).expect("read saved refresh day"),
            4
        );
        assert!(set_refresh_after_days(&connection, 7).is_err());

        let app_id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        connection
            .execute(
                "INSERT INTO apps (id, sha256, storage_path, size_bytes, uploaded_at, bundle_id)
                 VALUES (?1, 'settings-hash', 'settings.ipa', 1, datetime('now'), 'com.example.settings')",
                [app_id.to_string()],
            )
            .expect("insert app");
        connection
            .execute(
                "INSERT INTO jobs (
                    id, app_id, device_id, phase, created_at, completed_at, device_label
                 ) VALUES (?1, ?2, ?3, 'succeeded', datetime('now', '-5 days'),
                           datetime('now', '-5 days'), 'iPhone')",
                (
                    Uuid::now_v7().to_string(),
                    app_id.to_string(),
                    device_id.to_string(),
                ),
            )
            .expect("insert successful installation");

        assert_eq!(
            refresh_due_targets(&connection, 4)
                .expect("read day-four targets")
                .len(),
            1
        );
        assert!(
            refresh_due_targets(&connection, 6)
                .expect("read day-six targets")
                .is_empty()
        );

        drop(connection);
        std::fs::remove_file(path).expect("remove test database");
    }
    #[test]
    fn forgotten_installation_is_hidden_and_restored_after_success() {
        let path = std::env::temp_dir().join(format!("iphoneloadly-managed-{}.db", Uuid::now_v7()));
        let connection = initialize(&path).expect("initialize database");
        let app_id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        connection.execute(
            "INSERT INTO apps (id, sha256, storage_path, size_bytes, uploaded_at, bundle_id, display_name)
             VALUES (?1, 'managed-hash', 'managed.ipa', 1, datetime('now'), 'com.example.managed', 'Managed')",
            [app_id.to_string()],
        ).expect("insert app");
        connection.execute(
            "INSERT INTO jobs (id, app_id, device_id, phase, created_at, completed_at, device_label, app_display_name)
             VALUES (?1, ?2, ?3, 'succeeded', datetime('now'), datetime('now'), 'Test iPhone', 'Managed')",
            (Uuid::now_v7().to_string(), app_id.to_string(), device_id.to_string()),
        ).expect("insert job");
        assert_eq!(
            list_managed_installations(&connection)
                .expect("list managed")
                .len(),
            1
        );
        assert!(forget_managed_installation(&connection, app_id, device_id).expect("forget"));
        assert!(
            managed_app_identities(&connection, device_id)
                .expect("identities")
                .is_empty()
        );
        assert!(
            list_managed_installations(&connection)
                .expect("list forgotten")
                .is_empty()
        );
        restore_managed_installation(&connection, app_id, device_id).expect("restore");
        assert_eq!(
            list_managed_installations(&connection)
                .expect("list restored")
                .len(),
            1
        );
        drop(connection);
        std::fs::remove_file(path).expect("remove test database");
    }

    #[test]
    fn insert_job_snapshots_historical_app_version() {
        let path =
            std::env::temp_dir().join(format!("iphoneloadly-job-version-{}.db", Uuid::now_v7()));
        let connection = initialize(&path).expect("initialize database");
        let app_id = Uuid::now_v7();
        let device_id = Uuid::now_v7();
        insert_app(
            &connection,
            app_id,
            "version-hash",
            "version.ipa",
            1,
            "com.example.version",
            "Versioned App",
            Some("0.4.3"),
        )
        .expect("insert versioned app");
        let job_id = Uuid::now_v7();
        insert_job(&connection, job_id, app_id, device_id, "Test iPhone").expect("insert job");

        connection
            .execute(
                "UPDATE apps SET app_version = '0.4.4' WHERE id = ?1",
                [app_id.to_string()],
            )
            .expect("update app version");
        let job = find_job(&connection, job_id)
            .expect("find job")
            .expect("job exists");
        assert_eq!(job.app_version.as_deref(), Some("0.4.3"));

        let unversioned_app_id = Uuid::now_v7();
        insert_app(
            &connection,
            unversioned_app_id,
            "unversioned-hash",
            "unversioned.ipa",
            1,
            "com.example.unversioned",
            "Unversioned App",
            None,
        )
        .expect("insert unversioned app");
        let unversioned_job_id = Uuid::now_v7();
        insert_job(
            &connection,
            unversioned_job_id,
            unversioned_app_id,
            device_id,
            "Test iPhone",
        )
        .expect("insert unversioned job");
        let unversioned_job = find_job(&connection, unversioned_job_id)
            .expect("find unversioned job")
            .expect("unversioned job exists");
        assert!(unversioned_job.app_version.is_none());

        drop(connection);
        std::fs::remove_file(path).expect("remove test database");
    }
}
