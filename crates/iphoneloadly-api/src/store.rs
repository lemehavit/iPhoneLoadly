use std::path::Path;

use rusqlite::Connection;
use uuid::Uuid;

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
}

pub struct StoredApp {
    pub id: Uuid,
    pub sha256: String,
    pub size_bytes: u64,
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
            bundle_id TEXT
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
            installed_bundle_id TEXT
        );
        ",
    )?;
    let job_columns = {
        let mut columns = connection.prepare("PRAGMA table_info(jobs)")?;
        columns
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
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
    let app_columns = {
        let mut columns = connection.prepare("PRAGMA table_info(apps)")?;
        columns
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    if !app_columns.iter().any(|name| name == "deleted_at") {
        connection.execute_batch("ALTER TABLE apps ADD COLUMN deleted_at TEXT;")?;
    }
    if !app_columns.iter().any(|name| name == "bundle_id") {
        connection.execute_batch("ALTER TABLE apps ADD COLUMN bundle_id TEXT;")?;
    }
    connection.execute_batch(
        "UPDATE jobs SET completed_at = created_at
         WHERE phase = 'succeeded' AND completed_at IS NULL;",
    )?;
    Ok(connection)
}

pub fn insert_app(
    connection: &Connection,
    id: Uuid,
    sha256: &str,
    storage_path: &str,
    size_bytes: u64,
    bundle_id: &str,
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO apps (id, sha256, storage_path, size_bytes, uploaded_at, bundle_id) VALUES (?1, ?2, ?3, ?4, datetime('now'), ?5)",
        (id.to_string(), sha256, storage_path, size_bytes as i64, bundle_id),
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

pub fn app_path(connection: &Connection, id: Uuid) -> rusqlite::Result<Option<String>> {
    let mut statement =
        connection.prepare("SELECT storage_path FROM apps WHERE id = ?1 AND deleted_at IS NULL")?;
    let mut rows = statement.query([id.to_string()])?;
    match rows.next()? {
        Some(row) => Ok(Some(row.get(0)?)),
        None => Ok(None),
    }
}

pub fn list_apps(connection: &Connection) -> rusqlite::Result<Vec<StoredApp>> {
    let mut statement =
        connection.prepare("SELECT id, sha256, size_bytes FROM apps WHERE deleted_at IS NULL ORDER BY uploaded_at DESC")?;
    statement
        .query_map([], |row| {
            let id: String = row.get(0)?;
            Ok(StoredApp {
                id: Uuid::parse_str(&id).map_err(|_| rusqlite::Error::InvalidQuery)?,
                sha256: row.get(1)?,
                size_bytes: row.get::<_, i64>(2)? as u64,
            })
        })?
        .collect()
}

pub fn refresh_due_targets(connection: &Connection) -> rusqlite::Result<Vec<(Uuid, Uuid, String)>> {
    let mut statement = connection.prepare(
        "SELECT jobs.app_id, jobs.device_id, apps.storage_path
         FROM jobs JOIN apps ON apps.id = jobs.app_id
         WHERE jobs.phase = 'succeeded' AND apps.deleted_at IS NULL
           AND jobs.completed_at = (
                SELECT MAX(latest.completed_at) FROM jobs AS latest
                WHERE latest.app_id = jobs.app_id
                  AND latest.device_id = jobs.device_id
                  AND latest.phase = 'succeeded'
           )
           AND jobs.completed_at <= datetime('now', '-6 days')",
    )?;
    statement
        .query_map([], |row| {
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

pub fn refresh_attention(connection: &Connection) -> rusqlite::Result<Vec<RefreshAttention>> {
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
           AND jobs.completed_at = (
                SELECT MAX(latest.completed_at) FROM jobs AS latest
                WHERE latest.app_id = jobs.app_id AND latest.device_id = jobs.device_id
                  AND latest.phase = 'succeeded'
           )
           AND (julianday('now') - julianday(jobs.completed_at)) * 24 >= 120",
    )?;
    statement
        .query_map([], |row| {
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
        "INSERT INTO jobs (id, app_id, device_id, device_label, phase, created_at) VALUES (?1, ?2, ?3, ?4, 'queued', datetime('now'))",
        (id.to_string(), app_id.to_string(), device_id.to_string(), device_label),
    )?;
    Ok(())
}

pub fn find_job(connection: &Connection, id: Uuid) -> rusqlite::Result<Option<StoredJob>> {
    let mut statement = connection
        .prepare("SELECT id, app_id, device_id, phase, progress_percent, device_label, created_at, completed_at, failure_code FROM jobs WHERE id = ?1")?;
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
    }))
}

pub fn list_recent_jobs(connection: &Connection, limit: usize) -> rusqlite::Result<Vec<StoredJob>> {
    let mut statement = connection.prepare(
        "SELECT id, app_id, device_id, phase, progress_percent, device_label, created_at, completed_at, failure_code
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
    Ok(AppDeletion::Ready { storage_path: path })
}

pub fn restore_app(connection: &Connection, id: Uuid) -> rusqlite::Result<()> {
    connection.execute(
        "UPDATE apps SET deleted_at = NULL WHERE id = ?1",
        [id.to_string()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{initialize, managed_app_identities};
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
}
