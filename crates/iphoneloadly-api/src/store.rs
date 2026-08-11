use std::path::Path;

use rusqlite::Connection;
use uuid::Uuid;

pub struct StoredJob {
    pub id: Uuid,
    pub app_id: Uuid,
    pub device_id: Uuid,
    pub phase: String,
}

pub struct StoredApp {
    pub id: Uuid,
    pub sha256: String,
    pub size_bytes: u64,
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
            uploaded_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            app_id TEXT NOT NULL REFERENCES apps(id),
            device_id TEXT NOT NULL,
            phase TEXT NOT NULL,
            created_at TEXT NOT NULL,
            completed_at TEXT
        );
        ",
    )?;
    let has_completed_at = {
        let mut columns = connection.prepare("PRAGMA table_info(jobs)")?;
        columns
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .any(|name| name == "completed_at")
    };
    if !has_completed_at {
        connection.execute_batch("ALTER TABLE jobs ADD COLUMN completed_at TEXT;")?;
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
) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO apps (id, sha256, storage_path, size_bytes, uploaded_at) VALUES (?1, ?2, ?3, ?4, datetime('now'))",
        (id.to_string(), sha256, storage_path, size_bytes as i64),
    )?;
    Ok(())
}

pub fn app_exists(connection: &Connection, id: Uuid) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM apps WHERE id = ?1)",
        [id.to_string()],
        |row| row.get(0),
    )
}

pub fn app_path(connection: &Connection, id: Uuid) -> rusqlite::Result<Option<String>> {
    let mut statement = connection.prepare("SELECT storage_path FROM apps WHERE id = ?1")?;
    let mut rows = statement.query([id.to_string()])?;
    match rows.next()? {
        Some(row) => Ok(Some(row.get(0)?)),
        None => Ok(None),
    }
}

pub fn list_apps(connection: &Connection) -> rusqlite::Result<Vec<StoredApp>> {
    let mut statement = connection.prepare(
        "SELECT id, sha256, size_bytes FROM apps ORDER BY uploaded_at DESC",
    )?;
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
         WHERE jobs.phase = 'succeeded'
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

pub fn active_job_exists(connection: &Connection, app_id: Uuid, device_id: Uuid) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM jobs
            WHERE app_id = ?1 AND device_id = ?2
              AND phase IN ('queued', 'connecting', 'installing')
        )",
        (app_id.to_string(), device_id.to_string()),
        |row| row.get(0),
    )
}

pub fn insert_job(connection: &Connection, id: Uuid, app_id: Uuid, device_id: Uuid) -> rusqlite::Result<()> {
    connection.execute(
        "INSERT INTO jobs (id, app_id, device_id, phase, created_at) VALUES (?1, ?2, ?3, 'queued', datetime('now'))",
        (id.to_string(), app_id.to_string(), device_id.to_string()),
    )?;
    Ok(())
}

pub fn find_job(connection: &Connection, id: Uuid) -> rusqlite::Result<Option<StoredJob>> {
    let mut statement = connection.prepare(
        "SELECT id, app_id, device_id, phase FROM jobs WHERE id = ?1",
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
    }))
}

pub fn update_job_phase(connection: &Connection, id: Uuid, phase: &str) -> rusqlite::Result<()> {
    if phase == "succeeded" {
        connection.execute(
            "UPDATE jobs SET phase = ?1, completed_at = datetime('now') WHERE id = ?2",
            (phase, id.to_string()),
        )?;
    } else {
        connection.execute(
            "UPDATE jobs SET phase = ?1 WHERE id = ?2",
            (phase, id.to_string()),
        )?;
    }
    Ok(())
}
