//! Validation for IPA uploads before they enter a signing job.

use std::{
    fs::File,
    io::{Cursor, Read},
    path::{Component, Path},
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use zip::ZipArchive;

pub const MAX_COMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const MAX_EXPANDED_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 20_000;
pub const MAX_COMPRESSION_RATIO: u64 = 200;
const MAX_INFO_PLIST_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadMetadata {
    pub sha256: String,
    pub size_bytes: u64,
    pub app_bundle_path: String,
    pub bundle_id: String,
    pub display_name: String,
    pub app_version: Option<String>,
    pub info_plist_present: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UploadError {
    #[error("upload exceeds the configured size limit")]
    TooLarge,
    #[error("upload is not a readable IPA archive")]
    InvalidArchive,
    #[error("archive contains an unsafe path")]
    UnsafePath,
    #[error("archive contains too many entries")]
    TooManyEntries,
    #[error("archive expansion exceeds the configured limit")]
    ExpansionLimit,
    #[error("archive does not contain exactly one application bundle")]
    InvalidPayload,
    #[error("application Info.plist is missing")]
    MissingInfoPlist,
    #[error("application Info.plist does not contain a valid bundle identifier")]
    InvalidBundleIdentifier,
}

pub fn inspect_ipa(path: &Path) -> Result<UploadMetadata, UploadError> {
    let metadata = path.metadata().map_err(|_| UploadError::InvalidArchive)?;
    if metadata.len() > MAX_COMPRESSED_BYTES {
        return Err(UploadError::TooLarge);
    }

    let mut source = File::open(path).map_err(|_| UploadError::InvalidArchive)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|_| UploadError::InvalidArchive)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    let file = File::open(path).map_err(|_| UploadError::InvalidArchive)?;
    let mut archive = ZipArchive::new(file).map_err(|_| UploadError::InvalidArchive)?;
    if archive.len() > MAX_ENTRIES {
        return Err(UploadError::TooManyEntries);
    }

    let mut expanded_bytes = 0_u64;
    let mut app_bundle: Option<String> = None;
    let mut info_plist_present = false;
    let mut bundle_id = None;
    let mut display_name = None;
    let mut app_version = None;
    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .map_err(|_| UploadError::InvalidArchive)?;
        let name = entry.name().to_owned();
        validate_archive_path(&name)?;
        expanded_bytes = expanded_bytes.saturating_add(entry.size());
        if expanded_bytes > MAX_EXPANDED_BYTES {
            return Err(UploadError::ExpansionLimit);
        }
        if entry.compressed_size() > 0
            && entry.size() / entry.compressed_size() > MAX_COMPRESSION_RATIO
        {
            return Err(UploadError::ExpansionLimit);
        }

        if let Some(bundle) = main_bundle_from_entry(&name) {
            match &app_bundle {
                Some(existing) if existing != bundle => return Err(UploadError::InvalidPayload),
                None => app_bundle = Some(bundle.to_owned()),
                _ => {}
            }
        }
        if let Some(bundle) = &app_bundle
            && name == format!("{bundle}/Info.plist")
        {
            info_plist_present = true;
            if entry.size() > MAX_INFO_PLIST_BYTES {
                return Err(UploadError::ExpansionLimit);
            }
            let mut info_plist = Vec::new();
            entry
                .read_to_end(&mut info_plist)
                .map_err(|_| UploadError::InvalidArchive)?;
            let value = plist::Value::from_reader(Cursor::new(info_plist))
                .map_err(|_| UploadError::InvalidBundleIdentifier)?;
            let dictionary = value
                .as_dictionary()
                .ok_or(UploadError::InvalidBundleIdentifier)?;
            bundle_id = dictionary
                .get("CFBundleIdentifier")
                .and_then(plist_string)
                .map(str::to_owned);
            display_name = dictionary
                .get("CFBundleDisplayName")
                .and_then(plist_string)
                .or_else(|| dictionary.get("CFBundleName").and_then(plist_string))
                .map(str::to_owned);
            app_version = dictionary
                .get("CFBundleShortVersionString")
                .and_then(plist_string)
                .or_else(|| dictionary.get("CFBundleVersion").and_then(plist_string))
                .filter(|value| !value.trim().is_empty())
                .map(str::to_owned);
        }
    }
    let app_bundle_path = app_bundle.ok_or(UploadError::InvalidPayload)?;
    if !info_plist_present {
        return Err(UploadError::MissingInfoPlist);
    }
    let bundle_id = bundle_id
        .filter(|value| !value.trim().is_empty())
        .ok_or(UploadError::InvalidBundleIdentifier)?;
    let display_name = display_name
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| bundle_id.clone());
    Ok(UploadMetadata {
        sha256: format!("{:x}", hasher.finalize()),
        size_bytes: metadata.len(),
        app_bundle_path,
        bundle_id,
        display_name,
        app_version,
        info_plist_present,
    })
}

fn plist_string(value: &plist::Value) -> Option<&str> {
    value.as_string()
}

pub fn bundle_identifier(path: &Path) -> Result<String, UploadError> {
    Ok(inspect_ipa(path)?.bundle_id)
}

fn validate_archive_path(name: &str) -> Result<(), UploadError> {
    let path = Path::new(name);
    if path.is_absolute()
        || name.contains('\\')
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(UploadError::UnsafePath);
    }
    Ok(())
}

fn main_bundle_from_entry(name: &str) -> Option<&str> {
    let mut components = name.split('/');
    if components.next()? != "Payload" {
        return None;
    }
    let bundle = components.next()?;
    bundle
        .ends_with(".app")
        .then(|| &name[.."Payload/".len() + bundle.len()])
}
