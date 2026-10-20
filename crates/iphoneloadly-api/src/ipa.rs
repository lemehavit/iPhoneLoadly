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
    pub platform: AppPlatform,
}

/// The device family an IPA is built for, read from its Info.plist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppPlatform {
    Ios,
    Tvos,
    /// Info.plist names no platform; installs are allowed on any device.
    Unknown,
}

impl AppPlatform {
    /// Whether an app for this platform can be installed on the given device.
    pub fn installable_on_apple_tv(self, apple_tv: bool) -> bool {
        match self {
            Self::Unknown => true,
            Self::Tvos => apple_tv,
            Self::Ios => !apple_tv,
        }
    }

    fn from_info_plist(dictionary: &plist::Dictionary) -> Self {
        let names = dictionary
            .get("DTPlatformName")
            .and_then(plist_string)
            .into_iter()
            .chain(
                dictionary
                    .get("CFBundleSupportedPlatforms")
                    .and_then(plist::Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(plist_string),
            )
            .map(str::to_ascii_lowercase)
            .collect::<Vec<_>>();
        if names.iter().any(|name| name.starts_with("appletv")) {
            return Self::Tvos;
        }
        if names
            .iter()
            .any(|name| name.starts_with("iphone") || name.starts_with("ipad"))
        {
            return Self::Ios;
        }
        // UIDeviceFamily 3 is Apple TV; 1 and 2 are iPhone and iPad.
        let families = dictionary
            .get("UIDeviceFamily")
            .and_then(plist::Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(plist::Value::as_unsigned_integer)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if families.contains(&3) {
            Self::Tvos
        } else if families.iter().any(|family| matches!(family, 1 | 2)) {
            Self::Ios
        } else {
            Self::Unknown
        }
    }
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
    let mut platform = AppPlatform::Unknown;
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
            platform = AppPlatform::from_info_plist(dictionary);
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
        platform,
    })
}

fn plist_string(value: &plist::Value) -> Option<&str> {
    value.as_string()
}

pub fn bundle_identifier(path: &Path) -> Result<String, UploadError> {
    Ok(inspect_ipa(path)?.bundle_id)
}

pub fn app_platform(path: &Path) -> Result<AppPlatform, UploadError> {
    Ok(inspect_ipa(path)?.platform)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn platform(entries: &[(&str, plist::Value)]) -> AppPlatform {
        let mut dictionary = plist::Dictionary::new();
        for (key, value) in entries {
            dictionary.insert((*key).into(), value.clone());
        }
        AppPlatform::from_info_plist(&dictionary)
    }

    #[test]
    fn detects_tvos_and_ios_bundles() {
        assert_eq!(
            platform(&[("DTPlatformName", "appletvos".into())]),
            AppPlatform::Tvos
        );
        assert_eq!(
            platform(&[(
                "CFBundleSupportedPlatforms",
                plist::Value::Array(vec!["AppleTVOS".into()])
            )]),
            AppPlatform::Tvos
        );
        assert_eq!(
            platform(&[("DTPlatformName", "iphoneos".into())]),
            AppPlatform::Ios
        );
        assert_eq!(
            platform(&[("UIDeviceFamily", plist::Value::Array(vec![3_u64.into()]))]),
            AppPlatform::Tvos
        );
        assert_eq!(
            platform(&[(
                "UIDeviceFamily",
                plist::Value::Array(vec![1_u64.into(), 2_u64.into()])
            )]),
            AppPlatform::Ios
        );
        assert_eq!(platform(&[]), AppPlatform::Unknown);
    }

    #[test]
    fn platform_gates_device_class() {
        assert!(AppPlatform::Tvos.installable_on_apple_tv(true));
        assert!(!AppPlatform::Tvos.installable_on_apple_tv(false));
        assert!(AppPlatform::Ios.installable_on_apple_tv(false));
        assert!(!AppPlatform::Ios.installable_on_apple_tv(true));
        assert!(AppPlatform::Unknown.installable_on_apple_tv(true));
        assert!(AppPlatform::Unknown.installable_on_apple_tv(false));
    }
}
