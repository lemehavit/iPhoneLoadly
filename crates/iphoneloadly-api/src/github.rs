use std::path::Path;

use futures_util::StreamExt;
use reqwest::{Client, StatusCode};
use semver::Version;
use serde::Deserialize;
use thiserror::Error;

use crate::ipa;

const GITHUB_API: &str = "https://api.github.com";
const OFFICIAL_OWNER: &str = "lemehavit";
const OFFICIAL_REPO: &str = "iPhoneLoadly";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryRef {
    pub owner: String,
    pub repo: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Release {
    pub id: i64,
    pub tag_name: String,
    pub name: String,
    pub draft: bool,
    pub prerelease: bool,
    pub published_at: Option<String>,
    pub assets: Vec<ReleaseAsset>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReleaseAsset {
    pub id: i64,
    pub name: String,
    pub size: u64,
    #[serde(default)]
    pub digest: Option<String>,
    pub browser_download_url: String,
}

#[derive(Debug, Error)]
pub enum GitHubError {
    #[error("repository must be a public canonical GitHub repository")]
    InvalidRepository,
    #[error("asset pattern must not be empty and may contain only '*' wildcards")]
    InvalidPattern,
    #[error("GitHub request failed with status {0}")]
    Http(StatusCode),
    #[error("GitHub response was invalid")]
    InvalidResponse,
    #[error("GitHub download exceeded the IPA size limit")]
    TooLarge,
    #[error("GitHub download URL is not an allowed release asset URL")]
    InvalidDownloadUrl,
    #[error("release has no eligible IPA asset matching the pattern")]
    NoMatchingAsset,
    #[error("release has more than one eligible IPA asset matching the pattern")]
    AmbiguousAsset,
    #[error("release tag is not a valid version")]
    InvalidVersion,
}

pub struct GitHubClient {
    client: Client,
}

impl GitHubClient {
    pub fn new(version: &str) -> Result<Self, GitHubError> {
        let user_agent = format!("iPhoneLoadly/{version}");
        let client = Client::builder()
            .user_agent(&user_agent)
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                let url = attempt.url();
                if url.scheme() == "https"
                    && matches!(
                        url.host_str(),
                        Some("github.com")
                            | Some("api.github.com")
                            | Some("objects.githubusercontent.com")
                            | Some("release-assets.githubusercontent.com")
                    )
                {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .build()
            .map_err(|_| GitHubError::InvalidResponse)?;
        Ok(Self { client })
    }

    pub async fn releases(&self, repository: &RepositoryRef) -> Result<Vec<Release>, GitHubError> {
        let url = format!(
            "{GITHUB_API}/repos/{}/{}/releases?per_page=100",
            repository.owner, repository.repo
        );
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| GitHubError::InvalidResponse)?;
        if !response.status().is_success() {
            return Err(GitHubError::Http(response.status()));
        }
        response
            .json()
            .await
            .map_err(|_| GitHubError::InvalidResponse)
    }

    pub async fn latest_release(
        &self,
        repository: &RepositoryRef,
        include_prereleases: bool,
    ) -> Result<Release, GitHubError> {
        latest_eligible_release(&self.releases(repository).await?, include_prereleases)
            .ok_or(GitHubError::NoMatchingAsset)
    }

    pub async fn download_asset(
        &self,
        repository: &RepositoryRef,
        release: &Release,
        asset: &ReleaseAsset,
        destination: &Path,
    ) -> Result<(), GitHubError> {
        let url = reqwest::Url::parse(&asset.browser_download_url)
            .map_err(|_| GitHubError::InvalidDownloadUrl)?;
        let mut expected = reqwest::Url::parse("https://github.com")
            .map_err(|_| GitHubError::InvalidDownloadUrl)?;
        expected
            .path_segments_mut()
            .map_err(|_| GitHubError::InvalidDownloadUrl)?
            .extend([
                repository.owner.as_str(),
                repository.repo.as_str(),
                "releases",
                "download",
                release.tag_name.as_str(),
                asset.name.as_str(),
            ]);
        if url != expected {
            return Err(GitHubError::InvalidDownloadUrl);
        }
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|_| GitHubError::InvalidResponse)?;
        if !response.status().is_success() {
            return Err(GitHubError::Http(response.status()));
        }
        if response
            .content_length()
            .is_some_and(|size| size > ipa::MAX_COMPRESSED_BYTES)
        {
            return Err(GitHubError::TooLarge);
        }
        let mut output = tokio::fs::File::create(destination)
            .await
            .map_err(|_| GitHubError::InvalidResponse)?;
        let mut total = 0_u64;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| GitHubError::InvalidResponse)?;
            total = total.saturating_add(chunk.len() as u64);
            if total > ipa::MAX_COMPRESSED_BYTES {
                let _ = tokio::fs::remove_file(destination).await;
                return Err(GitHubError::TooLarge);
            }
            tokio::io::AsyncWriteExt::write_all(&mut output, &chunk)
                .await
                .map_err(|_| GitHubError::InvalidResponse)?;
        }
        tokio::io::AsyncWriteExt::flush(&mut output)
            .await
            .map_err(|_| GitHubError::InvalidResponse)?;
        output
            .sync_all()
            .await
            .map_err(|_| GitHubError::InvalidResponse)?;
        Ok(())
    }
}

pub fn parse_public_repository(input: &str) -> Result<RepositoryRef, GitHubError> {
    let input = input.trim();
    if input.is_empty()
        || input.contains('\0')
        || input.starts_with("http://")
        || input.contains('?')
        || input.contains('#')
    {
        return Err(GitHubError::InvalidRepository);
    }
    let rest = input
        .strip_prefix("https://github.com/")
        .map(|value| value.strip_suffix('/').unwrap_or(value))
        .unwrap_or(input);
    let parts = rest.split('/').collect::<Vec<_>>();
    if parts.len() != 2 {
        return Err(GitHubError::InvalidRepository);
    }
    let [owner, repo] = parts.as_slice() else {
        return Err(GitHubError::InvalidRepository);
    };
    if owner.is_empty()
        || repo.is_empty()
        || owner.contains(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
        || repo.contains(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_' && c != '.')
    {
        return Err(GitHubError::InvalidRepository);
    }
    Ok(RepositoryRef {
        owner: (*owner).to_owned(),
        repo: (*repo).to_owned(),
    })
}

pub fn validate_asset_pattern(pattern: &str) -> Result<(), GitHubError> {
    if pattern.trim().is_empty()
        || pattern
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\'))
    {
        return Err(GitHubError::InvalidPattern);
    }
    Ok(())
}
pub fn match_ipa_asset<'a>(
    release: &'a Release,
    pattern: &str,
) -> Result<&'a ReleaseAsset, GitHubError> {
    validate_asset_pattern(pattern)?;
    let matches = release
        .assets
        .iter()
        .filter(|asset| {
            asset.name.to_ascii_lowercase().ends_with(".ipa")
                && wildcard_match(pattern, &asset.name)
        })
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => Err(GitHubError::NoMatchingAsset),
        [asset] => Ok(asset),
        _ => Err(GitHubError::AmbiguousAsset),
    }
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let value = value.to_ascii_lowercase();
    let parts = pattern.split('*').collect::<Vec<_>>();
    if parts.len() == 1 {
        return value == pattern;
    }
    if !value.starts_with(parts[0]) || !value.ends_with(parts[parts.len() - 1]) {
        return false;
    }
    let mut offset = parts[0].len();
    for part in &parts[1..parts.len() - 1] {
        let Some(found) = value[offset..].find(part) else {
            return false;
        };
        offset += found + part.len();
    }
    true
}

pub fn latest_eligible_release(releases: &[Release], include_prereleases: bool) -> Option<Release> {
    releases
        .iter()
        .filter(|release| !release.draft && (include_prereleases || !release.prerelease))
        .max_by_key(|release| (release.published_at.as_deref().unwrap_or(""), release.id))
        .cloned()
}

pub fn official_repository() -> RepositoryRef {
    RepositoryRef {
        owner: OFFICIAL_OWNER.into(),
        repo: OFFICIAL_REPO.into(),
    }
}

pub fn official_version(tag: &str) -> Result<Version, GitHubError> {
    Version::parse(tag.strip_prefix('v').unwrap_or(tag)).map_err(|_| GitHubError::InvalidVersion)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(id: i64, tag_name: &str, prerelease: bool, names: &[&str]) -> Release {
        Release {
            id,
            tag_name: tag_name.into(),
            name: tag_name.into(),
            draft: false,
            prerelease,
            published_at: Some(format!("{id}")),
            assets: names
                .iter()
                .enumerate()
                .map(|(index, name)| ReleaseAsset {
                    id: index as i64,
                    name: (*name).into(),
                    size: 1,
                    digest: None,
                    browser_download_url: String::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn repository_parser_rejects_noncanonical_inputs() {
        assert_eq!(parse_public_repository("owner/repo").unwrap().repo, "repo");
        assert!(parse_public_repository("http://github.com/owner/repo").is_err());
        assert!(parse_public_repository("https://evil.example/owner/repo").is_err());
        assert!(parse_public_repository("https://github.com/owner/repo/issues").is_err());
        assert!(parse_public_repository("https://github.com/owner/repo?x=1").is_err());
    }

    #[test]
    fn asset_matching_is_case_insensitive_and_deterministic() {
        let first = release(1, "v1", false, &["other.zip", "MyApp.IPA"]);
        assert_eq!(
            match_ipa_asset(&first, "myapp.ipa").unwrap().name,
            "MyApp.IPA"
        );
        assert!(match_ipa_asset(&first, "*.ipa").is_ok());
        let ambiguous = release(2, "v2", false, &["a.ipa", "b.ipa"]);
        assert!(matches!(
            match_ipa_asset(&ambiguous, "*.ipa"),
            Err(GitHubError::AmbiguousAsset)
        ));
    }

    #[test]
    fn release_selection_excludes_drafts_and_prereleases_by_default() {
        let releases = vec![
            release(1, "v1", false, &[]),
            release(2, "v2", true, &[]),
            Release {
                draft: true,
                ..release(3, "v3", false, &[])
            },
        ];
        assert_eq!(latest_eligible_release(&releases, false).unwrap().id, 1);
        assert_eq!(latest_eligible_release(&releases, true).unwrap().id, 2);
    }
}
