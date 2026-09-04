use crate::cache::{CacheEntry, authority_fingerprint};
use crate::config::{AppProfile, Config, GitHubAppConfig, ProfileConfig};
use crate::domain::profile::AppAuthority;

pub(super) enum ConfiguredAuthority<'a> {
    Match(&'a AppProfile),
    Mismatch,
    Missing,
}

pub(super) fn matches(app: &GitHubAppConfig, cached_fingerprint: &str) -> bool {
    authority_fingerprint(&app.client_id, &app.account) == cached_fingerprint
}

pub(super) fn matches_authority(authority: &AppAuthority<'_>, cached_fingerprint: &str) -> bool {
    authority_fingerprint(authority.client_id, authority.account) == cached_fingerprint
}

pub(super) fn for_entry<'a>(config: &'a Config, entry: &CacheEntry) -> ConfiguredAuthority<'a> {
    match entry {
        CacheEntry::Base(entry) => for_source(config, &entry.profile, &entry.authority_fingerprint),
        CacheEntry::Scoped(entry) => for_source(
            config,
            &entry.source_profile,
            &entry.source_authority_fingerprint,
        ),
        CacheEntry::Run(entry) => for_source(
            config,
            &entry.source_profile,
            &entry.source_authority_fingerprint,
        ),
    }
}

pub(super) fn for_source<'a>(
    config: &'a Config,
    source_profile: &str,
    cached_fingerprint: &str,
) -> ConfiguredAuthority<'a> {
    match config.profiles.get(source_profile) {
        Some(ProfileConfig::App(app)) if matches(&app.github_app, cached_fingerprint) => {
            ConfiguredAuthority::Match(app)
        }
        Some(ProfileConfig::App(_)) => ConfiguredAuthority::Mismatch,
        Some(ProfileConfig::Scoped(_)) | None => ConfiguredAuthority::Missing,
    }
}
