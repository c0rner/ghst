use crate::cache::{CacheEntry, authority_fingerprint};
use crate::config::{BaseProfile, Config, GitHubAppConfig, ProfileConfig};

pub(super) enum ConfiguredAuthority<'a> {
    Match(&'a BaseProfile),
    Mismatch,
    Missing,
}

pub(super) fn matches(app: &GitHubAppConfig, cached_fingerprint: &str) -> bool {
    authority_fingerprint(&app.client_id, &app.account) == cached_fingerprint
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
        Some(ProfileConfig::Base(base)) if matches(&base.github_app, cached_fingerprint) => {
            ConfiguredAuthority::Match(base)
        }
        Some(ProfileConfig::Base(_)) => ConfiguredAuthority::Mismatch,
        Some(ProfileConfig::Scoped(_)) | None => ConfiguredAuthority::Missing,
    }
}
