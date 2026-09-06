use crate::config::{AppProfile, Config, GitHubAppConfig, ProfileConfig};
use crate::credential::stored::{StoredCredential, authority_fingerprint};

use crate::profile::AppAuthority;

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

pub(super) fn for_entry<'a>(
    config: &'a Config,
    entry: &StoredCredential,
) -> ConfiguredAuthority<'a> {
    match entry {
        StoredCredential::Base(entry) => {
            for_source(config, &entry.profile, &entry.authority_fingerprint)
        }
        StoredCredential::Scoped(entry) => for_source(
            config,
            &entry.source_profile,
            &entry.source_authority_fingerprint,
        ),
        StoredCredential::Run(entry) => for_source(
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
