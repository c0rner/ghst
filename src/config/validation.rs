use crate::config::error::ConfigError;
use crate::config::types::{Config, ProfileConfig};

/// Validates configuration invariants.
///
/// # Errors
///
/// Returns `ConfigError` if:
/// - Version is not equal to 1.
/// - `default_profile` is specified but does not exist in `profiles`.
/// - Base profile has empty credentials or account.
/// - Scoped profile source does not exist or points to another scoped profile (chaining).
pub(super) fn validate_config(config: &Config) -> Result<(), ConfigError> {
    // 1. Version check (must be 1)
    if config.version != 1 {
        return Err(ConfigError::UnsupportedVersion(config.version));
    }

    // 2. Validate default profile reference
    if let Some(ref default_p) = config.default_profile
        && !config.profiles.contains_key(default_p)
    {
        return Err(ConfigError::MissingDefaultProfile(default_p.clone()));
    }

    // 3. Validate profiles
    for (name, profile) in &config.profiles {
        match profile {
            ProfileConfig::Base(base) => {
                if base.github_app.account.trim().is_empty()
                    || base.github_app.client_id.trim().is_empty()
                {
                    return Err(ConfigError::InvalidBaseProfile {
                        profile: name.clone(),
                        reason: "github_app client ID and account cannot be empty".into(),
                    });
                }
                if base
                    .github_app
                    .client_secret
                    .as_ref()
                    .is_some_and(|secret| secret.trim().is_empty())
                {
                    return Err(ConfigError::InvalidBaseProfile {
                        profile: name.clone(),
                        reason: "github_app client secret cannot be empty when configured".into(),
                    });
                }
            }
            ProfileConfig::Scoped(scoped) => {
                if scoped.permissions.is_empty() {
                    return Err(ConfigError::InvalidScopedProfile {
                        profile: name.clone(),
                        reason: "scoped profile permissions map must not be empty".into(),
                    });
                }

                let source_profile = config.profiles.get(&scoped.source).ok_or_else(|| {
                    ConfigError::ScopedSourceNotFound {
                        profile: name.clone(),
                        source: scoped.source.clone(),
                    }
                })?;

                match source_profile {
                    ProfileConfig::Base(base) if base.github_app.client_secret.is_some() => {}
                    ProfileConfig::Base(_) => {
                        return Err(ConfigError::ScopedFromSecretlessBase {
                            profile: name.clone(),
                            source: scoped.source.clone(),
                        });
                    }
                    ProfileConfig::Scoped(_) => {
                        return Err(ConfigError::ScopedFromNonBase {
                            profile: name.clone(),
                            source: scoped.source.clone(),
                        });
                    }
                }
            }
        }
    }

    Ok(())
}
