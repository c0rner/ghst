use crate::config::error::ConfigError;
use crate::config::types::{Config, ProfileConfig};

/// Validates configuration invariants.
///
/// # Errors
///
/// Returns `ConfigError` if:
/// - Version is not equal to 1.
/// - `default_profile` is specified but does not exist in `profiles`.
/// - Root profile has empty credentials or account.
/// - Derived profile source does not exist or points to another derived profile (chaining).
pub fn validate_config(config: &Config) -> Result<(), ConfigError> {
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
            ProfileConfig::Root(root) => {
                if root.github_app.account.trim().is_empty()
                    || root.github_app.client_id.trim().is_empty()
                {
                    return Err(ConfigError::InvalidRootProfile {
                        profile: name.clone(),
                        reason: "github_app client ID and account cannot be empty".into(),
                    });
                }
                if root
                    .github_app
                    .client_secret
                    .as_ref()
                    .is_some_and(|secret| secret.trim().is_empty())
                {
                    return Err(ConfigError::InvalidRootProfile {
                        profile: name.clone(),
                        reason: "github_app client secret cannot be empty when configured".into(),
                    });
                }
            }
            ProfileConfig::Derived(derived) => {
                if derived.permissions.is_empty() {
                    return Err(ConfigError::InvalidDerivedProfile {
                        profile: name.clone(),
                        reason: "derived profile permissions map must not be empty".into(),
                    });
                }

                let source_profile = config.profiles.get(&derived.source).ok_or_else(|| {
                    ConfigError::ProfileNotFound {
                        profile: name.clone(),
                        source: derived.source.clone(),
                    }
                })?;

                match source_profile {
                    ProfileConfig::Root(root) if root.github_app.client_secret.is_some() => {}
                    ProfileConfig::Root(_) => {
                        return Err(ConfigError::DerivedFromSecretlessRoot {
                            profile: name.clone(),
                            source: derived.source.clone(),
                        });
                    }
                    ProfileConfig::Derived(_) => {
                        return Err(ConfigError::DerivedFromNonRoot {
                            profile: name.clone(),
                            source: derived.source.clone(),
                        });
                    }
                }
            }
        }
    }

    Ok(())
}
