use crate::credential::matches_authority_fingerprint;
use crate::profile::{AppAuthority, AppRegistration, NamedAppRegistration};
use crate::token::store::Record;

#[derive(Debug, PartialEq, Eq)]
pub enum ConfiguredAuthority<'a> {
    Match(AppRegistration<'a>),
    Mismatch,
    Missing,
}

pub fn matches_authority(authority: &AppAuthority<'_>, cached_fingerprint: &str) -> bool {
    matches_authority_fingerprint(authority.client_id, authority.account, cached_fingerprint)
}

pub fn for_entry<'a>(
    registrations: &[NamedAppRegistration<'a>],
    entry: &Record,
) -> ConfiguredAuthority<'a> {
    match entry {
        Record::Base(entry) => {
            for_source(registrations, &entry.profile, &entry.authority_fingerprint)
        }
        Record::Scoped(entry) => for_source(
            registrations,
            &entry.source_profile,
            &entry.source_authority_fingerprint,
        ),
        Record::Run(entry) => for_source(
            registrations,
            &entry.source_profile,
            &entry.source_authority_fingerprint,
        ),
    }
}

pub fn for_source<'a>(
    registrations: &[NamedAppRegistration<'a>],
    source_profile: &str,
    cached_fingerprint: &str,
) -> ConfiguredAuthority<'a> {
    let Some(reg) = registrations
        .iter()
        .find(|reg| reg.profile_name == source_profile)
    else {
        return ConfiguredAuthority::Missing;
    };

    if matches_authority(&reg.app.authority, cached_fingerprint) {
        ConfiguredAuthority::Match(reg.app)
    } else {
        ConfiguredAuthority::Mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::authority_fingerprint;

    #[test]
    fn test_provenance_resolution_without_config_types() {
        let auth_matching = AppAuthority {
            account: "acme-corp",
            client_id: "Iv1.matching",
        };
        let fp_matching = authority_fingerprint(auth_matching.client_id, auth_matching.account);

        let auth_different = AppAuthority {
            account: "different-org",
            client_id: "Iv1.different",
        };

        let reg_with_secret = NamedAppRegistration {
            profile_name: "dev-secret",
            app: AppRegistration {
                authority: auth_matching,
                client_secret: Some("secret123"),
            },
        };

        let reg_secretless = NamedAppRegistration {
            profile_name: "dev-secretless",
            app: AppRegistration {
                authority: auth_matching,
                client_secret: None,
            },
        };

        let reg_diff_authority = NamedAppRegistration {
            profile_name: "dev-diff-auth",
            app: AppRegistration {
                authority: auth_different,
                client_secret: Some("secret456"),
            },
        };

        let registrations = [reg_with_secret, reg_secretless, reg_diff_authority];

        // 1. Missing: source profile not in registrations
        assert_eq!(
            for_source(&registrations, "missing-profile", &fp_matching),
            ConfiguredAuthority::Missing
        );

        // 2. Same-name, different authority:
        assert_eq!(
            for_source(&registrations, "dev-diff-auth", &fp_matching),
            ConfiguredAuthority::Mismatch
        );

        // 3. Matching-secretless: matches and preserves None client_secret
        assert_eq!(
            for_source(&registrations, "dev-secretless", &fp_matching),
            ConfiguredAuthority::Match(reg_secretless.app)
        );

        // 4. Matching-secret: matches and preserves Some("secret123")
        assert_eq!(
            for_source(&registrations, "dev-secret", &fp_matching),
            ConfiguredAuthority::Match(reg_with_secret.app)
        );
    }
}
