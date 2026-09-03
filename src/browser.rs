use std::io::Write;
use tracing::{info, warn};

/// Print a prominent multiline authorization banner for GitHub OAuth Device Flow.
pub fn display_auth_instructions(target_account: &str, user_code: &str, verification_uri: &str) {
    let _ = write_auth_instructions(
        &mut std::io::stderr().lock(),
        target_account,
        user_code,
        verification_uri,
    );
}

/// Write a prominent multiline authorization banner for GitHub OAuth Device Flow.
pub fn write_auth_instructions<W: Write>(
    writer: &mut W,
    target_account: &str,
    user_code: &str,
    verification_uri: &str,
) -> std::io::Result<()> {
    write!(
        writer,
        "\n\
===================================================================\n\
DEVICE AUTHORIZATION REQUIRED\n\
===================================================================\n\
Target account:   {target_account}\n\
User Code:        {user_code}\n\
Verification URL: {verification_uri}\n\n\
This application will only ever request authorization following\n\
explicit user initiation from the ghst CLI.\n\n\
Please verify that GitHub shows your expected dedicated GitHub App\n\
on the verification screen before authorizing.\n\
===================================================================\n\n"
    )
}

/// Open the device verification URL in the default browser unless `no_browser` is set.
pub fn open_auth_url(verification_uri: &str, no_browser: bool) {
    if no_browser {
        info!("`no_browser` active; skipping browser launch");
        return;
    }

    match open::that(verification_uri) {
        Ok(()) => info!("Opened browser to {verification_uri}"),
        Err(err) => {
            warn!("Failed to open browser ({err}); please open manually: {verification_uri}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_instructions_label_target_account_and_guide_verification() {
        let mut output = Vec::new();
        write_auth_instructions(
            &mut output,
            "acme-corp",
            "WDJB-MJHT",
            "https://github.com/login/device",
        )
        .expect("write succeeds");
        let output = String::from_utf8(output).expect("valid utf-8");

        assert!(output.contains("Target account:   acme-corp"));
        assert!(!output.contains("GitHub App:"));
        assert!(output.contains(
            "Please verify that GitHub shows your expected dedicated GitHub App\non the verification screen before authorizing."
        ));
        assert!(!output.contains("\"acme-corp\""));
        assert!(output.contains("User Code:        WDJB-MJHT"));
        assert!(output.contains("Verification URL: https://github.com/login/device"));
    }
}
