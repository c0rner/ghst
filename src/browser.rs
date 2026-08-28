use tracing::{info, warn};

/// Print a prominent multiline authorization banner for GitHub OAuth Device Flow.
pub fn display_auth_instructions(app_name: &str, user_code: &str, verification_uri: &str) {
    eprintln!(
        "\n\
===================================================================\n\
DEVICE AUTHORIZATION REQUIRED\n\
===================================================================\n\
GitHub App:       {app_name}\n\
User Code:        {user_code}\n\
Verification URL: {verification_uri}\n\n\
This application will only ever request authorization following\n\
explicit user initiation from the ghst CLI.\n\n\
Please verify that the GitHub App name matches \"{app_name}\"\n\
on the verification screen before authorizing.\n\
===================================================================\n"
    );
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
