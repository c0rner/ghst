# Device Flow and human authorization

GitHub OAuth Device Flow allows command-line clients to authenticate without a local web server or redirect URI. It operates using the **public GitHub App client ID**: starting a flow does not prove possession of a client secret.

Because anyone who knows the client ID can initiate a device authorization flow, **human verification in a trusted browser is the primary security boundary**.

---

## The Out-of-Bound Authorization Attack

An attacker who knows your public App client ID can initiate a Device Flow and attempt to socially engineer you into approving it:

```
┌─────────────────────────┐
│ Attacker Machine        │ 1. Initiates Device Flow with public Client ID
│ (Polls GitHub endpoint) │
└───────────┬─────────────┘
            │ 2. Sends User Code via phishing/chat ("Please verify this code")
            ▼
┌─────────────────────────┐
│ Victim (Human Operator) │ 3. Visits https://github.com/login/device & approves code
└───────────┬─────────────┘
            │ 4. GitHub grants user access token + refresh token
            ▼
┌─────────────────────────┐
│ Attacker Receives Token │ Exfiltrates credential outside ghst's destruction guarantee!
└─────────────────────────┘
```

> [!CAUTION]
> **App Name Matching Is Not Protection Against Phishing**  
> Because the attacker uses your legitimate App's client ID, GitHub's browser prompt will display the correct App name.
>
> If you approve a code you did not personally generate, **the attacker receives the resulting tokens**. Furthermore, the attacker's client receives the refresh token (which GitHub allows rotating without a client secret), giving them long-term access outside `ghst`'s control.

---

## Safe Human Approval Checklist

Authorize a device code only when **all 5 conditions** are met:

- [ ] **1. Personal Initiation:** You personally executed `ghst login` in a trusted local terminal.
- [ ] **2. Active Waiting Terminal:** That exact terminal session is still running and waiting for authorization.
- [ ] **3. Manual Code Entry:** You manually typed or pasted the code printed by your terminal into `https://github.com/login/device`.
- [ ] **4. App Identity Match:** The browser verification screen displays the expected dedicated GitHub App name.
- [ ] **5. Target Account Match:** The target organization/account listed matches your intended authority ceiling.

> [!IMPORTANT]
> Never approve a user code received via email, chat, pull request comment, issue description, AI agent prompt, or another person's terminal. If in doubt, deny the browser prompt and initiate a fresh `ghst login`.

---

## Why `ghst` Requires Manual Code Entry

`ghst` deliberately opens only `https://github.com/login/device` without pre-filling the code (i.e. it never constructs `?user_code=...` links).

Requiring the operator to manually read the code from their local terminal and paste it into their browser forces an intentional cognitive link between the waiting terminal and the browser authorization.

---

## Credential Zeroing & Retention

`ghst` enforces strict memory hygiene during Device Flow:
- **Temporary State:** Device codes and user codes exist only in memory during the active login exchange and are never persisted to disk.
- **Immediate Refresh Token Destruction:** When GitHub returns an access token and refresh token, `ghst` validates and stores the base token, then **immediately zeroes and drops the refresh token in memory**.
- **No Refresh Retention:** `ghst` intentionally never persists refresh tokens, guaranteeing that child tools cannot abuse them to silently extend access.

