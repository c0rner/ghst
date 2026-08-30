# Security Policy

`ghst` issues short-lived, least-privilege GitHub user access tokens for developer CLI tools and AI
coding agents. Because it handles authentication and credentials, security is central to its design.

## Security Architecture & Threat Model

The complete, authoritative security architecture and threat model for `ghst` is published in the
**[ghst User Manual: Security Model](https://c0rner.github.io/ghst/security/)**
(source in [`docs/src/security/`](docs/src/security/)):

- **[Threat Model and Trust Assumptions](https://c0rner.github.io/ghst/security/threat-model.html)**:
  Security objectives, trusted operator assumptions, and out-of-scope boundaries.
- **[Authority and Permission Intersection](https://c0rner.github.io/ghst/security/authority-model.html)**:
  Effective access model, base token ceiling, scoped requests, and exclusion of installation access tokens.
- **[Device Flow and Human Authorization](https://c0rner.github.io/ghst/security/device-flow.html)**:
  Public client ID analysis, phishing risks, out-of-bound authorization attacks, and safe approval procedures.
- **[Client Secrets and Private Keys](https://c0rner.github.io/ghst/security/app-credentials.html)**:
  Why client-secret exposure has bounded consequences and why GitHub App private keys are strictly forbidden.
- **[Credential Consequences and Lifetimes](https://c0rner.github.io/ghst/security/credential-consequences.html)**:
  Credential combinations matrix, issuer-defined lifetimes, and independent token lifecycles.
- **[Local State and Process Isolation](https://c0rner.github.io/ghst/security/local-boundaries.html)**:
  Storage permissions (`0700`/`0600`), atomicity, symlink rejection, child exposure, and sandbox requirements.
- **[Credential Incident Response](https://c0rner.github.io/ghst/troubleshooting/incident-response.html)**:
  Containment escalation steps: workstation (`ghst revoke --all`), single user, single installation, and App-wide emergency revocation.

For the required GitHub App configuration checklist and settings table, see
**[Required GitHub App Setup](https://c0rner.github.io/ghst/getting-started/github-app.html)**.

---

## Reporting a Vulnerability

Please do not report suspected security vulnerabilities through public GitHub issues or discussions.

Instead, please report vulnerabilities privately using the repository's
**[GitHub Security Advisory Form](https://github.com/c0rner/ghst/security/advisories/new)**.

Maintainers will review disclosures promptly, coordinate remediation, and publish an advisory once
a fix is available.

