# Threat model and trust assumptions

## Security objective

`ghst` protects a trusted operator's GitHub authority from a less-trusted process running on the
operator's machine. Typical less-trusted processes include AI coding agents, repository scripts,
build tools, plugins, and commands that may act on untrusted input.

The objective is to ensure that the GitHub credential deliberately delegated to such a process:

- cannot exceed the dedicated App/user authority ceiling;
- is narrowed to the selected repositories and permissions when a scoped profile is used;
- has a GitHub-issued expiration that the recipient cannot extend with a refresh token from
  `ghst`;
- is exposed only through an explicit output or one foreground child environment; and
- remains recoverable for revocation when a one-off run is interrupted.

The tool reduces impact; it does not make token theft harmless. A stolen token remains usable
within its permissions and remaining lifetime until GitHub revokes or expires it.

## Trusted parties and assumptions

The security model assumes all of the following:

1. **The human operator is trusted.** The operator may already use their GitHub authority directly.
   They do not deliberately bypass `ghst`, copy broader credentials into the child, or approve
   someone else's Device Flow.
2. **GitHub App administrators are trusted.** They keep the required settings, install the App only
   where intended, grant the minimum permissions, and never generate a private key.
3. **The operator's GitHub account is protected.** An attacker who controls that account can grant
   or use its authority outside `ghst`.
4. **Device Flow approval is deliberate and in-bound.** The operator approves only a code printed
   by a `ghst login` invocation they personally started and that is still waiting locally.
5. **Less-trusted processes cannot read protected host state.** A sandbox or equivalent boundary
   denies them `ghst` configuration/cache files and other ambient GitHub credentials.
6. **GitHub enforces its documented token model.** A user access token depends on both the App's
   permissions and the user's permissions, and a scoped token cannot widen the supplied user
   token.

The operator remains accountable for authorizations made through their account. If they approve an
attacker-initiated device code, GitHub correctly treats that action as consent; `ghst` cannot infer
that the approval was socially engineered.

## Out of scope

`ghst` is not an insider-resistant control over the workstation owner. A trusted operator can use
another OAuth client, retain a refresh token outside `ghst`, alter local profiles, read cached
tokens, or invoke GitHub directly. Local file permissions cannot stop the same user from reading
their own files.

It is also not a malware containment system. A process with unrestricted host access may steal SSH
keys, credential-helper material, GitHub CLI authentication, browser state, or the `ghst` files
themselves. It may exfiltrate the token intentionally supplied to it.

Local `ghst` is therefore appropriate when an organization trusts developers with repository
access but wants them to delegate less authority to local tools. An organization that needs to
constrain the developer as an adversary needs a centrally administered boundary the developer
cannot change, in addition to or instead of `ghst`.
