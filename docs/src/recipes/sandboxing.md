# Process sandboxing & MicroVMs

`ghst` constrains token scope and credential lifetimes, but **it is not a process sandbox**.

When running semi-autonomous AI coding agents or executing untrusted repository scripts, pairing `ghst` with host isolation (kernel sandboxes, container isolation, or MicroVMs) provides complete defense-in-depth:
- **`ghst`** ensures the tool receives only short-lived, least-privilege GitHub credentials.
- **The sandbox** prevents the tool from accessing host files, SSH keys, ambient tokens, or other local processes.

---

## The Architectural Rule: `ghst` Stays Outside

Always run `ghst` on the **trusted host outside the sandbox**, placing the isolation runner inside the `ghst` execution boundary:

```
┌──────────────────────────────────────────────────────────────┐
│ Trusted Host Environment                                     │
│   ghst run (Mints token, sets GH_TOKEN / GITHUB_TOKEN)       │
│     │                                                        │
│     ▼                                                        │
│   ┌────────────────────────────────────────────────────────┐ │
│   │ Isolation Boundary (Sandbox / Container / MicroVM)     │ │
│   │   - Denies host ~/.config/ghst/ and ~/.cache/ghst/     │ │
│   │   - Denies host ~/.ssh/ and ~/.config/gh/              │ │
│   │   - Allows only project directory and workspace        │ │
│   │                                                        │ │
│   │   AI Coding Agent (Claude, Aider, Codex)               │ │
│   └────────────────────────────────────────────────────────┘ │
│     │                                                        │
│     ▼ (Exit event)                                           │
│   ghst automatically revokes the run token                   │
└──────────────────────────────────────────────────────────────┘
```

This ensures that the child process cannot read or tamper with `ghst`'s configuration (`~/.config/ghst/`) or cache entries (`~/.cache/ghst/`).

---

## Recipe 1: Kernel-Level Sandboxes (`nono`, Bubblewrap)

Kernel-level sandboxes use Linux Landlock, seccomp, and namespaces to restrict filesystem and network access with near-zero overhead.

### Using [`nono`](https://nono.sh/)
`nono` provides declarative directory and permission sandboxing:

```console
# ghst mints the token; nono restricts filesystem access to the current directory
$ ghst run --profile reader --repo auto -- \
    nono run --allow . -- your-agent
```

### Using Bubblewrap (`bwrap`)
Bubblewrap creates unprivileged user and mount namespaces. This example exposes the host system
read-only, masks the host home and runtime directories, and mounts only the current workspace as
writable:

```console
# Mask host user state before bind-mounting the workspace into the empty home
$ ghst run --profile reader -- \
    bwrap \
      --ro-bind / / \
      --tmpfs "$HOME" \
      --tmpfs /run \
      --tmpfs /tmp \
      --dev /dev \
      --proc /proc \
      --dir "$HOME/workspace" \
      --bind "$PWD" "$HOME/workspace" \
      --chdir "$HOME/workspace" \
      --setenv PWD "$HOME/workspace" \
      --unshare-all \
      --share-net \
      --new-session \
      --die-with-parent \
      -- your-agent
```

Because the read-only root initially includes host paths, the later `--tmpfs` mounts are essential:
they hide the host home directory, runtime sockets, and temporary files inside the sandbox. Adapt
the mounts to hide any credential stores located outside `$HOME`, `/run`, or `/tmp`. `--share-net`
retains host network access; add a separate network policy when the workload requires egress
restrictions.

---

## Recipe 2: Containerized Environments (Docker, Podman)

Containers run AI agents in isolated user-space environments without mounting host credential directories.

```console
# Forward GITHUB_TOKEN into the container without mounting host credentials
$ ghst run --profile reader -- \
    docker run --rm -it \
      -e GITHUB_TOKEN \
      -e GH_TOKEN \
      -v "$PWD":/workspace -w /workspace \
      ghcr.io/your-org/agent-image:latest
```

---

## Recipe 3: MicroVMs & Virtualization (Firecracker, QEMU)

MicroVMs provide a stronger isolation boundary through hardware virtualization, a separate guest
kernel, and an independent filesystem. The boundary still depends on the hypervisor, device model,
host configuration, and secure credential injection.

### Option A: Synchronous Foreground VM Lease (`ghst run`)
If your tool executes tasks in an existing or fast-booting VM over SSH, configure the guest SSH
server to accept `GH_TOKEN` and `GITHUB_TOKEN` from trusted clients:

```text
AcceptEnv GH_TOKEN GITHUB_TOKEN
```

Then tell the SSH client to send both variables from the environment created by `ghst run`:

```console
# SSH carries the token in its encrypted environment protocol, not in the remote command
$ ghst run --profile reader -- \
    ssh -o SendEnv=GH_TOKEN -o SendEnv=GITHUB_TOKEN \
      -i ~/.ssh/vm_key user@microvm-host your-agent
```

The guest SSH daemon must explicitly allow these names; otherwise it silently omits them. Restrict
the SSH key and guest account to the intended VM workflow, and ensure SSH server logs do not record
accepted environment values. When the SSH process exits, `ghst` requests revocation of the run
token.

### Option B: Ephemeral Token Injection via `ghst token`
For dynamic provisioning engines (such as spawning a Firecracker MicroVM snapshot per task), mint
the scoped token on the trusted host and send it through a confidential, ephemeral channel such as
VSOCK. The following illustrative runner accepts a secret on stdin rather than exposing it in a
process argument, boot argument, image, or cloud-init data:

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Mint a short-lived scoped token and retain its cache ID for cleanup
IFS=$'\t' read -r VM_TOKEN_ID VM_TOKEN < <(
    ghst token --profile contributor --repo auto --format json |
        jq -er '[.id, .token] | @tsv'
)

revoke_token() {
    exit_status=$?
    trap - EXIT
    unset VM_TOKEN
    if ! ghst revoke "$VM_TOKEN_ID"; then
        printf 'Token revocation failed; retry: ghst revoke %s\n' "$VM_TOKEN_ID" >&2
        if [ "$exit_status" -eq 0 ]; then
            exit_status=1
        fi
    fi
    exit "$exit_status"
}
trap revoke_token EXIT

# 2. Send the token over the runner's protected stdin/VSOCK channel
printf '%s\n' "$VM_TOKEN" | ./firecracker-runner \
    --kernel /path/to/vmlinux \
    --rootfs /path/to/rootfs.ext4 \
    --secret-env-stdin GITHUB_TOKEN \
    --workdir "$PWD"
```

The `EXIT` trap passes the JSON `id` to `ghst revoke`, so the cached token is targeted for remote
revocation whether the runner succeeds or fails. Treat `--secret-env-stdin` as the runner-specific
adapter point: it must carry the value into the guest without recording it in host or guest logs or
persistent metadata. The example requires `jq`.

---

## Essential Sandbox Security Checklist

When configuring policies for any sandbox, container, or MicroVM, verify that the guest environment explicitly denies access to:

- [ ] **Local `ghst` state:** `~/.config/ghst/` and `~/.cache/ghst/`
- [ ] **Ambient GitHub credentials:** `~/.config/gh/` (GitHub CLI auth) and Git credential-helper sockets
- [ ] **SSH authentication:** `~/.ssh/` and `$SSH_AUTH_SOCK` (SSH Agent)
- [ ] **Shell & system secrets:** Host environment files (`.env`), AWS/GCP credentials (`~/.aws/`, `~/.config/gcloud/`)
- [ ] **Network boundaries:** Restrict outbound traffic to `api.github.com` and required package managers if feasible
