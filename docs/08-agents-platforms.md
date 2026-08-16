# 08 — Agents & platforms

**Status: Draft**

## Two modes, one core (Decided)

Division is by **principal type**, not OS:

- **Workstation mode** — serves a human: holds the sender-bound session after
  WebAuthn login, auto-renews role credentials, hands them to local tools.
- **Host mode** — serves a machine: machine identity (TPM-attested), fetches
  service certs, serves credentials to local workloads.

Same core, `signet agent`, shipped in the same release train as the server.

## Language policy (Decided)

- **Server: Go**, stdlib-crypto-first (this decision is load-bearing for the
  dependency budget and is not per-platform).
- **Agent core: Go** — one cross-compiled daemon per OS. All protocol logic,
  renewal, and state live here.
- **OS-native shims: the platform's native language, freely** — C for PAM
  (.so), C++/COM for Windows Credential Provider, Obj-C/Swift for macOS
  Authorization Plugin / Secure Enclave glue. No square pegs. But shims are
  **thin by decree**: they marshal the OS's callback into a local IPC call to
  the daemon and render the result. Target: a few hundred lines each, no
  crypto, no policy, no network. (This is the Kanidm/Teleport/sssd shape, and
  it keeps the memory-unsafe, hard-to-test surface minuscule.)

## Platform integration points

| Layer | Linux | macOS | Windows |
|---|---|---|---|
| Sender-binding keystore | TPM 2.0 | Secure Enclave / Keychain | TPM via CNG |
| Local IPC | Unix socket | Unix socket | Named pipe |
| ssh integration | ssh-agent protocol | ssh-agent protocol | OpenSSH agent named pipe |
| OS logon (v2+, **out of v1 scope**) | PAM module | Authorization plugin | Credential Provider (COM) — *not* an LSA authentication package; writing those is how you brick auth |

Common integration surfaces on all three: ssh-agent protocol, localhost OIDC
helper (kubectl, browser SSO), file/env output for legacy tools.

## The v1 line (Decided)

v1 agents provide credentials **to tools and services**. They do **not**
gatekeep OS login. PAM/CredProvider/loginwindow integration is v2+, developed
against a dedicated snapshot-revertable VM lab (lockout bugs in logon shims
are the failure mode), on its own release cadence.

## Kubernetes: mostly no agent (Decided)

k8s is not a fourth OS — it already issues identity. Workloads present
projected ServiceAccount tokens directly to signet (`k8s-sa` verifier, 04):
no DaemonSet, nothing installed, and ESO/cert-manager work unmodified because
this is the Vault k8s-auth shape they already speak. Optional later: a
DaemonSet exposing the SPIFFE Workload API socket for SPIFFE-aware software.

## Rollout order (Decided)

1. Linux host mode + k8s SA attestation (the fleet + 5 clusters — the value)
2. macOS workstation mode (daily driver; ssh-agent + kubectl OIDC)
3. Linux workstation mode (macOS minus Secure Enclave)
4. Windows (in the CI cross-compile matrix from day one so it never rots;
   ships last)

## Security requirements (E-01 — promoted from open questions)

- **IPC authorization is mandatory** [AG-2]: peer-cred checks
  (`SO_PEERCRED`/`getpeereid`; Windows named-pipe ACLs + client PID/SID),
  socket `0600` in the user's runtime dir, per-request authorization. Root can
  always impersonate — accepted; the boundary is against *peer* users.
- **Agent pins Signet's trust bundle / server cert** for renewal [AG-3]; fail
  closed on pin mismatch. DPoP-style binding needs a server-side `jti` replay
  cache (+ server nonces across stateless nodes).
- **Host-mode file delivery** [AG-4]: strict perms/ownership, tmpfs where
  possible, atomic rotate + SIGHUP, prefer systemd credentials / socket handoff
  over on-disk files.
- Privileged agent operations require **per-use user presence** (biometric/PIN
  ACL on the binding key) — a hardware-bound key with no presence ACL is a
  silent local signing oracle. [E-05]

## Open questions

- Browser SSO handoff UX: localhost redirect listener vs native messaging.
- Exact keystore/binding mechanics per OS — Mission E-05.
