# Test plans and the findings register

Nine agents designed on-rails test plans, one per subsystem, on 2026-08-18.
Together they enumerate **~1,290 scenarios** and place current coverage at
roughly **25%**. Each plan grounds every claim in `file:line` and separates
what is covered from what is a gap.

| # | Area | Scenarios | Covered |
|---|---|---|---|
| 01 | Secrets / Vault-KV compat | 103 | 17 |
| 02 | Identity & attestation | 188 | 42 |
| 03 | OIDC & SSH dialects | 125 | ~0 |
| 04 | PKI & CA ceremonies | 133 | 26 |
| 05 | Trust bundles & fabric | 98 | 50 |
| 06 | Anchored audit | 92 | 23 |
| 07 | PAM activation | 102 | 27 |
| 08 | RBAC & scope algebra | 196 | 53 |
| 09 | Storage, consensus, seals | 254 | 28 |

## Findings register

Findings are reported by the agents that designed the plans. **Reported is not
confirmed.** Anything marked FIXED below was reproduced independently first.

### Fixed (verified, with regression tests)

| ID | Severity | Finding |
|---|---|---|
| SEC-B1 | **critical** | A malformed version list destroyed the live secret and returned 204. `versionList` rejected it correctly; the handler discarded the error with `_ =`, and nil means "current version". |
| PAM-F2 | **critical** | `kill` and `deny` had no authorization check at all, while the handler comment claimed enforcement inside `Apply`. Any authenticated principal could end anyone's elevated access. |
| ATT-B1 | **high** | One unsupported JWKS key failed the whole key set, on every login — so a cluster adding an Ed25519 key would break all authentication against that issuer. |
| TRUST-B1 | **high** | `ca bundle` published *every* issuer the root had signed into *every* domain's bundle, making the sibling-impersonation defence vacuous. Both existing tests missed it because both built the issuer set by hand instead of using the tool. |

### Open — reported, triaged, not yet acted on

Ordered by the severity the reporting agent assigned. Each still needs
independent reproduction before it is treated as real.

**Authorization / escalation**
- RBAC PE-10: `applyPutPrincipal` has no authorization check and permits a
  rename, which could re-home a principal into an attacker's subtree and defeat
  the K-1 mapping guard. Latent — no dialect exposes it today.
- RBAC PE-17: `filterRoles` (offline credential minting) does not check
  `ActivationRequired`, so a PAM-gated role may be embedded in a JWT or SSH
  certificate with no live activation. `HasAuthority` does check, so the online
  path is correct — the bypass lands on the credential class an RP accepts
  without asking anyone.
- RBAC D-02: `ScopeCovers("", path)` is true — an empty scope is silently a
  root scope. Reachability depends on one `ValidatePath` call in another file.
- RBAC DN-10: nothing clamps a new binding's `NotAfter` to the grantor's, so a
  time-bounded admin can self-grant an unbounded copy.
- PKI: `uriAllowed` is a bare `strings.HasPrefix`, so `spiffe://home.example`
  also permits `spiffe://home.example.evil/...`.

**Correctness / data**
- STORE 1: `Propose` can acknowledge writes that are never applied if `raft.db`
  is lost while `state.db` survives — reachable from the restore flow.
- STORE 2: `fsm.New` discards the `AppliedIndex()` error, re-arming version
  drift *and* barrier nonce reuse.
- STORE 3/4: `store.Open` accepts a root key that cannot decrypt the store; a
  missing `root.seal` is silently replaced.
- SEAL 5: `PKCS11Seal.KeyID()` is `token/label`, so a successor key under the
  same label reports an identical KeyID and rotation *looks* complete.
- PAM F1: the approval path discards the requested duration and grants the full
  `max_activation_sec`.
- AUDIT B: `Kernel.Witness` does read-modify-write outside `Apply`, so
  concurrent calls can erase a stored conflict.
- AUDIT C: the checkpoint key is pinned and persisted *before* `Extend` runs.

**Dialects**
- OIDC 1: `requested_token_lifetime=5m` yields a 5-**millisecond** token
  (`ParseDuration(v+"s")`).
- OIDC 2: no upper bound on ID-token lifetime for a non-expiring session.
- OIDC TX-34: any session may mint an ID token for any audience — no allow-list.
- SSH 4: `data.serial_number` returns the expiry, not the serial, so a KRL built
  from it revokes nothing.

**Missing operations** (design gaps, not bugs)
- There is no binding-deletion Op, no key-retirement path, and no CLI for
  `InstallKey`. Several documented behaviours describe paths no caller can take.

## How to read a plan

Every row: stable ID, preconditions, exact input, expected observable result,
and either a `file:line` citation proving it is covered or a GAP mark. Negative
cases are first-class — for most of these subsystems the refusals *are* the
feature.
