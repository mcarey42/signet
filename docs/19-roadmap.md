# 19 — What is left

Written 2026-08-18, immediately after v0.3.0. This is the honest inventory: not
a wish list, but everything known to be missing, unproven, or broken, with some
judgement about which of it actually matters.

Four categories, roughly in order of how much they should worry you.

---

## 1. Structural gaps — things that are absent, not broken

These are the ones that would stop a real deployment, and none of them is a bug
report. They were deferred deliberately and the deferral is now the problem.

### Nothing can be revoked

`KindRevokeSession` is the only removal operation in the entire system. There
is **no way to delete a binding, a mapping, a principal, an issuer, or to
retire a key.** Authority ends only when it expires.

That has consequences already visible elsewhere: finding F-04 ("a mapping
authored by a since-lapsed admin keeps minting sessions") is not really a bug,
it is this gap wearing a disguise. `keys.Key.Retired` exists as a field and is
never read or written, so a compromised signing key cannot be withdrawn — JWKS
accumulates every key forever.

For a system whose entire pitch is *short-lived credentials, revocation by
declining a renewal*, this is defensible for leaves and indefensible for the
grants themselves. **This is the single largest gap.**

### No browser SSO

`response_types_supported` is `["token"]`. There is no authorization-code flow,
no PKCE, no consent step — so Grafana, ArgoCD, Harbor and Proxmox, the v1
consumer list in `docs/07`, **cannot actually be served today.** `kubectl`
works because it uses a different flow entirely.

The docs promise something the code does not do. Either the flow gets built or
`docs/07` needs correcting; leaving both as they are is the wrong answer.

### Single node

One voter, no join, no promotion, no network transport. `docs/14` describes
non-voter growth and a demote/promote maintenance dance; none of it exists.
Every consensus property this project claims has been tested with a quorum of
one, which is to say barely tested at all.

### No backups

The format is designed (`docs/03`, Litestream-shaped generations over the Raft
log) and nothing ships. A domain today is exactly as durable as one directory.

### No agent

`docs/08` describes workstation and host modes. Kubernetes needs no agent,
which is why the MVP could skip it — but SSH and workstation login are the
reason a person would run this rather than ESO alone.

---

## 2. Open findings — 19, from the adversarial pass

Full list with severities in [`pentest/REGISTER.md`](pentest/REGISTER.md).
Reproduction detail is withheld until each is fixed.

| Worth doing next | Why |
|---|---|
| **SC-09** | May already be closed by the fail-closed watermark read. Verifying costs an hour and either removes an item or finds a real hole. |
| **CR-04** | Key material outliving its sealing in memory. Small, contained, unambiguous. |
| **SC-10** | Audit metadata corruption that `audit verify` reports as healthy — a monitoring blind spot in the subsystem whose whole job is detection. |
| **SC-07** | Reads served before the log finishes replaying. |
| **F5** | Not a defect: no witnessing cadence, so a node that goes quiet hides indefinitely. Fixing it means deciding what "overdue" means, which is a design question. |

The remaining low and unconfirmed items (`F-04`, `F-05`, `CR-06`, `F7/F8/F9`,
`SC-12`, `UC-02`–`UC-06`, `UC-08`) are individually cheap; several would fall
out of the structural work above rather than needing their own effort.

---

## 3. Coverage — the largest body of work

The on-rails pass enumerated **1,291 scenarios** across nine subsystems and
measured **266 covered (~21%)**. Roughly thirty regression tests have landed
since, so call it low-to-mid twenties.

| Area | Scenarios | Covered | Note |
|---|---|---|---|
| OIDC & SSH dialects | 125 | ~0 | **No test files exist at all.** Both dialects are proven only by manual runs against real clients. |
| Storage, consensus, seals | 254 | 28 | No crash-safety tests; nothing kills a process or injects an I/O fault. |
| RBAC & scope algebra | 196 | 53 | The security core. Gaps are mechanical cross-products and escalation paths that route around `applyPutBinding`. |
| Identity & attestation | 188 | 42 | `Kernel.Login` has no unit test. |
| PKI & CA ceremonies | 133 | 26 | No test file for `internal/kernel/pki.go` or the Vault PKI route. |
| Secrets / Vault-KV | 103 | 17 | Semantics tested, serialization mostly not. |
| PAM activation | 102 | 27 | The four documented semantics are covered; ordering and concurrency are not. |
| Trust bundles & fabric | 98 | 50 | Best-covered area. |
| Anchored audit | 92 | 23 | Cross-boundary paths largely uncovered. |

**The OIDC and SSH row is the one to fix first.** Zero automated coverage on
two dialects that mint offline credentials — the credential class no relying
party ever re-checks with us — is the worst ratio of risk to effort in the
table.

---

## 4. Unverified and unexplored

### Hardware

`docs/18` lists what only a real token can settle, pending the Pico2HSM. The
first question is not whether the tests pass but **whether it implements
`CKM_AES_GCM` at all** — it descends from SmartCard-HSM, whose mechanism list is
much narrower than SoftHSM's. If it does not, that is a finding: the seal needs
a fallback and the hardware story needs rewriting for that class of device.

Also outstanding there: non-extractability actually enforced, the `KeyID`
fingerprint working on that device, and PIN lockout behaviour.

### Explorations still pending

| ID | Priority | Subject |
|---|---|---|
| E-04 | P1 | Attestation ceremonies: TPM 2.0 enrollment, cloud instance identity, private-cluster OIDC discovery |
| E-05 | P1 | Sender-binding per platform — gates any hardware-bound step-up |
| E-08 | P1 | OIDC conformance: what Grafana, ArgoCD, Harbor actually require |
| E-09 | P1 | Seal ceremonies: TPM, cloud KMS, Shamir |
| E-07 | P2 | SAML risk survey |
| E-10 | P2 | Interop harness as a release gate |
| E-11 | P2 | Prior-art mining: Zitadel, Kanidm, SPIRE, Teleport, step-ca |

E-08 is worth pulling forward: it and the missing authorization-code flow are
the same question asked from two directions.

### Performance

`docs/17` records what is measured. Unmeasured: multi-node consensus, issuance
throughput, behaviour at O(10k) principals against a design envelope of O(1k),
and memory under sustained load.

---

## A suggested order

1. **Revocation.** It is the largest structural gap, it silently explains
   several findings, and everything else is easier once authority can be taken
   away as well as given.
2. **Tests for the OIDC and SSH dialects.** Worst risk-to-effort ratio on the
   board; they mint the credentials nobody re-checks.
3. **SC-09, CR-04, SC-10.** Cheap, contained, and one of them may already be
   closed.
4. **E-08 and the authorization-code flow**, together, so `docs/07` stops
   promising something that does not exist.
5. **Backups**, before anyone stores anything they would miss.

Multi-node, the agent, and SAML are real work but none of them is what stops
this being useful today.
