# 14 — Control plane & node lifecycle

**Status: Draft** (designed 2026-08-16)

How operators configure Signet, and how domains and nodes are born and grow.
Consumer-facing dialects are doc 07; this is the *operator* plane.

## Declarative, reconcilable control plane (Decided)

Configuration is **declarative and reconciled**, Terraform/GitOps-shaped —
automation-native first; interactive tools come later if needed. The
declarative surface *is* the desired-state half of the data model (13):
principals, groups, roles, bindings, mapping rules, trust links.

- **Plan / dry-run** (Terraform-plan style) before apply; the diff is recorded
  in the audit log.
- **The reconciler enforces delegation-only-narrows itself** (E-01 K-1): a
  domain's declared config cannot grant scope above the domain; a delegated
  admin's commits cannot exceed their subtree — checked at plan time *and*
  re-checked at issuance.
- **Desired state only.** Runtime state (sessions, minted credentials, JIT
  activations) is never declarative — see the PAM split in 13. Eligibility is
  declared; **activation is a runtime API call** (with step-up), not a commit.

## Node & domain lifecycle

### Genesis mode → operational mode (one-way, audited)

Two postures, and the transition between them is a distinct, one-way,
audited ceremony:

- **Genesis mode** — single node, **root key live in-process**,
  self-authorizing. The minimum needed to mint the first intermediate and the
  first admin. The first node is the sole authority and wins all votes by
  construction (quorum = 1) — safe *because* nothing joins the voter set
  without an authenticated node identity it issues.
- **Operational mode** — root key **offline/sealed**, only intermediates live,
  quorum established (or a deliberate single-node operational config).

**The risk is not the consensus transitions; it is lingering in genesis
posture** (root resident, maximal authority) past the bootstrap window.
"Seal genesis, enter operational" is an explicit ceremony (ties to E-09 seal /
11 ops). Single-node *operational* (root offline, one voter) is a safe
permanent config for small sites.

### Growing the Raft group — non-voters, never even (Decided, E-03/hashicorp-raft)

- New peers join as **non-voters (learners)**: they replicate the log and serve
  **stale-tolerant reads**, but are **not** counted in quorum. Writes and
  linearizable reads are **redirected to the leader** ("go ask this node
  instead") — a non-voter or partitioned-minority node never issues
  authoritatively.
- Promote to voter **only** when caught up, jumping **1 → 3** (or 3 → 5) so the
  cluster never *rests* at an even voter count (2 voters tolerate 0 failures).
  **Tooling refuses to leave the cluster parked at an even voter count.**
- **Maintenance** uses the same lever: demote a voter to non-voter, service it,
  promote it back — voter count stays odd throughout.
- **Authenticated join is mandatory**: a peer proves its node identity (node
  cert minted by the domain CA, gated by attestation or a one-time join token)
  before joining, over node-to-node mTLS under the domain's own CA. The
  bootstrap chicken-and-egg resolves cleanly — the genesis node *is* the CA.

### Child domain enrollment

From an existing (parent) domain: child genesis produces a root (sovereign
mode) or an intermediate request (subordinate mode); the parent authorizes and
signs (cross-cert or intermediate); the child enters operational mode. Mode is
per-child (02). Never force-configure Raft membership except in the documented
DR ceremony (11).

## First-deployment topology (Decided — doc 6 discussion)

A thin **root domain** (anchors only, mostly offline) over three child domains:
`home`, `aws`, `gcp`. Bring all three up **subordinate** first to get running,
then convert one (`aws`) to **sovereign** to exercise the cross-cert path.
Sequence: build the **MVP vertical slice on `home` single-node first**
(ESO reads a secret via the Vault-KV dialect + k8s-SA attestation), *then*
stand up the four-domain fabric to stress-test federation on a working base.

## Open

- Config schema/language (HCL-like? YAML? typed docs) and the reconciler's
  drift-detection cadence.
- JIT activation API shape (request → step-up challenge → short-TTL grant) and
  its audit envelope.
- Approval workflows for activation (single approver? quorum? out-of-band?).
