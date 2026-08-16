# 02 — Trust topology

**Status: Draft** (kernel model and delegation shape Decided; enforcement
model corrected per E-02; federation mechanics and bootstrap Open)
Evidence: [explorations/E-02-name-constraints.md](explorations/E-02-name-constraints.md)

## The kernel

One machine, four costumes. The kernel is:

- **Identity graph** — principals (humans, services, workloads, machines,
  domains) arranged under a hierarchical resource tree.
- **Policy engine** — role bindings evaluated at issuance time (see 05).
- **Key hierarchy** — per-domain roots (offline) → online intermediates →
  leaf credentials.
- **Replicated log** — per-domain Raft (see 03).

Credential dialects (OIDC, X.509/ACME, SSH certs, KV leases) are serializers
over one kernel decision: *principal P gets scope S for duration D, signed by
key K*. Dialects never touch storage or keys directly.

## Hierarchy = the PKI chain (Decided; enforcement model per E-02)

A parent domain delegates to a child by issuing a **name-constrained
intermediate CA** (RFC 5280) scoped to the child's namespace. The delegation
*shape* is unchanged — delegation only narrows, the org tree is literally the
cert chain, a child operates fully while partitioned. But E-02's empirical
verifier matrix killed the original claim that "every verifier enforces this,
offline": DNS constraints are enforced essentially universally, while **URI
constraints (the SPIFFE half) make chains unverifiable across the
rustls-webpki/pyca family and are silently ignored by GnuTLS** — the exact
breakage the SPIFFE spec warns about. So:

*The hierarchy is the PKI chain; the chain carries the scope; the **issuer**
enforces it; verifiers that can enforce it too, do.*

### Primary enforcement: the issuer (always on)

1. **Scope lives in the chain, enforcement lives in the issuer.** A child's
   signet reads its own intermediate's constraints — plus a **signed
   delegation record** from the parent covering scope certs can't express
   (OIDC issuer URLs, SSH principals, KV mount prefixes) — as its
   authoritative issuance scope, validated on every request *before signing*.
2. **Verify-after-sign gate** (charter principle 6): after signing, an
   independent code path re-verifies the full chain AND lints every SAN form
   (DNS, URI, IP, email) and Subject against the delegation scope — including
   forms the constraints don't cover, CN-only shapes, and URI host tricks.
   Disagreement ⇒ quarantine + log, never release.
3. **Append-only issuance log per domain, parent-auditable.** Every CA-key
   signature is logged; a cert that exists but isn't in the log is the
   compromise signal. This — not in-process checks — is what bounds a fully
   compromised child server.

### Containment: short-lived intermediates

Child intermediates live ~90 days, renewed every ~30 (both per-delegation
policy knobs). Revoking a subtree = **declining one renewal** — no CRL/OCSP
machinery required — and renewal time is when the parent reviews the child's
issuance log. **Partition floor**: lifetime − renewal interval is the maximum
partition a child survives at full function (~60 days at defaults); never
tune lifetimes down past the sovereignty requirement (charter principle 4).

### Defense-in-depth: name constraints, profiled (E-02)

- **Always emit DNS constraints** — enforcement is effectively universal.
- **Always close the cross-type gap**: also emit IP and email subtrees
  (delegated ranges/domains, or exclude-all when not delegated) — a DNS-only
  constraint leaves URI/IP/email forms *unlimited* in conforming verifiers.
- **URI constraints: per-delegation opt-in, default OFF** — emitting them
  hard-breaks verification of *legitimate* certs in rustls-webpki ≥0.103.12
  and pyca. Opt in only for closed Go/OpenSSL/Java/Apple ecosystems (the
  homelab's Go-only consumer set qualifies); when emitted, keep URI hosts
  inside the DNS permitted set (LibreSSL cross-checks them).
- **Mark the extension critical** (makes non-supporting verifiers fail
  closed); **never issue SAN-less certs**.
- Constraint enforcement code has a steady CVE tail even in the best stacks
  (Go, OpenSSL, pyca — see E-02 F5), which is why issuer-side stays primary
  permanently, regardless of ecosystem improvements.

### Workload-identity scoping: bundle partitioning, not constraints

For SPIFFE-style workload identity, adopt the SPIFFE federation model
verbatim, for **both** federation and sibling-domain isolation: verifiers
hold per-trust-domain bundles, select the bundle by the trust domain of the
presented ID, and **never merge bundles** (merging lets one domain forge
another's identities). The chain hierarchy remains the *distribution and
revocation* structure; it is not the workload-identity *authorization*
boundary at third-party verifiers.

### Child modes: subordinate vs sovereign (Decided)

Delegation is a **per-child mode**, not one fixed relationship. The governing
law: a credential is sovereign against the parent *iff relying parties verify
something the child controls* — a child secret confers no protection unless
the verifier's acceptance rule takes the child's public key as an input.
(A signature nobody checks is worthless; this is logical, not cryptographic.)

- **Subordinate mode (default, intra-org).** The child is a name-constrained
  intermediate under the parent root (the model above). The parent is
  legitimately all-powerful over the subtree — that is what one org's tree
  *means* — and DB-1 applies: no sovereignty against the parent. Correct for
  the homelab and most single-org trees.

- **Sovereign mode.** The child is **its own root**; the parent issues a
  **cross-certificate** endorsing that root for hierarchy/discovery only. RPs
  verify against the child's root (from the trust bundle), so the parent
  *cannot* mint in the child's namespace — it was never in the leaf path. Fully
  offline and partition-tolerant (the child signs its own leaves). A sovereign
  child is simply a **federated peer that also carries a parent cross-cert** —
  same machinery as "federation between equals," so no new architecture, just a
  policy knob + the federation/bundle format (E-12).

  Sovereign mode composes with three optional hardenings (design inputs to
  E-12):
  - **Self-certifying namespace** — derive the trust-domain label from the
    child key, `spiffe://<base32(H(child_root_pubkey))>/…` (RFC 3972 / onion /
    IPFS-CID style). The verifier rule "trust-domain segment == H(signing key)"
    *structurally* requires the child key — parent forgery is mathematically
    impossible with **zero RP configuration**. Cost: hash-shaped names need a
    friendly-name → self-certifying-name discovery layer.
  - **Transparency / key transparency (CONIKS/KT)** — for orgs that want the
    parent to retain issuing convenience but guarantee rogue issuance is
    *detectable*: append-only Merkle log of authorized keys/intermediates,
    inclusion proofs on credentials, child monitors for unauthorized entries,
    gossip catches split-view. Detection, not prevention; RP-offline (checks a
    compact proof).
  - **Threshold child key (FROST / threshold Ed25519)** — k-of-n shares so even
    a child-server compromise can't unilaterally mint (hardens the child side
    of DB-3); produces an ordinary Schnorr/Ed25519 signature, no special RP
    logic.

Note on per-issuance liveness (the nonce+timestamp idea): requiring a fresh
child signature over `H(contents ‖ nonce ‖ timestamp)` on *every leaf* proves
the child was live at mint time, but forces the child online for every
issuance (killing delegated partition-tolerance) and needs the RP to judge
nonce freshness (online, or clock-dependent — TIME-1). So it is **not** used
for the offline base case; it is the right mechanism for **online-tier**
endorsements (06 tiers 3–4), where a resource wants "the child authority
endorsed this *now*." Sovereign mode gets parent-non-impersonation for free
via cross-cert, without per-mint child participation.

### Parent power over a child (E-01 DB-1 — stated honestly)

A parent holds the root and can, offline, mint a **second** intermediate
bearing a child's exact name constraints and issue anywhere in the child's
namespace. RPs pin the root, so the child cannot prevent or locally detect
this. Therefore:

- **Within one org this is correct and desired** — the parent *is* more
  privileged; that is what the tree means. We say so, and do not imply a child
  is protected from its parent.
- **Real authority-sovereignty against a superior = be your own root and
  federate as an equal** (below). A "sovereign child" that chains to a parent
  root is a contradiction.
- **Detection** for orgs that want a hierarchy but also want to catch rogue
  re-issuance: optional child-intermediate SPKI pinning for cooperating RPs,
  and/or a transparency/epoch log of intermediates. Detection, not prevention;
  pinning also forfeits free rotation.
- **Prevention**: co-signing (child + parent both sign the child's
  authoritative bundle; RP requires both) — the only preventive option, at the
  cost of offline/partition-tolerant parent re-issue. A deliberate trade for a
  genuinely adversarial parent.

## Crypto-agility: PQC-hedged composite roots (Decided)

The trust anchor is **crypto-agile from day one** so an algorithm can be
retired without re-bootstrapping trust — aligned with catalyst / composite
certificate prior art (ITU-T X.509 `SubjectAltPublicKeyInfo`/`AltSignatureValue`;
IETF LAMPS composite signatures for PQC migration).

- **Roots/intermediates are AND-composite**: multiple algorithms
  (RSA + EC + PQC, e.g. ML-DSA) carried on one anchor, all verified. Forging
  the CA's authenticity then requires breaking **every** live algorithm at
  once — maximal hedge. Composite cost (bigger, 3× signing, still-stabilizing
  ASN.1) is paid on the few, long-lived anchors where it's worth it.
- **Leaves stay single-strong-algorithm and agile by rotation** — a
  ~15-min leaf gets its agility for free by rotating to a new algorithm on its
  next renewal; it need not carry three signatures.
- **"Which algorithms are currently acceptable" lives in the signed,
  monotonically-versioned trust bundle — NOT in mutable cert flags.** A signed
  cert is immutable; flags baked into it can't be changed without re-signing
  (= a new cert). So the algorithm-policy object rides the FED-1 bundle-epoch
  machinery: retiring RSA = publish epoch N+1 dropping it, propagated via the
  refresh path clients already run; surviving algorithms stay pinned, trust is
  never rebuilt from zero. Adding a new algorithm is likewise a bundle epoch.
- **The policy object is AND-signed by all currently-live algorithms** — an
  attacker who breaks one algorithm still can't forge the policy statement
  (this is the "cross-sign the flags, agreement as resilience" idea, relocated
  from the cert to the bundle).
- **Downgrade protection**: the policy states the minimum required strength;
  a verifier refuses a cert lacking a currently-required signature even if a
  weaker one validates (the algorithm analogue of TLS downgrade defense). OR-
  style "verify the strongest you support" is used only for migration
  compatibility, always under this floor.

## Federation between equals (Draft)

Peering (two sovereign orgs, or two roots in one org) does **not** require a
shared root. Trust between domains that lack a common ancestor is established
by **trust bundle exchange**: signed documents carrying a domain's root(s),
refreshed on an interval, verified against a pinned initial fingerprint.
Cross-domain writes never happen; only signed artifacts (bundles, revocations,
delegation certs) flow, asynchronously. Per E-02, leaning firmly
SPIFFE-bundle-compatible (mission E-12 settles the format).

**Federation security requirements (E-01 FED-1/2/3/4, now requirements not
options):** monotonic bundle epoch/sequence with signed `issued-at`;
**fail-closed on staleness** (a bundle older than max-age is not trusted for
high tiers); never accept an epoch lower than the last seen; pin the peer
**root SPKI** (not just an endpoint URL), with bundle updates signed by that
root; out-of-band confirmation for a peer's root rotation; **on-receipt
namespace scoping** (a peer anchor may assert only its own trust domain;
bundles never merged); treat all HTTP redirects on bundle endpoints as
temporary; out-of-band fingerprint is the default bootstrap, TOFU opt-in and
labeled lower-assurance.

## Trust configuration surface (Draft — deliberately minimal)

A node's entire trust config reduces to:

```
identity:
  chain: /path/or/slot        # my keypair + cert chain (position in hierarchy;
                              # my name constraints carry my X.509 scope)
  delegation: /path/or/slot   # parent-signed record of non-X.509 scope
                              # (OIDC issuer, SSH principals, KV prefixes)
trust:
  bundles:                    # who I trust — one for my own hierarchy,
    - name: example-root      # plus zero or more federated peers
      anchors: [...]
      refresh_endpoint: https://…   # optional; bundle updates are signed
      pin: sha256:…                 # bootstrap fingerprint (out-of-band)
```

Everything else is *derived from the chain + delegation record*, not
configured — and the **issuer** is the enforcement point for that scope, not
the relying party. Bootstrap of the very first trust (new child joining a
parent; two peers meeting) uses an out-of-band fingerprint or a one-time join
token; TOFU is permitted only where explicitly enabled.

## Open questions

- Bundle format: SPIFFE bundle endpoint format vs. our own signed document.
  Leaning SPIFFE-compatible (reinforced by E-02). → Mission E-12.
- Revocation transport between domains (signed revocation lists piggybacked
  on bundle refresh? epoch counters?). Note short-lived intermediates already
  bound subtree revocation at ≤ intermediate lifetime.
- **Issuance-log audit protocol** (new, from E-02): format, what the parent
  verifies at renewal, and whether logs are hash-chained (ties into 11's
  audit-log question). Feeds 01/03.
- **Intermediate renewal ceremony** (new, from E-02): renewal handshake,
  the partition-floor policy knob, and interaction with the freshness
  ladder (06).
- Parent-compromise resistance: child pinning of its own intermediate?
  (feeds 01 / E-01.)
- ~~Name-constraint enforcement reality~~ **Answered by E-02** (measured,
  5 verifiers × 15 chains): DNS solid everywhere; URI constraints break
  webpki-family verification of legitimate chains; hybrid model above.
