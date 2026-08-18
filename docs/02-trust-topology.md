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

## Anchors, issuers, and the two trust flows (Decided 2026-08-16)

Three separable decisions get conflated whenever someone says "the root CA".
Keeping them apart is what makes the rest of this document tractable.

### 1. A trust anchor is a role, not a property of a certificate

"Root" means *self-signed and installed in a trust store*. An intermediate
installed in a trust store **is** a root from that verifier's point of view: the
verifier walks up from the leaf, finds its anchor partway, and stops. It never
needs the certificate above.

That gives a spectrum, and every point on it is legitimate:

| Anchor the client holds | Can the parent impersonate this subtree? | Cost of rotating the subtree's CA |
|---|---|---|
| **Org root** (cascade) | Yes, freely — it holds the key above | Free: intermediates come and go beneath the anchor |
| **The subtree's own intermediate** (pinned) | **No, for clients that pinned it** | Those clients must be updated |
| **The subtree's own root** (sovereign) | No, ever — there is no key above | Entirely local |

The middle row is worth stating precisely because it is stronger than it looks.
A client anchored on intermediate `I_A` rejects a leaf from sibling `I_B` (the
chain never reaches its anchor) *and* rejects a parent-minted replacement `I_A′`
carrying the same subject and constraints, because an anchor is a specific
public key and `I_A′`'s signature will not verify against it. This is the
child-intermediate pinning offered as a DB-1 mitigation, and for pinning clients
it is preventive rather than merely detective.

What it costs is the indirection the root existed to provide. Anchoring on the
root lets intermediates rotate freely; anchoring on an intermediate means
rotation touches every pinning client. That trade — **isolation bought with
rotation cost** — is the whole decision.

Name constraints remain complementary rather than redundant: constraints bound
what a subtree may *claim* (enforced for root-trusting clients), pinning bounds
what a client will *accept*. Different directions, both worth having.

### 2. One CA identity, several issuers

Each domain level runs **three issuing intermediates**, one per signing node,
all signed by the same root. No private key is ever copied between nodes:

```
              root  (offline, durable, used a few times a decade)
                |
   +------------+------------+
   |            |            |
issuer A     issuer B     issuer C        <- one per node, own key, own custody
 (HSM)     (cloud KMS)   (file seal)
```

The provisioning flow is the same regardless of custody: the node generates its
key *where that key will live*, emits a CSR, the offline root signs it, and the
resulting certificate is installed. **The root key never touches the node**,
which is what makes heterogeneous custody routine rather than a special case —
a cloud HSM, a PKCS#11 token, and a file seal can all be issuers of one chain.

Why this rather than replicating one issuing key (Vault's model, and Signet's
own simple default):

- **Heterogeneous custody becomes possible at all.** A replicated key must live
  in shared storage; it cannot simultaneously be non-extractable in three
  different devices.
- **Failure is already partial.** Losing a node's HSM costs that node. The
  others were always issuing; there is nothing to fail over.
- **Revocation is granular.** Compromise of a node revokes one intermediate,
  not the chain.
- **Certificates are attributable.** The chain names which issuer — and
  therefore which custody — produced them.

The cost is provisioning: three ceremonies instead of none, and three
intermediates to rotate. Replicating a single sealed issuing key remains the
right default for simple deployments; per-node issuers are what a domain that
cares about custody or blast radius chooses.

### 3. Cascade and sovereign are two flows over the same machinery

**Cascade** (default, intra-org): the org root signs each domain's issuers.
Clients anchor on the org root, so a new domain or a rotated issuer requires no
client change — the anchor above absorbs it. The parent is legitimately
all-powerful, which is what a single organization's hierarchy means.

**Sovereign**: the domain holds its own root, and the parent's involvement is a
cross-certificate for discovery rather than authority. Clients that must not be
impersonable by the parent anchor on the domain's own root. Issuers below it
work exactly as in cascade — the difference is only which certificate sits at
the top and who holds the key for it.

The practical middle — cascade internally, pinned intermediates for a subset of
clients — needs no new mechanism, only a different anchor in those clients'
bundles.

### 4. What the trust bundle therefore carries

Anchor selection is **configuration in a signed artifact**, not a
re-installation exercise. A bundle names, and the root signs:

- the anchors this consumer should trust — an org root, one or more specific
  issuer intermediates, or a sovereign domain's own root;
- the **full issuer set** for each anchor, so a verifier can build paths without
  discovery;
- **revocation state** (CRL, or the epoch of a revocation list), so withdrawing
  one compromised issuer is a bundle update rather than a fleet-wide change;
- metadata: epoch, issued-at, max-age, and the algorithm policy (crypto-agility
  below).

That makes "trust only this domain and below" a line of configuration, and
makes rotating a pinned intermediate a publish-ahead-then-retire operation on
the same refresh path everything else already uses. Bundle mechanics, epochs,
and staleness rules are E-12.

### 5. Built and measured (2026-08-17, milestone 4b)

`internal/trust` implements the above; `signet ca bundle` publishes and
`signet trust fetch|verify|show|pin|install` consume. Three findings from
running it against real verifiers, one of which changes the guidance.

**The root signs bundles, so publishing is a root ceremony.** A bundle declares
the trust set, and an *issuing* key is authorized to mint leaves within a
namespace — not to say who is trusted. Had issuers been allowed to sign
bundles, compromising one node would compromise the whole trust fabric, since
that node could publish a bundle naming itself an anchor. The cost is that
withdrawing an issuer needs the offline root. That is the right cost: it is a
rare, serious event, and the design already leans on short lifetimes rather
than revocation lists for everything routine.

**Pinning an intermediate is verifier-dependent — measured, not assumed.**
Anchoring on a non-self-signed certificate is accepted by Go's `crypto/x509`
(any cert in the root pool is a valid anchor) and **refused by OpenSSL** unless
run with `-partial_chain`. Same bundle, same anchor, opposite results, for
reasons unrelated to the certificates. This is the E-02 finding again in a new
place: *enforcement is not uniform across verifiers, so it cannot be assumed*.
The pinned mode therefore ships with a warning printed at the moment an
operator selects it, naming the flag, rather than being silently offered as
equivalent to the cascade mode. A self-signed "pseudo-root" variant — the
issuing node re-signing its own certificate as a self-signed anchor — is the
portable alternative and remains open (E-12).

**Bundle revocation binds only consumers that build their own paths.**
`signet trust fetch -issuers-out` writes the surviving issuer set with
withdrawn ones omitted, which is what makes revocation bite; a consumer that
instead accepts whatever chain a server presents, under the root anchor, will
not notice. Withdrawing an issuer in a bundle is therefore a *complement to*
letting its short-lived certificate expire, never a substitute for it.

Rollback is refused in two independent places: at the consumer, against its
remembered epoch (`internal/trust.State`, persisted so it survives restarts),
and inside `Apply`, so a node cannot be walked backwards through the log
either. Staleness fails closed on both paths.

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

- Bundle format: shipped as our own signed document (base64 payload + ECDSA
  signature over the exact transmitted bytes, `internal/trust`). SPIFFE bundle
  endpoint compatibility remains open and is now an interop question rather
  than a design one. → Mission E-12.
- **Online freshness statements**: revocation currently rides the root-signed
  bundle, so withdrawing an issuer needs a ceremony. A delegated online key
  signing short-lived revocation deltas is the natural extension once
  leaf-level revocation is needed. → E-12.
- **Self-signed pseudo-root variant** for portable intermediate pinning, given
  the OpenSSL `-partial_chain` finding above. → E-12.
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
