# E-02 — Name-constraint enforcement reality

**Mission**: P0, feeds [02-trust-topology](../02-trust-topology.md).
**Date**: 2026-08-16. **Status**: Complete.

## Question

Signet's delegation model ("Hierarchy = the PKI chain", 02 §Decided) bets that
RFC 5280 name constraints on intermediate CAs — DNS constraints *and* URI
constraints scoping SPIFFE IDs like `spiffe://child.example/…` — are reliably
enforced by real-world verifiers, so that "a child cannot mint outside its
constraint, and every independent verifier enforces this, offline." Is that
sound as the **primary** enforcement mechanism, or must primary enforcement be
signet-side issuance validation with name constraints as defense-in-depth?

## Method / sources

**Empirical**: a Go harness (`crypto/x509`, ECDSA P-256) generated fifteen
root → name-constrained-intermediate → leaf chains covering permitted/excluded
DNS, URI, IP, and email constraints, cross-type gaps, mixed SANs, CN-only
leaves, and non-critical extensions; verified in-process by Go and, from the
emitted PEMs, by four more verifiers on the same machine (macOS 26.6.1):

1. Go 1.26.6 `Certificate.Verify` (custom roots, `ExtKeyUsageAny`, no
   `DNSName` — every rejection below happened during pure chain building,
   independent of hostname verification)
2. OpenSSL 3.6.3 `openssl verify -CAfile root -untrusted int leaf`
   (re-run with `-x509_strict`: identical results)
3. LibreSSL 3.3.6 (macOS `/usr/bin/openssl`)
4. Apple Security.framework (`security verify-cert … -L`, basic X.509 policy)
5. pyca/cryptography 49.0.0 `x509.verification` ClientVerifier — its own
   Rust path validator, CABF-profiled, same strictness family as webpki

Harness source: scratchpad `nctest/main.go` + `pyca_test.py` (session
scratchpad; reproduce from the case table below — the harness is ~150 lines).

**Research**: web survey (sub-mission, all claims URL-sourced) of OpenSSL
version history, rustls-webpki current + historical behavior and 2026
advisories, Java PKIX, Chrome/Firefox/Apple verifiers, the SPIFFE X509-SVID
and Federation specs plus SPIRE source, Netflix BetterTLS results, the
critical/non-critical CA/B history, and the name-constraint CVE record
(OpenSSL, Go, Node, GnuTLS, pyca). Key primary sources: RFC 5280 §4.2.1.10;
X509-SVID spec §4.2; rustls-webpki GHSA-965h-392x-2mh5 + issue #514; BoringSSL
`pki/name_constraints.cc`; mozilla::pkix `pkixnames.cpp`; Apple trustd
`nameconstraints.c`; CVE-2018-4086; CA/B BR §7.1.2.10.8; Go release notes
1.10/1.15/1.17 and CVE-2024-45341 / CVE-2025-61727 / CVE-2026-27137/33810;
BetterTLS 2017 + 2021 reports.

### Empirical case definitions

| case | intermediate constraints (critical unless noted) | leaf SANs |
|---|---|---|
| dns-permitted-ok | permit DNS `child.example`; exclude DNS `secret.child.example` | DNS `svc.child.example` |
| dns-violation | same | DNS `evil.other.example` |
| dns-excluded | same | DNS `a.secret.child.example` |
| uri-permitted-ok | permit URI `child.example` | URI `spiffe://child.example/ns/prod/sa/api` |
| uri-violation | same | URI `spiffe://other.example/ns/prod/sa/api` |
| crosstype-dnsconstr-urileaf | permit DNS only (no URI constraint) | URI `spiffe://other.example/anything` |
| crosstype-uriconstr-dnsleaf | permit URI only (no DNS constraint) | DNS `evil.other.example` |
| ip-permitted-ok / ip-violation | permit IP `10.0.0.0/8` | IP `10.1.2.3` / `192.168.1.1` |
| email-permitted-ok / -violation | permit email `child.example` | `alice@child.example` / `alice@other.example` |
| mixed-goodDNS-badURI | permit DNS + URI `child.example` | DNS `svc.child.example` **and** URI `spiffe://other.example/wl` |
| cn-only-no-san | permit DNS `child.example` | no SAN ext; Subject CN `evil.other.example` |
| noncritical-violation / -ok | permit DNS `child.example`, extension **non-critical** | DNS `evil.other.example` / `svc.child.example` |

### Empirical results (measured, this machine, 2026-08-16)

| case | RFC 5280 expectation | Go 1.26 | OpenSSL 3.6.3 | LibreSSL 3.3.6 | Apple (macOS 26) | pyca 49 (Rust) |
|---|---|---|---|---|---|---|
| dns-permitted-ok | VALID | VALID | VALID | VALID | VALID | VALID |
| dns-violation | REJECT | REJECT | REJECT | REJECT | REJECT | REJECT |
| dns-excluded | REJECT | REJECT | REJECT | REJECT | REJECT | REJECT |
| uri-permitted-ok | VALID | VALID | VALID | VALID | VALID | **REJECT** — "unsupported name constraint" |
| uri-violation | REJECT | REJECT | REJECT | REJECT | REJECT | REJECT (same wrong reason) |
| crosstype-dnsconstr-urileaf | VALID (URI form unconstrained) | VALID | VALID | **REJECT** | VALID | VALID |
| crosstype-uriconstr-dnsleaf | VALID (DNS form unconstrained) | VALID | VALID | VALID | VALID | VALID |
| ip-permitted-ok | VALID | VALID | VALID | VALID | VALID | VALID |
| ip-violation | REJECT | REJECT | REJECT | REJECT | REJECT | REJECT |
| email-permitted-ok | VALID | VALID | VALID | VALID | VALID | VALID |
| email-violation | REJECT | REJECT | REJECT | REJECT | REJECT | REJECT |
| mixed-goodDNS-badURI | REJECT | REJECT | REJECT | REJECT | REJECT | REJECT |
| cn-only-no-san | ambiguous (CN-as-host is legacy practice) | VALID | **REJECT** (CN checked as DNS) | **REJECT** | VALID | REJECT (SAN ext required) |
| noncritical-violation | REJECT | REJECT | REJECT | REJECT | REJECT | REJECT |
| noncritical-ok | VALID | VALID | VALID | VALID | VALID | VALID |

Representative rejection texts: Go — `x509: a root or intermediate certificate
is not authorized to sign for this name: URI "spiffe://other.example/…" is not
permitted by any constraint`; OpenSSL — `error 47 … permitted subtree
violation`; pyca, **for any chain whose intermediate merely carries a URI
constraint, including the fully compliant uri-permitted-ok** —
`validation failed: candidates exhausted: unsupported name constraint`.

## Findings

### F1. DNS name constraints are solidly enforced by every modern stack

All five tested verifiers enforce permitted and excluded DNS subtrees, and all
enforce them **even when the extension is non-critical**. Research corroborates
across the untested stacks: OpenSSL since 1.0.0, Go since 1.10, Java PKIX
(including CN-as-dNSName synthesis), mozilla::pkix (CN fallback too, 100% on
BetterTLS 2017), Chrome's verifier (BoringSSL `pki/`), Apple since macOS
10.13.3 (CVE-2018-4086, the BetterTLS-driven fix), rustls-webpki, pyca ≥42.
The one weak stack is **GnuTLS**: DNS/email only, with a still-open
case-folding bypass (`Bad.Example.COM` evades an excluded `bad.example.com`,
gnutls#1803) and CVE-2026-42011 (permitted subtrees ignored when earlier CAs
carried only excluded subtrees).

### F2. URI name constraints are the fault line — and the failure mode is not "silently permitted," it is "legitimate chains rejected"

The mission brief assumed the risk was *spotty enforcement* (a violating cert
slipping through). The measured and researched reality is mostly the opposite:

- **Enforce correctly (host-part matching)**: Go ≥1.10, OpenSSL ≥1.0.0 (hence
  Node.js and CPython `ssl`), LibreSSL, Java PKIX, current Apple trustd.
- **Hard-reject any chain containing a URI constraint**: rustls-webpki
  ≥0.103.12 rejects *unconditionally* (issue #514 confirms: "a chain
  containing a URI name constraint is now rejected unconditionally");
  versions 0.101.0–0.103.11 **silently ignored excluded-URI subtrees**
  (GHSA-965h-392x-2mh5 / RUSTSEC-2026-0098) — both bad, in opposite ways.
  pyca/cryptography behaves the same (measured above). webpki still has no
  URI SAN verification API at all (rustls/webpki#9, SPIFFE-motivated, open).
- **Reject only when critical + a URI SAN is present, else ignore**: Chrome's
  verifier (`kSupportedNameTypes` = RFC822|DNS|dirName|IP; unsupported types
  tracked only when critical) and mozilla::pkix (rejects on same-type SAN
  presence regardless of criticality).
- **Silently skip URI subtrees**: GnuTLS ("limited to DNS names and emails").

So placing a URI constraint on Signet intermediates makes every leaf under
them **unverifiable by the entire rustls/webpki ecosystem** (much of
cloud-native Rust: linkerd2-proxy, quinn/rustls-based meshes, pyca-based
Python tooling), while providing no scoping at all against GnuTLS verifiers.

### F3. The cross-type gap is real, RFC-conformant, and easy to get wrong

A DNS-only constraint does **not** constrain URI SANs (and vice versa) in
Go, OpenSSL, Apple, and pyca — measured. An intermediate constrains only the
name *forms* it lists; every uncovered form is unlimited. A parent that
constrains a child to `DNS:child.example` but forgets URI/IP/email subtrees
has, from the verifier's perspective, delegated unlimited authority over
those forms. Conversely LibreSSL is *stricter* than RFC: it extracts the host
from URI (and email) SANs and additionally checks it against **DNS** permitted
subtrees — measured: a URI SAN `spiffe://other.example/…` under a DNS-only
constraint is rejected by LibreSSL but valid everywhere else. Consequence:
DNS and URI subtrees on a Signet intermediate must always be host-aligned or
LibreSSL clients will reject legitimate certs.

### F4. Mixed SANs poison whole certs; CN handling diverges; criticality is safe to assert

- A leaf with one in-scope SAN and one out-of-scope SAN is rejected by all
  five stacks — constraints are per-certificate, not per-name. Good.
- CN-only leaves: OpenSSL/LibreSSL check Subject CN against DNS constraints;
  Go and Apple accept the chain (Go ignores CN entirely since 1.17). Signet
  must never treat constraints as bounding CN-only certs — and must never
  issue SAN-less certs (pyca refuses them outright anyway).
- Critical vs non-critical: RFC 5280 says MUST-critical; the CA/B "MAY be
  non-critical" exception (Ballot 75, 2012, still in BR §7.1.2.10.8) existed
  because pre-2018 Apple rejected critical-NC chains and ignored non-critical
  ones. That platform is gone. Every stack tested enforces non-critical
  constraints anyway, and marking critical is what makes unsupporting
  verifiers fail *closed* (Chrome only fail-closes on critical). For a
  private PKI in 2026: **mark critical**.

### F5. Enforcement code itself has a steady bug tail

Name-constraint verifiers keep yielding CVEs even in the best stacks: Go —
URI-constraint bypass via IPv6 zone IDs (CVE-2024-45341), excluded subtree
vs wildcard miss (CVE-2025-61727), email-constraint mismatch ignored
(CVE-2026-27137), case-sensitivity bypass (CVE-2026-33810), constraints
applied to the wrong cert's names pre-1.21 (go#59171); OpenSSL — the 3.0.7
punycode overflows lived in NC email checking (CVE-2022-3602/3786); Node —
SAN-string injection bypassing constraints (CVE-2021-44532); pyca — wildcard
escapes (GHSA-m2h6-j472-rp4c, GHSA-m959-cc7f-wv43). CVE-2021-3450 (OpenSSL
`X509_STRICT`) turns out to be a basicConstraints bypass, not NC — but the
overall record says: relying-party constraint checking is a moving target,
not a bedrock.

### F6. SPIFFE looked at this exact bet and declined it

X509-SVID spec §4.2, verbatim: *"There is a distinct lack of support for URI
type name constraints in the wild. Libraries which don't support them will
reject such certificates, preventing path validation from occurring
successfully… signing certificates MAY apply URI name constraints as the
implementor sees fit, though caution is urged."* SPIRE emits **no** name
constraints on its CAs (credtemplate builder sets neither
`PermittedURIDomains` nor any other subtree). Trust-domain scoping in SPIFFE
is done **verifier-side by bundle partitioning**: per-trust-domain bundles,
never merged ("Doing so would enable one trust domain to forge identities
belonging to another" — Federation spec §4.2), and the verifier must select
the bundle matching the presented ID's trust domain (§7.3). The 2026
rustls-webpki behavior is exactly the breakage the spec predicted.

## Recommendation

**The bet, as stated, is unsound.** "Every independent verifier enforces
this, offline" is true for DNS constraints on modern stacks, but false for
the URI/SPIFFE half of the model — where the dominant failure mode is that
constraint-bearing chains are *unverifiable* in the webpki family, and
unconstrained in GnuTLS. Name constraints cannot be the primary enforcement
mechanism. Adopt the hybrid the charter already gestures at (principle 3,
"Issuer-side enforcement"):

### Primary: signet-side issuance validation (authoritative, always on)

1. **Scope lives in the chain; enforcement lives in the issuer.** A child
   domain's Signet reads its own intermediate's constraints (plus a signed
   delegation record from the parent covering scope that certs can't express
   — OIDC issuer URLs, SSH principals, KV mount prefixes) as its authoritative
   issuance scope. Every issuance request is validated against that scope
   *before signing*. This preserves 02's "everything is derived from the
   chain, not configured."
2. **Verify-after-sign lint gate.** After signing and before releasing any
   cert, the issuing node re-validates: (a) full chain verification of the
   new cert against the domain's own trust bundle using Go's verifier, and
   (b) an independent scope lint that checks **every** SAN (DNS, URI, IP,
   email) and the Subject against the delegation scope — including forms the
   chain's constraints don't cover (the F3 gap), CN-only shapes (F4), and
   URI host tricks like IPv6 zone IDs (F5). Two code paths must agree or the
   cert is quarantined and the event logged. Cheap (microseconds) and catches
   both compromise and Signet's own bugs.
3. **Append-only issuance log per domain, auditable by the parent.** Every
   signature the domain's CA key makes is logged (feeds 01/03). Parent audits
   child logs opportunistically; a cert that exists but isn't in the log is
   the compromise signal. This is what actually bounds a *fully compromised*
   child server, which no amount of in-process validation survives.

### Containment: short-lived intermediates

4. **Child intermediates are renewed frequently and live modestly.** A
   compromised or misbehaving child is cut off by *not renewing*, without
   CRL/OCSP machinery. Concretely: intermediate lifetime 90 days, renewed
   every 30 → a revoked subtree dies ≤90 days out even if revocation
   artifacts never propagate, while a partition of up to ~60 days leaves the
   child fully operational. **Do not** push lifetimes to days/weeks: charter
   principle 4 (partition tolerance) puts a floor under intermediate
   lifetime — lifetime minus renewal interval is the maximum survivable
   partition. Make both knobs per-delegation policy; pair renewal with
   parent-side review of the child's issuance log (item 3).

### Defense-in-depth: name constraints, carefully profiled

5. **Always emit DNS constraints** (permitted subtrees = delegated DNS
   namespace; excluded as needed). Enforcement is effectively universal (F1).
6. **Close the cross-type gap explicitly**: on every constrained
   intermediate, also emit IP subtrees (delegated ranges, or exclude
   `0.0.0.0/0` and `::/0` when no IP issuance is delegated) and email
   subtrees (delegated domain, or exclude all). Enforcement of IP/email is
   solid in every stack tested (measured VALID/REJECT correctly in all five).
7. **URI constraints are a per-delegation opt-in, default OFF.** Emitting
   them breaks rustls-webpki and pyca verification of *legitimate* certs
   (F2) — in the first deployment that's a risk to any Rust-based mesh or
   Python tooling, and the SPIFFE spec itself urges against relying on them.
   Offer `uri_constraints: emit` for closed ecosystems known to be
   Go/OpenSSL/Java/Apple-only, where they add real offline containment.
   When emitted, keep URI subtree hosts inside the DNS permitted set
   (LibreSSL cross-check, F3).
8. **Mark the extension critical** (F4). **Never issue SAN-less certs.**
9. **SPIFFE-style workload identity is scoped by bundle partitioning, not
   constraints** — adopt the SPIFFE federation model verbatim for both
   federation *and* sibling-domain isolation: verifiers hold per-trust-domain
   bundles and select the bundle by the presented ID's trust domain; bundles
   are never merged. The chain hierarchy remains the *distribution* and
   *revocation* structure; it is not the workload-identity *authorization*
   boundary for third-party verifiers.

Net effect on the model: delegation still "only narrows," but the narrowing
is enforced at the point Signet controls (issuance) and *additionally*
communicated to relying parties via constraints where the ecosystem can
digest them. The elegant sentence in 02 becomes: *the hierarchy is the PKI
chain; the chain carries the scope; the issuer enforces it; verifiers that
can enforce it too, do.*

## Impact on design docs

**02-trust-topology.md** (do not edit yet — fold in after review):

- §"Hierarchy = the PKI chain (Decided)": the bullet "every independent
  verifier enforces this, offline" must be rewritten — verifier enforcement
  is real for DNS but inconsistent-to-hostile for URI forms. State the
  hybrid: issuer-side validation primary (charter P3), constraints as
  defense-in-depth per the profile above (DNS+IP+email always, critical,
  URI opt-in). The section can stay **Decided** with the enforcement claim
  corrected; the *shape* (delegation via constrained intermediates) survives.
- Same section, add a consequence: intermediates are short-lived
  (90d/30d renewal, per-delegation policy); "revoking a subtree = revoking
  one intermediate" becomes "= declining one renewal," and the partition
  floor (lifetime − renewal interval ≥ max tolerated partition) must be
  stated next to the partition-tolerance claim.
- §"Federation between equals": strengthen — bundle partitioning is not just
  the federation mechanism, it is the *workload-identity scoping* mechanism
  everywhere (SPIFFE Federation §4.2/§7.3 semantics: bundles never merged,
  bundle selected by trust domain of presented ID). Feeds E-12; leaning
  SPIFFE-compatible is now firmly justified.
- §"Trust configuration surface": "allowed issuance scope … derived from the
  chain" stands, but add the signed delegation record for non-X.509 scope
  (OIDC issuer, SSH principals, KV prefixes) and note the issuer, not the
  relying party, is the enforcement point.
- §"Open questions": close "Name-constraint enforcement reality" citing this
  report; add two new items — (a) issuance-log audit protocol
  (parent-audits-child; feeds 01/03), (b) intermediate renewal ceremony
  and its partition-floor policy knob (feeds 06/11).

**Also touched**: 01-threat-model (child-compromise containment now =
issuance log + non-renewal + constraint DiD; parent-compromise question
unchanged), 06-credential-lifecycle (intermediate renewal joins the freshness
ladder), 10-testing-strategy (add a BetterTLS-style cross-verifier
name-constraint suite — the 15-case matrix here is the seed; run Go, OpenSSL,
LibreSSL, pyca, and rustls-webpki in CI against every profile change).

## Confidence, and what would change the conclusion

**High** on the core verdict. The empirical matrix (5 verifiers × 15 cases,
run today on current versions) and the independent web research agree on
every overlapping cell, including the surprising ones (pyca/webpki hard
reject; LibreSSL cross-type strictness), and the SPIFFE community reached
the same conclusion from production experience.

Would change the conclusion:

- **rustls-webpki shipping URI-constraint enforcement** (or the opt-in
  ignore of webpki#514 becoming default) *and* pyca following — the two
  fail-closed stacks are the main reason URI constraints default OFF. If
  the webpki family enforces correctly, flip the default to emit, keeping
  issuer-side as primary regardless (the CVE tail in F5 alone justifies
  that ordering permanently).
- **BetterTLS publishing a fresh (post-2021) run** showing regressions in
  DNS-constraint enforcement in a stack the first deployment depends on —
  would demote constraints further, from defense-in-depth to advisory.
- Evidence that the first deployment's actual verifier set is strictly
  Go/OpenSSL (ESO, cert-manager, kubectl, Grafana, ArgoCD are all Go; sshd
  doesn't consume X.509) — would justify enabling `uri_constraints: emit`
  for the homelab profile specifically, as a worked example of the opt-in.

**Untested empirically here** (research-only): Java PKIX, Chrome, Firefox,
GnuTLS, rustls-webpki itself (no Rust toolchain on this host — pyca's
Rust verifier served as the family proxy, and webpki's behavior is
documented in its own 2026 advisories). Running the matrix through actual
rustls-webpki is the first task for the CI suite proposed for doc 10.
