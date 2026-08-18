# 04 — Test plan: PKI and the CA ceremonies

**Status: Draft.** Scope: `internal/ca`, `internal/kernel/pki.go`,
`internal/dialect/vaultkv/pki.go`, `cmd/signet/ca.go`, and the genesis CA path in
`cmd/signet/main.go`. Companion to [10-testing-strategy](../10-testing-strategy.md)
layers 1, 5 and 6.

Everything below is grounded in `file:line` against the tree as of 2026-08-18.
No source or existing test was modified in producing it.

---

## 0. The three rules this plan is built on

**R1 — The issuer is the primary control; constraints are defence in depth.**
E-02 measured five verifiers against fifteen chains
([E-02 §Empirical results](../explorations/E-02-name-constraints.md), lines 66–91)
and found enforcement is *not* uniform: pyca/rustls-webpki **reject a fully
compliant chain** merely for carrying a URI constraint (`uri-permitted-ok`
REJECT, E-02:73), LibreSSL is *stricter* than RFC and rejects a URI SAN under a
DNS-only constraint (`crosstype-dnsconstr-urileaf` REJECT, E-02:75), and
OpenSSL/LibreSSL reject CN-only leaves that Go accepts (E-02:82). Therefore
**every refusal test in this plan must assert Signet's own refusal, at the
issuer, without reference to what any verifier would have done.** A test that
proves "a verifier rejects it" proves nothing about `checkNames`
(`internal/ca/ca.go:465`), and a test that proves "Go's verifier accepted it"
proves nothing about the wider world.

**R2 — Verify-after-sign means the certificate must be WITHHELD, not returned.**
`Sign` builds `issued` at `internal/ca/ca.go:398` *before* the gate runs at
`ca.go:407-411`. Tests must assert the returned `*Issued` is `nil` and no PEM
escaped, not merely that `err != nil`. Every existing gate test asserts only the
error (`ca_test.go:164, 179, 194, 209`).

**R3 — Check our certificates with something that is not our code.** `Verify`
(`ca.go:422`) uses `crypto/x509`; so does every current Go test. Where a
scenario is marked **EXT** it must be asserted with `openssl` / LibreSSL / pyca
against emitted PEM, in the style already established by
`test/trust/run.sh:10` ("Verification here is done with openssl, not with
Signet's own code. Checking our certificates with our own verifier would prove
considerably less") and `test/kind/run.sh:138-143`.

### Measured while writing this plan (2026-08-18, this machine)

Three claims below were checked empirically rather than asserted, with a
standalone harness (scratchpad, ~90 lines) emitting the *exact* constraint
profile `applyNameConstraints` produces (`internal/ca/ca.go:219-234`) and
verifying with Go 1.26, OpenSSL 3.6.3, and LibreSSL 3.3.6:

| emitted profile / leaf | Go | OpenSSL 3.6.3 | LibreSSL 3.3.6 |
|---|---|---|---|
| permit DNS `example.com`; leaf DNS `web.example.com` | ACCEPT | ACCEPT | ACCEPT |
| same; leaf DNS **`*.example.com`** | **ACCEPT** | **ACCEPT** | **ACCEPT** |
| same; leaf DNS `web.example.com.` (trailing dot) | REJECT `cannot parse dnsName` | — | — |
| **`ExcludedEmailAddresses = [""]`**; leaf email `a@example.com` | REJECT | **ACCEPT** | REJECT |
| control: `ExcludedEmailAddresses = ["evil.test"]`; leaf email `a@evil.test` | REJECT | REJECT | REJECT |
| control: `ExcludedIPRanges = 0.0.0.0/0, ::/0`; leaf IP `10.1.2.3` / `fd00::1` | REJECT | REJECT | REJECT |

The control row matters: OpenSSL *does* enforce excluded email subtrees, it
simply treats the empty-string form as matching nothing. So the exclude-all-email
line at `ca.go:233` — the line that closes the email half of the cross-type gap
doc 02:65-67 declares mandatory — **is a no-op in the most widely deployed
verifier**, and the wildcard hole (`PKI-ISS-17`) is caught by no verifier at all.
See `PKI-NC-04`, `PKI-EXT-04`, Q4, Q7.

### Coverage summary

| Group | Scenarios | Covered today | Partial | GAP |
|---|---:|---:|---:|---:|
| A. Split ceremony (`CER`) | 24 | 6 | 3 | 15 |
| B. Name constraints as emitted (`NC`) | 11 | 1 | 1 | 9 |
| C. Issuance against roles, positive (`ISS`) | 17 | 4 | 3 | 10 |
| D. Negative issuance (`NEG`) | 32 | 7 | 0 | 25 |
| E. Verify-after-sign gate (`GATE`) | 10 | 4 | 0 | 6 |
| F. Issuance log (`LOG`) | 8 | 0 | 0 | 8 |
| G. Multi-issuer selection (`SEL`) | 8 | 1 | 1 | 6 |
| H. Vault sign route (`API`) | 13 | 1 | 2 | 10 |
| I. External-verifier suite (`EXT`) | 10 | 2 | 0 | 8 |
| **Total** | **133** | **26** | **10** | **97** |

"Covered" means an existing assertion would fail if the behaviour regressed.
"Partial" means the code path runs in an existing test but the property in the
scenario is not asserted.

### Top gaps by risk

1. **`PKI-NEG-11` / Q8 — `uriAllowed` is a bare `strings.HasPrefix`**
   (`ca.go:508-515`). A role permitting `spiffe://home.example` also permits
   `spiffe://home.example.evil/...`. Because URI constraints are deliberately
   never emitted, this predicate is the *only* control over SPIFFE identity
   issuance in the entire system. Same bug class the DNS path documents itself
   as avoiding.
2. **`PKI-NC-04` / Q4 — exclude-all-email is a no-op in OpenSSL** (measured).
   The email half of the cross-type gap doc 02 calls mandatory is open in the
   most widely deployed verifier.
3. **`PKI-NC-08` / Q2 — `genesis -ca-common-name` without `-ca-domains`
   produces a wholly unconstrained intermediate**, discarding `-ca-ip-ranges`
   and contradicting that flag's own help text. `ca sign-issuer` refuses the
   same configuration.
4. **`PKI-ISS-17` / Q7 — wildcard SANs are issuable under `AllowSubdomains`**
   and accepted by every verifier tested. No knob exists to refuse them.
5. **`PKI-GATE-07`, `PKI-GATE-08`, `PKI-GATE-09` — the withholding property is
   never asserted.** Every existing gate test checks `err != nil` only
   (`ca_test.go:164,179,194,209`); none checks that no certificate was
   returned, and nothing at all covers "signed but not logged ⇒ withheld"
   (`kernel/pki.go:204-212`), which is the charter's principle-6 promise.

Runners-up: `PKI-CER-11`/Q1 (`AssembleIssuer` does not do what its comment
says), and the total absence of any test for `internal/kernel/pki.go` or the
Vault sign route.

---

## A. The split ceremony (`PKI-CER-*`)

The flow under test — root created once and kept offline, each node generating
its issuing key in its own custody and receiving a CSR-signed intermediate — is
`cmd/signet/ca.go:26-30` over `internal/ca/ceremony.go:41,113,160,220,249`.

| ID | Preconditions | Input | Expected | Coverage |
|---|---|---|---|---|
| `PKI-CER-01` | none | `NewRoot("Test", 10y, now)` | Self-signed; `IsCA`; `KeyUsage == CertSign\|CRLSign`; `MaxPathLen == 1`; `BasicConstraintsValid`; `Subject.CN == "Test Root CA"`; `NotBefore == now-5m` | **GAP** — `ceremony.go:80-89` unasserted. `ceremony_test.go:44` only checks err |
| `PKI-CER-02` | none | `NewRoot(...)` then `AssembleIssuer` | `Root.KeyPEM` non-empty and returned to the caller; the byte string of the root key appears nowhere in the assembled `Material` | Covered — `ceremony_test.go:142-168` |
| `PKI-CER-03` | SoftHSM token (`make softhsm`) | `NewRootInHardware(ss, "Test", "lbl", 10y, now)` | `Root.KeyPEM` empty, `Root.Ref != nil`; cert self-signature verifies; a second call with the same label is either idempotent or a clean error | **GAP** — `ceremony.go:59-73` untested |
| `PKI-CER-04` | file seal | `NewIssuerRequest(fileSeal, "issuer a", "lbl")` | `KeyPEM` set, `Ref` nil; `csr.CheckSignature() == nil`; `csr.Subject.CN == "issuer a"`; CSR public key equals the public half of `KeyPEM` | Partial — helper at `ceremony_test.go:59`; the last two properties unasserted |
| `PKI-CER-05` | SoftHSM signing seal | `NewIssuerRequest(pkcs11Seal, cn, label)` | `Ref` set, `KeyPEM` **empty**; CSR public key equals the token key; no private bytes anywhere in the returned struct | **GAP** — `ceremony.go:114-128` untested |
| `PKI-CER-06` | root exists | inspect what crosses the wire | `IssuerRequest` sent to the root carries only `CSRPEM`; `SignIssuer` takes no key from the node; the node's `KeyPEM`/`Ref` never leave `issuer-pending.json` (`cmd/signet/ca.go:175-182`) | Partial — asserted only indirectly (`ceremony_test.go:160-167`) |
| `PKI-CER-07` | one root | three `NewIssuerRequest` + `SignIssuer` | Three issuers, distinct SPKIs, each chains to the one root, each carries `PermittedDNSDomains == ["example.com"]` | Covered — `ceremony_test.go:42-100` |
| `PKI-CER-08` | root + issuer | inspect issuer cert | `MaxPathLenZero == true` / `MaxPathLen == 0` (`ceremony.go:195`), so the issuer cannot certify a sub-CA. **EXT**: build a sub-CA under it and confirm `openssl verify` refuses the 4-cert path | **GAP** |
| `PKI-CER-09` | two roots A and B | `LoadRootSigner(rootA.CertPEM, rootB.KeyPEM, nil, nil)` then `SignIssuer` | Refused. Today `LoadRootSigner` (`ceremony.go:220-245`) does **not** check the key matches the certificate, so the refusal comes late, from the release gate at `ceremony.go:212-215`. Assert (a) it is refused and (b) which layer refused — that is the regression signal | **GAP** — see Q3 |
| `PKI-CER-10` | signed issuer cert | `AssembleIssuer(rootPEM, issuerPEM, req)` | `Material` carries root cert, issuer cert, and the node's own key/ref; root private key absent | Covered — `ceremony_test.go:156-167` |
| `PKI-CER-11` | node X's `req`, node Y's signed cert | `AssembleIssuer(rootPEM, issuerY, reqX)` | **Should refuse**: the certificate's SPKI does not match the key this node holds. `ceremony.go:257-258` claims exactly this ("Confirm the certificate actually matches the key this node holds") but `ceremony.go:259-261` only parses the certificate. **Suspected live bug** | **GAP** — see Q1 |
| `PKI-CER-12` | root A cert, issuer signed by root B | `AssembleIssuer(rootA, issuerB, req)` | **Should refuse**: the material does not form a chain. Today accepted here and again by `ca.Load` (`ca.go:239-289`) and `applyPutCA` (`kernel/pki.go:38-40`), which also never verify the chain. Failure surfaces later as every issuance being withheld | **GAP** — see Q1 |
| `PKI-CER-13` | built binary | full CLI ceremony for two nodes | `ca request` → `ca sign-issuer` → `ca install` succeeds per node; each node signs with its own issuer | Covered — `test/trust/run.sh:40-49` |
| `PKI-CER-14` | node with no `issuer-pending.json` | `signet ca install -cert c -root-cert r` | Refusal naming the missing file and telling the operator to run `ca request` *on this node* (`cmd/signet/ca.go:300-307`) | **GAP** |
| `PKI-CER-15` | `root/root.crt` exists | `signet ca init-root -out root ...` again | Refusal: "Refusing to overwrite a root" (`cmd/signet/ca.go:85-89`); the existing root and key are untouched on disk (compare bytes) | **GAP** |
| `PKI-CER-16` | root dir | `signet ca sign-issuer` without `-domains` | Refusal explaining the namespace is the security decision of the ceremony (`cmd/signet/ca.go:210-215`) | **GAP** |
| `PKI-CER-17` | root dir | sign two different CSRs, then re-sign the first key | `root/issuers/` holds two files named by SPKI fingerprint (`cmd/signet/ca.go:394-405`); the re-sign **replaces** the first entry rather than adding a third | **GAP** — the replace property is what stops stale duplicates entering every future bundle |
| `PKI-CER-18` | root with 24h TTL | `SignIssuer(..., ttl=365d)` | Refused with the "would outlive its root" message (`ceremony.go:182-186`) | Covered — `ceremony_test.go:127-138` |
| `PKI-CER-19` | root | CSR with empty Subject CN | Refused: "carries no common name" (`ceremony.go:174-176`) | **GAP** |
| `PKI-CER-20` | root | CSR with one byte flipped | Refused; the CSR signature check is at `ceremony.go:169-173` | Covered — `ceremony_test.go:104-123` |
| `PKI-CER-21` | root | CSR over an RSA-2048 key | Define the answer. Today `SignIssuer` accepts it (`x509.CreateCertificate` at `ceremony.go:199` is algorithm-agnostic) while `ca.Load` can only parse EC (`ca.go:283` `ParseECPrivateKey`) — so an RSA issuer is certifiable but not loadable | **GAP** — see Q6 |
| `PKI-CER-22` | SoftHSM | `init-root -in-hardware` → `sign-issuer -seal ...` → `install` | End-to-end hardware ceremony; `root.ref` written 0600 (`cmd/signet/ca.go:121-125`); no `root.key` produced; `sign-issuer` without `-seal` refuses with the "held in hardware" message (`cmd/signet/ca.go:231-234`) | **GAP** |
| `PKI-CER-23` | domain with two issuers | `signet ca issuers -data-dir …` | Lists both, custody column `sealed`/`hardware` (`cmd/signet/ca.go:380-387`) | **GAP** |
| `PKI-CER-24` | clock at `now` | any ceremony | `NotBefore == now-5m` on root, issuer, and leaf (`ceremony.go:84,190`, `ca.go:370`) — the skew allowance is deliberate and a regression to `now` would break freshly-issued certs on skewed clients | **GAP** |

---

## B. Name constraints as emitted (`PKI-NC-*`)

`applyNameConstraints` (`internal/ca/ca.go:219-234`) is the whole profile. Doc
02 (`docs/02-trust-topology.md:63-79`) promises: DNS always, IP and email always
(closing the cross-type gap), URI opt-in default OFF, extension critical, never
SAN-less.

| ID | Preconditions | Input | Expected | Coverage |
|---|---|---|---|---|
| `PKI-NC-01` | — | `SignIssuer(..., permittedDNS=["example.com"], permittedIPs=nil)` | `PermittedDNSDomains == ["example.com"]` **and** `PermittedDNSDomainsCritical == true` (`ca.go:223-224`) | Partial — `ceremony_test.go:95-99` checks the domains, never the critical bit |
| `PKI-NC-02` | — | same input, plus leaves carrying `10.1.2.3` and `fd00::1` | `ExcludedIPRanges` contains exactly `0.0.0.0/0` and `::/0` (`ca.go:228-231`). **Measured: this half works** — both leaves are rejected by Go, OpenSSL 3.6.3 and LibreSSL 3.3.6 alike, which is why the email result in `PKI-NC-04` is a specific defect rather than a general limit on exclude-all encodings | **GAP** (behaviour correct, assertion missing) |
| `PKI-NC-03` | — | `permittedIPs=[10.0.0.0/8]` | `PermittedIPRanges == [10.0.0.0/8]` and `ExcludedIPRanges` empty (`ca.go:225-227`) | **GAP** |
| `PKI-NC-04` | — | any constrained issuer, leaf carrying an email SAN | `ExcludedEmailAddresses == [""]` (`ca.go:233`) must actually exclude all email. **MEASURED: it does not.** Go and LibreSSL reject the leaf; **OpenSSL 3.6.3 accepts it**, while rejecting the same leaf under a *named* excluded subtree. The email cross-type gap is open in OpenSSL. Test must assert the fix across all three verifiers, not just Go | **GAP — confirmed defect**; see Q4 |
| `PKI-NC-05` | — | every issuer Signet emits | `PermittedURIDomains` and `ExcludedURIDomains` are **empty** — E-02 F2 says emitting them makes legitimate leaves unverifiable in the whole rustls-webpki/pyca family | **GAP** |
| `PKI-NC-06` | — | a delegation that opts in to URI constraints | Doc 02:70-74 promises `uri_constraints: emit` as a per-delegation opt-in. **There is no such parameter anywhere in the code** — `applyNameConstraints` takes only DNS and IP. Either the doc is ahead of the code or the feature is dropped | **GAP (unimplemented)** — see Q5 |
| `PKI-NC-07` | — | `SignIssuer(..., permittedDNS=nil, permittedIPs=[10.0.0.0/8])` | `applyNameConstraints` returns at `ca.go:220-222` before doing anything, so the issuer gets **no constraints at all** — no DNS, no IP exclusion, no email exclusion, and the caller's IP ranges are silently discarded. Assert this is refused, or that the early return is keyed on "no constraints requested at all" | **GAP** — see Q2 |
| `PKI-NC-08` | — | `signet genesis -ca-common-name X` with no `-ca-domains` | Same wholly-unconstrained intermediate, reachable from the primary CLI: `main.go:341` `permitted := splitList("")` → nil → `NC-07`. Note `-ca-ip-ranges`' own help text (`main.go:176`) promises "IP SANs are excluded outright" by default, which is false in this configuration. Contrast `ca sign-issuer`, which *requires* `-domains` (`cmd/signet/ca.go:210`) | **GAP** — highest-risk single finding |
| `PKI-NC-09` | constrained issuer | leaf with DNS SAN inside the subtree | **EXT**: `openssl verify -CAfile root -untrusted issuer leaf` succeeds; re-run with `-x509_strict` | Covered for the shape — `test/trust/run.sh:88-91`, `test/kind/run.sh:138-143` — **GAP** for `-x509_strict` |
| `PKI-NC-10` | constrained issuer | hand-forged leaf with DNS SAN outside the subtree, signed by the issuer key | **EXT**: `openssl verify` fails with `permitted subtree violation` (error 47). This is the defence-in-depth half; `GATE-01` is the primary half and must be asserted separately | **GAP** |
| `PKI-NC-11` | issuer constrained to DNS only, role permits a URI prefix | leaf with a `spiffe://` URI SAN | **EXT, expected to FAIL on LibreSSL**: E-02 F3 (`E-02:75`, `crosstype-dnsconstr-urileaf`) measured LibreSSL rejecting exactly this shape. Signet's default profile can therefore issue SPIFFE leaves that LibreSSL clients refuse. Measure it, record it, and decide whether URI SANs require a DNS-host-aligned constraint | **GAP** — see Q5 |

---

## C. Issuance against PKI roles — positive (`PKI-ISS-*`)

Role shape: `internal/ca/ca.go:114-123`. Test role helper: `ca_test.go:57-63`.

| ID | Preconditions | Input | Expected | Coverage |
|---|---|---|---|---|
| `PKI-ISS-01` | role `{example.com}`, `AllowBareDomains` | CSR CN+SAN `example.com` | Issued; SAN list is exactly `["example.com"]` | Partial — `domainAllowed` unit only (`ca_test.go:258-261`); never through `Sign` |
| `PKI-ISS-02` | role `{example.com}`, `AllowSubdomains` | CSR CN+SAN `web.example.com` | Issued; CN, SAN, `IsCA == false`, serial and chain present | Covered — `ca_test.go:65-104` |
| `PKI-ISS-03` | same | SAN `a.b.example.com` | Issued (multi-label subdomains are subdomains) | Partial — `ca_test.go:266` at unit level only |
| `PKI-ISS-04` | role with several `AllowedDomains` | SANs drawn from two of them in one request | Issued; both SANs present | **GAP** |
| `PKI-ISS-05` | role `AllowSubdomains` | SAN `WEB.EXAMPLE.COM.` (upper case, trailing dot) | `domainAllowed` says yes (`ca.go:486`). But the *unnormalised* name is what enters `tmpl.DNSNames` (`ca.go:376`), and — measured — Go's constraint matcher then fails with `x509: cannot parse dnsName "web.example.com."`, so with a constrained issuer the gate withholds the certificate behind a confusing error. Assert the whole-path behaviour, then decide: normalise on the way in, or refuse up front | **GAP** — unit test at `ca_test.go:273-275` asserts only the predicate |
| `PKI-ISS-06` | role `AllowIPSANs`, issuer signed with `-ip-ranges 10.0.0.0/8` | CSR with IP SAN `10.1.2.3` | Issued; `cert.IPAddresses == [10.1.2.3]`. **Both halves are required** — the role permits the *form*, the issuer's `PermittedIPRanges` permits the *range* | **GAP** — no positive IP test exists |
| `PKI-ISS-07` | role `AllowedURIPrefix: ["spiffe://home.example/ns/prod/"]` | CSR with URI SAN `spiffe://home.example/ns/prod/sa/api` | Issued; `cert.URIs` carries it exactly | **GAP** — no positive URI test exists anywhere |
| `PKI-ISS-08` | role `MaxTTLSeconds = 86400` | `TTL: 365d` | Silently **clamped** to 24h, not refused (`ca.go:352-354`) | Covered — `ca_test.go:232-246` |
| `PKI-ISS-09` | same | `TTL: 0` | Clamped to the role maximum (same branch, `ttl <= 0`) | **GAP** |
| `PKI-ISS-10` | role `MaxTTLSeconds = 0` | `TTL: 0` | 24h default (`ca.go:349-351`); and `Verify`'s TTL check is skipped entirely when `MaxTTLSeconds == 0` (`ca.go:449`) — assert the leaf is still bounded by the issuer | **GAP** |
| `PKI-ISS-11` | issuer expiring in 1h, role max 24h | `TTL: 24h` | `NotAfter` clamped to the issuer's `NotAfter` (`ca.go:356-359`); `Verify`'s "leaf outlives its issuer" check (`ca.go:454-456`) passes | **GAP** |
| `PKI-ISS-12` | role `{example.com}`, subdomains | `CommonName: "web.example.com"`, `ExcludeCNFromSANs: true`, CSR SAN `api.example.com` | CN in Subject, **not** in `DNSNames` (`ca.go:341-343`), but still scope-checked (`ca.go:471-473`) | **GAP** |
| `PKI-ISS-13` | — | `Request.CommonName` empty, CSR CN `web.example.com` | CSR CN used (`ca.go:336-339`) | **GAP** |
| `PKI-ISS-14` | — | CSR SANs `[web.example.com]` + `Request.DNSNames = [web.example.com, api.example.com]` | Merged and deduped (`ca.go:340,583-594`); `web.example.com` appears once | **GAP** |
| `PKI-ISS-15` | kernel with role, CA, and a principal bound `sign` at the role's scope | `k.SignCertificate(ctx, sess, "default", "srv", req)` | Issued, and an `IssuanceRecord` exists for the serial | **GAP** — `internal/kernel` has **no** `pki_test.go` at all |
| `PKI-ISS-16` | issuer whose material was sealed then rewrapped | `Material.Rewrap(from, to)` then sign | Signing still works after a seal rotation; certificates are untouched (`ca.go:610-627`) | Partial — `kernel/sealrotate_test.go:39-43` installs a CA but does not sign after rotating |
| `PKI-ISS-17` | role `{example.com}`, `AllowSubdomains` | SAN `*.example.com` | **Currently issued, and accepted by every verifier** — measured ACCEPT in Go, OpenSSL 3.6.3 and LibreSSL 3.3.6. `domainAllowed` matches `HasSuffix("*.example.com", ".example.com")` (`ca.go:501`); the gate passes; nothing downstream objects. There is no `allow_wildcard` knob (Vault has one). Also test `*.com` (correctly refused by the issuer's constraint) and `www.*.example.com` | **GAP** — see Q7 |

---

## D. Negative issuance (`PKI-NEG-*`)

Every row is an assertion that **Signet refuses**, independent of any verifier
(R1). For each, assert the error is non-nil, the returned `*Issued` is nil (R2),
and — where the kernel is involved — that no issuance record was written.

### D.1 Requests that lie

| ID | Preconditions | Input | Expected | Coverage |
|---|---|---|---|---|
| `PKI-NEG-01` | role `{example.com}` | CSR with a flipped byte | Refused at `ca.go:332-334` | Covered — `ca_test.go:216-230` |
| `PKI-NEG-02` | — | `CSRPEM` = random bytes / empty / a PEM CERTIFICATE block / a valid CSR wrapped in the wrong PEM type | Refused at `ca.go:551-561`; message names the CSR, never panics. Candidate for a Go fuzz target (doc 10 layer 3) | **GAP** |
| `PKI-NEG-03` | role `{example.com}` subdomains | SAN `evil.test` | Refused — "not permitted by role" | Covered — `ca_test.go:118-119` |
| `PKI-NEG-04` | same | SAN `notexample.com` | Refused | Covered — `ca_test.go:120-121` |
| `PKI-NEG-05` | same | SAN `evilexample.com` (suffix without a dot boundary) | Refused (`ca.go:501` requires the `.`) | Covered — `ca_test.go:122-123` |
| `PKI-NEG-06` | same | SANs `[web.example.com, evil.test]` | Refused **entirely** — one bad name poisons the request (matches E-02 F4, constraints are per-certificate) | Covered — `ca_test.go:123-125` |
| `PKI-NEG-07` | same | CSR clean, `Request.DNSNames = ["evil.test"]` | Refused — the dialect-supplied names are checked too (`ca.go:340`) | Covered — `ca_test.go:125-127` |
| `PKI-NEG-08` | role without `AllowIPSANs` | CSR with IP SAN `10.0.0.1` | Refused at `ca.go:474-476` | Covered — `ca_test.go:128-129` |
| `PKI-NEG-09` | role with `AllowIPSANs`, issuer with **no** delegated IP range | CSR with IP SAN `10.0.0.1` | Refused — the role permits the form, but the issuer excludes `0.0.0.0/0`, so the gate's chain build fails (`ca.go:432-439`) and the certificate is withheld. **This is the scenario that proves the two controls compose** | **GAP** |
| `PKI-NEG-10` | role with no `AllowedURIPrefix` | CSR with URI SAN `spiffe://other.example/ns/x` | Refused at `ca.go:477-481` | Covered — `ca_test.go:130-131` |
| `PKI-NEG-11` | role `AllowedURIPrefix: ["spiffe://home.example"]` | URI SAN `spiffe://home.example.evil/ns/x` | **Should be refused. Currently issued** — `uriAllowed` is a raw `strings.HasPrefix` with no authority boundary (`ca.go:508-515`), the same class of bug that `domainAllowed` carefully avoids for DNS. And because URI constraints are never emitted (`NC-05`), **there is no second line of defence**. Also test prefix `"s"`, which matches every `spiffe://` URI | **GAP — suspected live bug**, see Q8 |
| `PKI-NEG-12` | role `AllowedURIPrefix: ["spiffe://home.example/ns/prod"]` | URI `spiffe://home.example/ns/production-evil/sa/x` | Same bug, path-segment variant | **GAP** |
| `PKI-NEG-13` | role `{example.com}` subdomains | URI `spiffe://home.example/%2e%2e/x`, `spiffe://home.example%00.evil/x`, and an IPv6-zone host (E-02 F5 / CVE-2024-45341) | Refused or normalised — never accepted on the strength of a decoded-vs-raw mismatch between `url.Parse` (`ca.go:386`) and `uriAllowed` (which matches on `u.String()`, `ca.go:575-581`) | **GAP** |
| `PKI-NEG-14` | role `{example.com}` | `CommonName: "web.example.com evil.test"` and a valid SAN | `looksLikeDNS` returns false for anything containing a space (`ca.go:517-519`), so the CN is neither scope-checked nor added to SANs — an arbitrary unvalidated Subject. Decide whether the CN must always be checked | **GAP** — see Q9 |
| `PKI-NEG-15` | role `{example.com}` | `CommonName: "10.0.0.1"` with a valid DNS SAN | CN is IP-shaped so `looksLikeDNS` is false; it lands in the Subject unchecked while the role forbids IP SANs. Assert the intended behaviour | **GAP** |
| `PKI-NEG-16` | role `{example.com}` | CSR carrying an email SAN `alice@evil.test` | The email is dropped, not carried (`Sign` never copies `csr.EmailAddresses`). Note `checkNames` (`ca.go:465`) takes no email argument at all, so if a future path ever set them nothing would lint them — assert the drop, and treat the lint gap as a finding | **GAP** |
| `PKI-NEG-17` | role `{example.com}` | CSR carrying `basicConstraints CA:TRUE` and `keyUsage keyCertSign` as requested extensions | Not copied into the leaf; `cert.IsCA == false`; the gate would catch it regardless (`ca.go:441-443`) | **GAP** |

### D.2 TTL and lifetime

| ID | Preconditions | Input | Expected | Coverage |
|---|---|---|---|---|
| `PKI-NEG-18` | role max 24h | `TTL: 365d` | **Clamped, not refused** (`ca.go:352-354`) — record this as the supported answer so a future "refuse instead" change is a deliberate break, and assert the emitted `NotAfter ≤ now+24h` | Covered — `ca_test.go:232-246` |
| `PKI-NEG-19` | issuer already expired | any valid request | Refused: `notAfter` clamps into the past (`ca.go:357-358`) and the gate's chain build fails on expiry (`ca.go:432-439`). Assert *nothing* is returned rather than a zero-length-validity certificate | **GAP** |
| `PKI-NEG-20` | issuer valid, `now` before the issuer's `NotBefore` | request at `now` | Refused by the gate; assert the message is legible enough to diagnose a clock problem | **GAP** |

### D.3 Authority material and installation

| ID | Preconditions | Input | Expected | Coverage |
|---|---|---|---|---|
| `PKI-NEG-21` | material with `IntermediateKeyPEM` in plaintext | `applyPutCA` | Refused with the "refusing to store a plaintext intermediate key" message (`kernel/pki.go:43-48`) — the log must never carry a key the barrier alone can open | **GAP** |
| `PKI-NEG-22` | material whose intermediate PEM is corrupt | `applyPutCA` | Refused via `ca.Load(m, nil)` (`kernel/pki.go:38-40`, `ca.go:244-247`) | **GAP** |
| `PKI-NEG-23` | grantor without domain-wide admin | `InstallCA` | Refused (`kernel/pki.go:28-30` → `apply.go:287-293`) — installing an authority is domain-wide power | **GAP** |
| `PKI-NEG-24` | `Material` sealed, `Load(m, nil)` | `Sign(...)` | Refused: "loaded without its key and cannot sign" (`ca.go:323-325`); the public-only load still publishes the chain (`ca.go:270-274`, `CAChain` at `kernel/pki.go:146`) | **GAP** |
| `PKI-NEG-25` | `Material` with `IntermediateRef`, seal that cannot sign | `Load(m, s)` | Refused with the "held in hardware but …" message (`ca.go:256-261`) | **GAP** |
| `PKI-NEG-26` | material whose intermediate cert does not chain to its root cert | `InstallCA` then `SignCertificate` | Today: install succeeds, every subsequent issuance is withheld by the gate. Assert the current behaviour and file the earlier refusal as the fix (`CER-12`) | **GAP** |

### D.4 Roles and authorization

| ID | Preconditions | Input | Expected | Coverage |
|---|---|---|---|---|
| `PKI-NEG-27` | — | `PutPKIRole` with neither `AllowedDomains` nor `AllowedURIPrefix` | Refused (`kernel/pki.go:66-68`) | **GAP** |
| `PKI-NEG-28` | — | `PutPKIRole` with `Scope: "pki/../.."` or other invalid path | Refused by `ValidatePath` (`kernel/pki.go:63-65`) | **GAP** |
| `PKI-NEG-29` | grantor admin at `/pki/a` | `PutPKIRole` with `Scope: "/pki/b"` | Refused: "grantor … lacks admin authority at …" (`kernel/pki.go:75-81`) — role definition narrows exactly like a grant | **GAP** |
| `PKI-NEG-30` | role at `/pki/server`, principal **not** bound `sign` there | `SignCertificate` | `ErrDenied` before the CA key is touched (`kernel/pki.go:182-188`); dialect maps to 403 (`vaultkv/pki.go:75-77`) | **GAP** |
| `PKI-NEG-31` | — | `SignCertificate` with an unknown role name / unknown CA name | `ErrNotFound` in both cases (`kernel/pki.go:176-178`, `pki.go:271-273`); dialect maps to 404 | **GAP** |
| `PKI-NEG-32` | role permitting `{evil.test}` created by an admin at its own scope; issuer delegated only `example.com` | `SignCertificate` for `evil.test` | **Refused** — `checkNames` passes (the role allows it) but the gate's chain build enforces the issuer's `PermittedDNSDomains` and withholds. This is the one place a name constraint is load-bearing *inside* Signet, and it is untested | **GAP** |

---

## E. The verify-after-sign gate (`PKI-GATE-*`)

`Verify` (`ca.go:422-462`) re-parses the DER, rebuilds the chain against the
CA's own anchors, and re-runs `checkNames` from the certificate's own bytes.
The existing tests forge certificates directly with `c.key` — the right
technique, because it simulates *Sign itself having the bug*.

| ID | Preconditions | Input | Expected | Coverage |
|---|---|---|---|---|
| `PKI-GATE-01` | CA + role | forged cert, SAN `evil.test`, signed by the issuer key | `Verify` refuses (`ca.go:460-461`) | Covered — `ca_test.go:144-166` |
| `PKI-GATE-02` | role max 24h | forged cert with 72h lifetime | Refused (`ca.go:449-453`); note the deliberate 1-minute slack | Covered — `ca_test.go:168-181` |
| `PKI-GATE-03` | — | forged leaf with `IsCA: true` | Refused (`ca.go:441-443`) | Covered — `ca_test.go:184-196` |
| `PKI-GATE-04` | — | forged cert with no SANs, CN only | Refused (`ca.go:444-448`) — E-02 F4: constraints bound SANs, not the CN | Covered — `ca_test.go:200-211` |
| `PKI-GATE-05` | issuer expiring in 1h | forged cert with 24h lifetime, in-scope name, role max 0 (check skipped) | Refused: "leaf outlives its issuer" (`ca.go:454-456`). Must be constructed so the *role* TTL check cannot fire first, or the test proves the wrong branch | **GAP** |
| `PKI-GATE-06` | CA loaded from root A + issuer A | cert signed by issuer **B** | Refused at the chain step (`ca.go:432-439`) with a `chain:` prefixed error | **GAP** |
| `PKI-GATE-07` | CA + role | any request that fails the gate (reuse `NEG-09` or `NEG-32`) | `Sign` returns `(nil, err)` — assert `issued == nil` explicitly, and that no PEM was written to any out-param. All four existing gate tests assert only `err != nil` (`ca_test.go:164,179,194,209`) | **GAP** — this is R2, the point of the whole mechanism |
| `PKI-GATE-08` | kernel, role, CA | request that fails the gate | **No** `IssuanceRecord` exists afterwards (`SignCertificate` returns at `kernel/pki.go:199-202` before proposing) — a withheld certificate must leave no phantom log line | **GAP** |
| `PKI-GATE-09` | kernel whose proposer fails (no quorum / injected error) | valid request | `(nil, "issuance not recorded, certificate withheld: …")` (`kernel/pki.go:204-212`); assert the PEM never reaches the caller even though the signature was made | **GAP** |
| `PKI-GATE-10` | — | code-shape assertion | `Verify` must not consult any value computed by `Sign` — it takes only `der`, `role`, `now` (`ca.go:422`). A regression that passed the pre-computed name lists in would defeat the mechanism silently. Enforce by review checklist, or a test that mutates `tmpl` after `CreateCertificate` and confirms `Verify` still reads the DER | **GAP** |

---

## F. The issuance log (`PKI-LOG-*`)

`applyRecordIssuance` at `kernel/pki.go:88-104`, record shape at `pki.go:107-115`,
reader at `pki.go:283-298`. Doc 02:31-34 makes this the control that bounds a
fully compromised node: "a cert that exists but isn't in the log is the
compromise signal".

| ID | Preconditions | Input | Expected | Coverage |
|---|---|---|---|---|
| `PKI-LOG-01` | kernel, role, CA, authorized session | one successful `SignCertificate` | Exactly one record; `Serial`, `Role`, `Subject`, `SANs`, `NotAfter`, `Requester`, `IssuedSec` all populated (`kernel/pki.go:204-208`) | **GAP** |
| `PKI-LOG-02` | same | inspect record vs certificate | `record.Serial == formatSerial(cert.SerialNumber)` (`ca.go:534-541`) — the log key must be resolvable back to a certificate in the wild | **GAP** |
| `PKI-LOG-03` | role permitting DNS + IP + URI | request with all three SAN forms | `record.SANs` equals dns ++ ips ++ uris as issued (`ca.go:405`) — the log must record what was *issued*, not what was *asked for* | **GAP** |
| `PKI-LOG-04` | principal without admin at `/` | `IssuanceLog` | `ErrDenied` (`kernel/pki.go:284-286`) | **GAP** |
| `PKI-LOG-05` | three issuances at t0 < t1 < t2 | `IssuanceLog` | The doc comment says "newest serials last" (`kernel/pki.go:283`), but records are keyed by a **random 128-bit serial** (`ca.go:525-532`) and scanned in key order (`pki.go:289`), so the result is in random order, never chronological. Assert the real contract and fix the comment — or key the bucket so the claim becomes true | **GAP — doc/behaviour mismatch** |
| `PKI-LOG-06` | domain with N issuances | restart the node / restore from snapshot | All N records survive | **GAP** |
| `PKI-LOG-07` | existing record for serial S | a second `RecordIssuance` for S | `tx.Put` overwrites (`kernel/pki.go:100`). "Append-only" is a property of the Raft log, not of this bucket; and unlike `PutCA`/`PutPKIRole`, `applyRecordIssuance` performs **no grantor authority check at all**. Assert the intended contract | **GAP** — see Q10 |
| `PKI-LOG-08` | domain that has issued N certificates | operator cross-check | Every serial observed in the field appears in the log, and the log's count matches. This is the detection story doc 02:31-34 rests on; today there is no command that performs the comparison | **GAP** |

---

## G. Multi-issuer selection (`PKI-SEL-*`)

`IssuerName` / `SigningAuthority` at `kernel/pki.go:219-248`.

| ID | Preconditions | Input | Expected | Coverage |
|---|---|---|---|---|
| `PKI-SEL-01` | CA stored as `issuer/node-a` | `SigningAuthority(ctx, "node-a")` | `"issuer/node-a"` | Partial — exercised end-to-end at `test/trust/run.sh:40-77`, never asserted directly |
| `PKI-SEL-02` | no `issuer/node-z`, a `default` CA exists | `SigningAuthority(ctx, "node-z")` | `"default"` — the documented fallback for single-node or shared-key domains (`pki.go:222-227`) | **GAP** |
| `PKI-SEL-03` | neither exists | `SigningAuthority(ctx, "node-z")` | `ErrNotFound` wrapping a message that names the node, the key it looked for, and both remedies (`pki.go:242-246`) | **GAP** |
| `PKI-SEL-04` | `ca install` run with default `-node-id signet-0` (`cmd/signet/ca.go:292`), `serve` run with default `-node-id ""` (`main.go:607`) | any sign request | Today: `SigningAuthority("")` looks for `issuer/`, misses, falls back to `default`, and if genesis never made one the domain reports "no certificate authority" despite an issuer being installed. Assert the behaviour and align the defaults or detect the mismatch | **GAP** — operator trap |
| `PKI-SEL-05` | two per-node issuers + `default` | `Issuers(ctx)` | All three returned with their custody visible (`IntermediateRef` set vs `SealedKey`) (`pki.go:252-264`) | **GAP** |
| `PKI-SEL-06` | two nodes, own issuers | `GET /v1/pki/ca_chain` on each | Each node publishes **its own** chain, selected via `SigningAuthority` (`vaultkv/pki.go:100-111`); the two differ | **GAP** |
| `PKI-SEL-07` | two nodes, own issuers, one root | leaf from A, leaf from B | **EXT**: a consumer anchored on the root accepts both; a consumer pinned to issuer A accepts A's leaf and refuses B's | Covered — `test/trust/run.sh:88-99` (note `-partial_chain`, `run.sh:93-95`) |
| `PKI-SEL-08` | node A's issuer removed, node B's present | request on node A | Falls back to `default` or errors — it must **never** silently sign with another node's issuer, which would break the attributability claim in doc 02:266-268 | **GAP** |

---

## H. The Vault dialect sign route (`PKI-API-*`)

`internal/dialect/vaultkv/pki.go`. There is **no** PKI test in
`internal/dialect/vaultkv/handler_test.go` — every row below that is not
carried by a shell script is a gap. Request shape per E-06 F3 (`vaultkv/pki.go:16-19`,
`E-06:189`): every value arrives as a string.

| ID | Preconditions | Input | Expected | Coverage |
|---|---|---|---|---|
| `PKI-API-01` | role `srv`, authorized token | `POST /v1/pki/sign/srv` with cert-manager's exact body: `{csr, common_name, alt_names:"a,b", ip_sans:"", uri_sans:"", ttl:"2160h0m0s", exclude_cn_from_sans:"true"}` | 200; `data.certificate` parses; `data.serial_number` matches the cert | Partial — `test/trust/run.sh:71-75` and `test/kind/run.sh:117-133` exercise it; response fields beyond `certificate` unasserted |
| `PKI-API-02` | — | `ttl` as `"2160h0m0s"`, `"720h"`, `"3600"`, `3600` (JSON number), `""`, `"nonsense"` | First four accepted (`pki.go:124-135`, `str` at `pki.go:137-147`), `""` means role default, `"nonsense"` → 400 | **GAP** |
| `PKI-API-03` | role permitting several names | `alt_names: "a.example.com, b.example.com ,"` | Whitespace trimmed, empties dropped (`csv`, `pki.go:159-171`) | **GAP** |
| `PKI-API-04` | — | `exclude_cn_from_sans` as `true`, `"true"`, `"1"`, `"TRUE"`, absent | First three truthy, last two false (`truthy`, `pki.go:149-157`). `"TRUE"` is currently false — confirm that matches the clients we pin | **GAP** |
| `PKI-API-05` | — | body without `csr` | 400 "missing 'csr'" (`pki.go:48-51`) | **GAP** |
| `PKI-API-06` | — | body that is not JSON / is a JSON array | 400 "malformed request body" (`pki.go:42-46`), no panic | **GAP** |
| `PKI-API-07` | — | no `X-Vault-Token` / an expired token | 403 "permission denied" (`pki.go:35-39`) — and **nothing is signed**; assert no issuance record appears | **GAP** |
| `PKI-API-08` | token bound elsewhere | valid body, role `srv` | 403 via `ErrDenied` (`pki.go:75-77`); unknown role → 404 via `ErrNotFound` (`pki.go:78-80`) | **GAP** |
| `PKI-API-09` | role `{a.example.net}` | `common_name: "evil.test"` | 400 with a legible message (`pki.go:81-85`) — a refusal must read as a client error, not a server fault | Partial — `test/kind/run.sh:148-152` asserts cert-manager reports the refusal, not the status code |
| `PKI-API-10` | happy path | inspect response | `data` carries `certificate`, `issuing_ca`, `ca_chain`, `serial_number`, `expiration`, `private_key_type` (`pki.go:90-97`); `expiration` is a Unix second matching the cert | **GAP** |
| `PKI-API-11` | happy path | inspect `data.ca_chain` | Should be an array of **individual** PEMs (`E-06:189`, `["<PEM>", …]`). Today it is `[issuing_ca, issuing_ca ++ root]` (`pki.go:93`, `ChainPEM` at `ca.go:292-294`) — the intermediate appears twice and element 2 is two concatenated certificates. Tolerated by cert-manager's PEM scanner, non-conformant to the dialect | **GAP — suspected bug** |
| `PKI-API-12` | happy path | `GET /v1/pki/ca/pem` and `GET /v1/pki/ca_chain` | Root only vs intermediate ++ root (`pki.go:100-119`); `Content-Type: application/pem-certificate-chain`; no session required, by design | Partial — `test/kind/run.sh:138` fetches `ca_chain`; `ca/pem` untested |
| `PKI-API-13` | `PKIMount: ""` | `POST /v1/pki/sign/srv` | 404 — the routes are never registered (`pki.go:22-24`). Also: `Config.CAName` (`handler.go:51,70-71`) is set by `serve` (`main.go:632`) and **never read** by the sign route, which uses `SigningAuthority` instead — dead configuration that could mislead an operator | **GAP** |

---

## I. External-verifier suite (`PKI-EXT-*`)

Per R3 and doc 10 layer 2 ("a cross-verifier name-constraint suite … runs on
every issuance-profile change"). These belong in a `test/pki/run.sh` alongside
`test/trust/run.sh`, driving the built binary and asserting with foreign tools.
Verifier set from E-02: Go, OpenSSL 3.x, LibreSSL (`/usr/bin/openssl` on macOS),
pyca `x509.verification`, and — the one E-02 could not run — rustls-webpki.

| ID | Preconditions | Input | Expected | Coverage |
|---|---|---|---|---|
| `PKI-EXT-01` | real ceremony, real leaf | `openssl verify -CAfile root.crt -untrusted issuer.crt leaf.crt` | Accepted | Covered — `test/trust/run.sh:88-91`, `test/kind/run.sh:138-143` |
| `PKI-EXT-02` | two issuers | leaf from B against an anchor pinned to A | Refused | Covered — `test/trust/run.sh:98-99` |
| `PKI-EXT-03` | any issuer | `openssl x509 -in issuer.crt -text -noout` | Shows `X509v3 Name Constraints: critical`, the permitted DNS subtree, the excluded IP subtrees, the excluded email subtree — i.e. the profile doc 02:63-72 promises, read out of the bytes by a foreign parser | **GAP** |
| `PKI-EXT-04` | any issuer | leaf with an email SAN, verified by OpenSSL, LibreSSL and pyca | **Measured today: OpenSSL 3.6.3 ACCEPTS it** under `ExcludedEmailAddresses = [""]` (`ca.go:233`), Go and LibreSSL reject. Control with a named excluded subtree (`evil.test`) is rejected by all three, so OpenSSL enforces the extension and merely ignores the empty form. Pin this as a regression test once the encoding is fixed | **GAP — confirmed defect**; see Q4 |
| `PKI-EXT-05` | issuer constrained to DNS only; role permitting a `spiffe://` prefix | real leaf with a URI SAN, verified by **LibreSSL** | E-02 F3 predicts **REJECT**. If reproduced, Signet's default profile cannot serve SPIFFE identities to LibreSSL clients — a shipped interop limit that must be documented or fixed | **GAP** — highest-value external test |
| `PKI-EXT-06` | any Signet issuer | pyca `x509.verification` ClientVerifier over a real chain | Accepted — proving the emitted profile stays webpki-clean because it carries no URI constraints (`NC-05`). This is the regression test that stops someone "helpfully" adding URI constraints later | **GAP** |
| `PKI-EXT-07` | issuer with a delegated IP range | leaf with an in-range IP SAN, then an out-of-range one | Accepted / rejected by OpenSSL, LibreSSL, and pyca alike (E-02 measured IP enforcement solid in all five) | **GAP** |
| `PKI-EXT-08` | any leaf | `openssl verify -x509_strict` | Same verdicts as without the flag (E-02 re-ran its matrix with `-x509_strict`: identical results). A divergence means Signet emits something structurally sloppy | **GAP** |
| `PKI-EXT-09` | genesis-issued server certificate | `openssl x509 -text` on `tls.crt` from `-server-cert-out` (`main.go:400-470`) | `Extended Key Usage: TLS Web Server Authentication, TLS Web Client Authentication`; `Key Usage: Digital Signature, Key Encipherment` (`ca.go:372-373`) — and a decision recorded about `KeyEncipherment` on an ECDSA key, which is meaningless for ECDHE | **GAP** |
| `PKI-EXT-10` | kind cluster | cert-manager obtains a certificate through the Vault issuer and the out-of-scope Certificate is refused | Both outcomes asserted, plus `openssl verify` against the published chain | Covered — `test/kind/run.sh:117-152` |

---

## Questions for the maintainer

**Q1 — `AssembleIssuer` does not do what its comment says.**
`internal/ca/ceremony.go:257-258` states it confirms "the certificate actually
matches the key this node holds", and gives the reason: "a mismatch here would
surface much later, as unexplained signature failures". The body
(`ceremony.go:259-261`) only parses the certificate. It never compares the
certificate's SPKI to `req.KeyPEM`/`req.Ref`, and never checks that the
certificate chains to `rootCertPEM`. In a two-node ceremony the natural operator
error — installing node B's certificate on node A — is accepted, stored, and
only detected when the first issuance is withheld by the gate, which is exactly
the "much later" the comment promises to prevent. Should `AssembleIssuer` verify
SPKI match and chain, or should the comment be corrected? (`PKI-CER-11`,
`PKI-CER-12`, `PKI-NEG-26`)

**Q2 — an issuer with no delegated DNS namespace gets no constraints at all.**
`applyNameConstraints` returns immediately when `permittedDNS` is empty
(`ca.go:220-222`), which discards any `permittedIPs` the caller passed and skips
the IP and email exclusions doc 02:65-67 calls mandatory. `signet genesis
-ca-common-name X` with no `-ca-domains` reaches this (`main.go:341`), producing
a wholly unconstrained intermediate — while the `-ca-ip-ranges` help text
(`main.go:176`) tells the operator that IP SANs are "excluded outright" by
default. `signet ca sign-issuer` refuses this configuration outright
(`cmd/signet/ca.go:210-215`). Should genesis require `-ca-domains` too, or
should the early return be narrowed to "nothing was requested"? (`PKI-NC-07`,
`PKI-NC-08`)

**Q3 — `LoadRootSigner` does not bind the key to the certificate.**
`ceremony.go:220-245` parses a certificate and a key independently and returns
both. Handing it `rootA.crt` with `rootB.key` — plausible with two root
directories on one offline machine — succeeds, and the mismatch is caught only
by the release gate at `ceremony.go:212-215`, after a signature has been made
with the wrong root key. Should it compare public halves up front?
(`PKI-CER-09`)

**Q4 — `ExcludedEmailAddresses = [""]` is a no-op in OpenSSL. Measured, not
suspected.** `ca.go:233` excludes all email by naming a single empty
`rfc822Name`. Go treats a zero-length constraint as matching everything (an
explicit NSS-compatibility choice, not a specification), and LibreSSL agrees —
but OpenSSL 3.6.3 accepts a leaf with `a@example.com` under it, while rejecting
the same leaf under `ExcludedEmailAddresses = ["evil.test"]`. E-02's matrix
measured *permitted* email subtrees only (`E-02:79-80`), so the exclude-all form
Signet actually emits was never tested — this is exactly the hole a
cross-verifier suite over the *real* profile exists to find. Since doc 02:65-67
counts the email subtree as mandatory cross-type closure, the current encoding
does not deliver it. Candidate fix: express "no email may be issued" as an empty
*permitted* rfc822Name subtree (a permitted subtree that nothing can match, e.g.
`invalid.`), which every stack enforces uniformly, rather than an empty excluded
subtree. (`PKI-NC-04`, `PKI-EXT-04`)

**Q5 — the URI-constraint opt-in does not exist.**
Doc 02:70-74 and E-02 recommendation 7 promise `uri_constraints: emit` as a
per-delegation opt-in, default OFF, and note the homelab's Go-only consumer set
qualifies. `applyNameConstraints` takes no URI parameter and there is no flag on
`ca sign-issuer` or `genesis`. Is the feature deferred, or dropped? Related: with
URI constraints never emitted, an issuer's delegated namespace does **not** bound
the SPIFFE IDs its roles may mint — only `uriAllowed` does (see Q8) — and E-02 F3
predicts LibreSSL will reject URI SANs under DNS-only constraints anyway
(`PKI-NC-11`, `PKI-EXT-05`).

**Q6 — which key algorithms are supported?** `SignIssuer` will certify an RSA or
Ed25519 CSR (`ceremony.go:199` is algorithm-agnostic), but `ca.Load` can only
recover an EC private key (`ca.go:283`) and every generator hard-codes P-256
(`ceremony.go:42,115,130`). Is a non-EC issuer supposed to be possible? Same
question for leaf CSRs: `Sign` will happily certify an RSA leaf public key.
(`PKI-CER-21`)

**Q7 — are wildcard names supposed to be issuable?** With `AllowSubdomains`,
`domainAllowed` accepts `*.example.com` (`ca.go:501`, `HasSuffix` on
`".example.com"`), and — measured today — Go, OpenSSL and LibreSSL all accept
`*.example.com` under a permitted DNS subtree of `example.com`, so **no verifier
catches it either**: both the role check and the verify gate pass, and so does
every relying party. (`*.com` is correctly rejected, so the hole is bounded by
the delegated namespace, not unbounded.) Vault has an explicit
`allow_wildcard_certificates` knob; Signet has none, so a role that meant "any
host under example.com" also grants "every host under example.com in one
certificate". Intended? (`PKI-ISS-17`)

**Q8 — `uriAllowed` has no authority or path boundary. Suspected live bug.**
`ca.go:508-515` is a bare `strings.HasPrefix`. A role permitting
`spiffe://home.example` therefore also permits `spiffe://home.example.evil/ns/x`,
and one permitting `spiffe://home.example/ns/prod` also permits
`spiffe://home.example/ns/production-evil/sa/x`. This is precisely the mistake
`domainAllowed` documents itself as avoiding ("Component-wise suffix only:
`evilexample.com` must not match `example.com`", `ca.go:499-500`). Because URI
constraints are never emitted (Q5), nothing downstream catches it either — for
SPIFFE identities `uriAllowed` is the *only* control in the entire system.
Suggested fix: parse both sides as URLs and require scheme equality, exact host
equality, and a path-segment-boundary prefix. (`PKI-NEG-11`, `PKI-NEG-12`)

**Q9 — how much of the Subject is policy?** `looksLikeDNS` (`ca.go:517-519`)
gates whether the CN is scope-checked at all, so a CN containing a space, or one
that parses as an IP, bypasses `checkNames` entirely and lands in the Subject
unvalidated. Modern verifiers ignore the CN, but E-02 F4 measured
OpenSSL/LibreSSL checking it against DNS constraints when no SAN is present, and
the Subject is what appears in every operator log and dashboard. Should a
non-DNS CN be refused, or is an unvalidated Subject accepted by design?
(`PKI-NEG-14`, `PKI-NEG-15`)

**Q10 — the issuance log has no authority check and no ordering guarantee.**
`applyRecordIssuance` (`kernel/pki.go:88-104`) is the only PKI apply function
with no grantor check — compare `applyPutCA` (`pki.go:28-30`) and
`applyPutPKIRole` (`pki.go:75-81`) — and it overwrites any existing record for
the same serial. Separately, `IssuanceLog`'s comment claims "newest serials
last" (`pki.go:283`) while records are keyed by random 128-bit serials
(`ca.go:525-532`) and scanned in key order, so the result is unordered. Since
doc 02:31-34 makes this log the control that bounds a fully compromised node,
both properties matter. Should records be keyed by `issued-at ++ serial`, and
should the apply path require authority? (`PKI-LOG-05`, `PKI-LOG-07`)

**Q11 — should PKI issuance consult `RolePolicy`?** `filterRoles`
(`kernel/issue.go:200-250`) enforces `MinTier`, `RequiredAMR`, and `MaxTTLSec`
for token issuance. `SignCertificate` (`kernel/pki.go:166-214`) checks only
`HasAuthority(VerbSign, role.Scope)`. An X.509 certificate is an offline
credential in exactly the sense doc 02 worries about — it is verified with no
callback to Signet — so a role gated at tier 3 for tokens is ungated for
certificates. Deliberate separation, or a gap in the "central tier-gate across
all dialects" invariant (doc 10 layer 2, E-01 K-2)?

**Q12 — what is the intended `-node-id` default?** `ca install` defaults to
`signet-0` (`cmd/signet/ca.go:292`) and `serve` defaults to `""`
(`main.go:607`). An operator who takes both defaults installs `issuer/signet-0`
and then serves from a node that looks for `issuer/`, falls back to `default`,
and — in a domain built by the split ceremony rather than by `genesis
-ca-common-name` — reports having no certificate authority at all. Should the
defaults match, or should `SigningAuthority` refuse an empty node id?
(`PKI-SEL-04`)

---

## Notes on running these

- The tree is on NFS without `flock`: use `make test` and `make build`, never
  bare `go test` / `go build` (Makefile header, `Makefile:1-6`).
- Hardware scenarios (`PKI-CER-03`, `-05`, `-22`) need `make softhsm` first
  (`Makefile:52-60`) and the `pkcs11` build tag.
- Shell scenarios should follow `test/trust/run.sh`'s `refutes` helper
  (`run.sh:22`) so that a negative case which *succeeds* is reported as a
  failure — the failure mode a hand-written `|| true` silently hides.
- Time-dependent scenarios (`PKI-ISS-11`, `PKI-NEG-19`, `PKI-GATE-05`) should
  inject `now` through the existing `now time.Time` parameters
  (`ca.go:322`, `ceremony.go:161`) rather than sleeping. The one place a real
  clock earned its keep is staleness, where it caught a live bug
  (`test/trust/run.sh:125-127`).
