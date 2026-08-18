# Test plan 02 — Identity, attestation & sessions

**Status: Draft** · Area owner: kernel + attest · Companion to `docs/10-testing-strategy.md`

This is the on-rails test matrix for the authentication path: evidence in, session
out. It covers `internal/attest` (JWS/JWKS verification, the `Verifier` interface,
`K8sSA`, `Registry`), the kernel's `Login` / session lifecycle / token hashing, the
issuer + mapping Ops that configure it, and the freshness-tier filter that decides
what a session may carry offline.

Every claim about current behaviour below is cited to `file:line` against the tree
at the time of writing. Every row is a **supported scenario** — the negative cases
are not "things that happen to fail", they are behaviour the system is required to
exhibit, and a change that makes one of them succeed is a security regression.

## How to run

The source tree lives on NFS, which has no `flock`. **Never run bare `go test` /
`go build` here** — the Go toolchain locks `go.mod` and fails. Use the Makefile,
which builds from a local-disk mirror (`Makefile:2-26`):

```
make test        # unit + integration, all packages
make build       # binary
make test-hsm    # seal tests against SoftHSM (separate, cgo + pkcs11 tag)
./test/kind/run.sh   # real kind cluster, real ESO + cert-manager (interop)
```

## Notation

| Column | Meaning |
|---|---|
| **ID** | Stable. Never renumber; retire instead. |
| **Threat** | The E-01 control this row defends. `—` where the row is a functional contract, not a security one. |
| **Coverage** | `COVERED` (an existing test asserts exactly this), `PARTIAL` (an adjacent assertion exists but not this one), `GAP` (nothing asserts it). |

Shared fixture referenced throughout:

- **F-SIGNER** — `internal/attest/jwt_test.go:30-47`: an RSA-2048 key (`kid: rsa-1`)
  and a P-256 key (`kid: ec-1`) in one JWKS, plus `mint(alg, claims)` at
  `jwt_test.go:51-87` which can also emit `alg=none` and the HS256 confusion form.
- **F-SACLAIMS** — `jwt_test.go:98-118`: a well-formed projected ServiceAccount
  token body for `system:serviceaccount:external-secrets:external-secrets`,
  `iss=https://kubernetes.default.svc.cluster.local`, `aud=["signet"]`, `exp=+1h`.
- **F-DOMAIN** — a bootstrapped domain: root principal + grantorless
  `domain-admin` binding at `/` (`internal/kernel/apply_test.go:79-84`), a kernel
  over `directProposer` (`internal/kernel/issue_test.go:102-115`).

---

## A. JWS core verification — `IA-JWS-*`

Entry point `VerifyJWS` (`internal/attest/jwt.go:136-218`). The ordering matters and
is itself under test: **the signature is checked (jwt.go:159-176) before the payload
is decoded or parsed (jwt.go:178-185)**, so unauthenticated bytes never reach the
claims decoder. Only the JOSE header is parsed pre-verification (jwt.go:141-152),
which is unavoidable and is therefore the fuzz target (docs/10 layer 3).

| ID | Preconditions | Input | Expected result | Threat | Coverage |
|---|---|---|---|---|---|
| IA-JWS-01 | F-SIGNER pinned as issuer JWKS, `iss`/`aud` registered | F-SACLAIMS signed `RS256`, `kid=rsa-1` | `*Claims` returned; `Issuer`, `Subject`, `Audience`, `Expiry`, `IssuedAt`, `Raw` populated | — | COVERED `jwt_test.go:120-139` |
| IA-JWS-02 | as above | F-SACLAIMS signed `ES256`, `kid=ec-1` | accepted, same claim shape | — | COVERED `jwt_test.go:126-138` |
| IA-JWS-03 | as above | header `{"alg":"none"}`, empty signature segment | error `jws: no pinned key verifies this signature` (both key branches reject the alg first: jwt.go:224-226, 229-231) | AT-2 | COVERED `jwt_test.go:152` |
| IA-JWS-04 | as above | header `{"alg":"HS256"}`, signature = HMAC-SHA256 over `signed` keyed with the RSA modulus bytes | rejected — key type drives the algorithm, never the header (jwt.go:220-244) | AT-2 | COVERED `jwt_test.go:153-154` |
| IA-JWS-05 | as above | valid `RS256` signature, but header `kid=ec-1` | rejected: `rsa-1` is skipped on kid mismatch (jwt.go:162), `ec-1` rejects `RS256` (jwt.go:229-231) | AT-2 | **GAP** |
| IA-JWS-06 | as above | valid `ES256` signature, but header `kid=rsa-1` | rejected, mirror of IA-JWS-05 | AT-2 | **GAP** |
| IA-JWS-07 | as above | valid `RS256` signature, header `kid=does-not-exist` | rejected — a `kid` selects a key, it never introduces one (jwt.go:161-163) | AT-2 | **GAP** |
| IA-JWS-08 | as above | valid `RS256` signature, header carries **no** `kid` | accepted — with `hdr.Kid == ""` every pinned key is tried, and only the RSA one verifies (jwt.go:162) | — | **GAP** (positive case; guards against over-tightening the kid rule and breaking kid-less issuers) |
| IA-JWS-09 | as above | well-formed token, last signature byte flipped | rejected | AT-2 | **GAP** — `jwt_test.go:175-181` tampers the *payload*, not the signature |
| IA-JWS-10 | as above | well-formed token, payload replaced with a different-`sub` body, original signature kept | rejected | AT-0 | COVERED `jwt_test.go:175-181` |
| IA-JWS-11 | as above | token signed by a *different* RSA key of the same size | rejected | AT-2 | COVERED `jwt_test.go:182-183` |
| IA-JWS-12 | as above | `"not.a.jwt"` | error `jws: not three segments` (jwt.go:137-140) | — | COVERED `jwt_test.go:184` |
| IA-JWS-13 | as above | 2 segments; 4 segments; empty string | error `jws: not three segments` in all three | — | **GAP** (only the 3-segment-garbage form is covered) |
| IA-JWS-14 | as above | header segment is not base64url | `jws: header: ...` (jwt.go:146-149) | — | **GAP** |
| IA-JWS-15 | as above | header segment decodes to non-JSON | `jws: header: ...` (jwt.go:150-152) | — | **GAP** |
| IA-JWS-16 | as above | signature segment is not base64url | `jws: signature: ...` (jwt.go:153-156) | — | **GAP** |
| IA-JWS-17 | issuer signs a body that is valid base64 but not JSON | signature verifies, payload does not parse | `jws: payload: ...` (jwt.go:182-185) — reached only *after* signature verification | — | **GAP** |
| IA-JWS-18 | as above | `ES256`, signature is DER-encoded (`SEQUENCE{r,s}`) rather than raw `R‖S` | rejected: `bad ECDSA signature length` (jwt.go:232-234) | — | **GAP** |
| IA-JWS-19 | as above | `ES256`, signature 63 or 65 bytes | rejected on length | — | **GAP** |
| IA-JWS-20 | as above | `ES256`, `r=0` or `s=0` (64 zero-ish bytes) | rejected by `ecdsa.Verify` | — | **GAP** |
| IA-JWS-21 | as above | header `{"alg":"RS512"}` / `{"alg":"ES384"}` / `{"alg":"PS256"}` over a correct-for-that-alg signature | rejected — only `RS256` (RSA) and `ES256` (EC) are accepted (jwt.go:224, 229). This is an allow-list, and widening it is a deliberate act | AT-2 | **GAP** |
| IA-JWS-22 | as above | header `{"typ":"at+jwt"}` or no `typ` at all, otherwise valid | **accepted** — `typ` is decoded (jwt.go:144) and never checked. Pinning current behaviour; see Q7 | AT-0 | **GAP** |
| IA-JWS-23 | as above | payload with `exp` 5s in the past | accepted — `Skew` is 30s (jwt.go:128, 211-213) | TIME-1 | **GAP** (boundary) |
| IA-JWS-24 | as above | payload with `exp` 31s in the past | rejected: `jws: expired at ...` | TIME-1 | PARTIAL — `jwt_test.go:161-164` uses `exp = -2h`, far from the boundary |
| IA-JWS-25 | as above | payload with **no** `exp` claim | rejected: `jws: token has no expiry` (jwt.go:208-210) — this is what refuses legacy non-expiring k8s SA tokens | AT-1 | COVERED `jwt_test.go:165-166` |
| IA-JWS-26 | as above | payload with `exp: 0` | rejected (same branch — `rc.Exp == 0`) | AT-1 | **GAP** |
| IA-JWS-27 | as above | `nbf` 20s in the future | accepted — inside `Skew` (jwt.go:214-216) | TIME-1 | **GAP** |
| IA-JWS-28 | as above | `nbf` 60s in the future | rejected: `jws: not yet valid` | TIME-1 | **GAP** — explicitly required, nothing exercises `nbf` today |
| IA-JWS-29 | as above | `iat` far in the future, `exp` valid | **accepted** — `iat` is recorded (jwt.go:190-192) but never validated. Pinning current behaviour; see Q7 | TIME-1 | **GAP** |
| IA-JWS-30 | as above | `exp` far in the future (e.g. +10y), otherwise valid | accepted at the JWS layer; the *session* it produces is bounded elsewhere (see IA-SES-06) | TIME-2 | **GAP** |

## B. JWKS handling, key rotation, key hygiene — `IA-JWK-*`

`ParseJWKS` (`jwt.go:46-60`) is called on **every** verification via
`K8sSA.Verify` (`k8ssa.go:70`) — key material is re-decoded per login, not cached.
`JWK.publicKey` (`jwt.go:62-104`) is the only place raw key material becomes a
`crypto.PublicKey`.

| ID | Preconditions | Input | Expected result | Threat | Coverage |
|---|---|---|---|---|---|
| IA-JWK-01 | — | `{}` | `ParseJWKS` error `jwks: no keys` | AT-2 | COVERED `jwt_test.go:207` |
| IA-JWK-02 | — | `{"keys":[]}` | error `jwks: no keys` | AT-2 | COVERED `jwt_test.go:207` |
| IA-JWK-03 | — | `not json` | error | AT-2 | COVERED `jwt_test.go:207` |
| IA-JWK-04 | — | `{"keys":[{"kty":"oct","k":"aaa"}]}` (symmetric key in an issuer key set) | error `unsupported key type "oct"` (jwt.go:101-103) | AT-2 | COVERED `jwt_test.go:207` |
| IA-JWK-05 | — | one valid RSA key **plus** one `kty:"OKP"` Ed25519 key | **whole key set rejected** (jwt.go:54-58 fails the set on the first bad key) → the issuer verifies nothing at all. See Bug B-1 | AT-1 | **GAP** |
| IA-JWK-06 | — | EC key whose `(x,y)` is not on `P-256` | rejected: `point is not on the curve` (jwt.go:97-99) | AT-2 | **GAP** |
| IA-JWK-07 | — | EC key with `crv:"P-384"` | key *parses* (jwt.go:83), but no token can ever verify against it — `verifySignature` only accepts `ES256` with a 64-byte signature (jwt.go:229-234). Fails closed, silently. See Q4 | — | **GAP** |
| IA-JWK-08 | — | RSA key with `e` = `AQ` (exponent 1) | key parses (`jwt.go:73-75` bounds only the *upper* end); verification then fails inside `rsa.VerifyPKCS1v15`, which rejects `e < 3` (Go ≥1.20 / go.mod `go 1.25.0`). Net: rejected — **but by the standard library, not by Signet's own check** | AT-2 | **GAP** |
| IA-JWK-09 | — | RSA key with `e` > 2³¹ | `implausible exponent` (jwt.go:73-75) | AT-2 | **GAP** |
| IA-JWK-10 | — | RSA key with a 512-bit modulus | key parses and *verifies* tokens — no minimum key size is enforced. Reachable only through a domain-admin-registered issuer. Pinning current behaviour; see Q5 | AT-2 | **GAP** |
| IA-JWK-11 | — | key with `n` or `e` an empty string | `empty value` (jwt.go:263-271) | — | **GAP** |
| IA-JWK-12 | — | key with `use:"enc"`, otherwise a valid RSA signing key | **accepted for signature verification** — `use` and `alg` on the JWK are decoded (jwt.go:37-38) and never enforced. Pinning current behaviour; see Q7 | AT-2 | **GAP** |
| IA-JWK-13 | **Rotation, overlap window**: issuer JWKS holds `old` and `new` | token signed by `old`, `kid=old` | accepted — retired keys stay pinned until their tokens expire | AT-1 | **GAP** |
| IA-JWK-14 | same set | token signed by `new`, `kid=new` | accepted | AT-1 | **GAP** |
| IA-JWK-15 | **Rotation, completed**: `old` removed from the pinned set | token signed by `old` | rejected: `no pinned key verifies this signature` — this is the mechanism by which a compromised cluster key is retired | AT-1 | **GAP** |
| IA-JWK-16 | Issuer registered, then `PutIssuer` re-run with the same `Name` and a rotated JWKS | `applyPutIssuer` (`apply.go:200-222`) writes to `BucketIssuers` keyed by `Name` (apply.go:218) → in-place replacement | next `Login` uses the new key set with no restart | AT-1 | **GAP** |
| IA-JWK-17 | Two issuers registered under different names, disjoint key sets | token from issuer A presented at a mapping bound to issuer B | rejected — B's key set does not verify A's signature, *and* the `iss` check would reject it independently (jwt.go:197-199) | **AT-0, AT-1** | **GAP** — this is the "verifier audience/issuer isolation" property test docs/10:17-18 names as a release requirement |
| IA-JWK-18 | — | 1 MiB JWKS with 10 000 keys, token that matches none | terminates, rejects; bounded work per login. Documents the per-login parse cost (`k8ssa.go:70`) | — | **GAP** |

## C. Issuer & audience pinning — `IA-PIN-*`

The invariant: **a request never supplies key material, an issuer URL, or an
audience**. `attest.Issuer` (`k8ssa.go:27-32`) is built only from the stored issuer
record (`kernel.go:113-115`), which is written only by `applyPutIssuer` under
domain-wide authority (`apply.go:210-212`, `apply.go:276-295`). `Evidence`
(`kernel.go:67-73`) has exactly two fields — a rule name and opaque material — so
there is no channel by which a caller could smuggle a JWKS URL, `jku`, or `x5u`.

| ID | Preconditions | Input | Expected result | Threat | Coverage |
|---|---|---|---|---|---|
| IA-PIN-01 | issuer registered with `URL = https://k8s.example` | token with `iss = https://evil.example` | rejected: `jws: issuer %q is not the registered issuer` (jwt.go:197-199) | AT-0, AT-1 | COVERED `jwt_test.go:159-160` |
| IA-PIN-02 | as above | token with `iss = https://k8s.example/` (trailing slash) | rejected — the comparison is byte-exact, not URL-normalised. This is deliberate: normalisation is where SPIRE CVE-2021-27099 lived | AT-0 | **GAP** |
| IA-PIN-03 | as above | token with **no** `iss` claim | rejected (`c.Issuer == ""` ≠ registered URL) | AT-0 | **GAP** |
| IA-PIN-04 | issuer record has `URL = ""` (impossible via `PutIssuer` — `apply.go:201-203` rejects it — reachable only by calling `VerifyJWS` directly) | any token | rejected: `issuer == ""` fails closed (jwt.go:197) | AT-0 | **GAP** |
| IA-PIN-05 | issuer registered with `Audience = "signet"` | token `aud: ["vault"]` | rejected: `jws: audience %v does not include %q` (jwt.go:205-207) | AT-0, AT-1 | COVERED `jwt_test.go:155-156` |
| IA-PIN-06 | as above | token with no `aud` claim | rejected | AT-0, AT-1 | COVERED `jwt_test.go:157-158` |
| IA-PIN-07 | as above | token `aud: "signet"` (JSON **string**, not array) | accepted — `parseAudience` handles both forms (jwt.go:246-259) | — | **GAP** |
| IA-PIN-08 | as above | token `aud: ["vault","signet"]` | **accepted** — membership, not equality (`slicesContain`, jwt.go:205). E-01:423 asks for "reject tokens whose `aud` is not exactly Signet's". See Q1 | AT-0 | **GAP** |
| IA-PIN-09 | as above | token `aud: 42` / `aud: {"a":1}` | rejected: `jws: audience is neither a string nor an array` (jwt.go:255-257) | AT-0 | **GAP** |
| IA-PIN-10 | issuer record has `Audience = ""` | any otherwise-valid token | rejected: `jws: no required audience configured` (jwt.go:202-204) — a missing requirement is not a satisfied one | AT-0 | COVERED `jwt_test.go:196-204` |
| IA-PIN-11 | `PutIssuer` with `Audience = ""` | Op applied | rejected: `issuer: a Signet-specific audience is required` (apply.go:204-206) — the fail-closed check exists at *both* config-write and verify time | AT-0 | **GAP** |
| IA-PIN-12 | `PutIssuer` with empty `JWKS` | Op applied | rejected: `issuer: no pinned key set` (apply.go:207-209) | AT-2 | **GAP** |
| IA-PIN-13 | `PutIssuer` with `JWKS = {"keys":[]}` | Op applied | **accepted** — `apply.go:207` checks byte length only, so a key set that parses to nothing is stored. Failure surfaces at first login. See Bug B-2 | AT-2 | PARTIAL — `apply_test.go:220`, `apply_test.go:235` rely on this acceptance without asserting on it |
| IA-PIN-14 | `PutIssuer` with `Verifier = "webauthn"` (not in `Default()`) | Op applied | **accepted** — the verifier name is not validated at write time (`apply.go:200-222`). `Login` then fails with `attest: no verifier named "webauthn"` (k8ssa.go:135-141). Fails closed; see Q6 | AT-0 | **GAP** |
| IA-PIN-15 | delegated `domain-admin` at `/clusters/lab` only | that principal proposes `PutIssuer` | rejected: `grantor %s lacks domain-wide admin authority` (apply.go:287-293). Registering a trust anchor decides whose signatures are believed at all | AT-0, K-1 | COVERED `apply_test.go:217-224` |
| IA-PIN-16 | domain has bindings; grantorless `PutIssuer` | Op applied | rejected: `missing grantor` (apply.go:277-285) | K-1 | PARTIAL — `apply_test.go:260-272` covers the equivalent for `PutBinding` |
| IA-PIN-17 | structural | reflect over `kernel.Evidence` | exactly the fields `Rule`, `Material`; no URL/JWKS/audience/issuer field exists. Fails if anyone adds a request-supplied key source | **AT-2** | **GAP** — the analogue of the `op_test.go:40-55` shape test, and the cheapest possible guard for the strongest claim in `jwt.go:26-29` |

## D. Kubernetes ServiceAccount identity extraction — `IA-K8S-*`

`K8sSA.Verify` (`k8ssa.go:69-104`), `parseSubject` (`k8ssa.go:107-118`).

| ID | Preconditions | Input | Expected result | Threat | Coverage |
|---|---|---|---|---|---|
| IA-K8S-01 | issuer pinned | F-SACLAIMS, `RS256` | `Identity{Verifier:"k8s-sa", Issuer:<iss>, Subject:<sub>, Namespace:"external-secrets", Account:"external-secrets", UID:"uid-123", Expiry:<exp>}` | — | COVERED `jwt_test.go:120-139` |
| IA-K8S-02 | as above | `sub: "system:node:worker-1"` | rejected: `subject %q is not a service account` (k8ssa.go:109-111) — a node token is not a workload token | AT-0 | COVERED `jwt_test.go:167-168` |
| IA-K8S-03 | as above | `sub: "system:serviceaccount:kube-system:admin"` while `kubernetes.io.namespace = external-secrets` | rejected: `namespace in sub disagrees with kubernetes.io claim` (k8ssa.go:88-90) | AT-0 | COVERED `jwt_test.go:169-174` |
| IA-K8S-04 | as above | `sub: "system:serviceaccount:external-secrets:other"` while `kubernetes.io.serviceaccount.name = external-secrets` | rejected: `service account in sub disagrees ...` (k8ssa.go:91-93) | AT-0 | **GAP** — only the namespace half of the cross-check is exercised |
| IA-K8S-05 | as above | `sub: "system:serviceaccount:ns"` (one field) | rejected: `subject %q is malformed` (k8ssa.go:113-116) | AT-0 | **GAP** |
| IA-K8S-06 | as above | `sub: "system:serviceaccount::name"` (empty namespace) | rejected: malformed | AT-0 | **GAP** |
| IA-K8S-07 | as above | `sub: "system:serviceaccount:ns:"` (empty account) | rejected: malformed | AT-0 | **GAP** |
| IA-K8S-08 | as above | `sub: "system:serviceaccount:ns:name:extra"` | **accepted** as `(ns, "name:extra")` — `strings.Cut` splits on the first colon only (k8ssa.go:113). Kubernetes never mints this shape; pinning behaviour. See Q8 | AT-0 | **GAP** |
| IA-K8S-09 | as above | valid token with **no** `kubernetes.io` claim at all | accepted; `Namespace`/`Account` come from `sub`, `UID` is empty (k8ssa.go:86-93 skip on empty, k8ssa.go:101) | — | **GAP** |
| IA-K8S-10 | as above | valid token whose `kubernetes.io` claim is malformed JSON-shaped (e.g. `"kubernetes.io": "nope"`) | accepted — the unmarshal error is deliberately discarded (`_ =`, k8ssa.go:87) and the cross-check degrades to `sub` alone. Pinning behaviour; see Q8 | AT-0 | **GAP** |
| IA-K8S-11 | as above | material with surrounding whitespace / trailing `\n` | accepted — trimmed at `k8ssa.go:74` | — | **GAP** |
| IA-K8S-12 | as above | material is empty | rejected: `jws: not three segments` | — | **GAP** |
| IA-K8S-13 | issuer registered with a JWKS that does not parse | any token | rejected: `k8s-sa: issuer %q: jwks: ...` (k8ssa.go:70-73) — note this is checked *before* any token bytes are touched | AT-2 | PARTIAL — `jwt_test.go:206-212` covers `ParseJWKS` alone |
| IA-K8S-14 | as above | `Identity.Expiry` equals the token's `exp` | used downstream to clamp session TTL (`kernel.go:127-132`) | TIME-2 | **GAP** |

## E. Verifier registry & selection — `IA-REG-*`

`Verifier` (`k8ssa.go:16-24`), `Registry` (`k8ssa.go:121-141`), `Default()`
(`k8ssa.go:133`). The AT-0 rule: **the verifier is chosen by configuration keyed to
the issuer, never inferred from the evidence.**

| ID | Preconditions | Input | Expected result | Threat | Coverage |
|---|---|---|---|---|---|
| IA-REG-01 | — | `Default().Get("k8s-sa")` | returns `K8sSA{}` | — | **GAP** |
| IA-REG-02 | — | `Default().Get("webauthn")` | error `attest: no verifier named "webauthn"` (k8ssa.go:135-141) | AT-0 | **GAP** |
| IA-REG-03 | — | enumerate `Default()` | exactly one verifier, `k8s-sa`. Adding a verifier is a deliberate act that must update this test *and* docs/04's table | AT-0 | **GAP** |
| IA-REG-04 | two issuers registered, one `verifier:"k8s-sa"`, one `verifier:"future-tpm"` | login through a mapping bound to the second | the verifier comes from the *issuer record* (`kernel.go:109-112`), never from the token's header or claims | **AT-0** | **GAP** |
| IA-REG-05 | — | `NewRegistry(K8sSA{}, K8sSA{})` | last registration wins, no panic (k8ssa.go:123-129) | — | **GAP** |
| IA-REG-06 | structural | `Verifier.Verify` signature | returns `(*Identity, error)` and nothing role- or permission-shaped — a verifier that could return authorization would put policy on the auth path (k8ssa.go:11-15, 37-45) | K-3 | **GAP** (compile-time contract; assert by shape test or leave as review checklist) |

## F. Mapping rules — `IA-MAP-*`

`Mapping` + `Matches` (`kernel/model.go:161-186`), `applyPutMapping`
(`apply.go:224-272`). Matchers are **exact lists, never patterns** — a matcher
language on the authentication path is a policy engine through the back door
(`op.go:353-356`).

| ID | Preconditions | Input | Expected result | Threat | Coverage |
|---|---|---|---|---|---|
| IA-MAP-01 | mapping `namespaces:["demo"], service_accounts:["client"]` | `Matches("demo","client")` | `true` | — | COVERED `apply_test.go:250-252` |
| IA-MAP-02 | as above | `Matches("other","client")` | `false` | AT-1 | COVERED `apply_test.go:247-249` |
| IA-MAP-03 | as above | `Matches("demo","other")` | `false` | AT-1 | COVERED `apply_test.go:247-249` |
| IA-MAP-04 | `Mapping{}` (both lists empty) | `Matches("","")` | `false` — a rule that accidentally accepts everything is an authentication bypass (model.go:172-177) | **K-1** | COVERED `apply_test.go:253-255` |
| IA-MAP-05 | mapping `namespaces:["demo"]` only, `service_accounts` empty | `Matches("demo","client")` | `false` — both lists must be satisfied | K-1 | **GAP** |
| IA-MAP-06 | `PutMapping` with no matchers at all | Op applied | rejected: `mapping: must name the namespaces and service accounts it accepts` (apply.go:228-230) | **K-1** | COVERED `apply_test.go:239-244` |
| IA-MAP-07 | `PutMapping` with `namespaces:["demo"]`, `service_accounts:[]` | Op applied | rejected, same branch | K-1 | **GAP** |
| IA-MAP-08 | mapping `namespaces:["dem*"]` | `Matches("demo","client")` | `false` — `containsExact` (model.go:179-186). **Globs are strings, not patterns** | **K-1** | **GAP** — the property that most needs a named test |
| IA-MAP-09 | mapping `namespaces:["demo"]` | `Matches("Demo","client")` | `false` — case-sensitive | K-1 | **GAP** |
| IA-MAP-10 | mapping `namespaces:["demo"]` | `Matches(" demo","client")` / `Matches("demo\n","client")` | `false` — no trimming, no normalisation | AT-0 | **GAP** |
| IA-MAP-11 | mapping `namespaces:["demo","staging"]` | `Matches("staging","client")` | `true` — lists are unions | — | **GAP** |
| IA-MAP-12 | `PutMapping` naming an issuer that is not registered | Op applied | rejected: `mapping: no registered issuer %q` (apply.go:231-235) | AT-0 | **GAP** |
| IA-MAP-13 | `PutMapping` whose `Principal` does not exist | Op applied | rejected: `mapping: principal %s does not exist` (apply.go:241-247) | K-1 | **GAP** |
| IA-MAP-14 | `PutMapping` with `Grantor: ""` in a non-empty domain | Op applied | rejected: `mapping: missing grantor` (apply.go:248-250) — unlike bindings, mappings have **no** bootstrap exemption | **K-1** | **GAP** |
| IA-MAP-15 | delegated `domain-admin` at `/clusters/lab`; target principal at `/clusters/lab/apps/runner` | `PutMapping` by that admin | accepted (apply.go:251-257) | K-1 | COVERED `apply_test.go:197-204` |
| IA-MAP-16 | same admin; target principal at `/clusters/prod/apps/billing` | `PutMapping` by that admin | rejected: `mapping: grantor %s lacks admin authority over %s`. **The ESC1 guard** | **K-1** | COVERED `apply_test.go:206-213` |
| IA-MAP-17 | as IA-MAP-15, randomised over 400 tree shapes (mirroring `apply_test.go:131-175` for bindings) | `PutMapping` at random target paths | accepted **iff** `ScopeCovers(delegatedScope, targetPath)` | **K-1** | **GAP** — bindings get the property test, mappings get two hand-picked cases |
| IA-MAP-18 | mapping written by admin-of-S; **S's admin binding is later removed or lapses (`NotAfter`)** | login through that mapping | E-01:291-294 requires the narrowing to be "enforced at rule-write time *and* re-checked at issuance". `Login` (`kernel.go:81-134`) performs **no** re-check. See Bug B-3 | **K-1** | **GAP** |
| IA-MAP-19 | two mappings, same `(ns, sa)` pair, different principals | login naming each rule in turn | each yields its own principal — the rule name selects policy, and the caller choosing a rule can only reach principals that rule already names | K-1 | **GAP** |
| IA-MAP-20 | `PutMapping` re-applied with the same `Name` | Op applied | in-place replacement (`BucketMappings` keyed by `Name`, apply.go:268) — subject to the same authority check | K-1 | **GAP** |

## G. Login end to end — `IA-LOG-*`

`Kernel.Login` (`kernel.go:81-134`). Order of operations is the contract:
resolve rule → resolve its pinned issuer → verify evidence → *then* match →
*then* mint. Policy is never consulted before verification.

| ID | Preconditions | Input | Expected result | Threat | Coverage |
|---|---|---|---|---|---|
| IA-LOG-01 | F-DOMAIN; issuer `this-cluster` pinned to F-SIGNER's JWKS; mapping `eso` → principal `/clusters/svc/apps/eso`, `ttl_seconds:900` | `Evidence{Rule:"eso", Material:<F-SACLAIMS token for demo/signet-client>}` | returns `(token, Session)`; `Session.Principal` = the mapped principal, `AMR = ["k8s-sa"]`, `Verifier = "k8s-sa"`, `Expiry = now+900s` (kernel.go:133) | — | **GAP** — *`Login` has no unit test at all* |
| IA-LOG-02 | as above | `Rule:"no-such-rule"` | error `no mapping rule named %q` (kernel.go:88-93); no session created | K-1 | **GAP** |
| IA-LOG-03 | mapping stored whose issuer record was never written | valid token | error `mapping %q names unregistered issuer %q` (kernel.go:97-103) | AT-0 | **GAP** |
| IA-LOG-04 | issuer record names `verifier:"tpm"` | valid token | error from `Registry.Get` (kernel.go:109-112); **fails closed** | AT-0 | **GAP** |
| IA-LOG-05 | as IA-LOG-01 | token for `demo/impostor` (a real, correctly attested, *different* SA) | error `mapping %q does not accept %s/%s` (kernel.go:119-121). Attestation succeeded; authorization did not — the two steps are separate | **K-1, AT-1** | PARTIAL — asserted end to end at `test/kind/externalsecret.yaml:96-140` + `test/kind/run.sh:110-117`, never in Go |
| IA-LOG-06 | two clusters registered as issuers A and B; mapping `m-b` bound to B | valid token minted by cluster **A** for `aud=signet` | rejected — B's pinned key set does not verify it and `iss` mismatches | **AT-1** (cross-cluster replay) | **GAP** |
| IA-LOG-07 | as IA-LOG-01, but the token's `aud` is the API server's default | login | rejected before any policy is read | AT-0, AT-1 | PARTIAL (unit-level via IA-PIN-05) |
| IA-LOG-08 | mapping with `ttl_seconds: 0` | valid token | session TTL defaults to **1h** (kernel.go:123-126) | TIME-2 | **GAP** |
| IA-LOG-09 | mapping `ttl_seconds: 3600`; evidence `exp` = now+300s | valid token | session expiry = now+300s — *the session never outlives the evidence that produced it* (kernel.go:127-132) | **TIME-2** | **GAP** |
| IA-LOG-10 | mapping `ttl_seconds: 300`; evidence `exp` = now+3600s | valid token | session expiry = now+300s (mapping is the tighter bound) | TIME-2 | **GAP** |
| IA-LOG-11 | mapping `ttl_seconds: 31536000` (one year) | valid token, evidence `exp` = now+1h | session expiry = now+1h. There is **no independent domain-wide session-TTL ceiling**; see Q3 | TIME-2 | **GAP** |
| IA-LOG-12 | mapping points at a principal that was destroyed after the mapping was written | valid token | `applyCreateSession` rejects: `session: principal %s does not exist` (apply.go:170-174) → `Login` returns the error, no session | K-1 | PARTIAL — `apply_test.go:289` covers the Apply half |
| IA-LOG-13 | as IA-LOG-01 | the **same** token replayed twice inside its `exp` | **both succeed**, producing two independent sessions. Projected SA tokens are bearer evidence with no `jti`/replay cache. See Q2 | AT-1 | **GAP** |
| IA-LOG-14 | as IA-LOG-01, kernel clock advanced past the token's `exp` via `SetClock` | replay of a previously-accepted token | rejected at `VerifyJWS` — `Login` passes `k.now()` into the verifier (kernel.go:113-115) | TIME-1 | **GAP** (and see Bug B-4: `SetClock` is honoured here but **not** by the TTL clamp two lines later) |
| IA-LOG-15 | any failure mode above, behind the Vault dialect | `POST /v1/auth/kubernetes/login` | uniform `403 permission denied` (`vaultkv/handler.go:490-495`) — no oracle distinguishing "bad rule" from "bad token" from "unmatched mapping" | AT-0 | **GAP** |
| IA-LOG-16 | dialect layer | `POST .../login` with `jwt` or `role` missing | `400`, and the kernel is never called (handler.go:481-484) | — | **GAP** |
| IA-LOG-17 | dialect layer, structural | the dialect passes `body.JWT` to the kernel untouched (handler.go:486-489) | a dialect that parsed, trimmed, or inspected the token would be a candidate authentication bypass; assert the material reaching `Verify` is byte-identical to the request body | AT-0 | **GAP** |
| IA-LOG-18 | successful login | response envelope | `auth.client_token` is the raw token, `auth.accessor` is the session **ID** (not the token, not its hash) (handler.go:503-520) | DB-3 | **GAP** |

## H. Session lifecycle — `IA-SES-*`

`CreateSession` (`kernel.go:143-169`), `LookupSession` (`kernel.go:174-193`),
`RevokeSession` (`kernel.go:195-198`), `applyCreateSession` / `applyRevokeSession`
(`apply.go:166-195`).

| ID | Preconditions | Input | Expected result | Threat | Coverage |
|---|---|---|---|---|---|
| IA-SES-01 | F-DOMAIN | `CreateSession(actor, principal, 1h, ["k8s-sa"], "k8s-sa")` | returns a raw token and a `Session` with `TokenHash = HashToken(token)`, `AuthTime = now`, `Expiry = now+3600` | — | PARTIAL — used as a fixture in ~8 tests (`issue_test.go:86`, `fsm_test.go:53`, `handler_test.go:54`) but never asserted on |
| IA-SES-02 | session created | `LookupSession(rawToken)` | returns the same `Session` (ID, Principal, AMR, AuthTime, Expiry, Verifier all round-trip) | — | PARTIAL — `fsm_test.go:71-74` asserts only that it resolves |
| IA-SES-03 | session created | `LookupSession("signet.bogus")` | `ErrNoSession` (kernel.go:180-183) | — | PARTIAL — via the dialect's 403 at `handler_test.go:238-240` |
| IA-SES-04 | session created | `LookupSession("")` | `ErrNoSession`; hashing an empty string must not resolve to any stored key | — | **GAP** |
| IA-SES-05 | session with `ttl = 30s`, clock advanced 31s | `LookupSession(rawToken)` | `ErrNoSession` — expiry is evaluated **lazily on read**, there is no sweeper (kernel.go:171-173, 189-191) | **TIME-2** | **GAP** |
| IA-SES-06 | session with `ttl = 30s`, clock advanced exactly to `Expiry` | lookup | `ErrNoSession` — the check is `>=` (kernel.go:189) | TIME-1 | **GAP** |
| IA-SES-07 | session with `ttl = 0` | lookup at now+10y | resolves — `Expiry == 0` means non-expiring (kernel.go:150-152, 189). Reachable today only from `signet token` / genesis with `-ttl 0` | TIME-2 | **GAP** |
| IA-SES-08 | expired session record | lookup | returns `ErrNoSession` but the record is **not deleted** — it remains in `BucketSessions` and in every snapshot. Pinning behaviour; see Q9 | — | **GAP** |
| IA-SES-09 | session created | `RevokeSession(actor, rawToken)` then `LookupSession(rawToken)` | first call succeeds; lookup returns `ErrNoSession` — **the revoked-token rejection case** | **TIME-2** | **GAP** |
| IA-SES-10 | session revoked | `RevokeSession` again with the same token | succeeds (idempotent — `applyRevokeSession` deletes unconditionally, apply.go:190-195) | — | **GAP** |
| IA-SES-11 | no such session | `RevokeSession(actor, "signet.never-existed")` | succeeds with no error and no state change — deliberately no oracle for "was this a real token?" | AT-0 | **GAP** |
| IA-SES-12 | two sessions for the same principal | revoke one | the other still resolves — sessions are keyed by token hash, not by principal | — | **GAP** |
| IA-SES-13 | dialect layer, valid bearer | `POST /v1/auth/token/revoke-self` | `204`; subsequent authenticated request → `403` (handler.go:552-563) | TIME-2 | **GAP** |
| IA-SES-14 | dialect layer, no bearer | `POST .../revoke-self` | `403`, kernel not called (handler.go:553-556) | — | **GAP** |
| IA-SES-15 | dialect layer, bearer that is not a live session | `POST .../revoke-self` | `204` — same response as the real thing (see IA-SES-11). Note the actor recorded is `""` (handler.go:558); see Bug B-5 | — | **GAP** |
| IA-SES-16 | `CreateSession` for a principal ID that does not exist | Op applied | rejected: `session: principal %s does not exist` (apply.go:170-174), and **no partial state is written** | K-1 | COVERED `apply_test.go:289, 276-306` |
| IA-SES-17 | `CreateSession` with empty `ID` or empty `TokenHash` | Op applied | rejected: `session: missing ID or token hash` (apply.go:167-169) | — | **GAP** |
| IA-SES-18 | node restarted twice | lookup of a token minted before the first restart | resolves; the session is durable state, not process memory | — | COVERED `fsm_test.go:68-88` |
| IA-SES-19 | session revoked, then node restarted | lookup | still `ErrNoSession` — revocation survives replay | TIME-2 | **GAP** |
| IA-SES-20 | replay of a log containing `CreateSession` at a fixed index onto a fresh store | compare `SnapshotRaw()` | byte-identical — the raw token is generated at *propose* time, so `Apply` stays pure | **DB-3** | COVERED `apply_test.go:90-126` (includes a `CreateSession` at `apply_test.go:99`) |
| IA-SES-21 | 10 000 `newToken()` calls | collect | all distinct, all prefixed `signet.`, all decoding to 32 bytes of `crypto/rand` (kernel.go:495-501) | DB-3 | **GAP** |
| IA-SES-22 | — | `HashToken` | SHA-256, lowercase hex, 64 chars, stable across builds (kernel.go:490-493). This value is a durable store key — changing it orphans every live session | — | **GAP** |
| IA-SES-23 | scoped read after login (`AMR`/`AuthTime` propagation) | issue a credential from a `Login`-minted session | `Claims.AMR == ["k8s-sa"]`, `Claims.AuthTime == session.AuthTime` (issue.go:170) | AT-5 | **GAP** |
| IA-SES-24 | `CreateSession` called with an `actor` that holds no authority over `principal` | Op applied | **succeeds** — `applyCreateSession` (apply.go:166-188) performs *no* authority check, unlike `PutBinding`/`PutMapping`/`PutIssuer`. Not reachable from any dialect today. See Bug B-6 / Q10 | **DB-3, K-3** | **GAP** |

## I. Token storage & secret hygiene — `IA-TOK-*`

Contract (docs/15 contract 2, `op.go:145-148`): the raw bearer token exists in
exactly two places — the client's hands, and the return value of `CreateSession`.

| ID | Preconditions | Input | Expected result | Threat | Coverage |
|---|---|---|---|---|---|
| IA-TOK-01 | — | encode `op.CreateSession` and inspect the JSON body | no field whose name contains `token` other than `token_hash` | **DB-3** | COVERED `op_test.go:38-55` |
| IA-TOK-02 | session created | scan `BucketSessions` keys and decrypted values | the key is the hex hash; no value contains the raw token substring | DB-3 | **GAP** |
| IA-TOK-03 | session created | `SnapshotRaw()` over every bucket | the raw token appears nowhere, in ciphertext or plaintext | **DB-3, BK-1** | **GAP** |
| IA-TOK-04 | login + revoke | dump `BucketAudit` records | `CreateSession`'s audit `Subject` is the principal ID (apply.go:373-374); no token, no hash | DB-3, AL-1 | **GAP** |
| IA-TOK-05 | revoke | dump the `RevokeSession` audit record | **records neither a subject nor (via the dialect) an actor** (apply.go:375-376, handler.go:558). A revocation is currently unattributable. See Bug B-5 | **AL-1** | **GAP** |
| IA-TOK-06 | every failure mode in section G | inspect the returned `error` strings | no error embeds the raw evidence or the raw token. (`Login`'s errors carry rule name and `ns/sa` only — kernel.go:92, 102, 120) | DB-3 | **GAP** |
| IA-TOK-07 | store on disk | `Tx.Put` path | all session values are sealed by the barrier before hitting bbolt (`store.go:111-118`), AAD-bound to `(bucket, key)` | BK-1 | **GAP** for the sessions bucket specifically |
| IA-TOK-08 | genesis | `signet genesis` stdout | raw tokens **are** printed (`cmd/signet/main.go:284`, `:304`) — by design, this is the one moment a domain can hand out its first credentials. In Kubernetes this lands in the init-container log and is scraped by `test/kind/run.sh:66-68`. Assert the tokens go to **stdout only** and never to the audit log or the store | **DB-3** | **GAP** — and see Q11 |
| IA-TOK-09 | `signet token` subcommand | stdout | the bare token and nothing else (`main.go:692`), so it is pipeable without leaking context into shell history | — | **GAP** |
| IA-TOK-10 | timing | `LookupSession` with a valid vs an invalid token | resolution is a hashed-key store lookup, never a comparison of raw secret bytes (kernel.go:177) | — | **GAP** (documented property; no timing test proposed) |

## J. Freshness-tier gate — `IA-TIER-*`

`filterRoles` (`issue.go:200-252`), tier constants (`issue.go:37-42`),
`loadRolePolicy` (`issue.go:254-265`). The E-01 K-2 requirement: the gate is
enforced **once, centrally, in the mint path**, and a serializer receives claims
that are already filtered (`issue.go:118-126`).

| ID | Preconditions | Input | Expected result | Threat | Coverage |
|---|---|---|---|---|---|
| IA-TIER-01 | principal holds `kv-reader`(no policy), `kv-writer`(tier 1 + `RequiredAMR:webauthn`), `kv-admin`(tier 3); session `AMR=["k8s-sa"]` | `Issue` | claims carry exactly `["kv-reader"]` | **K-2** | COVERED `issue_test.go:124-145` |
| IA-TIER-02 | role at `MinTier: TierStepUp` (4) | `Issue` | role absent — the gate is `>= TierOnlineOnly` (issue.go:223-225), so tier 4 is excluded too | **K-2** | **GAP** — only tier 3 is exercised |
| IA-TIER-03 | role at `MinTier: TierShortLeash` (2) with `MaxTTLSec: 60`; request `TTL: 1h` | `Issue` | role present, credential lifetime ≤ 60s | K-2 | COVERED `issue_test.go:197-228` |
| IA-TIER-04 | role with **no** `RolePolicy` record | `Issue` | treated as tier 1 and embedded (issue.go:258-261). This is docs/06's documented default; note the tension with E-01's "missing signal = insufficient" (Q12) | K-2 | PARTIAL — implied by IA-TIER-01's `kv-reader` |
| IA-TIER-05 | role with `RequiredAMR:"webauthn"`; session `AMR=["webauthn"]` | `Issue` | role **present** — the gate is a condition, not a blanket refusal (issue.go:226-228) | AT-5 | COVERED `issue_test.go:149-180` |
| IA-TIER-06 | role with `RequiredAMR:"webauthn"`; session `AMR=[]` | `Issue` | role absent | AT-5 | COVERED `issue_test.go:124-145` |
| IA-TIER-07 | role with `RequiredAMR:"webauthn"`; session `AMR=["webauthn-ish"]` | `Issue` | role absent — `containsExact` (model.go:179-186), no prefix or fuzzy match | AT-5 | **GAP** |
| IA-TIER-08 | **session minted by `Login` from a k8s SA token** (`AMR=["k8s-sa"]`), role requires `webauthn` | `Issue` | role absent — a workload can never inflate its way into a human-factor role | **AT-5, K-2** | **GAP** — the Login↔tier-gate join is untested |
| IA-TIER-09 | serializer that appends a role it was not given | `Issue` | credential refused: `refusing to release credential: ...` (issue.go:184-188). Verify-after-sign | **K-2** | COVERED `issue_test.go:184-193` |
| IA-TIER-10 | binding with `NotAfter` in the past | `Issue` | role absent (issue.go:212-214) | TIME-2 | PARTIAL — `apply_test.go:364-365` covers the equivalent in `HasAuthority` |
| IA-TIER-11 | binding at `/clusters/lab`, request `Scope: /clusters/prod` | `Issue` | role absent (issue.go:215-218) | K-1 | COVERED `issue_test.go:259-292` |
| IA-TIER-12 | session `Expiry` = now+30s, request `TTL: 1h` | `Issue` | credential expiry ≤ session expiry (issue.go:242-247) | TIME-2 | COVERED `issue_test.go:231-255` |
| IA-TIER-13 | session already past its `Expiry` | `Issue` | error `session has expired` (issue.go:248-250). Note `Issue` takes a `Session` **value** and never re-reads it — the dialect's `LookupSession` is what normally enforces this | TIME-2 | **GAP** |
| IA-TIER-14 | roles resolved from several bindings in arbitrary order | `Issue` twice | `Claims.Roles` identical and sorted (issue.go:239-241) | — | **GAP** |
| IA-TIER-15 | two bindings for the same role at different scopes, both covering | `Issue` | role appears **once** (issue.go:234-237) | — | **GAP** |
| IA-TIER-16 | tier-3 role, **every** registered serializer (OIDC, SSH CA, and any future one) | `Issue` across the dialect table | no offline credential ever carries an online-only role | **K-2** | **GAP** — docs/10:16 names this as a cross-dialect property test; today it exists only against `captureSerializer` |
| IA-TIER-17 | `PutRolePolicy` with `MinTier: 0` or `5` | Op applied | rejected: `role policy: tier %d out of range` (issue.go:55-57) | K-2 | **GAP** |
| IA-TIER-18 | `PutRolePolicy` by a non-domain admin | Op applied | rejected (issue.go:58-60 → apply.go:276-295) — tier lives on the role and only its owner may write it (E-13 F3) | **K-2** | **GAP** |
| IA-TIER-19 | `PutRolePolicy` naming an unknown role | Op applied | rejected: `unknown role %q` (issue.go:49-51) | — | **GAP** |

## K. End-to-end / interop — `IA-E2E-*`

Run by `./test/kind/run.sh` against a real kind cluster, the upstream ESO chart, and
upstream cert-manager. Per docs/10:50-51, interop uses **real clients, never mocks**.

| ID | Preconditions | Input | Expected result | Threat | Coverage |
|---|---|---|---|---|---|
| IA-E2E-01 | kind cluster; its `/openid/v1/jwks` fetched out of band and mounted as a ConfigMap (`run.sh:42-49`); issuer pinned in `genesis.json` (`signet.yaml:48-53`) | ESO SecretStore with `role: eso`, `audiences: ["signet"]` (`externalsecret.yaml:37-43`) | ESO authenticates as `demo/signet-client`, syncs `LITELLM_MASTER_KEY` | AT-1 | COVERED `run.sh:102-107` |
| IA-E2E-02 | as above | ExternalSecret for `cluster-main/apps/forbidden` | refused — attested correctly, out of the mapped principal's scope | K-1 | COVERED `run.sh:108-115` |
| IA-E2E-03 | as above; SA `demo/impostor` (`externalsecret.yaml:104-140`) | same `role: eso` mapping | refused — the mapping names service accounts exactly | **K-1, AT-1** | COVERED `run.sh:108-115` |
| IA-E2E-04 | as above | ExternalSecret for a nonexistent path | refused with the `404 {"errors":[]}` shape, distinct from a permission failure | — | COVERED `run.sh:108-115` |
| IA-E2E-05 | as above | a SecretStore requesting `audiences: ["vault"]` | login refused — the audience is what stops a token minted for another service from being replayed | **AT-0, AT-1** | **GAP** — the negative-audience case is absent from the kind suite |
| IA-E2E-06 | as above | a SecretStore whose SA lives in a namespace the mapping does not list | login refused | **K-1** | **GAP** — only the wrong-SA half is exercised, not the wrong-namespace half |
| IA-E2E-07 | as above; cluster signing keys rotated, ConfigMap re-pinned, `PutIssuer` re-run | ESO re-login | succeeds against the new key set with no restart | AT-1 | **GAP** |
| IA-E2E-08 | as above; ConfigMap left at the **stale** key set after cluster rotation | ESO re-login | refused, and refused *loudly* — a pinned-key-set outage must not degrade to "trust anything" | **AT-2** | **GAP** |
| IA-E2E-09 | ESO holds a live session; the mapping is deleted | ESO's next refresh after session expiry | login fails; the *existing* session keeps working until it expires (revocation latency = session TTL, 900s here) | TIME-2 | **GAP** — the docs/10:46-47 "revocation propagation ≤ one role-TTL" case |
| IA-E2E-10 | ESO holds a live session; that session is revoked server-side | next refresh | fails immediately | TIME-2 | **GAP** |
| IA-E2E-11 | cert-manager attests as `demo/certmanager-client` via mapping `certmanager` (`signet.yaml:62-67`) | Certificate request in-scope | issued, verifies against the published chain under `openssl` | — | COVERED `run.sh:133`, `run.sh:141` |
| IA-E2E-12 | cert-manager, domain outside the signing role | Certificate request | refused | K-1 | COVERED `run.sh:148-152` |

---

## Coverage summary

| Section | Scenarios | COVERED | PARTIAL | GAP |
|---|---:|---:|---:|---:|
| A. JWS core verification (`IA-JWS`) | 30 | 8 | 1 | 21 |
| B. JWKS & rotation (`IA-JWK`) | 18 | 4 | 0 | 14 |
| C. Issuer/audience pinning (`IA-PIN`) | 17 | 4 | 2 | 11 |
| D. k8s SA extraction (`IA-K8S`) | 14 | 3 | 1 | 10 |
| E. Verifier registry (`IA-REG`) | 6 | 0 | 0 | 6 |
| F. Mapping rules (`IA-MAP`) | 20 | 6 | 0 | 14 |
| G. Login end to end (`IA-LOG`) | 18 | 0 | 3 | 15 |
| H. Session lifecycle (`IA-SES`) | 24 | 3 | 3 | 18 |
| I. Token hygiene (`IA-TOK`) | 10 | 1 | 0 | 9 |
| J. Freshness tier gate (`IA-TIER`) | 19 | 7 | 2 | 10 |
| K. End-to-end interop (`IA-E2E`) | 12 | 6 | 0 | 6 |
| **Total** | **188** | **42** | **12** | **134** |

Roughly **22% fully covered, 6% partially, 71% uncovered.** The covered fraction is
not evenly spread: the JOSE attack corpus (`jwt_test.go:142-192`) and the tier gate
(`issue_test.go`) are genuinely well tested, while **`Kernel.Login` — the function
that joins verification to policy — has no unit test whatsoever**, and the session
lifecycle is exercised only incidentally as other tests' fixtures.

## Top gaps by risk

1. **`Login` is untested (IA-LOG-01..18, 18 scenarios).** Every property the design
   documents about the authentication path — verify-then-match ordering, TTL
   clamping to evidence expiry, fail-closed on an unknown verifier, uniform errors
   — lives in `kernel.go:81-134` and is asserted nowhere in Go. The kind suite
   exercises the happy path plus one impostor case, which is 20 minutes of cluster
   spin-up away from any developer's inner loop. **This is the single highest-value
   gap in the area.**

2. **Cross-issuer / cross-cluster replay isolation (IA-JWK-17, IA-LOG-06,
   IA-REG-04).** `docs/10:17-18` names "verifier audience/issuer isolation" as a
   release-gating property test for AT-0. There is no test with **two** issuers
   registered simultaneously, so the property that a token from cluster A cannot
   authenticate against cluster B's mapping is currently asserted by construction
   only. AT-1 rates this HIGH and cites four real CVEs in the same shape.

3. **Session revocation and expiry (IA-SES-05, 06, 09, 10, 13, 19).** Revocation is
   the *only* control that shortens the credential window below TTL (docs/06:79-83),
   and nothing tests that a revoked token stops working, that revocation survives a
   restart, or that lazy expiry fires. `Kernel.SetClock` exists (`kernel.go:55-56`)
   precisely to make these testable and is **called by zero tests** — see Bug B-4,
   which currently makes half of them untestable anyway.

4. **Mapping matchers are never property-tested (IA-MAP-08, 09, 10, 17).** Bindings
   get a 400-iteration randomised delegation-narrows test (`apply_test.go:131-175`);
   mappings — which E-01 K-1 calls "the single most important kernel control" — get
   two hand-picked cases. Nothing asserts that a glob is a literal, that matching is
   case-sensitive, or that no whitespace normalisation happens. A future "helpful"
   change to `containsExact` would sail through CI.

5. **Cross-dialect tier-gate property test (IA-TIER-16), plus tier 4 (IA-TIER-02).**
   `docs/06:56-63` and `docs/10:16` both demand *"no offline credential ever carries
   an online-only role"* proven across **all present and future** serializers. Today
   it is proven against one test double. The OIDC and SSH CA serializers ship in this
   tree and are not in the loop, and step-up (tier 4) has no test at all.

Runners-up worth scheduling: the `Evidence` shape test (IA-PIN-17) is a two-line
guard for the strongest claim the package makes; the token-hygiene sweep over
snapshots (IA-TOK-03) is the only thing that would catch a raw token leaking into a
backup; and `nbf` handling (IA-JWS-27/28) is a whole validation branch with zero
exercise.

## Suspected live bugs

**B-1 — one unsupported key in a JWKS disables the entire issuer.**
`ParseJWKS` (`jwt.go:54-58`) returns an error if *any* key in the set fails
`publicKey()`. `K8sSA.Verify` calls it on every login (`k8ssa.go:70`), so a cluster
that adds a single key of a type Signet does not model (`OKP`/Ed25519, or an
`oct` entry) makes **every** workload on that cluster fail to authenticate — a
total, cluster-wide auth outage triggered by a change on the Kubernetes side.
Skipping unparseable keys (they can never verify anything anyway) preserves the
security property and removes the outage. *Severity: availability, HIGH. Test:
IA-JWK-05.*

**B-2 — `PutIssuer` accepts a key set that parses to nothing.**
`apply.go:207-209` checks `len(o.JWKS) == 0` — the byte length — so
`{"keys":[]}` is stored as a valid trust anchor. Two existing tests
(`apply_test.go:220`, `apply_test.go:235`) depend on this. The misconfiguration
surfaces only at the first login attempt, as an authentication failure with no
pointer at the cause. `applyPutIssuer` should call `attest.ParseJWKS` and reject.
Same branch: `o.Verifier` is never validated against the registry (IA-PIN-14).
*Severity: operability, MED.*

**B-3 — mapping-rule narrowing is enforced at write time only, not re-checked at
issuance.** E-01 K-1 (`E-01:291-294`) and `docs/04:35-40` both require the ESC1
guard "enforced at rule-write time *and* re-checked at issuance (defense in
depth)". `applyPutMapping` does the write-time half (`apply.go:251-257`);
`Kernel.Login` (`kernel.go:81-134`) does no re-check at all. Consequence: when a
delegated admin's authority is revoked or lapses via `NotAfter`, every mapping they
authored keeps minting sessions for its target principal indefinitely. This is a
documented v1 control that is half-implemented. *Severity: MED (requires a prior
delegated-admin compromise or an offboarding), but it is the exact defence-in-depth
layer the threat model asks for. Test: IA-MAP-18.*

**B-4 — `SetClock` is not honoured by the two TTL clamps.** `Kernel.now` is
injectable (`kernel.go:42, 55-56`) and used for verification, session expiry, and
authority checks — but `kernel.go:129` (`time.Until(id.Expiry)`) and
`issue.go:244` (`time.Until(time.Unix(s.Expiry, 0))`) call the wall clock
directly. Under a fake clock the kernel therefore holds two disagreeing notions of
"now", and a test that advances the clock to check evidence-bounded session TTL or
session-bounded credential TTL gets an incoherent answer. In production both
resolve to the same host clock, so this is not exploitable — but it is why
`SetClock` has **zero callers** across the whole tree, and it blocks IA-LOG-09,
IA-LOG-14, IA-SES-05/06 and IA-TIER-13 from being written honestly.
*Severity: testability, MED — it is load-bearing for this plan.*

**B-5 — session revocation is unattributable in the audit log.**
`NewAuditRecord` for `RevokeSession` sets `Actor` and `AtSec` but no `Subject`
(`apply.go:375-376`), and the Vault dialect passes an empty actor
(`handler.go:558`). The resulting audit record therefore identifies neither who
revoked nor what was revoked. Against docs/11's "enough provenance to distinguish a
legitimately issued change from a forged one" and E-01 AL-1, this is a hole: a
mass-revocation denial-of-service would leave an audit trail of identical anonymous
entries. The token hash is already in the Op and is a safe subject value.
*Severity: auditability, MED.*

**B-6 — `CreateSession` performs no authority check (design gap, not yet
exploitable).** `applyCreateSession` (`apply.go:166-188`) validates only that the
principal exists, while its three peers — `applyPutBinding`, `applyPutMapping`,
`applyPutIssuer` — all enforce delegation-narrows or domain authority in `Apply`.
`Kernel.CreateSession` is an exported method whose `actor` argument is decorative.
Today the only callers are genesis (root) and `Login` (self), so nothing is
reachable; but E-01 DB-3 calls the session key the golden-ticket key, and the one Op
that mints sessions is the one Op with no authorization invariant in the serialized
writer. *Severity: latent, MED. Test: IA-SES-24.*

## Questions for the maintainer

1. **Audience: membership or equality?** `jwt.go:205` accepts any token whose `aud`
   *includes* the configured audience; E-01:423 says "reject tokens whose `aud` is
   not exactly Signet's". Which is the intended contract? Membership is friendlier
   to a workload that needs one projected token for several consumers; equality is
   what the threat model literally asks for. IA-PIN-08 asserts whichever you pick.

2. **Evidence replay within its validity window.** The same projected SA token can
   be presented repeatedly to mint multiple concurrent sessions (IA-LOG-13). Is
   that intended (it matches Vault's k8s auth), or should evidence be single-use
   with a `jti`/`(iss,sub,iat)` replay cache? This decision changes whether
   IA-LOG-13 is a positive or a negative test.

3. **Is there a domain-wide ceiling on session TTL?** `Login` honours
   `mapping.TTLSeconds` with no upper bound, defaulting to 1h when unset
   (`kernel.go:123-126`). docs/06 says "hours (configurable per attestation source;
   homelab default 12h)". Should a mapping be able to request a year, and should
   the default live in config rather than as a literal in `Login`?

4. **P-384 / P-521 in a JWKS.** `publicKey` accepts them (`jwt.go:79-88`) but
   `verifySignature` only implements `ES256` with a 64-byte signature
   (`jwt.go:229-234`), so such a key silently verifies nothing. Should `ParseJWKS`
   reject curves the verifier cannot use, or should `ES384`/`ES512` be implemented?
   Right now the failure mode is a mystery outage.

5. **Minimum RSA key size.** None is enforced (`jwt.go:64-76`). Pinned key sets
   limit the exposure, but a 1024-bit floor is one line. Wanted?

6. **Should `PutIssuer` validate `Verifier` against the registry?** Doing so
   requires `Apply` to know the verifier set, which is a build-time property, not
   state — so it stays pure, but it does couple the FSM to `attest`. Acceptable, or
   deliberately deferred?

7. **Unvalidated JOSE fields.** `typ` (jwt.go:144), `iat` (jwt.go:190-192), and the
   JWK's own `use`/`alg` (jwt.go:37-38) are all decoded and never checked. Which of
   these should become hard requirements — `typ` in particular is cheap insurance
   against cross-format confusion if Signet ever verifies a second JWT shape.

8. **Subject parsing strictness.** `parseSubject` splits on the first colon only, so
   `system:serviceaccount:ns:name:extra` parses as account `name:extra`
   (IA-K8S-08); and a `kubernetes.io` claim that fails to unmarshal is silently
   ignored (`k8ssa.go:87`), degrading the cross-check to `sub` alone (IA-K8S-10).
   Both are unreachable from a real API server. Tighten anyway, or document as
   accepted?

9. **Expired session records are never reclaimed.** `LookupSession` refuses them
   (`kernel.go:189-191`) but nothing deletes them, so `BucketSessions` grows without
   bound and carries every expired session into every snapshot and backup. Is a
   compaction pass planned, or is the lazy-expiry-forever behaviour intentional?

10. **Should `CreateSession` be authorized?** See B-6. If the answer is "yes, in
    `Apply`", the natural rule is: `actor == principal`, or `actor` holds admin at
    the principal's path — with genesis exempted the way bootstrap bindings are.

11. **Genesis tokens on stdout.** `main.go:284` and `:304` print raw bearer tokens,
    which in the Kubernetes deployment become container-log content readable by
    anyone with `kubectl logs -n signet` (and `test/kind/run.sh:66-68` relies on
    exactly that). Is a file-descriptor or file-path delivery mode wanted before v1,
    and should IA-TOK-08 assert stdout-only as a *requirement* or flag it as debt?

12. **"Missing tier signal = insufficient" vs "tier 1 is the default".**
    `loadRolePolicy` returns `MinTier: TierOffline` for a role with no policy
    record (`issue.go:258-261`), which matches docs/06's table ("1 Offline
    (default)") but reads against E-01 K-2's "treat a missing freshness/tier signal
    as insufficient, never satisfied (fail closed)". Which reading governs for a
    role nobody has written a policy for? IA-TIER-04 pins the answer.

13. **Follower reads of session state.** `LookupSession` and `Login` read the local
    store directly (`kernel.go:86`, `:176`). In a multi-voter domain a follower could
    honour a session that the leader has already revoked, for the length of the
    replication lag. Is that within the accepted revocation window (docs/06:79-83),
    or should session reads be leader-only / lease-read?
