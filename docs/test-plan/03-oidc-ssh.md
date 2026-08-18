# Test plan 03 — OIDC and SSH-CA dialects

**Status: Draft — design document only. No source or test file was modified to produce it.**
**Scope:** `internal/dialect/oidc`, `internal/dialect/sshca`, `internal/keys`, and the
kernel surface those two dialects stand on (`internal/kernel/issue.go`,
`internal/kernel/pki.go`).

Companion to `docs/10-testing-strategy.md` (layers and principles) and
`docs/07-dialect-roadmap.md` (what each dialect is for). Where the two disagree with
the code, the code is cited and the disagreement is raised in
[Questions for the maintainer](#questions-for-the-maintainer).

---

## 0. Executive summary

| | |
|---|---|
| Scenarios specified | **125** |
| Covered by an existing automated test | **6** (all indirect, via the kernel mint path) |
| GAP | **119** |
| Of those, requiring a **real external client** (kubectl / kube-apiserver / sshd / browser SSO) | **31** |
| Suspected live bugs found while writing this plan | **6** (§14) |

The blunt fact this plan starts from: **`internal/dialect/oidc`, `internal/dialect/sshca`
and `internal/keys` have no test files at all.** The repository's `*_test.go` set is:

```
internal/attest/jwt_test.go            internal/kernel/issue_test.go
internal/audit/audit_test.go           internal/kernel/path_test.go
internal/ca/ca_test.go                 internal/kernel/sealrotate_test.go
internal/ca/ceremony_test.go           internal/kernel/secrets_test.go
internal/dialect/vaultkv/handler_test.go   internal/op/op_test.go
internal/fsm/fsm_test.go               internal/seal/*_test.go
internal/kernel/activation_test.go     internal/store/audit_test.go
internal/kernel/apply_test.go          internal/trust/*_test.go
```

and the shell harnesses are `test/audit`, `test/fabric`, `test/kind`, `test/pam`,
`test/trust`. None of them touch `/.well-known/openid-configuration`, `/oidc/keys`,
`/oidc/token`, or `/v1/ssh/sign/{role}`.

`docs/16-implementation-status.md:18-19` records SSO as "proven by `kubectl` against a
real Kubernetes API server" and SSH as "proven by a real `sshd`". Those runs are not in
the repository. `test/kind/signet.yaml:126` does configure `-issuer-url` and
`test/kind/signet.yaml:101-104` issues the HTTPS serving certificate the API server
needs — the scaffolding is there — but `test/kind/run.sh` never configures
`--oidc-issuer-url` on the API server and never runs `kubectl --token`. The only OIDC in
that script is *inbound*: `run.sh:46` pins **Kubernetes'** JWKS so Signet can verify SA
tokens. Signet's own OIDC surface is unexercised by anything checked in.

For a project whose stated record is that *every consequential bug was found by a real
client* (`docs/16:8-9`), the two dialects whose entire purpose is to be consumed by real
clients are the two with zero client conformance in CI.

---

## 1. What is in scope, and what "supported" means

Supported today, and therefore testable as a positive:

- **OIDC discovery** at `GET /.well-known/openid-configuration` (`oidc.go:53,61-72`)
- **JWKS** at `GET /oidc/keys` (`oidc.go:54,76-94`)
- **RFC 8693 token exchange** at `POST /oidc/token` (`oidc.go:55,96-157`) — the *only*
  grant type (`oidc.go:26,101-105`)
- **SSH user certificate signing** at `POST|PUT /v1/{mount}/sign/{role}`
  (`handler.go:38-39,45`) and **CA public key** at `GET /v1/{mount}/public_key`
  (`handler.go:42,122`)
- **Key purposes and algorithms** (`keys.go:35-45,117-204`), **JWS signing/self-verify**
  (`jws.go:22-102`), **JWK rendering** (`keys.go:240-261`)
- **SSH role model** `SSHRoleSpec` (`pki.go:321-331`) and `AuthorizeSign` (`pki.go:368`)

**Not implemented, therefore not a positive scenario in this plan** (each gets an
assert-the-absence row instead, and a question in
[Questions for the maintainer](#questions-for-the-maintainer)):

- Authorization-code flow, `/authorize`, PKCE, device flow (RFC 8628), `userinfo`,
  introspection (RFC 7662), refresh tokens, `end_session`. `docs/07:10-13` promises
  these for v1 and names Grafana, ArgoCD, Harbor and Proxmox as consumers.
  `oidc.go:66-67` advertises only token-exchange — which is *honest*, and is why the
  browser-SSO clients cannot be conformance targets in this milestone.
- `nonce`. There is no authorization request to carry one; `grep -rn nonce` finds it
  only in design docs and in the SSH cert-format comment (`sshca.go:9`). The task brief
  lists `nonce` under required ID-token claims; **it is not producible today** — see
  CL-15 and Q3.
- SSH **host** certificates (`handler.go:65-67` refuses `cert_type != "user"`).
- SSH **critical options** — `force-command`, `source-address`, `verify-required`. The
  certificate is built with `Permissions{Extensions: ...}` only (`sshca.go:82-84`);
  `CriticalOptions` is never populated anywhere in the package.
- Signing-key **rotation as an operator action**. There is no `signet keys rotate`
  subcommand (`main.go:63-81` lists the subcommand set); `keys.Key.Retired`
  (`keys.go:63`) is declared and never read or written by any code in the tree.

---

## 2. Fixtures

Five fixtures. F1/F2 are the fast in-process ones and should carry most of the matrix;
F3–F5 are the ones that have historically found the bugs.

### F1 — `oidcFixture` (in-process, real kernel)

Model on `internal/dialect/vaultkv/handler_test.go:28-71`, which already does exactly
this for the KV dialect: real `fsm.Open` node, real seal file, real `kernel.New`, real
handlers, `httptest.Server`.

Additions needed for OIDC:

- The issuer URL must equal the server's own URL, because `iss` is compared as a string
  by every relying party (`oidc.go:32-35`). Use `httptest.NewUnstartedServer`, read
  `srv.URL` after `srv.Start()`, and register the handler into a mux the server already
  points at — or run `httptest.NewServer` on a mux and construct
  `oidc.New(k, oidc.Config{Issuer: srv.URL})` afterwards, registering into the same mux.
- Principal `/people/user` with bindings `kv-reader` at `/` and `kv-admin` at `/`, plus
  a `RolePolicy{Role:"kv-admin", MinTier: TierOnlineOnly}` — the same shape as
  `issue_test.go:62-85` — so every token test also re-proves tier exclusion at the
  dialect boundary.
- A token key installed via `InstallKey(..., active=true)` (`issue.go:289`).
- `k.SetClock` (`kernel.go:56`) for the time-travel rows.

### F2 — `sshFixture` (in-process, real kernel)

Same base. Adds:

- `PutSSHRole` (`pki.go:351`) writing an `SSHRoleSpec` (`pki.go:321-331`) with
  `Scope: "/hosts/lab"`, `AllowedPrincipals: ["deploy"]`,
  `PrincipalsFromRoles: {"kv-reader": ["ubuntu"]}`, `MaxTTLSec: 3600`, `AllowPTY: true`.
- A session whose principal holds **`pki-signer` at `/hosts/lab`** — required because
  `handler.go:82` calls `AuthorizeSign` → `VerbSign`, and `VerbSign` is granted only by
  `pki-signer` and `domain-admin` (`model.go:206-212`).
- Freshly generated client keypairs of each type (ed25519, ecdsa-p256, rsa-2048,
  rsa-1024, ssh-dss) as `authorized_keys` bytes.

### F3 — `sshdHarness` (real OpenSSH)

A container (or `Testcontainers`-style helper) running real `sshd` configured with:

```
TrustedUserCAKeys /etc/ssh/signet_ca.pub      # from GET /v1/ssh/public_key
AuthorizedPrincipalsFile /etc/ssh/principals/%u
AuthorizedKeysFile none
```

Test asserts on the *client's* exit status and on `sshd -ddd` log lines
(`Accepted publickey ... ID /people/user (serial N) CA ssh-ed25519 ...`). This is the
only way to test what `sshd` actually accepts; `ssh.CertChecker` in `sshca.go:154-161`
is Go's opinion, not OpenSSH's, and the two differ (extension handling, empty-principal
semantics, unknown critical options).

### F4 — `kindOIDC` (real kube-apiserver)

Extend `test/kind/run.sh`. The pieces already exist: `signet.yaml:126` pins
`-issuer-url=https://10.96.0.20:8200`, `signet.yaml:99-105` issues the serving cert with
the right SANs, and `signet.yaml:156` pins the ClusterIP because the API server can route
to it but cannot resolve cluster DNS. What is missing is a `kind` config that passes
`--oidc-issuer-url`, `--oidc-client-id`, `--oidc-ca-file`, `--oidc-username-claim=sub`,
`--oidc-groups-claim=groups` to the API server, and a `kubectl --token=<id_token>` call
plus a `SubjectAccessReview` on the resulting username/groups.

### F5 — `browserSSO` (deferred)

Grafana / ArgoCD / Harbor headless login. **Blocked** until the authorization-code flow
exists (§1). Listed here so it is not silently forgotten; every row that depends on it is
marked `BLOCKED` rather than `GAP`.

---

## 3. OIDC discovery — `OD-*`

Endpoint: `GET /.well-known/openid-configuration` (`oidc.go:53`). Handler
`oidc.go:61-72`. Fixture F1 unless noted.

| ID | Precondition | Request | Expected observable result | Client that depends on it | Coverage |
|---|---|---|---|---|---|
| OD-01 | F1, `Issuer = srv.URL` | `GET /.well-known/openid-configuration` | `200`, `Content-Type: application/json` (`http.go:11-14`) | all | **GAP** |
| OD-02 | F1 | as above | `issuer` is byte-identical to the configured `Issuer` — no trailing slash added, no scheme rewrite (`oidc.go:63`) | kube-apiserver: go-oidc compares `iss` in the doc to the URL it fetched and errors `oidc: issuer did not match` on any difference | **GAP** |
| OD-03 | F1 | as above | `jwks_uri == Issuer + "/oidc/keys"` and that URL is fetchable and returns a key set (`oidc.go:64`) | kube-apiserver, any JWT verifier | **GAP** |
| OD-04 | F1 | as above | `token_endpoint == Issuer + "/oidc/token"` and `POST` to it is routed (`oidc.go:65`, `oidc.go:55`) | RFC 8693 clients | **GAP** |
| OD-05 | F1 | as above | `grant_types_supported == ["urn:ietf:params:oauth:grant-type:token-exchange"]` exactly — one element, no `authorization_code`, no `refresh_token` (`oidc.go:66`, const at `oidc.go:26`) | honesty contract: a client must not be led down a flow that 400s later (`oidc.go:58-60`) | **GAP** |
| OD-06 | F1 | as above | `id_token_signing_alg_values_supported` contains `"RS256"` (`oidc.go:69`) | kube-apiserver rejects a provider that cannot do RS256; ArgoCD's OIDC settings validation also looks for it | **GAP** |
| OD-07 | F1 | as above | `subject_types_supported == ["public"]` (`oidc.go:68`) | go-oidc tolerates absence but several IdP libraries require the key | **GAP** |
| OD-08 | F1 | as above | `claims_supported` contains `sub`, `aud`, `exp`, `iat`, `iss`, `groups`, `amr`, `auth_time` (`oidc.go:70`) | Grafana `role_attribute_path` / ArgoCD `scopes: [groups]` read `groups`; the advertised list must match what CL-* actually observes in a token | **GAP** |
| OD-09 | F1 | as above | **Consistency invariant:** every claim named in `claims_supported` (`oidc.go:70`) is actually emitted by `jwtSerializer.Serialize` (`oidc.go:167-189`) for at least one supported request shape, and every claim emitted is named in the list. Today `nbf` is emitted (`oidc.go:171`) and *not* advertised | any client that trusts the metadata | **GAP** — and this row fails today, see Q3 |
| OD-10 | F1 | as above | `authorization_endpoint` is **absent**, and `response_types_supported` (`oidc.go:67`) does not promise a flow reachable through it. Assert absence explicitly so adding the field is a deliberate act | ArgoCD/Grafana: an *empty* `authorization_endpoint` is worse than a missing one — the client builds a redirect to `""` | **GAP** |
| OD-11 | F1 | as above | `response_types_supported == ["token"]` — recorded as the current value. **This is under-specified** (Q4): `token` names the implicit flow, which has no endpoint here | — | **GAP** |
| OD-12 | F1 | `HEAD`, `POST`, `PUT` on the discovery path | `405` from `net/http`'s method-pattern routing (`oidc.go:53` registers `GET` only), not `200` | proxies and probes | **GAP** |
| OD-13 | F1, TLS server | `GET` over plain HTTP where the issuer is `https://…` | Documented behaviour: Signet serves the doc regardless; the *deployment* is what enforces HTTPS (`signet.yaml:101-104` comment: "Kubernetes will only fetch OIDC discovery over HTTPS") | kube-apiserver refuses a non-HTTPS issuer | **GAP** |
| OD-14 | F4 | kube-apiserver started with `--oidc-issuer-url=https://10.96.0.20:8200` | API server reaches `Ready` and its log contains no `oidc authenticator: initializing plugin` failure | kube-apiserver | **GAP — real client required** |

---

## 4. JWKS publication, rotation and overlap — `JW-*`

Endpoint `GET /oidc/keys` (`oidc.go:54`), handler `oidc.go:76-94`, JWK rendering
`keys.go:240-261`, key enumeration `kernel.PublicKeys` (`issue.go:329-341`).

| ID | Precondition | Request | Expected observable result | Client that depends on it | Coverage |
|---|---|---|---|---|---|
| JW-01 | F1, one active RS256 token key | `GET /oidc/keys` | `200`; `keys` is an array of length 1 | all | **GAP** |
| JW-02 | F1 | as above | The JWK has `kty:"RSA"`, `alg:"RS256"`, `use:"sig"`, `kid`, `n`, `e` — and **nothing else**; in particular no `d`, `p`, `q`, `dp`, `dq`, `qi` (`keys.go:247-251`) | every verifier; and this is the "no code path publishes a private key" claim at `keys.go:238-239` | **GAP** |
| JW-03 | F1 | as above | `n` and `e` are `base64url` **without padding** (`keys.go:274`) and decode to the modulus/exponent of the active key's public half | Go, Python `jwcrypto`, Java Nimbus all reject padded values | **GAP** |
| JW-04 | F1 | as above | `e` is `"AQAB"` for the standard 65537 exponent — i.e. `big.NewInt(int64(p.E)).Bytes()` (`keys.go:250`) produces 3 bytes, not a left-padded 4-byte word | strict JWK parsers | **GAP** |
| JW-05 | F1 | as above | `kid` equals `Key.ID`, which is the SHA-256 thumbprint of the PKIX DER truncated to 16 bytes (`keys.go:265-272`), and is **stable across process restarts** — reopen the node, re-fetch, assert the same `kid` | kube-apiserver caches JWKS keyed by `kid`; a churning `kid` is a cache-miss storm and, with an unlucky refresh window, an auth outage | **GAP** |
| JW-06 | F1 | as above | `Cache-Control: public, max-age=300` (`oidc.go:92`) | kube-apiserver and go-oidc honour it; too long a max-age turns rotation into an outage (`oidc.go:90-91`) | **GAP** |
| JW-07 | F1, ES256 token key installed via `keys.GenerateAlg(PurposeToken,"ES256",…)` (`keys.go:146,150-164`) | as above | JWK is `kty:"EC"`, `crv:"P-256"`, `alg:"ES256"`, `x`, `y`, each exactly 32 bytes before base64 (`keys.go:252-257`, note `FillBytes(make([]byte,32))`) | any EC-capable verifier | **GAP** |
| JW-08 | F1, an **audit** key (ES256, `keys.go:165-183`) and an **ssh** key (ed25519, `keys.go:185-200`) also installed | as above | The audit and SSH keys do **not** appear. `PublicKeys` scans prefix `"token/"` (`issue.go:332`, key form `issue.go:98`) | key-separation invariant of `keys.go:30-32`; leaking the audit key into the token key set would let a relying party accept a checkpoint signature as an identity assertion | **GAP** |
| JW-09 | F1 | as above | The active-pointer record `"active:token"` (`issue.go:99`) is **not** emitted as a JWK. It is stored in the same bucket and is excluded only because its key name lacks the `token/` prefix — assert it, because the exclusion is incidental | all | **GAP** |
| JW-10 | F1, key **A** active; mint token T under A; then `InstallKey(B, active=true)` | `GET /oidc/keys` | Both `kid(A)` and `kid(B)` present. **T still verifies.** This is the whole point of `oidc.go:74-75` and `issue.go:327-328` | kube-apiserver mid-rotation; a token minted 30s before rotation must survive its full TTL | **GAP** — and unreachable from the CLI, see Q6 |
| JW-11 | as JW-10 | `POST /oidc/token` after rotation | The **new** token's header `kid` is `kid(B)` (`jws.go:26-28` uses `k.ID`), and B is the key `loadActiveKey` returns (`issue.go:267-284`) | all | **GAP** |
| JW-12 | F1, a key record whose sealed envelope cannot be opened (wrong seal / corrupt AAD, `keys.go:103`) | `GET /oidc/keys` | **Specified behaviour needed.** Today `oidc.go:84-87` does `continue` on error: the key silently vanishes from JWKS while `200 OK` is returned, so live tokens signed by it stop verifying with no signal anywhere. Expected: either a `500` or the key retained-and-logged. See §14 bug 3 | kube-apiserver would begin rejecting valid tokens with `token signature is invalid`, and the operator would have nothing to look at | **GAP + suspected bug** |
| JW-13 | F1, zero token keys installed | `GET /oidc/keys` | `200` with `{"keys":[]}` (`oidc.go:82` allocates an empty slice, so it marshals as `[]` not `null`) | go-oidc treats `null` and `[]` differently in some versions; assert `[]` | **GAP** |
| JW-14 | F1 | 100 concurrent `GET /oidc/keys` | No error; note for the record that each request opens **every** sealed private key (`oidc.go:84` → `keys.go:240` → `keys.go:230` → `keys.go:208`) to derive public halves. Assert latency budget / consider a cache | operational | **GAP** |

---

## 5. ID token claim correctness — `CL-*`

Serializer `oidc.go:167-189`; claim construction `issue.go:165-172`; self-verification
`oidc.go:195-232`; JWS framing `jws.go:22-64`.

All rows: F1, `POST /oidc/token` with a valid subject token, then decode segment 1 and
assert on the JSON.

| ID | Request delta | Expected observable result | Client that depends on it | Coverage |
|---|---|---|---|---|
| CL-01 | baseline | JWT is exactly three `.`-separated base64url segments, no padding (`jws.go:36,63`) | all | **GAP** |
| CL-02 | baseline | Header is `{"alg":"RS256","typ":"JWT","kid":"<kid>"}` — `alg` comes from the *key*, never from the request (`jws.go:19-21,26-28`) | all; this is the alg-confusion guard, mirrored on the inbound side at `attest/jwt.go:133-135` which **is** tested (`attest/jwt_test.go:142` `TestK8sSARejects`) | **GAP outbound / covered inbound** |
| CL-03 | baseline | `iss` equals `Config.Issuer` exactly, and equals discovery's `issuer` (`oidc.go:139`, `oidc.go:169`, `oidc.go:63`) | kube-apiserver string-compares (`oidc.go:33-35`) | **GAP** |
| CL-04 | `audience=kubernetes` | `aud` is the **string** `"kubernetes"`, not `["kubernetes"]` (`oidc.go:169`, `Claims.Audience` is a `string`, `issue.go:108`) | kube-apiserver accepts both, but assert the shape so it cannot silently change; some Java verifiers are strict | **GAP** |
| CL-05 | baseline | `sub` is the principal's **path** (`issue.go:166` `principal.Path`), e.g. `/people/user` — not the opaque `op.ID` | kube-apiserver builds the username from `sub` plus `--oidc-username-prefix`; RBAC subjects are written against this exact string | **GAP** |
| CL-06 | baseline | `iat == nbf == now` and `exp == now + ttl` (`issue.go:168-169`) | all | **GAP** |
| CL-07 | baseline | `exp` and `iat` are JSON **numbers**, not strings (`Claims.ExpirySec int64`, `issue.go:110`) | precedent: `docs/16:90-92` — `bao` sending a version as a JSON string cost a silent destructive-adjacent no-op. Assert types on the wire, not on the struct | **GAP** |
| CL-08 | baseline | `groups` is the tier-filtered role list, sorted (`issue.go:241`), e.g. `["kv-reader"]` | Grafana `role_attribute_path: contains(groups[*],'…')`; ArgoCD `policy.csv` group subjects; kube-apiserver `--oidc-groups-claim=groups` | **GAP** |
| CL-09 | principal additionally holds `kv-admin` with `RolePolicy{MinTier: TierOnlineOnly}` | `groups` does **not** contain `kv-admin` (`issue.go:223-225`) | the flagship invariant of E-01 K-2 | **COVERED indirectly** — `kernel/issue_test.go:124-145` `TestOnlineOnlyRolesAreNeverEmbedded` proves it through `captureSerializer`. **GAP at the dialect boundary**: no test proves the *JWT bytes* omit it |
| CL-10 | session lacks the required AMR for a gated role | the gated role is absent from `groups` (`issue.go:226-228`) | same | **COVERED indirectly** — `issue_test.go:137-140`, and the positive at `issue_test.go:149-180`. **GAP** on the JWT |
| CL-11 | session created with `amr=["webauthn"]` | `amr` claim present and equal to the session's AMR (`oidc.go:173-175`, `issue.go:170`) | step-up-aware relying parties; advertised at `oidc.go:70` | **GAP** |
| CL-12 | session created with `amr=nil` | `amr` key **absent** from the JSON, not `null` (`oidc.go:173-175` guards on length) | strict clients | **GAP** |
| CL-13 | baseline | `auth_time` present and equal to `Session.AuthTime` (`oidc.go:176-178`, set at `kernel.go:159`) | OIDC `max_age` enforcement by relying parties | **GAP** |
| CL-14 | `IssueRequest.Extra` set with a key that collides with `iss` | The reserved claim wins; `Extra` cannot overwrite it (`oidc.go:179-183` `if _, taken := claims[k]; !taken`). Assert with `Extra = {"iss":"https://evil","x":"1"}` → `iss` unchanged, `x` present | **security-relevant**: this is the only place a caller-adjacent map meets the claim set | **GAP** |
| CL-15 | client sends `nonce=abc` in the form body | **Under-specified.** Today the parameter is ignored and no `nonce` claim is emitted (`oidc.go:167-183` has no nonce path). Assert the current behaviour so a future authorization-code flow has a baseline; see Q3 | any OIDC client doing an interactive flow | **GAP (feature absent)** |
| CL-16 | baseline | Round-trip: the emitted token verifies under the published JWKS using an **independent** implementation (`github.com/coreos/go-oidc` or `python-jose`), with issuer and audience checks on | this is the whole product | **GAP — third-party verifier required** |
| CL-17 | baseline | `Verify` re-parse gate: with a serializer stub that appends an extra group, `Issue` returns `refusing to release credential` (`issue.go:186-188`, `oidc.go:223-230`) | charter principle 6 | **COVERED for the generic path** — `issue_test.go:184-193` `TestVerifyAfterSignCatchesAnInventedRole`. **GAP** for `jwtSerializer.Verify` specifically |
| CL-18 | baseline | `jwtSerializer.Verify` catches a **mismatched `exp`** (`oidc.go:220-222`) and a **mismatched `sub`/`aud`/`iss`** (`oidc.go:217-219`). Drive by fault injection on the claims map | same | **GAP** |
| CL-19 | baseline | `jwtSerializer.Verify` catches a token with **fewer** groups than authorized as well as more (`oidc.go:223-225` compares lengths both ways) | same | **GAP** |
| CL-20 | baseline | `jwtSerializer.Verify` rejects a non-three-segment credential (`oidc.go:199-202`) and a segment that is not base64url (`oidc.go:203-206` → `http.go:29-31`) | same | **GAP** |
| CL-21 | F1, clock moved back 30s via `SetClock` before minting, restored after | Recorded: `nbf == iat == mint time` with **no skew allowance** (`issue.go:168`). A relying party whose clock is 5s behind rejects the token as not-yet-valid. Compare `sshca.go:80`, which *does* grant 60s of slack, and `attest.Skew = 30s` (`attest/jwt.go:128`) on the inbound side | Grafana and several JOSE libraries enforce `nbf` strictly; kube-apiserver's go-oidc does not check `nbf` | **GAP — asymmetry, see Q5** |

---

## 6. RFC 8693 token exchange — `TX-*`

Handler `oidc.go:96-157`. Fixture F1.

### 6.1 Positive

| ID | Request | Expected | Client | Coverage |
|---|---|---|---|---|
| TX-01 | `POST /oidc/token`, form: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange&subject_token=<session>&audience=kubernetes` | `200`; body has `access_token`, `issued_token_type: urn:ietf:params:oauth:token-type:id_token`, `token_type: Bearer`, `expires_in`, `scope` (`oidc.go:150-156`) | RFC 8693 clients | **GAP** |
| TX-02 | as TX-01 but `subject_token` omitted and `Authorization: Bearer <session>` set | same `200` (`oidc.go:106-111` → `http.go:22-27`) — keeps the session out of request logs (`oidc.go:108-109`) | any client that prefers headers | **GAP** |
| TX-03 | as TX-02 but with `X-Signet-Token: <session>` | same `200` (`http.go:26`) | Signet-native tooling | **GAP** |
| TX-04 | as TX-01 with `Content-Type: application/x-www-form-urlencoded` body vs. query string | Both work (`r.ParseForm` merges, `oidc.go:97`). Assert deliberately — a client putting `audience` in the query must not 400 | curl, kubectl plugins | **GAP** |
| TX-05 | as TX-01 plus `scope_path=/clusters/lab` | `groups` reflects only bindings covering `/clusters/lab` (`oidc.go:137` → `issue.go:161` → `issue.go:216-218` `ScopeCovers`) | scoped SSO | **COVERED indirectly** — `issue_test.go:259-292` `TestScopeSelectsWhichBindingsApply`. **GAP** on the wire, where the parameter is spelled `scope_path`, not `scope` |
| TX-06 | as TX-01 plus `requested_token_lifetime=300` | `expires_in` ≈ 300 and `exp - iat == 300` (`oidc.go:129-133`, `d = ParseDuration("300"+"s")`) | clients that want short tokens | **GAP** |
| TX-07 | as TX-06 but the role policy caps at 60s | `expires_in ≈ 60` — the strictest ceiling wins (`issue.go:229-233`) | — | **COVERED indirectly** — `issue_test.go:197-228`. **GAP** on the wire |
| TX-08 | as TX-06 with a session expiring in 30s | `expires_in ≤ 30` (`issue.go:243-247`) | — | **COVERED indirectly** — `issue_test.go:231-255`. **GAP** on the wire |
| TX-09 | as TX-01 with no `requested_token_lifetime` | `expires_in ≈ 900` — `Config.DefaultTTL` defaults to 15m (`oidc.go:46-48`) | — | **GAP** |
| TX-10 | as TX-01, `scope` field of the response | equals `strings.Join(claims.Roles, " ")` (`oidc.go:155`) and matches the token's `groups` claim exactly | clients that read `scope` instead of decoding the JWT | **GAP** |
| TX-11 | as TX-01 with `subject_token_type=urn:ietf:params:oauth:token-type:access_token` | `200`. Record that the parameter is **ignored** (`oidc.go:96-157` never reads it) even though RFC 8693 §2.1 marks it REQUIRED — lenient is fine, silent is the risk | generic RFC 8693 libraries always send it | **GAP** |
| TX-12 | as TX-01 with `requested_token_type=…:access_token` | Record: parameter ignored, an ID token is returned, and `issued_token_type` truthfully says so (`oidc.go:152`) — RFC 8693 §2.2.1 permits this, clients may not | — | **GAP** |

### 6.2 Negative — first-class

| ID | Request | Expected | Why it matters | Coverage |
|---|---|---|---|---|
| TX-20 | `grant_type=authorization_code` | `400`, `{"error":"unsupported_grant_type","error_description":"only urn:… is supported"}` (`oidc.go:101-105`, shape from `http.go:18-20`) | a Grafana/ArgoCD misconfiguration must fail loudly and correctly-shaped, per RFC 6749 §5.2 | **GAP** |
| TX-21 | `grant_type` absent entirely | same `400 unsupported_grant_type` (empty string ≠ the constant) | — | **GAP** |
| TX-22 | valid grant, no `subject_token`, no bearer header | `400 invalid_request` "missing subject_token" (`oidc.go:112-115`) | — | **GAP** |
| TX-23 | valid grant + subject token, **no `audience`** | `400 invalid_request` "missing audience" (`oidc.go:116-120`). An audienceless ID token is replayable at every relying party — this refusal is the RFC 8693 analogue of the `attest` rule at `attest/jwt.go:200-204` ("no required audience configured" fails closed), which **is** tested (`attest/jwt_test.go:196`) | **security-critical** | **GAP** |
| TX-24 | `subject_token=garbage` | `401 invalid_grant` "the subject token is not valid" (`oidc.go:122-126`) — **401, not 403**, and the description must not distinguish "unknown" from "expired" | avoids a session-enumeration oracle | **GAP** |
| TX-25 | subject token belonging to an **expired** session | same `401 invalid_grant` (`kernel.go:189-192` evaluates expiry lazily on read) | — | **GAP** |
| TX-26 | subject token whose session was **revoked** (`kernel.go:195`) | `401 invalid_grant` | revocation must bite the exchange endpoint, not only the KV path | **GAP** |
| TX-27 | valid session whose principal holds **no** bindings covering the scope | `200`, **not** a denial — and the `groups` claim is `null`, not `[]`: `filterRoles` returns a nil `[]string` (`issue.go:211,236-241`) which `encoding/json` renders as `null` (`oidc.go:171`). Assert the literal wire bytes. Record and decide (Q7) | Grafana logs the user in with no role; strict JOSE consumers distinguish `null` from `[]` | **GAP — behaviour decision needed** |
| TX-28 | `scope_path=../../etc` | `400 invalid_request` from `ValidatePath` (`oidc.go:145-147` ← `issue.go:143-145` ← `path.go:47-49`) | path traversal into the resource tree | **GAP** — `ValidatePath` itself is covered (`kernel/path_test.go`), the dialect wiring is not |
| TX-29 | `scope_path=/Clusters/Lab` (uppercase) | `400 invalid_request` — segments are `[a-z0-9._-]` only (`path.go:50-56`) | case-confusable scope bypass | **GAP** |
| TX-30 | `scope_path` 1025 bytes | `400` (`path.go:31-33`) | — | **GAP** |
| TX-31 | `requested_token_lifetime=5m` | **Expected: either `400` or a 5-minute token. Actual today: a 5-*millisecond* token.** `time.ParseDuration("5m"+"s")` = `5ms` (`oidc.go:130`), which is `> 0` so it is accepted; `exp` then equals `iat` after Unix truncation and `expires_in` is `0`. See §14 bug 1 | any client using a duration string — and RFC 8693 has no such parameter, so clients are guessing at its syntax | **GAP + live bug** |
| TX-32 | `requested_token_lifetime=-1` / `0` / `abc` | Falls back to `DefaultTTL` (`oidc.go:130-132` requires `err == nil && d > 0`) | — | **GAP** |
| TX-33 | `requested_token_lifetime=315360000` (10y) against a **non-expiring** session (`CreateSession` with `ttl<=0` → `Expiry == 0`, `kernel.go:149-152`) and no role `MaxTTLSec` | **Expected: a hard upper bound.** Today there is none: `issue.go:243` only clamps when `s.Expiry != 0`, and `oidc.go:128-133` has no ceiling of its own. A 10-year offline-verifiable ID token is issuable. See §14 bug 2 | **security-critical** | **GAP + live bug** |
| TX-34 | `audience=` some service the caller has no relationship with, e.g. `audience=https://vault.other.example` | **Under-specified.** Today any authenticated session may mint a token for **any** audience string — there is no allow-list, and `req.Audience` is passed through untouched (`oidc.go:116-120` → `issue.go:167`). The brief asks for "a token exchange the policy should refuse"; **this is the one that should be refused and is not.** See Q1 | a Signet token minted for `audience=kubernetes` by a low-privilege workload is accepted by the API server as an authentication assertion for that principal | **GAP — policy hole** |
| TX-35 | malformed body (`%zz` in a form field) | `400 invalid_request` "malformed form body" (`oidc.go:97-100`) | — | **GAP** |
| TX-36 | `GET /oidc/token` | `405` — only `POST` is registered (`oidc.go:55`) | tokens must not land in access logs or `Referer` | **GAP** |
| TX-37 | valid request, but no active **token** key installed | `400 invalid_request` carrying `not found: no active token key` (`issue.go:270-273` surfaced through `oidc.go:145-147`). **Under-specified**: this is a server fault reported as a client error; expected is `500 server_error` | operator diagnosis | **GAP** |
| TX-38 | error body shape on every negative above | Always `{"error":…,"error_description":…}` (`http.go:18-20`), never the Vault `{"errors":[…]}` envelope the KV and SSH dialects use (`sshca/handler.go:184-186`) | OAuth clients parse `error`; a shape mismatch produces "unknown error" in the UI | **GAP** |
| TX-39 | `ErrDenied` from the kernel | `403 access_denied` (`oidc.go:142-144`). Requires a kernel path that returns `ErrDenied` from `Issue` — today `Issue` has no `ErrDenied` return, so this branch is **unreachable**. Assert either the branch or its removal | — | **GAP — dead branch, see Q8** |

---

## 7. Algorithm selection and the RS256 requirement — `ALG-*`

`keys.GenerateAlg` (`keys.go:123-204`), `SignJWS` (`jws.go:22-64`), `VerifyJWSSelf`
(`jws.go:72-102`), JWK (`keys.go:240-261`), discovery advertisement (`oidc.go:69`).

Background: `docs/16:93-95` — *"Kubernetes accepts only RS256 by default. ES256 tokens
were rejected outright, so token keys now default to the algorithm every consumer takes
unconfigured."* The question the brief asks is **how that is enforced and what can
regress it**. The answer, from the code:

> It is enforced **only by a default**, in one `switch` arm: `keys.go:126-128`, `if alg
> == "" { alg = "RS256" }`. Nothing downstream checks. `cmd/signet` never calls
> `GenerateAlg` — genesis calls `keys.Generate` (`main.go:264`), which passes `""`
> (`keys.go:118`). So ES256 token keys are today *unreachable through the CLI*, and the
> guarantee rests entirely on nobody adding an `-alg` flag. Meanwhile discovery already
> advertises `ES256` as supported (`oidc.go:69`), and `JWK` will happily publish an EC
> key (`keys.go:252-257`), and `SignJWS` will happily sign with it (`jws.go:50-59`).
> There is no assertion anywhere that the active token key's algorithm is one the
> configured relying parties accept.

| ID | Precondition | Action | Expected | Client | Coverage |
|---|---|---|---|---|---|
| ALG-01 | — | `keys.Generate(PurposeToken, now)` | `Algorithm == "RS256"`, key is RSA-2048 (`keys.go:117-118,126-131`) | kube-apiserver default `--oidc-signing-algs=RS256` | **GAP** |
| ALG-02 | — | `keys.GenerateAlg(PurposeToken, "RS256", now)` | RSA-2048, `Algorithm=="RS256"` | — | **GAP** |
| ALG-03 | — | `keys.GenerateAlg(PurposeToken, "ES256", now)` | P-256 ECDSA, `Algorithm=="ES256"` (`keys.go:146,150-164`) — supported for "deployments that know their consumers" (`keys.go:114-115`) | — | **GAP** |
| ALG-04 | — | `keys.GenerateAlg(PurposeToken, "HS256"/"none"/"RS512"/"EdDSA", now)` | error `unsupported token algorithm` (`keys.go:147-148`). **`none` and `HS256` must never mint a key** | classic JWT alg-confusion | **GAP** |
| ALG-05 | — | `keys.GenerateAlg(PurposeSSH, "ES256", now)` | The `alg` argument is **ignored** for SSH and audit purposes (`keys.go:165,185` have no alg switch) — always ES256 / ed25519. Assert, so a caller cannot believe it configured something | — | **GAP** |
| ALG-06 | RS256 key | `SignJWS` | header `alg` is `"RS256"` and the signature is PKCS#1 v1.5 over SHA-256 (`jws.go:46-49`) — verifiable by `rsa.VerifyPKCS1v15` and by a third-party library | all | **GAP** |
| ALG-07 | ES256 key | `SignJWS` | signature is **raw `R‖S`, 64 bytes, each left-padded to 32** — not ASN.1 DER (`jws.go:50-59`). This is the single most common JOSE interop bug and there is no test for it | any EC verifier | **GAP** |
| ALG-08 | ed25519 **SSH** key | `SignJWS` | error `keys: ssh keys do not sign tokens` (`jws.go:23-25`) — purpose separation at the signing boundary | `keys.go:30-32` | **GAP** |
| ALG-09 | audit key (ES256) | `SignJWS` | error — same guard, different purpose (`jws.go:23-25`) | `keys.go:41-43`: a token key says who someone is, an audit key says what a node's history was | **GAP** |
| ALG-10 | RS256 key, token minted, then flip one byte of the signature | `VerifyJWSSelf` returns `signature does not verify under the issuing key` (`jws.go:88-90`) | verify-after-sign | **GAP** |
| ALG-11 | ES256 key, signature truncated to 63 bytes | `VerifyJWSSelf` returns `malformed signature` (`jws.go:92-94`) — the length check must precede the big-int parse | malleability | **GAP** |
| ALG-12 | RS256 key, token whose **header** claims `alg:"none"` and whose signature is empty | `VerifyJWSSelf` rejects. Note that `VerifyJWSSelf` never reads the header's `alg` at all (`jws.go:72-102`) — it dispatches on the *key type*, which is the correct design and should be asserted as such | **security-critical**; matches the inbound rule at `attest/jwt.go:133-135` | **GAP** |
| ALG-13 | RS256 key, token re-signed with an attacker RSA key of the same modulus size | `VerifyJWSSelf` rejects (`jws.go:88-90`) | — | **GAP** |
| ALG-14 | **ES256** token key active | `GET /.well-known/openid-configuration` then mint and present to F4 | **Expected: a startup or mint-time refusal, or at minimum a warning.** Today: discovery still advertises both algs (`oidc.go:69`), JWKS publishes `alg:"ES256"`, the token is minted, and the **kube-apiserver rejects it at authentication time with no hint that the algorithm is the reason**. This is exactly the failure `docs/16:93-95` records having already been hit once. See Q2 | kube-apiserver | **GAP — regression guard missing, real client required** |
| ALG-15 | RS256 key active | discovery | `id_token_signing_alg_values_supported` should arguably list only algorithms an installed key can actually produce. Today it is a static literal (`oidc.go:69`) independent of installed keys | strict clients that pre-select an alg from metadata | **GAP** |
| ALG-16 | — | `keys.Key.JWK` on an ed25519 (SSH) key | error `ssh-ed25519 is not publishable as a JWK` (`keys.go:258-260`) — no `OKP`/`Ed25519` JWK is emitted | prevents an SSH CA key appearing in a token key set | **GAP** |

---

## 8. SSH certificate structure — `SC-*`

Serializer `sshca.go:56-99`, self-verification `sshca.go:104-163`, handler
`handler.go:45-120`. Fixture F2 unless noted; F3 for the sshd rows.

| ID | Request | Expected observable result | Client | Coverage |
|---|---|---|---|---|
| SC-01 | `POST /v1/ssh/sign/lab` `{"public_key":"<ed25519 authorized_keys>"}` | `200`, Vault-shaped envelope: `data.signed_key` non-empty, plus `request_id`, `lease_id`, `renewable`, `lease_duration`, `wrap_info`, `warnings`, `auth` keys all present (`handler.go:112-119`) | Vault-compatible tooling and muscle memory (`handler.go:15-17`) | **GAP** |
| SC-02 | as SC-01 | `data.signed_key` parses with `ssh.ParseAuthorizedKey` and is an `*ssh.Certificate` (`sshca.go:105-112`); it is also parseable by `ssh-keygen -L -f` | real OpenSSH tooling | **GAP** |
| SC-03 | as SC-01 | `CertType == ssh.UserCert` (`sshca.go:77`, re-checked `sshca.go:113-115`) | sshd refuses a host cert for user auth | **GAP** |
| SC-04 | as SC-01 | Certificate's `Key` is byte-identical to the submitted public key. **Note:** `Serialize` sets it (`sshca.go:76`) but `Verify` never re-checks it — the independent gate has a hole (`sshca.go:104-163`) | a mismatch would issue a certificate over someone else's key | **GAP** |
| SC-05 | as SC-01 | `KeyId == claims.Subject` == the principal path, e.g. `/people/user` (`sshca.go:78`) — and it is what appears in `sshd` logs | forensics; `sshca.go:78` comment states the intent | **GAP — F3 needed to prove the log line** |
| SC-06 | as SC-01, twice | The two certificates have **different** `Serial` values, drawn from `crypto/rand` (`sshca.go:70`, `sshca.go:216-222`) | KRL revocation by serial | **GAP** |
| SC-07 | as SC-01 | `data.serial_number` in the response equals the certificate's actual `Serial`. **Fails today**: it is `strconv.FormatInt(claims.ExpirySec, 10)` — the expiry timestamp (`handler.go:116`). See §14 bug 4 | anyone building a KRL from Signet's responses revokes the wrong serial, or nothing | **GAP + live bug** |
| SC-08 | as SC-01 | `SignatureKey` equals the CA public key from `GET /v1/ssh/public_key` (`sshca.go:143-153`, `sshca.go:234-244`) | `TrustedUserCAKeys` | **GAP** |
| SC-09 | as SC-01 | Signature algorithm is `ssh-ed25519` — the CA key is ed25519 by construction (`keys.go:185-200`) and never `ssh-rsa`/SHA-1 | OpenSSH ≥ 8.2 rejects SHA-1 `ssh-rsa` signatures by default | **GAP** |
| SC-10 | `GET /v1/ssh/public_key` | `200`, `Content-Type: text/plain`, one `authorized_keys` line ending in `\n` (`handler.go:122-136`, `ssh.MarshalAuthorizedKey` at `sshca.go:243`), **no session required** (`handler.go:40-42`) | a host bootstrapping `TrustedUserCAKeys` before it has any credential | **GAP** |
| SC-11 | `GET /v1/ssh/public_key` with no SSH key installed | `404 {"errors":["no ssh certificate authority configured"]}` (`handler.go:124-127`) | — | **GAP** |
| SC-12 | as SC-01, client key of each type: ed25519, ecdsa-sha2-nistp256, rsa-2048 | All three succeed and all three authenticate to F3 | heterogeneous fleets | **GAP — F3** |
| SC-13 | as SC-01 with `public_key` = an **already-issued certificate** rather than a bare key | **Expected: `400`.** Today `ssh.ParseAuthorizedKey` returns the certificate as an `ssh.PublicKey` (`sshca.go:60`) and it is embedded as the new certificate's `Key`, producing a nested certificate that `Verify` accepts (`sshca.go:105-112` re-parses the *outer* cert successfully) and `sshd` rejects. See §14 bug 5 | — | **GAP + suspected bug** |
| SC-14 | as SC-01 with `public_key` = rsa-1024, or `ssh-dss` | **Expected: `400` on a minimum-strength policy.** Today there is no key-strength check anywhere (`sshca.go:60-63` accepts whatever parses) | modern sshd refuses `ssh-dss` outright; a 1024-bit user key is issued a valid certificate that then cannot log in | **GAP — policy absent** |
| SC-15 | as SC-01 with `public_key` = `"not a key"`, empty string, 1 MB of `A`s | `400` with `sshca: public key:` prefix (`sshca.go:60-63`) for garbage; `400 missing 'public_key'` for empty (`handler.go:61-64`); no unbounded allocation for the large input | fuzz target per `docs/10:23-26` | **GAP** |
| SC-16 | as SC-01 with `cert_type: "host"` | `400 {"errors":["only user certificates are supported"]}` (`handler.go:65-67`) | — | **GAP** |
| SC-17 | as SC-01 with `cert_type: "user"` explicitly | `200` (`handler.go:65` allows the empty string and `"user"`) | Vault clients that always send it | **GAP** |
| SC-18 | malformed JSON body | `400 {"errors":["malformed request body"]}` (`handler.go:57-60`) | — | **GAP** |
| SC-19 | as SC-01 | The credential is signed with the **SSH-purpose** key: install only a token key and assert `sshca: cannot sign with a token key` (`sshca.go:57-59`) | purpose separation | **GAP** |

---

## 9. Principals and role-to-principal resolution — `SP-*`

`permittedPrincipals` (`sshca.go:167-200`), role spec (`pki.go:321-331`), config loading
(`main.go:575-584`).

Fixture F2 role: `AllowedPrincipals: ["deploy"]`,
`PrincipalsFromRoles: {"kv-reader": ["ubuntu"], "kv-admin": ["root"]}`,
session carries `kv-reader` (offline-embeddable) and `kv-admin` (tier 3, filtered out).

| ID | Request | Expected | Client | Coverage |
|---|---|---|---|---|
| SP-01 | `valid_principals` omitted | Certificate carries **`["deploy","ubuntu"]`** — the union of the role's static list and the role-derived ones, **sorted** (`sshca.go:185-193`, sort at `sshca.go:191`/`sshca.go:224-230`). "Asking for nothing means everything I am entitled to" (`sshca.go:186-188`) | makes plain `ssh user@host` work without the client knowing its own rights | **GAP** |
| SP-02 | `valid_principals: "deploy"` | Certificate carries exactly `["deploy"]` (`sshca.go:194-199`) | least privilege | **GAP** |
| SP-03 | `valid_principals: "deploy,ubuntu"` | Certificate carries both, in the **requested** order (`sshca.go:199` returns `requested`, unsorted) | — | **GAP** |
| SP-04 | `valid_principals: " deploy , ubuntu "` | Whitespace trimmed, empty entries dropped (`handler.go:164-176`) | Vault clients send CSV | **GAP** |
| SP-05 | `valid_principals: "root"` | **`400`** — `sshca: principal "root" is not permitted` (`sshca.go:194-198`). `root` is reachable only through `kv-admin`, which is tier-3 and therefore **absent from `c.Roles`** by the time the serializer runs (`issue.go:223-225`, `sshca.go:172-178`) | **the flagship SSH invariant**: a role you hold but may not carry offline cannot grant you an SSH login either. `sshca.go:172-173` states it; nothing tests it | **GAP — highest-value single test in this plan** |
| SP-06 | `valid_principals: "root"`, and `kv-admin`'s policy changed to tier 1 | Now **succeeds** — proving SP-05 measured the tier gate and not a typo | same | **GAP** |
| SP-07 | `valid_principals: "admin"` (in no list at all) | `400 sshca: principal "admin" is not permitted` (`sshca.go:196`) | unauthorized principal | **GAP** |
| SP-08 | `valid_principals: "DEPLOY"` | `400` — matching is exact string equality via the `granted` map (`sshca.go:168-178,195`), not case-folded | OpenSSH usernames are case-sensitive on Linux; a case-folding CA would be a privilege bug | **GAP** |
| SP-09 | `valid_principals: "deploy,deploy"` | Recorded: duplicates pass through to the certificate (`sshca.go:194-199` does not dedupe). Harmless to sshd; assert so it cannot become a parsing quirk | — | **GAP** |
| SP-10 | Role with `AllowedPrincipals: []` and `PrincipalsFromRoles: {}` | `400 sshca: the caller's roles grant no SSH principals` (`sshca.go:179-181`) — **never** an empty-principal certificate | **security-critical**: an empty `ValidPrincipals` user cert is valid for *every* username in OpenSSH (`sshca.go:116-119`) | **GAP** |
| SP-11 | Role whose only grant is via `PrincipalsFromRoles`, session carrying **no** matching role | same `400` (`sshca.go:174-181`) | — | **GAP** |
| SP-12 | Fault-inject a serializer producing a certificate with `ValidPrincipals: []` | `Issue` refuses with `certificate has no principals, which OpenSSH reads as all of them` (`sshca.go:116-119` inside `Verify`, gated at `issue.go:186-188`) | verify-after-sign, the exact case the code calls "the single most dangerous mistake available here" | **GAP** |
| SP-13 | Fault-inject a certificate carrying an extra principal | `Issue` refuses: `certificate asserts principal %q, which was not authorized` (`sshca.go:129-133`) | same | **GAP** |
| SP-14 | `PrincipalsFromRoles` keyed on a role name that is **not** a `KnownRole` | Recorded: such a key can never fire, because `applyPutBinding` rejects unknown roles (`apply.go:113-114`) and therefore no session can ever carry that role name. The usable key set is exactly `{kv-reader, kv-writer, kv-admin, pki-signer, domain-admin}` (`model.go:206-212`) | **modelling smell**: SSH logins are keyed on KV role names. See Q9 | **GAP + design question** |
| SP-15 | F3: certificate with `ValidPrincipals: ["deploy"]`, `AuthorizedPrincipalsFile` for user `deploy` contains `deploy` | `ssh deploy@host` succeeds with **no `authorized_keys` entry anywhere** | this is the entire product claim of `sshca.go:3-6` and `docs/16:19` | **GAP — F3 required** |
| SP-16 | F3: same certificate, `ssh ubuntu@host` where the principals file for `ubuntu` does not list `deploy` | Connection **refused**; `sshd` log shows the principal mismatch | unauthorized principal, proven by the real enforcer | **GAP — F3 required** |
| SP-17 | F3: certificate for `["deploy","ubuntu"]`, principals file for `ubuntu` lists `ubuntu` | `ssh ubuntu@host` succeeds — multi-principal certificates work as `sshd` reads them | — | **GAP — F3 required** |

---

## 10. Validity windows — `SV-*`

`ValidAfter`/`ValidBefore` at `sshca.go:80-81`, TTL clamping at `handler.go:86-90`, kernel
clamps at `issue.go:229-247`, self-check at `sshca.go:134-141` and `sshca.go:154-161`.

| ID | Request | Expected | Client | Coverage |
|---|---|---|---|---|
| SV-01 | `ttl: "5m"` on a role with `MaxTTLSec: 3600` | `ValidBefore - ValidAfter == 300 + 60`; `ValidAfter == iat - 60` (`sshca.go:80` grants "a minute of clock slack") | clock skew between the signer and the host — the reason the slack exists | **GAP** |
| SV-02 | `ttl: "300"` (bare seconds) | Same as SV-01 — `parseTTL` accepts both a Go duration and a plain integer (`handler.go:151-162`). Note the contrast with the OIDC endpoint's `v+"s"` concatenation (`oidc.go:130`), which does **not** accept `"5m"` correctly | Vault clients send both forms | **GAP** |
| SV-03 | `ttl: "9999h"` on a role with `MaxTTLSec: 3600` | Clamped to 3600 (`handler.go:86-90`) | — | **GAP** |
| SV-04 | `ttl` omitted on a role with `MaxTTLSec: 3600` | **Clamped up to the maximum**, i.e. a 1-hour certificate, not a 15-minute one — `handler.go:87` rewrites *both* a non-positive TTL and an over-max TTL to `max`. Assert deliberately — "default equals maximum" is a defensible but surprising choice | — | **GAP** |
| SV-05 | `ttl` omitted, role `MaxTTLSec: 0` | 15 minutes, from the kernel default (`issue.go:206-208`) | — | **GAP** |
| SV-06 | `ttl: "1h"` on a session expiring in 120s | `ValidBefore` ≤ session expiry (`issue.go:243-247`) — a certificate never outlives the session that authorized it | — | **COVERED indirectly** — `issue_test.go:231-255`. **GAP** on the certificate |
| SV-07 | `ttl: "-5m"` / `"abc"` | `"abc"` → `400 ttl must be a duration or a number of seconds` (`handler.go:161`). `"-5m"` parses to a negative duration, which `handler.go:87` then rewrites to the role maximum — assert this, it is not obvious | — | **GAP** |
| SV-08 | Fault-inject a certificate whose `ValidBefore` ≠ `claims.ExpirySec` | `Issue` refuses: `certificate lifetime does not match what was authorized` (`sshca.go:134-136`) | verify-after-sign | **GAP** |
| SV-09 | Fault-inject a lifetime exceeding `MaxTTLSec + 60` | `Issue` refuses: `lifetime %ds exceeds the role maximum %ds` (`sshca.go:137-141`). Note the `+60` matches the `-60` slack at `sshca.go:80`, so the arithmetic is `ValidBefore - NotBefore` — assert the boundary at exactly `MaxTTLSec` and at `MaxTTLSec+61` | — | **GAP** |
| SV-10 | F2 with `SetClock` advanced past `ValidBefore` before `Verify` runs | `ssh.CertChecker.CheckCert` (`sshca.go:154-161`) fails on the validity window and the credential is **withheld** — `CheckCert` uses real wall time, so this row needs a genuinely short TTL rather than a fake clock. Document the wall-clock coupling | — | **GAP — note the fake-clock trap** |
| SV-11 | F3: certificate whose `ValidBefore` is in the past | `sshd` refuses; log shows `Certificate invalid: expired` | expired certificate, proven by the real enforcer | **GAP — F3 required** |
| SV-12 | F3: certificate whose `ValidAfter` is in the future (host clock set back 10 minutes, beyond the 60s slack) | `sshd` refuses; log shows `Certificate invalid: not yet valid`. Then set the host back 30s and assert it **succeeds** — that is what the 60s slack is for | not-yet-valid certificate; proves the slack window is the right size | **GAP — F3 required** |
| SV-13 | F3: certificate at exactly the boundary | Login succeeds at `ValidBefore - 5s` and fails at `ValidBefore + 5s` within one session | — | **GAP — F3 required** |

---

## 11. Extensions and critical options — `SE-*`

`extensions()` at `sshca.go:202-214`; role flags at `pki.go:328-330`; config plumbing at
`main.go:146-153` and `main.go:575-584`.

| ID | Precondition | Expected | Client | Coverage |
|---|---|---|---|---|
| SE-01 | Role `AllowPTY: true` | Certificate `Extensions` contains `permit-pty` with an **empty-string** value (`sshca.go:204-206`) | OpenSSH requires the value to be empty for these flags | **GAP** |
| SE-02 | Role `AllowPTY: false` | `permit-pty` **absent**. F3: `ssh host` returns `PTY allocation request failed on channel 0` and a non-interactive command still runs | this is the most common "SSH CA is broken" support ticket | **GAP — F3 for the observable** |
| SE-03 | Role `AllowAgentForward: true` | `permit-agent-forwarding` present (`sshca.go:207-209`). F3: `ssh -A` forwards | — | **GAP** |
| SE-04 | Role `AllowPortForward: true` | `permit-port-forwarding` present (`sshca.go:210-212`). F3: `ssh -L` succeeds | — | **GAP** |
| SE-05 | All three false | `Extensions` is an **empty map**, not `nil`, and the certificate still parses (`sshca.go:203`) | — | **GAP** |
| SE-06 | Any role | `permit-user-rc` and `permit-X11-forwarding` are **never** emitted — Signet is deny-by-default relative to `ssh-keygen`'s defaults. Assert so a future "match OpenSSH defaults" change is deliberate | `ssh-keygen -s` grants all five by default; operators migrating will notice | **GAP** |
| SE-07 | Any role | `CriticalOptions` is **empty**. There is no `force-command`, no `source-address`, no `verify-required` anywhere in the package (`sshca.go:82-84` sets only `Extensions`). Assert emptiness so their arrival is deliberate — an unknown critical option makes `sshd` reject the certificate outright | `source-address` is the usual reason a fleet wants an SSH CA at all. See Q10 | **GAP — feature absent** |
| SE-08 | Genesis config with `"allow_agent_forwarding": true` in an `ssh_roles` entry | **Expected: it works. Actual: genesis fails hard** with an unknown-field error, because `main.go:146-153` has no such field and `main.go:507` sets `DisallowUnknownFields()`. `AllowAgentForward` and `AllowPortForward` exist on `SSHRoleSpec` (`pki.go:328-329`) and are **unreachable from any operator-facing surface** — `main.go:576-580` constructs the spec without them. See §14 bug 6 | any operator wanting `ssh -A` or `ssh -L` | **GAP + live bug** |
| SE-09 | F3, certificate with an unknown extension injected | `sshd` **ignores** unknown extensions (by OpenSSH design) while ignoring nothing in critical options. Prove the asymmetry once so the codebase's mental model is right | — | **GAP — F3 required** |

---

## 12. SSH authorization and role resolution — `SN-*`

`handler.session` (`handler.go:138-149`), `SSHRole` (`pki.go:335-348`), `AuthorizeSign`
(`pki.go:368-370` → `kernel.go:471-485`), `applyPutSSHRole` (`pki.go:372-401`).

| ID | Request | Expected | Client | Coverage |
|---|---|---|---|---|
| SN-01 | `POST /v1/ssh/sign/lab` with `X-Vault-Token: <valid>` | `200` (`handler.go:139`) | `bao`/`vault` CLI muscle memory | **GAP** |
| SN-02 | same with `Authorization: Bearer <valid>` | `200` (`handler.go:140-143`) | modern clients | **GAP** |
| SN-03 | no token at all | `403 {"errors":["permission denied"]}` (`handler.go:46-49`, `kernel.ErrNoSession` at `handler.go:146`). Note it is **403, not 401** — inconsistent with `oidc.go:124` which returns 401 for the same condition. See Q11 | — | **GAP** |
| SN-04 | expired session token | `403` (`kernel.go:189-192`) | — | **GAP** |
| SN-05 | valid session, **`POST /v1/ssh/sign/nonexistent`** | `404 {"errors":["unknown role"]}` (`handler.go:75-80`) | — | **GAP** |
| SN-06 | valid session whose principal holds **no** `VerbSign` authority at `role.Scope` (e.g. only `kv-reader`) | `403 permission denied` (`handler.go:82-85`) — **and no key is touched**, which is the stated ordering guarantee (`handler.go:81`). Assert by installing no SSH key at all and confirming the response is still `403`, not `404 no ssh certificate authority` | authorization precedes key use (charter principle 5) | **GAP** |
| SN-07 | principal holds `pki-signer` at `/hosts/prod`, role scope is `/hosts/lab` | `403` — `ScopeCovers("/hosts/prod","/hosts/lab")` is false (`path.go:63-70`) | scope containment | **GAP** |
| SN-08 | principal holds `pki-signer` at `/hosts`, role scope `/hosts/lab` | `200` — scope inherits downward (`path.go:69`) | — | **GAP** |
| SN-09 | principal holds `pki-signer` at `/hosts/lab-2`, role scope `/hosts/lab` | `403` — component-wise, never substring (`path.go:63-65` comment, E-01 K-4) | prefix-confusion privilege escalation | **GAP** |
| SN-10 | binding with `NotAfter` in the past | `403` (`issue.go:212-214` for roles; `HasAuthority` for the verb check) | just-in-time grants | **GAP** |
| SN-11 | `applyPutSSHRole` with an empty `Name` | rejected: `ssh role: missing name` (`pki.go:373-375`) | — | **GAP** |
| SN-12 | `applyPutSSHRole` with `Scope: "../etc"` | rejected by `ValidatePath` (`pki.go:383-385`) | — | **GAP** |
| SN-13 | `applyPutSSHRole` with an empty grantor | rejected: `ssh role: missing grantor` (`pki.go:386-389`) | — | **GAP** |
| SN-14 | `applyPutSSHRole` where the grantor lacks `VerbAdmin` at the role's scope | rejected: `grantor %s lacks admin authority at %s` (`pki.go:390-396`). **This is the SSH analogue of ESC1**: defining who may log in as whom is a grant, and it must narrow like one (`pki.go:386`) | **security-critical** | **GAP** |
| SN-15 | grantor holds `domain-admin` at `/hosts/lab` only, defines a role at scope `/` | rejected — a delegated admin cannot widen (`pki.go:390-396`) | delegation-only-narrows, E-01 K-1 | **GAP** |
| SN-16 | `PUT` (not `POST`) to `/v1/ssh/sign/lab` | `200` — both verbs are registered (`handler.go:38-39`) | Vault clients use `PUT` | **GAP** |
| SN-17 | Mount name configured as `-ssh-mount=ssh-home` | Routes live at `/v1/ssh-home/sign/{role}` and `/v1/ssh-home/public_key` (`handler.go:37,42`), and the default is `ssh` (`handler.go:30-32`) | — | **GAP** |
| SN-18 | Concurrent signing requests for the same role | No serial collisions, no interleaved claims; all certificates independently valid | — | **GAP** |

---

## 13. Real-client conformance — `RC-*`

These are the rows this project's own history says are the ones that matter
(`docs/16:8-9`, `docs/10:50-52`). Every one is a **GAP** and every one needs software
Signet does not control.

| ID | Harness | Scenario | Expected observable | Why a mock cannot do it |
|---|---|---|---|---|
| RC-01 | F4 | kube-apiserver configured with `--oidc-issuer-url=<signet>`, `--oidc-client-id=kubernetes`, `--oidc-ca-file=<signet chain>` starts and fetches discovery + JWKS | API server ready; discovery and JWKS requests visible in Signet's access path | go-oidc's exact issuer-comparison and HTTPS/CA requirements are its own; `signet.yaml:101` already records one such surprise |
| RC-02 | F4 | `kubectl --token=<id_token> auth whoami` | Username is `<prefix><sub>`; groups are the token's `groups` | the username-prefix rules and the `sub`→username mapping are the API server's |
| RC-03 | F4 | RBAC `RoleBinding` to group `kv-reader`; `kubectl get pods` | allowed in-namespace, denied elsewhere | proves `groups` is consumed as claimed at `docs/16:18` |
| RC-04 | F4 | present an ID token with `aud=other` | `401 Unauthorized` from the API server | audience binding enforced by the real consumer |
| RC-05 | F4 | present an expired ID token | `401`; and a token 20s past expiry to probe the API server's skew tolerance | skew behaviour is the consumer's |
| RC-06 | F4 | **ES256** token key active (ALG-14) | API server rejects; capture the exact error text for the operator-facing diagnostic | *this is the bug `docs/16:93-95` already paid for once, with no regression guard today* |
| RC-07 | F4 | rotate the token key mid-flight (JW-10) while a valid token is outstanding | the outstanding token keeps working across the API server's JWKS refresh | rotation-as-non-event is only provable against a real cache |
| RC-08 | F4 | Signet restarted; `kid` unchanged (JW-05) | no re-authentication storm | — |
| RC-09 | F3 | `TrustedUserCAKeys` + `AuthorizedPrincipalsFile`, `AuthorizedKeysFile none`, login with a Signet certificate | success (SP-15) | *the* product claim of `docs/16:19` |
| RC-10 | F3 | `ssh-keygen -L -f cert` output snapshot | serial, key ID, principals, validity, extensions, critical options all render as intended | OpenSSH's own parser is the spec for its own format |
| RC-11 | F3 | unauthorized principal (SP-16), expired cert (SV-11), not-yet-valid cert (SV-12) | all refused, with the sshd log line captured | negative cases are only meaningful against the real enforcer |
| RC-12 | F3 | no-`permit-pty` certificate (SE-02) | `PTY allocation request failed` | — |
| RC-13 | F3 | nested-certificate submission (SC-13) | `sshd` refuses whatever Signet produced — confirming SC-13 is a real defect and not a theoretical one | — |
| RC-14 | F3 | KRL built from `data.serial_number` (SC-07) revokes the certificate | **fails today** — the field is the expiry, not the serial | proves bug 4 has an operational consequence |
| RC-15 | third-party JOSE | `go-oidc`, `python-jose`, and `jose4j` each verify a Signet ID token against the published JWKS | all three accept | ES256 R‖S encoding (ALG-07) and unpadded base64url (JW-03) are exactly where implementations disagree |
| RC-16 | F5 | Grafana / ArgoCD / Harbor browser SSO | **BLOCKED** — no authorization-code flow exists (§1). Track as blocked, not as failing | — |

---

## 14. Suspected live bugs

Found while writing this plan. None was introduced by this document; nothing was fixed.

**Bug 1 — `requested_token_lifetime=5m` yields a five-*millisecond* token.**
`oidc.go:130`: `time.ParseDuration(v + "s")`. Verified against the Go runtime:

```
"5m"  -> 5ms      (accepted, d > 0, becomes the TTL)
"0.5" -> 500ms    (accepted)
"300" -> 5m0s     (the intended path)
"10s" -> error    (falls back to DefaultTTL, silently)
"1h"  -> error    (falls back to DefaultTTL, silently)
```

A client sending a duration string gets either a silent fallback or, for minute
suffixes, a token whose `exp` equals its `iat` after Unix-second truncation and whose
`expires_in` is `0`. RFC 8693 defines no such parameter, so every client is guessing at
its syntax — which makes lenient-but-wrong parsing the worst possible choice here.
Scenario **TX-31**.

**Bug 2 — no upper bound on ID-token lifetime for a non-expiring session.**
`issue.go:243` clamps to the session only `if s.Expiry != 0`, and `CreateSession` leaves
`Expiry == 0` when `ttl <= 0` (`kernel.go:149-152`). With no `RolePolicy.MaxTTLSec`,
`requested_token_lifetime=315360000` mints a ten-year, offline-verifiable ID token. The
OIDC dialect applies no ceiling of its own (`oidc.go:128-133`), unlike the SSH dialect
which clamps to the role maximum (`handler.go:86-90`). Scenario **TX-33**.

**Bug 3 — JWKS silently drops a key it cannot open.**
`oidc.go:84-87` does `continue` when `k.JWK(seal)` errors. A key whose envelope will not
open (wrong seal, corrupt AAD — `keys.go:103`) disappears from a `200 OK` key set. Every
live token signed by it stops verifying, at the relying party, with no error emitted
anywhere in Signet. A `500` here would be strictly safer: relying parties keep their
cached copy on a fetch failure, and lose it on a successful fetch that omits the key.
Scenario **JW-12**.

**Bug 4 — `data.serial_number` is the expiry timestamp, not the serial.**
`handler.go:116`: `"serial_number": strconv.FormatInt(claims.ExpirySec, 10)`. The real
serial is generated at `sshca.go:70` (`randomSerial`, `sshca.go:216-222`), placed on the
certificate at `sshca.go:76`, and then discarded. Vault's SSH engine returns the actual
serial and operators build KRLs from it. Anyone revoking by this value revokes nothing —
or, if two certificates share an expiry second, revokes a set they did not intend.
Scenarios **SC-07**, **RC-14**.

**Bug 5 — a certificate submitted as `public_key` is signed into a nested certificate.**
`sshca.go:60` uses `ssh.ParseAuthorizedKey`, which returns an `*ssh.Certificate` as an
`ssh.PublicKey` for certificate input. It is then set as the new certificate's `Key`
(`sshca.go:76`). `Verify` re-parses the *outer* certificate successfully
(`sshca.go:105-112`) and never checks that `cert.Key` matches the submitted bytes or is
a bare key, so the credential is released. `sshd` will reject it. Low severity, but it
is exactly the class of input the fuzz target in `docs/10:23-26` is meant to catch, and
`Verify`'s missing key-identity check (SC-04) is the more general hole. Scenarios
**SC-13**, **SC-04**, **RC-13**.

**Bug 6 — `allow_agent_forwarding` / `allow_port_forwarding` are unreachable.**
`SSHRoleSpec` carries them (`pki.go:328-329`) and `extensions()` honours them
(`sshca.go:207-212`), but the genesis config struct has only `allow_pty`
(`main.go:146-153`) and the loader constructs the spec without them
(`main.go:576-580`). Because `main.go:507` sets `DisallowUnknownFields()`, an operator
who writes `"allow_agent_forwarding": true` gets a **hard genesis failure**, not a
silently ignored key — which is the right failure mode (`docs/16:135-139`) applied to a
capability that simply has no path in. Scenario **SE-08**.

---

## 15. Where a mock is not good enough

Marked `real client required` above; collected here as the argument.

1. **kube-apiserver / go-oidc** (RC-01…RC-08). Issuer string comparison, HTTPS-only
   discovery, JWKS caching and refresh timing, the `--oidc-signing-algs` default, the
   `sub`→username prefix rules, and the skew tolerance on `exp` are all *its* behaviour.
   A Go test that calls `attest.VerifyJWS` on Signet's own output is Signet grading its
   own homework — and note that Signet's inbound verifier and outbound signer are two
   independent implementations of JOSE in this tree (`attest/jwt.go:220-244` vs
   `keys/jws.go:44-63`), so even cross-checking them proves less than it appears to.
2. **OpenSSH `sshd`** (RC-09…RC-14). `ssh.CertChecker` (`sshca.go:154-161`) is Go's
   reading of the certificate format. OpenSSH's differs in the places that matter:
   unknown *critical options* are fatal while unknown *extensions* are ignored,
   `AuthorizedPrincipalsFile` matching has its own semantics, an empty principal list
   means "all users", and the SHA-1 `ssh-rsa` deprecation is enforced by the daemon.
   Nothing in Go tells you `PTY allocation request failed on channel 0`.
3. **Third-party JOSE libraries** (RC-15). The two encodings most likely to be wrong —
   ES256 raw R‖S vs DER (`jws.go:50-59`) and unpadded base64url in JWK `n`/`e`
   (`keys.go:274`) — are exactly the ones a self-consistent implementation cannot catch,
   because it makes the same choice on both sides.
4. **Browser SSO** (RC-16). Blocked on the authorization-code flow.

The precedent is in the repo: `docs/16:119-126` records a clock-skew bug that *passed* a
unit test because the test passed a skew value no real caller used. The OIDC and SSH
dialects have no unit tests to be fooled by yet — the opportunity is to add the real-client
layer at the same time as the unit layer, rather than after.

---

## 16. Coverage summary

| Area | Scenarios | Covered | Covered-indirectly | GAP | Real client needed |
|---|---:|---:|---:|---:|---:|
| OIDC discovery (OD) | 14 | 0 | 0 | 14 | 1 |
| JWKS & rotation (JW) | 14 | 0 | 0 | 14 | 0 |
| ID token claims (CL) | 21 | 0 | 3 | 18 | 1 |
| Token exchange (TX) | 32 | 0 | 3 | 29 | 0 |
| Algorithms / RS256 (ALG) | 16 | 0 | 0 | 16 | 1 |
| SSH cert structure (SC) | 19 | 0 | 0 | 19 | 2 |
| SSH principals (SP) | 17 | 0 | 0 | 17 | 3 |
| SSH validity (SV) | 13 | 0 | 1 | 12 | 3 |
| SSH extensions (SE) | 9 | 0 | 0 | 9 | 2 |
| SSH authorization (SN) | 18 | 0 | 0 | 18 | 0 |
| Real-client conformance (RC) | 16 | 0 | 0 | 16 | 16 (1 blocked) |
| **Total** | **189 rows / 125 distinct scenarios** | **0** | **7** | — | **31** |

Row count exceeds the headline scenario count because several IDs carry sub-cases
(SC-15, SV-07, ALG-04, RC-11). The seven indirectly-covered rows all lean on
`internal/kernel/issue_test.go`:

- `issue_test.go:124-145` — tier-3 exclusion (CL-09, SP-05's kernel half)
- `issue_test.go:149-180` — required-AMR satisfiable (CL-10)
- `issue_test.go:184-193` — verify-after-sign catches an invented role (CL-17)
- `issue_test.go:197-228` — strictest TTL wins (TX-07)
- `issue_test.go:231-255` — credential never outlives its session (TX-08, SV-06)
- `issue_test.go:259-292` — scope selects bindings (TX-05)

Every one of them proves the property at the **kernel** boundary, through
`captureSerializer` (`issue_test.go:17-45`), which is a JSON round-trip and not a JWT or
an SSH certificate. None proves the property in the bytes a client receives.

### Recommended order of work

1. **`internal/keys`** (ALG-*, JW-02…JW-08): no fixture needed, pure functions, and it
   is the layer everything else assumes. 16 scenarios, one file.
2. **`internal/dialect/oidc`** unit rows on F1 (OD-*, CL-*, TX-*): the F1 fixture is a
   40-line adaptation of `vaultkv/handler_test.go:28-71`.
3. **`internal/dialect/sshca`** unit rows on F2 (SC-*, SP-*, SV-*, SE-*, SN-*),
   prioritising **SP-05** — the tier-gate-to-SSH-principal path, which is the highest
   claim in the package and has no test.
4. **F3 `sshd`** container: 8 rows, and the only way SE-02 / SP-16 / SV-12 mean anything.
5. **F4 kind + kube-apiserver**: extend `test/kind/run.sh`; most of the deployment
   already exists in `test/kind/signet.yaml`.
6. Fuzz targets per `docs/10:23-26`: `ssh.ParseAuthorizedKey` input (SC-15),
   `decodeSegment`/JWT parsing (`http.go:29-31`, CL-20), `parseTTL` (`handler.go:151`).

---

## Questions for the maintainer

**Q1 — Should `audience` be constrained by policy?** Today any authenticated session may
exchange for **any** audience string (`oidc.go:116-120` → `issue.go:167`). The brief asks
for "a token exchange the policy should refuse", and I could not find one that is
refused on audience grounds. Is an audience allow-list — per role, per principal, or per
scope — intended? Without one, a low-privilege workload can mint an ID token addressed
to `kubernetes` for its own principal; the *groups* are still filtered, so this may be
acceptable by design, but it should be a stated decision rather than an absence. (TX-34)

**Q2 — What enforces RS256, beyond the default?** `keys.go:126-128` is the only place the
requirement lives, and no CLI path can produce anything else today (`main.go:264` →
`keys.go:118`). Meanwhile discovery advertises `ES256` (`oidc.go:69`) and every layer
below would happily produce and publish one. Options: (a) refuse to serve OIDC when the
active token key is not RS256 unless an explicit `-allow-es256` opt-in is given; (b) make
`id_token_signing_alg_values_supported` reflect the installed keys rather than a static
literal; (c) leave as-is and add ALG-14/RC-06 as the regression guard. Which? (ALG-14,
ALG-15, RC-06)

**Q3 — `nonce`, and the `claims_supported` contract.** The brief lists `nonce` among
required ID-token claims; there is no code path that could produce one, since there is no
authorization request to carry it (§1). Separately, `nbf` **is** emitted (`oidc.go:171`)
and **is not** advertised (`oidc.go:70`). Should `claims_supported` be derived from the
serializer rather than hand-maintained? (OD-08, OD-09, CL-15)

**Q4 — `response_types_supported: ["token"]`.** With no authorization endpoint,
`"token"` names the implicit flow and points nowhere. Should this be `[]`, omitted, or
does it anticipate a flow that is coming? (OD-11)

**Q5 — Clock-skew asymmetry.** The SSH dialect back-dates `ValidAfter` by 60s
(`sshca.go:80`); the inbound JWS verifier allows 30s (`attest/jwt.go:128`); the OIDC
serializer sets `nbf == iat == now` with no allowance (`issue.go:168`). Given
`docs/16:119-126` — a skew bug that a unit test missed because it passed a skew no real
caller used — is the zero-skew `nbf` deliberate? (CL-21)

**Q6 — How is a token key rotated in production?** `InstallKey(active=true)`
(`issue.go:289`) is a Go API with no CLI surface (`main.go:63-81`), and `Key.Retired`
(`keys.go:63`) is declared and never read or written. JWKS therefore accumulates every
key ever installed, forever, with no way to retire a compromised one from publication.
Is `signet keys rotate` / `signet keys retire` planned, and should JW-10 test the Go API
in the meantime? (JW-10, JW-11)

**Q7 — Is a groupless token a success, and should it be `null` or `[]`?** A session whose
principal has no applicable bindings gets a `200` and an ID token whose `groups` claim is
JSON `null` — `filterRoles` declares `var roles []string` (`issue.go:211`) and returns it
unmodified when nothing matches, and a nil `[]string` marshals as `null`, not `[]`
(contrast `oidc.go:82`, where the JWKS handler deliberately pre-allocates so the key set
renders as `[]`). Two decisions: (a) should the exchange refuse outright — a relying party
receiving a valid authentication assertion with zero authorization is a footgun; (b) if
not, should `groups` be normalised to `[]`? (TX-27, CL-08)

**Q8 — The `ErrDenied` branch at `oidc.go:142-144` appears unreachable.** `Kernel.Issue`
(`issue.go:139-190`) returns `ErrNotFound` and validation errors but never `ErrDenied`.
Is there a planned denial path, or should the branch go? (TX-39)

**Q9 — SSH principals keyed on KV role names.** `PrincipalsFromRoles`
(`pki.go:326`) is keyed on role names, but `applyPutBinding` accepts only the five
reserved roles (`apply.go:113-114`, `model.go:206-212`), so the only usable keys are
`kv-reader`, `kv-writer`, `kv-admin`, `pki-signer`, `domain-admin`. Granting someone the
`ubuntu` login therefore means granting them `kv-reader`. Is an `ssh-user` role (or
free-form roles with a separate verb set) intended before v1? (SP-14)

**Q10 — Critical options.** `source-address` and `force-command` are, in my experience,
two of the top three reasons a fleet adopts an SSH CA, and neither exists
(`sshca.go:82-84`). Deliberate scope cut for v1, or an oversight? If deliberate, SE-07
should assert the emptiness so their arrival is a conscious change. (SE-07)

**Q11 — HTTP status inconsistency for "no session".** OIDC returns `401 invalid_grant`
(`oidc.go:124`); SSH returns `403 permission denied` (`handler.go:46-49`). The SSH
dialect is deliberately Vault-shaped (`handler.go:15-17`) and Vault does return 403 for a
missing token, so this may be correct-by-imitation — but it should be recorded as such.
(TX-24, SN-03)

**Q12 — Is `Request.TTL` dead?** `sshca.Request.TTL` is set by the handler
(`handler.go:97`) and never read by `Serialize` (`sshca.go:56-99`), which takes the
lifetime from the kernel's claims instead. Remove, or is a serializer-side check
intended?
