# E-06 — Vault API compatibility surface (the Compat Line)

**Mission:** E-06 (P0) · **Feeds:** doc 07 (primary), docs 09/10 · **Date:** 2026-08-16
**Status: Complete — Compat Line spec below**

## Question

Signet will replace OpenBao by speaking a Vault-compatible API so existing
consumers work **unmodified**. What is the *exact* surface those consumers
call? Deliverable: a Compat Line — Tier A (bug-compatible), Tier B (loose),
Tier C (out of scope with evidence) — derived from consumer **source code**,
not API docs.

Consumer set (priority order):

1. External Secrets Operator (ESO) — Vault provider, kubernetes + token auth, KV v2 (KV v1 delta noted). Homelab primary: `remoteRef {key, property}` against a KVv2 mount.
2. cert-manager — Vault issuer (`pki/sign`), kubernetes + token + approle auth.
3. Generic tooling — `vault`/`bao` CLI (`kv get/put/list/delete`, `login` token+userpass), curl, Go (`hashicorp/vault/api`) and Python (`hvac`) client cores.

## Method / sources

Sparse clones read locally on 2026-08-16 (commit SHAs pinned); hvac fetched raw.
All line references are to these commits.

- **external-secrets** `5a1d5960c51d7f6680d4fd60bab905590851c8ae` (2026-08-15) — `providers/v1/vault/{client_get.go, client_push.go, client_get_all_secrets.go, auth.go, auth_kubernetes.go, auth_token.go, auth_approle.go, auth_userpass.go, client.go, provider.go, validate.go, util/vault.go}`
  https://github.com/external-secrets/external-secrets/tree/5a1d5960/providers/v1/vault
- **cert-manager** `4bed4fdde4634cd34624e46c989db1b81f7ccdbb` (2026-08-15) — `internal/vault/vault.go`, `pkg/apis/certmanager/v1/const.go`
  https://github.com/cert-manager/cert-manager/blob/4bed4fdd/internal/vault/vault.go
- **hashicorp/vault** `744b611b5700b3b7f82d76b4d6938a91b9989367` (2026-08-14) — `api/{client.go, logical.go, request.go, response.go, secret.go, auth.go, auth_token.go, sys_health.go}`, `api/auth/{kubernetes,approle,userpass}/*.go`, `command/{kv_helpers.go, kv_get.go, kv_put.go, kv_list.go, kv_delete.go}`, `builtin/credential/{token,userpass}/cli.go`, `sdk/helper/certutil/{helpers.go, types.go}`
- **openbao** `2352464f5c80de520c10849bc61c3dcb7033754f` (2026-08-15) — `api/client.go`, `internal/command/kv_helpers.go`, `internal/command/status.go`, `api/sys_seal.go`
- **hvac** (main, fetched 2026-08-16) — `hvac/adapters.py`, `hvac/api/secrets_engines/kv_v2.py`, `hvac/exceptions.py`

Both ESO and cert-manager are compiled against `hashicorp/vault/api`, so the
Go client's transport behavior *is* part of the contract. OpenBao's `api` and
CLI are faithful forks (same header constants `api/client.go:63-70`, same kv
preflight `internal/command/kv_helpers.go:64`); everything below holds for
`bao` identically.

## Findings

### F1. The wire contract every consumer inherits from the Go client

From `vault/api/{client,logical,request,response,secret}.go`:

- **URL prefix**: everything is `/v1/<path>`. Query params for read data (`?version=N`).
- **Request headers**:
  - `X-Vault-Token: <token>` on every authenticated call (`request.go:132-134`).
  - `X-Vault-Request: true` on **every** request — set unconditionally at client construction (`client.go:663`) and by hvac (`adapters.py:344`). Signet must accept and ignore it.
  - `X-Vault-Namespace` sent **only** when a namespace is explicitly configured (`client.go:1005,1602`; hvac `adapters.py:350`). ESO sets it only if `store.Namespace != nil` (`auth.go:53-54`); homelab stores don't set it. Vault OSS ignores the header — Signet should too (accept, ignore).
  - `X-Vault-Wrap-TTL`, `X-Vault-MFA`, `X-Vault-Policy-Override`, `X-Vault-Index`, `X-Vault-Forward`, `X-Vault-Inconsistent` exist in the client but are never sent by our consumer set unless opt-in flags are enabled (ESO sends `X-Vault-Inconsistent` only when `forwardInconsistent: true`). Ignore all of them.
- **LIST is not (only) the LIST verb.** `Logical.List` builds a `LIST` request then rewrites it to `GET` with `?list=true` (`logical.go:193-200`). So the Go client and both CLIs *always* send `GET <path>?list=true`. curl users may send the `LIST` method. Signet must route **both**.
- **Writes are `PUT`**, not POST (`Logical.WriteWithContext`, `logical.go:232`). cert-manager's raw requests use `POST`. Treat PUT and POST as equivalent on logical paths (Vault does).
- **404 semantics (the single most load-bearing behavior).** `ParseRawResponseAndCloseBody` (`logical.go:138-161`): on HTTP 404, if the body has no `data` and no `warnings`, the call returns `(nil, nil)` — *no error*. ESO maps that to `NoSecretError` (`client_get.go:140-141`) which drives its "secret absent" logic. A 404 whose body *does* carry `data`/`warnings` is returned as a normal secret (this is how Vault serves deleted-but-not-destroyed KVv2 versions). Signet: return `404` + `{"errors":[]}` for missing secrets — ESO treats deleted and missing identically (`data.data == null` → `NoSecretError`, `client_get.go:151-153`), so Signet does **not** need Vault's "404-with-body" quirk. Empty body also works (`io.EOF → nil,nil`), but match Vault: `{"errors":[]}`.
- **Error shape.** Any status outside 200–399 (except 429 on `/v1/sys/health`) becomes a `ResponseError` parsing body `{"errors": ["msg", ...]}` (`response.go:59-101`). Non-JSON bodies are tolerated (RawError path) but every string-matching consumer expects the array. hvac maps status→exception (`400 InvalidRequest, 403 Forbidden, 404 InvalidPath, 500/502/503 …`, `exceptions.py`) and joins the `errors` array. **Contract: all errors are `{"errors":[<strings>]}` with correct status; 403 = permission denied, 404 = missing path, 400 = bad request.**
- **Success envelope** (`secret.go:21-58`): consumers JSON-decode into
  ```json
  {"request_id":"", "lease_id":"", "lease_duration":0, "renewable":false,
   "data":{...}, "warnings":null, "auth":null, "wrap_info":null, "mount_type":""}
  ```
  All top-level fields are optional-tolerant on decode, **but**: `auth.metadata` is typed `map[string]string` (`secret.go:332`) and lookup-self `data.meta`/`data.metadata` values must be strings (`secret.go:225-240`) — a non-string value fails the whole JSON decode or errors the CLI login. Numbers decode via `json.Number` (`UseNumber()` everywhere), so integers may be sent bare.
- **Redirects**: client follows exactly one 301/302/307 (`client.go` httpRequest path); Signet (single active node) should simply never redirect.
- **Retries**: retryablehttp with `MaxRetries=2`, retrying 429, 5xx (≠501) and 412 (`client.go:1884-1895`). Signet: never emit 412 (that's an Enterprise consistency signal); 429 only if we genuinely rate-limit.
- **TLS**: consumers pin CA bundles client-side; nothing server-side beyond real TLS.

### F2. External Secrets Operator — endpoint inventory

**Correction to doc 07's assumption: ESO does NOT auto-discover mounts.**
`grep -rn 'sys/internal/ui\|sys/' providers/v1/vault/` → zero hits. The KV
version (`v1`/`v2`) and mount path come from the SecretStore CR
(`spec.provider.vault.version`, default `v2`); path building is entirely
client-side (`client_get.go:289-321` `buildPath` inserts `/data/`,
`buildMetadataPath` inserts `/metadata/`). Mount preflight is a **CLI**
behavior (F4), not an ESO one.

ESO wraps the Go client via interfaces (`util/vault.go`): `ReadWithDataWithContext`, `ListWithContext`, `WriteWithContext`, `DeleteWithContext`, `Auth().Login`, `AuthToken().{LookupSelfWithContext,RevokeSelfWithContext}`. Full call inventory:

| # | Call site | Method + path | Request | Response fields ESO parses |
|---|---|---|---|---|
| 1 | login (k8s auth) `auth_kubernetes.go:56-71` → `api/auth/kubernetes` | `PUT /v1/auth/<mount>/login` (mount default `kubernetes`) | `{"jwt":"<SA JWT>","role":"<role>"}` | **only** `auth.client_token` (`api/auth.go:104-115` errors if empty). Rest of auth block ignored. |
| 2 | login (approle) `auth_approle.go` → `api/auth/approle` | `PUT /v1/auth/<mount>/login` (default `approle`) | `{"role_id","secret_id"}` | `auth.client_token` |
| 3 | login (userpass) `auth_userpass.go` → `api/auth/userpass` | `PUT /v1/auth/<mount>/login/<username>` | `{"password"}` | `auth.client_token` |
| 4 | token check `auth.go:169-223` `checkToken` (used by `Validate()` and token-cache reuse) | `GET /v1/auth/token/lookup-self` | — | `data.type` (string; `"batch"` → don't reuse), `data.ttl` (**must be a JSON number** — unchecked `ttl.(json.Number)` assertion at `auth.go:193`, a string panics the provider), `data.expire_time` (**key must exist**: RFC3339 string or `null`; `null` = non-expiring; `ttl<60 && expire_time!=null` → treated expired) |
| 5 | token revoke on Close `auth.go:225-239` | `PUT /v1/auth/token/revoke-self` | `{}` (token in header) | nothing (error only) |
| 6 | **read secret** `client_get.go:124-161` | `GET /v1/<mount>/data/<path>[?version=N]` | — | KVv2: `data.data` (map; `null` → NoSecret; **missing key `data` → hard error** `errDataField`). KVv1: whole `data`. `lease_*`/`metadata` ignored. |
| 7 | read metadata `client_get.go:191-228` (metadataPolicy: Fetch, find-by-tag, push guard) | `GET /v1/<mount>/metadata/<path>` | — | `data.created_time`, `data.current_version` (number; used as CAS int, `client_push.go:251-273`), `data.delete_version_after`, `data.custom_metadata` (map, string values preferred) |
| 8 | list (GetAllSecrets/find) `client_get_all_secrets.go:111-148` | `GET /v1/<mount>/metadata/<path>/?list=true` (recursive) | — | `data.keys` (`[]string`, dirs end with `/`) |
| 9 | push data `client_push.go:35-161` | `PUT /v1/<mount>/data/<path>` | `{"data":{...}}` + optional `{"options":{"cas":N}}` | response ignored |
| 10 | push metadata `client_push.go:150-156` | `PUT /v1/<mount>/metadata/<path>` | `{"custom_metadata":{"managed-by":"external-secrets"}}` | ignored |
| 11 | delete (PushSecret GC) `client_push.go:163-218` | `DELETE /v1/<mount>/data/<path>` then `DELETE /v1/<mount>/metadata/<path>` | — | ignored |

Auth flow answers to the mission's direct questions:

- **Yes** — ESO's kubernetes auth POSTs the ServiceAccount JWT (TokenRequest API, 10-min token, `auth_kubernetes.go:78-87`) as `{"jwt","role"}` to `auth/<mount>/login` and consumes the standard Vault token response; the *only* verbatim requirement is `auth.client_token` non-empty, plus JSON-decodability of the rest (string-valued `auth.metadata` if present).
- **Lease/renewability fields**: `auth.lease_duration` and `auth.renewable` may be static (`0`/`false`) — ESO discards the login Secret (`_, err = c.auth.Login(...)`) and never calls `renew-self`. Freshness is governed instead by **lookup-self** `data.ttl`/`data.expire_time` (row 4): return real remaining seconds, or `expire_time: null` for static tokens.
- ESO token auth (`auth_token.go`) does zero login calls — the token from the k8s Secret goes straight into `X-Vault-Token`; it's validated via lookup-self in `Validate()`.
- No `sys/health`, no `sys/seal-status`, no version endpoints anywhere in ESO.

KV v1 delta (Tier B): same calls without the `/data/`//`metadata/` infixes and without the envelope-within-envelope: secret fields live directly in `data`; `custom_metadata` is stored *inside the secret* (`client_push.go:85-87,128-131`); metadata fetch and find-by-tag unsupported by ESO on v1.

### F3. cert-manager Vault issuer — endpoint inventory

`internal/vault/vault.go`; requests are raw (`client.NewRequest` + `RawRequest`), paths partly include `/v1` (CRD-supplied).

| # | Call site | Method + path | Request | Response fields parsed |
|---|---|---|---|---|
| 1 | `Sign` `vault.go:162-203` | `POST /v1/<spec.vault.path>` — homelab shape: `pki/sign/<role>` | `{"common_name","alt_names":"a,b","ip_sans","uri_sans","ttl":"2160h0m0s","csr":"<PEM>","exclude_cn_from_sans":"true"}` — **all values strings**; `ttl` is a Go `Duration.String()` (accepts `h/m/s` units) | `data.certificate`, `data.issuing_ca`, `data.ca_chain` (`[]string`, optional) via `certutil.CertBundle` mapstructure (`sdk/helper/certutil/types.go:109-116`); `serial_number`/`private_key_type` tolerated, extra keys ignored |
| 2 | kubernetes auth `vault.go:556-657` | `POST <mountPath>/login`, default mountPath **`/v1/auth/kubernetes`** (`const.go:42`) | `{"role","jwt"}` (JWT from TokenRequest, audiences `vault://ns/name` + server URL, 600 s) | `auth.client_token` via `Secret.TokenID()` — falls back to `data.id` if no auth block |
| 3 | approle auth `vault.go:430-478` | `POST /v1/auth/<path>/login`, default `approle` | `{"role_id","secret_id"}` | `auth.client_token` |
| 4 | client-cert auth `vault.go:480-554` | `POST <mountPath>/login`, default `/v1/auth/cert` (mTLS) | `{"name"}` | `auth.client_token` |
| 5 | token auth `vault.go:213-222` | none (header only) | — | — |
| 6 | **health probe** `IsVaultInitializedAndUnsealed` `vault.go:891-923` | `GET /v1/sys/health` (namespace-less client) | — | **status code only**: 200 OK; 429/472/473 treated healthy; 501 → "not initialized"; 503 → "sealed"; body never parsed |

So cert-manager **hard-requires `sys/health`** — it is called before issuing.
The Go client special-cases 429 on `/v1/sys/health` as non-error
(`response.go:62`). Signet single-active: always return `200` with the
standard JSON body (body content free, status code is the contract).

No renew/lookup calls: cert-manager re-authenticates on every issuer sync and
never renews or revokes tokens (known Vault-operator complaint — token churn;
Signet can mitigate with short default TTLs on these logins).

### F4. `vault` / `bao` CLI — endpoint inventory

From `vault/command/kv_*.go`, `builtin/credential/{token,userpass}/cli.go`;
OpenBao identical (`internal/command/kv_helpers.go`).

| # | Command | Method + path | Parsed |
|---|---|---|---|
| 1 | every `kv` subcommand, **including with `-mount=`** (`kv_get.go:129-134`) | `GET /v1/sys/internal/ui/mounts/<path>` (preflight, `kv_helpers.go:50-119`) | `data.path` (string mount path), `data.options.version` — **must be the JSON *string* `"2"`** (unchecked `versionRaw.(string)` at `kv_helpers.go:108` — a number panics the CLI). 404 → assumes KV v1. 403 → error (with special hint). |
| 2 | `kv get` | `GET /v1/<mount>/data/<path>[?version=N]` | prints `data.data` map and `data.metadata` (`created_time`, `version`, …) if present (`kv_get.go:187-231`); `-field=x` indexes into `data.data` |
| 3 | `kv put` | `PUT /v1/<mount>/data/<path>` `{"data":{...}[,"options":{"cas":N}]}` | prints response `data` (version, created_time) if present — tolerant |
| 4 | `kv list` | `GET /v1/<mount>/metadata/<path>?list=true` | `data.keys` |
| 5 | `kv delete` | `DELETE /v1/<mount>/data/<path>`; `-versions=` → `PUT /v1/<mount>/delete/<path>` `{"versions":[...]}` | — |
| 6 | `login` (token) | `GET /v1/auth/token/lookup-self` (`token/cli.go:85-146`) | `data.id`, `data.accessor`, `data.policies[]`, `data.meta` (string map or null), `data.ttl`, `data.renewable` |
| 7 | `login -method=userpass` | `PUT /v1/auth/userpass/login/<username>` `{"password"}` (`userpass/cli.go:50-51`) | full `auth` block printed: `client_token`, `accessor`, `policies`, `lease_duration`, `renewable`, `metadata` |
| 8 | `status` (`bao status`) | `GET /v1/sys/seal-status` (`status.go:83`, `api/sys_seal.go:16`) | `type`, `initialized`, `sealed`, `t`, `n`, `version`, `cluster_name`… (display only) |

The homelab's documented pattern `bao kv get -mount=secrets-home-solcore-dot-net -field=master-key cluster-svc/apps/litellm` exercises rows 1 (preflight!) and 2. **`sys/internal/ui/mounts/:path` is therefore Tier A** — not because of ESO (which never calls it) but because of the CLI.

### F5. hvac (Python) core

`adapters.py`: same `/v1/` prefix, `X-Vault-Token`, `X-Vault-Request: true`,
`X-Vault-Namespace` only when set. KV v2 methods hit the same
`/{mount}/data|metadata|delete|undelete|destroy/{path}` routes. Errors:
status-code-driven exceptions with the `errors` array joined. Nothing new
beyond F1; already covered.

### F6. What consumers ignore (Signet's freedom)

- `request_id`, `lease_id`, `warnings`, `wrap_info`, `mount_type`, `Age` — never parsed by our set; emit constants (`""`, `0`, `null`).
- KVv2 read `data.metadata` — ignored by ESO, pretty-printed by CLI; any plausible values fine.
- Login response beyond `auth.client_token` — decorative for ESO/cert-manager; CLI userpass prints it (so keep it well-formed).
- Write/delete responses — fully ignored (Vault returns 200+metadata for KVv2 data writes and 204 for others; both fine, keep Vault's shapes).
- `auth.renewable`/`auth.lease_duration` — may be static; nobody in the set runs a LifetimeWatcher.
- Wrapping (`X-Vault-Wrap-TTL`, `sys/wrapping/*`) — CLI kv preflight explicitly disables wrapping; ESO/cert-manager never set it.
- Enterprise consistency headers (`X-Vault-Index` et al.) — no-op unless opted in; never emit 412.

## Recommendation — the Compat Line

### Tier A — implement bug-compatible (~15 routes)

Transport invariants (apply to all): `/v1/` prefix; JSON envelope of F1;
errors `{"errors":[...]}` with 400/403/404 discipline; 404-for-missing with
empty errors array; accept `GET ?list=true` **and** `LIST`; treat PUT≡POST;
accept & ignore `X-Vault-Request`, `X-Vault-Namespace`, `X-Vault-Inconsistent`;
never redirect; never 412.

**Auth (5):**
1. `POST /v1/auth/{mount:kubernetes}/login` — req `{jwt, role}`; resp `{"auth":{"client_token","accessor","policies":[],"token_policies":[],"metadata":{string:string}|null,"lease_duration":int,"renewable":bool,"entity_id":"","orphan":true},"lease_duration":0,...}`. Verify JWT per doc 04 (TokenReview or issuer JWKS). Bug-compat: `client_token` non-empty; `metadata` values strings.
2. `POST /v1/auth/{mount:approle}/login` — req `{role_id, secret_id}`; same resp.
3. `POST /v1/auth/{mount:userpass}/login/{username}` — req `{password}`; same resp.
4. `GET /v1/auth/token/lookup-self` — resp `data`: `{"id","accessor","type":"service","policies":[],"meta":null,"ttl":<number>,"expire_time":<RFC3339|null>,"renewable":bool,"num_uses":0,"creation_time":<number>,...}`. **Bug-compat: `ttl` is a JSON number; `type` a string ≠ "batch" for reusable tokens; `expire_time` key always present (null ⇒ non-expiring).**
5. `POST|PUT /v1/auth/token/revoke-self` — 204, body ignored.

**KV v2 (7, per kv mount):**
6. `GET /v1/{mount}/data/{path}[?version=N]` — resp `data`: `{"data":{...}|null,"metadata":{"created_time","custom_metadata":null|{},"deletion_time":"","destroyed":false,"version":n}}`. Missing/deleted ⇒ `404 {"errors":[]}`. **`data.data` key must exist on 200.**
7. `POST|PUT /v1/{mount}/data/{path}` — req `{"data":{...}[,"options":{"cas":N}]}`; CAS enforced when sent (`cas:0` ⇒ create-only) → violation `400 {"errors":["check-and-set parameter did not match the current version"]}`; resp 200 with `data` = version metadata.
8. `GET /v1/{mount}/metadata/{path}` — resp `data`: `{"created_time","current_version":<number>,"delete_version_after":"0s","custom_metadata":null|{string:string},"oldest_version","updated_time","versions":{...}}`. ESO parses the first four.
9. `LIST` / `GET ?list=true` `/v1/{mount}/metadata/{path}` — `data.keys: []string`, dir entries end `/`; empty ⇒ 404 empty-errors.
10. `POST|PUT /v1/{mount}/metadata/{path}` — req `{"custom_metadata":{...}}` (accept `max_versions`, `cas_required`, ignore-tolerantly) — 204.
11. `DELETE /v1/{mount}/data/{path}` — soft-delete latest — 204.
12. `DELETE /v1/{mount}/metadata/{path}` — destroy secret + history — 204.

**sys (2):**
13. `GET /v1/sys/internal/ui/mounts/{path}` — resp `data`: `{"path":"<mount>/","type":"kv","options":{"version":"2"}}` for KV mounts (**`version` a string**), `{"type":"system"|...,"options":null}` for others; unauthenticated token ⇒ 403 with errors array; unknown path under a real mount still resolves to the mount (Vault resolves longest-prefix mount).
14. `GET /v1/sys/health` — status-code contract: 200 (init+unsealed+active). Body: Vault-shaped `{"initialized":true,"sealed":false,"standby":false,"version":"...",...}` (unparsed today, cheap insurance). Never 501/503 while serving.

**PKI (1):**
15. `POST /v1/{pki-mount}/sign/{role}` — req (all string values) `{csr, common_name, alt_names:"csv", ip_sans:"csv", uri_sans:"csv", ttl:"<go-duration>", exclude_cn_from_sans:"true"}`; resp `data`: `{"certificate":"<PEM>","issuing_ca":"<PEM>","ca_chain":["<PEM>",...],"serial_number":"aa:bb:..","expiration":<unix>}`. Must parse Go duration strings (`"2160h0m0s"`) *and* bare seconds/`"720h"` forms.

### Tier B — implement loosely (parsed by tooling, tolerant consumers)

- `GET /v1/sys/seal-status` — for `bao status` / human ops: `{"type":"shamir","initialized":true,"sealed":false,"t":0,"n":0,"progress":0,"version":"signet-x.y","cluster_name":...}` (display-only).
- `POST|PUT /v1/auth/token/renew-self` — return the token's auth block unchanged (accept `increment`, may no-op). Not called by our set; cheap and unblocks Vault Agent/Nomad-style users later.
- KV v2 version ops used by CLI power commands: `PUT /v1/{mount}/delete/{path}` `{"versions":[..]}`, `undelete/`, `destroy/`; `GET /v1/{mount}/config` (hvac reads it in some flows).
- KV **v1** dialect: `GET|PUT|DELETE|LIST /v1/{mount}/{path}` with fields directly in `data`. ESO supports it; homelab doesn't use it. Small once v2 exists.
- `POST /v1/{pki-mount}/issue/{role}` — same serializer as `sign` plus `private_key`/`private_key_type` in response. Not in this mission's consumer evidence (cert-manager only signs), but the fleet's own rotation scripts likely `bao write pki-.../issue/<role>` — verify against `fleet` repo before v1 freeze and promote to Tier A if so.
- `GET /v1/auth/token/lookup` + `lookup-accessor` — admin/debug convenience.
- `Authorization: Bearer <token>` as an alternative to `X-Vault-Token` (Vault supports it; none of our consumers use it).

### Tier C — explicitly out of scope (evidence: zero call sites in the consumer set)

- **Enterprise namespaces** — header is *sent* only when configured; homelab CRs don't set it; Vault OSS ignores it. Signet: accept & ignore the header, no namespace semantics. (grep: ESO `SetNamespace` only under `store.Namespace != nil`; cert-manager passes `""` by default.)
- **Wrapping** (`sys/wrapping/wrap|unwrap|lookup`, `X-Vault-Wrap-TTL`, cubbyhole) — CLI preflight disables it; no consumer wraps.
- **transit, ssh (Vault dialect), database/dynamic secrets, sys/leases/**\* — no call sites; Signet has its own SSH-cert dialect (doc 07 §3).
- **sys/raw, sys/init, sys/rekey, sys/generate-root, sys/audit, sys/policy, sys/mounts (write), sys/capabilities, replication/MFA/identity APIs** — operator surface of Vault itself; Signet has its own admin plane. `sys/mounts` read is *not* needed — the CLI uses `sys/internal/ui/mounts`.
- **Response wrapping of auth (`wrap_info`), batch tokens, token roles/orphan trees** — ESO checks `type != "batch"`; always issue `"service"`.
- **`X-Vault-Index`/FGRP consistency protocol and 412 replies** — Enterprise-only; clients no-op without it.

### Honest size estimate

The dialect is a serializer over kernel ops (KV store with versions +
token/identity + X.509 issuance already exist per docs 03–06):

- Transport shim (envelope, errors, list-rewrite, header tolerance): ~300 LoC + table tests.
- KV v2 semantics (versioned read/write/CAS/soft-delete/destroy/metadata/list): the real work — ~800–1200 LoC over the kernel KV, assuming kernel stores version history natively (doc 03 decision point).
- Auth logins (3) + lookup/revoke-self: ~400 LoC of serialization; JWT/TokenReview verification is kernel (doc 04), not dialect.
- sys/health, seal-status, internal/ui/mounts: ~150 LoC.
- pki sign/(issue): ~250 LoC over the kernel CA.

**Total: roughly 2–3 k LoC of dialect code + a conformance test pack.** The
conformance pack matters more than the code: run real ESO + cert-manager +
`bao` CLI against Signet in kind (mission E-10) asserting the panic-prone
details (ttl-as-number, options.version-as-string, expire_time-key-present,
404-empty-errors, GET?list=true).

## Impact on design docs

- **07 §v1 item 2** — reword: "Vault-compatible KV v2 API (+ k8s auth method shape)" → enumerate the Tier A list above (15 routes incl. `sys/internal/ui/mounts`, `sys/health`, `pki/sign`, token lookup/revoke-self, approle+userpass logins). Drop the implication that ESO's surface alone defines it; the `bao` CLI and cert-manager add the `sys/*` and pki routes.
- **07 Open questions, "Vault API compatibility breadth"** — answer it: the line is Tier A/B/C above; **no transit**, no wrapping, no namespaces; approle is *in* (cert-manager + ESO both ship it, cost is one route).
- **07 v1.x item 4 (ACME)** — note that cert-manager can be served *before* ACME lands via the Tier A `pki/sign` route + `sys/health`; ACME then becomes the preferred path, Vault-issuer the bridge.
- **09 (module layout)** — dialect/vault module boundary: transport shim vs KV-semantics vs auth serializers as above; KV version history becomes an explicit kernel requirement (feeds 03).
- **10 (testing)** — add the bug-compat conformance assertions list (this doc, "size estimate" paragraph) as fixture cases; pin consumer versions tested (ESO ≥ current, cert-manager ≥ current, bao CLI).
- **06 (credential lifecycle)** — record that Vault-dialect logins may issue short-TTL non-renewable service tokens (`renewable:false`) since no consumer renews; lookup-self must report live remaining TTL.

## Confidence and what would change the conclusion

**High** for ESO, cert-manager, Go client, CLI (read from pinned source at
head-of-main, 2026-08-14/15 commits). **Medium** for hvac (core files read;
long tail of helper methods unreviewed) and for the claim that nothing probes
`sys/seal-status` in-cluster (inframonitor and homelab scripts weren't in
scope — grep them before freeze).

Would change the conclusion:

1. **ESO regressing to mount auto-discovery** or adding preflight — watch `providers/v1/vault` upstream; today's evidence is definitive (no `sys/` references).
2. **Homelab fleet PKI scripts** calling `pki/issue/<role>`, cert or CRL endpoints (`/v1/pki/ca`, `/crl`) — would promote those from Tier B/C to A. Check the `fleet`/`openbao_server` role source (out of this mission's tree).
3. Older deployed consumer versions (e.g. ESO < v0.10 used `pkg/provider/vault` but same call set; cert-manager < 1.12 used `RawRequest` identically) — if the homelab pins old images, re-verify against those tags; spot-checks suggest the surface has been stable for years.
4. If any consumer is later configured with `readYourWrites: true`, Signet must *echo* an `X-Vault-Index` header (opaque value suffices) — currently unnecessary.

## Addendum — homelab verification (post-report, 2026-08-16)

The two flagged unknowns were checked against the actual homelab source:

1. **`pki/issue` is not used anywhere.** `grep -rE 'pki[-a-z]*/(issue|sign)'`
   across `fleet/` and `infrastructure/`: every caller signs CSRs via
   `pki-home-solcore-dot-net/sign/<role>` (openbao_server TLS rotate template,
   truenas_cert role — the latter via AppRole auth, confirming approle in
   Tier A). `pki/issue/{role}` stays Tier B.
2. **`sys/health` body IS parsed in this homelab** — the report's "body
   unparsed, Vault-shaped body is cheap insurance" is upgraded to hard
   contract: `inframonitor/tools/gen_targets.py:156-160` asserts
   `initialized == true` and `sealed == false` (JSON booleans; mismatch ⇒
   crit page), warns on `standby == true`, displays `version`. The
   `fleet/roles/truenas_cert` refresh script also curls `sys/health`
   (status-code gate). Tier A route 14 must emit at minimum:
   `{"initialized":true,"sealed":false,"standby":false,"version":"..."}` with
   real boolean semantics tied to actual seal state.
