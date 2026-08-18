# Test plan 01 — SECRETS / Vault KV v2 compatibility surface

**Scope:** the on-rails behaviour of the KV half of the Vault dialect — every
scenario a user (or a real client) is entitled to rely on.
**Status: Draft — design only.** No source or existing test was modified to
produce this. Every "current behaviour" claim below is either cited to
`file:line` or was observed by running throwaway probes against a real
in-process kernel + `httptest` server in a scratch mirror of the tree (the NFS
mount has no `flock`, so probes ran from a local-disk copy; nothing was written
back). Probe-observed rows are marked **[observed]**.

**Surface under test**

| Concern | Code |
|---|---|
| Routes, envelopes, error shapes | `internal/dialect/vaultkv/handler.go:79-155`, `:565-858`, `:899-920` |
| Authorization + read path | `internal/kernel/kernel.go:205-367`, `:471-485` |
| State machine (versions, CAS, trim) | `internal/kernel/secrets.go:40-241` |
| Ops on the wire | `internal/op/op.go:138-202` |
| Buckets | `internal/store/store.go:21-22` |
| Pinned compat line | `docs/07-dialect-roadmap.md:14-36`, `docs/explorations/E-06-vault-compat.md:41-63`, `:160-190` |

**Consumer shorthand** — ESO = External Secrets Operator (via
`hashicorp/vault/api`); CLI = `vault`/`bao` CLI; GoAPI = anything compiled
against `hashicorp/vault/api` (covers ESO *and* cert-manager); hvac = the
Python client; ops = human/curl/fleet scripts.

**Coverage verdicts** — `COVERED` (an existing test asserts the observable
result), `PARTIAL` (a nearby test asserts part of it, e.g. at kernel level but
not over HTTP), `GAP` (nothing asserts it).

---

## 0. Standing preconditions

Unless a row says otherwise, every scenario assumes:

- **P0** A single-node kernel with a leader elected, a KV mount named
  `secrets-home-solcore-dot-net` mapped to tree prefix `/secrets`
  (`handler.go:41-59`, `:66-77`; the test harness shape is
  `handler_test.go:27-74`).
- **P1** A principal `root` holding `domain-admin` at `/`
  (`model.go:206-212`, `apply_test.go:79-83`), and a live non-expired session
  token for it (`kernel.go:143-169`).
- **P2** A seed secret at `/secrets/cluster-svc/apps/litellm` with two keys
  (`handler_test.go:58-61`).
- **P3** The token is presented as `X-Vault-Token` (`handler.go:880-888`).

Path notation: `M` = `/v1/secrets-home-solcore-dot-net`.

---

## 1. Version lifecycle — read / write

| ID | Preconditions | Request | Expected observable result | Depended on by | Covered? |
|---|---|---|---|---|---|
| SEC-RW-01 | P0-P3 | `GET M/data/cluster-svc/apps/litellm` | 200. Body is the full envelope (`handler.go:899-910`): `request_id`,`lease_id`,`renewable`,`lease_duration`,`data`,`wrap_info`,`warnings`,`auth` all present. `data.data` is an object of string→string; `data.metadata` has `created_time` (RFC3339), `custom_metadata`, `deletion_time`, `destroyed`, `version` (`handler.go:598-607`). | ESO (`data.data` then index by `property`), CLI `kv get` | **COVERED** `handler_test.go:99-121` |
| SEC-RW-02 | P0-P3 | `PUT M/data/apps/newthing` `{"data":{"password":"hunter2"}}` | 200; `data.version` = 1 as a **JSON number**; `created_time` RFC3339; `custom_metadata` null; `deletion_time` ""; `destroyed` false (`handler.go:851-857`). A subsequent GET returns the value. | ESO push, CLI `kv put` | **PARTIAL** — round trip asserted at `handler_test.go:217-230`; the *response body shape* of a write is not asserted. **GAP** for the body. |
| SEC-RW-03 | SEC-RW-02 done | `POST M/data/apps/newthing` `{"data":{"k":"v"}}` | Identical to PUT: 200, `data.version` = 2. PUT≡POST on every logical path (`handler.go:96-97`, `:106-107`, `:111-116`). **[observed]** | cert-manager & curl users POST; E-06 F1 line 52 | **GAP** |
| SEC-RW-04 | secret has versions 1..3 | `GET M/data/<p>?version=2` | 200; `data.metadata.version` = 2; `data.data` is version 2's values (`handler.go:576-582`, `kernel.go:225-234`). | CLI `kv get -version=`, hvac | **PARTIAL** — kernel-level only, `secrets_test.go:53-80`. No HTTP test. |
| SEC-RW-05 | P0-P3 | `GET M/data/<p>?version=0` | 200 with the *current* version — 0 means current (`kernel.go:225-227`). **[observed]** | GoAPI callers that always send `version` | **GAP** |
| SEC-RW-06 | P0-P3 | `GET M/data/<p>?version=abc` | 400 `{"errors":["version must be a number"]}` (`handler.go:578-581`). **[observed]** | hvac (400→`InvalidRequest`) | **GAP** |
| SEC-RW-07 | secret exists with current version 3 | `GET M/data/<p>?version=99` | 404 `{"errors":[]}` — a version that never existed is *absent*, not an error (`kernel.go:228-234` → `handler.go:585-590`). **[observed]** | ESO, GoAPI (`(nil,nil)`) | **GAP** |
| SEC-RW-08 | P0-P3 | Ten sequential writes to one path | `data.version` increments 1..10 monotonically; each version independently readable by `?version=N`. The counter is durable across restart — it is stored in `secret_meta`, not derived (`secrets.go:67`, `model.go:118`). | CLI, ops | **PARTIAL** — kernel `secrets_test.go:53-80`; durability across restart at `fsm_test.go:92-136` but not for the version counter specifically. |
| SEC-RW-09 | P0-P3 | `PUT M/data/<p>` `{"data":{}}` | 200, version created. Read returns `data.data` = `{}` (empty object, **not** null). **[observed]** | ESO (`{}` is a secret; `null` is NoSecret) | **GAP** |
| SEC-RW-10 | P0-P3 | `PUT M/data/<p>` `{"foo":1}` (no `data` key) | 200, version 1 created; subsequent read returns 200 with **`data.data: null`**. Per E-06:84 ESO maps `data.data == null` to `NoSecretError`, so this writes a secret that reads as absent. **[observed]** | ESO | **GAP** — and see Q3. |
| SEC-RW-11 | P0-P3 | `PUT M/data/<p>` `{"data":{"port":8080}}` | 400 `{"errors":["malformed request body"]}` — values are decoded into `map[string]string` (`handler.go:833`), so non-string JSON values are refused outright. **[observed]** | hvac / curl / ops writing typed JSON | **GAP** — and see Q3. |
| SEC-RW-12 | P0-P3 | `PUT M/data/<p>` `{` | 400 `{"errors":["malformed request body"]}` (`handler.go:838-841`). **[observed]** | all | **GAP** |
| SEC-RW-13 | P0-P3, path contains uppercase | `GET M/data/Apps/Thing` | 400 `{"errors":["path \"/secrets/Apps/Thing\": illegal byte 'A' in segment \"Apps\" (allowed: a-z 0-9 . _ -)"]}` — the SPIFFE path grammar (`path.go:24-60`) rejects it *before* authorization or lookup (`kernel.go:206-208`). This is **not** Vault behaviour (Vault would 404) and is a deliberate contract that must be pinned so it cannot regress silently. **[observed]** | ESO/CLI users migrating mixed-case Vault paths | **GAP** — and see Q1. |
| SEC-RW-14 | P0-P3 | `GET M/data/` + 72 path segments | 400 `{"errors":["path: depth 72 exceeds limit 64"]}` (`path.go:41-43`). Similarly >1024 bytes (`path.go:31-33`). **[observed]** | ops | **GAP** |

## 2. Version lifecycle — soft delete / undelete / destroy

| ID | Preconditions | Request | Expected observable result | Depended on by | Covered? |
|---|---|---|---|---|---|
| SEC-VER-01 | secret with versions 1,2 | `DELETE M/data/<p>` (no body) | **204, empty body** (`handler.go:713`). Only the *current* version is soft-deleted; the empty version list means "current" (`handler.go:710`, `secrets.go:114-117`). Version 1 still reads. | ESO PushSecret GC, CLI `kv delete` | **PARTIAL** — kernel `secrets_test.go:121-135`; over HTTP the 204 is asserted incidentally at `handler_test.go:265-267`. |
| SEC-VER-02 | SEC-VER-01 done | `GET M/data/<p>` | 404 `{"errors":[]}` — a soft-deleted version reads as absent, deliberately *without* Vault's 404-with-a-body quirk (`kernel.go:228-234` and its comment; E-06:53 authorises the deviation). | ESO ("deleted" and "missing" are the same to it) | **COVERED** `handler_test.go:268-270` |
| SEC-VER-03 | SEC-VER-01 done | `GET M/data/<p>?version=1` | 200 — deleting the current version must not affect older ones. | CLI, ops | **PARTIAL** — kernel `secrets_test.go:129-134`, not over HTTP |
| SEC-VER-04 | version 1 soft-deleted | `PUT M/delete/<p>` `{"versions":[1]}` (numeric) | 204; version 1 hidden, current untouched. | hvac, GoAPI | **PARTIAL** — the *undelete* twin is covered at `handler_test.go:253-279`; `delete` with an explicit list is not |
| SEC-VER-05 | version 1 soft-deleted | `PUT M/undelete/<p>` `{"versions":[1]}` | 204; version 1 readable again with its original values. | hvac, GoAPI | **COVERED** `handler_test.go:253-279` (numeric case) |
| SEC-VER-06 | version 1 soft-deleted | `PUT M/undelete/<p>` `{"versions":["1"]}` (**strings** — what the CLI sends) | 204 **and the value actually comes back**. Regression guard: decoding strictly into `[]uint64` silently rewrote this as "version 0", a destructive no-op reporting success (`handler.go:772-805`). | CLI | **COVERED** `handler_test.go:253-279` (string case) |
| SEC-VER-07 | secret with versions 1,2 | `PUT M/undelete/<p>` (no body) | 204; empty body means the current version (`handler.go:731`, `secrets.go:114-117`). **[observed]** | CLI, ops | **GAP** |
| SEC-VER-08 | version 1 exists | `PUT M/destroy/<p>` `{"versions":[1]}` | 204; version 1's *data record* is deleted from `secret_data` (`secrets.go:132-136`), its metadata entry survives with `destroyed:true`. A later read is 404. | CLI `kv destroy`, hvac | **PARTIAL** — kernel `secrets_test.go:100-111`; not over HTTP |
| SEC-VER-09 | version 1 destroyed | `PUT M/undelete/<p>` `{"versions":[1]}` | 204 (success — the request is honoured) but the version **stays gone**: destruction is final and undelete skips destroyed versions (`secrets.go:126-131`). Read remains 404. | ops (the safety property) | **PARTIAL** — kernel `secrets_test.go:104-108`; not over HTTP |
| SEC-VER-10 | secret exists | `PUT M/destroy/<p>` `{"versions":[9999]}` | 204; unknown versions are skipped, not errors (`secrets.go:118-121`). No other version is touched. | CLI, hvac | **GAP** |
| SEC-VER-11 | secret exists, current already soft-deleted | `DELETE M/data/<p>` again | 204 — soft delete is idempotent; `deletion_time` is refreshed. **[observed]** | ESO GC re-runs | **GAP** |
| SEC-VER-12 | secret with versions 1,2 | `DELETE M/metadata/<p>` | 204; metadata record and **every** version's data are removed (`secrets.go:149-169`). Subsequent `GET M/data/<p>` → 404, `GET M/metadata/<p>` → 404, path disappears from LIST. | ESO PushSecret GC (step 2), CLI `kv metadata delete` | **PARTIAL** — kernel `secrets_test.go:163-186`; not over HTTP, and the LIST-disappearance is unasserted |
| SEC-VER-13 | SEC-VER-12 done | `PUT M/data/<p>` `{"data":{"k":"v3"}}` | 200 with `data.version` = **1** — destroying a secret resets its version counter, because the metadata record is what holds it (`secrets.go:165-167`, `:67`). This matches Vault. **[observed]** | ops | **GAP** |
| SEC-VER-14 | no such path | `DELETE M/metadata/<p>` | **204** — destroying an absent secret is not an error; the caller's intent is met (`secrets.go:157-159`). **[observed]** | ESO GC on an already-collected secret | **PARTIAL** — kernel `secrets_test.go:182-185`; not over HTTP |
| SEC-VER-15 | no such path | `DELETE M/data/<p>` | **404 `{"errors":[]}`** — asymmetric with SEC-VER-14, because `applyVersionAction` returns `ErrNotFound` for a missing path (`secrets.go:111-113`) while `applyDestroySecret` does not. Benign for GoAPI (a 404 with no `data`/`warnings` decodes as `(nil,nil)`, i.e. success) but visible to `curl`/hvac, where 404 raises `InvalidPath`. **[observed]** | ESO GC (step 1), hvac | **GAP** — and see Q4 |
| SEC-VER-16 | no such path | `PUT M/undelete/<p>` or `PUT M/destroy/<p>` `{"versions":[1]}` | 404 `{"errors":[]}` (`secrets.go:111-113`). **[observed]** | hvac, ops | **GAP** |
| SEC-VER-17 | version 1 soft-deleted **and** version 2 current | `GET M/metadata/<p>` | 200; `versions["1"].deletion_time` is a non-empty RFC3339 stamp, `versions["1"].destroyed` false; `versions["2"].deletion_time` "" (`handler.go:631-638`, `:807-812`). **[observed]** | CLI `kv metadata get`, ops | **GAP** |
| SEC-VER-18 | version 1 destroyed | `GET M/metadata/<p>` | 200; `versions["1"].destroyed` is `true` and the entry is retained — a destroyed version leaves a tombstone, so the history cannot be laundered by destroying it. **[observed]** | ops, audit | **GAP** |

## 3. Metadata operations

| ID | Preconditions | Request | Expected observable result | Depended on by | Covered? |
|---|---|---|---|---|---|
| SEC-META-01 | P0-P3 | `GET M/metadata/cluster-svc/apps/litellm` | 200; `data` carries **all** of `created_time`, `updated_time`, `current_version` (number), `oldest_version`, `max_versions`, `cas_required`, `delete_version_after` (the literal string `"0s"`), `custom_metadata`, `versions` (object keyed by decimal version string) (`handler.go:639-649`). Reading metadata never decrypts a value (`kernel.go:252-275`). | ESO metadata policy / find-by-tag / push CAS (E-06:85) | **GAP** — no test asserts this body at all |
| SEC-META-02 | P0-P3 | `PUT M/metadata/<p>` `{"custom_metadata":{"managed-by":"external-secrets"}}` | **204, empty body** (`handler.go:694`); a subsequent metadata GET echoes `custom_metadata` verbatim. | ESO push (E-06:88) | **GAP** |
| SEC-META-03 | metadata has `custom_metadata` | `GET M/data/<p>` | 200; the read envelope's `data.metadata.custom_metadata` mirrors the path-level custom metadata (`handler.go:602`, `kernel.go:246`), and is `null` — never `{}` — when empty (`handler.go:814-819`). | ESO, CLI | **GAP** |
| SEC-META-04 | no such path | `PUT M/metadata/<p>` `{"max_versions":4}` | 204 — metadata may precede any value (`secrets.go:179-183`). `GET M/metadata/<p>` then returns 200 with `current_version:0`, `oldest_version:0`, `versions:{}`; `GET M/data/<p>` returns **404 `{"errors":[]}`**; and the path **does** appear in a LIST. **[observed]** | ops setting policy before first write | **GAP** |
| SEC-META-05 | P0-P3 | `PUT M/metadata/<p>` `{"max_versions":3,"cas_required":true}` then `GET M/metadata/<p>` | 204, then 200 with `max_versions:3` and `cas_required:true` — the two policy knobs round-trip. **[observed]** | CLI `kv metadata put`, ops | **PARTIAL** — the *effect* of `cas_required` is asserted at `secrets_test.go:188-201`; the round-trip through HTTP metadata is unasserted |
| SEC-META-06 | `max_versions:3` set | `PUT M/metadata/<p>` `{"max_versions":0}` | 204, but `max_versions` **stays 3** — zero means "unspecified", so the ceiling cannot be cleared through this route (`secrets.go:187-189`). Must be pinned as intended or fixed. **[observed]** | ops | **GAP** — see Q2 |
| SEC-META-07 | `cas_required:true` set | `PUT M/metadata/<p>` `{"custom_metadata":{"managed-by":"external-secrets"}}` | **Intended:** `cas_required` survives a metadata push that does not mention it. **Actual:** it is silently reset to `false` (`handler.go:685` decodes an absent `cas_required` as `false`, `secrets.go:190` assigns it unconditionally), while `max_versions` is preserved by the `>0` guard on the line above. **[observed — see Bug B2]** | ESO push (E-06:88 sends exactly this body) | **GAP** — this is the test that would have caught B2 |
| SEC-META-08 | no such path | `GET M/metadata/<p>` | 404 `{"errors":[]}` (`kernel.go:269-271` → `handler.go:762-763`). **[observed]** | ESO metadata fetch on an unmanaged path | **GAP** |
| SEC-META-09 | secret written at t0, metadata written at t1 | `GET M/metadata/<p>` | `created_time` reflects first touch, `updated_time` advances on every write **and every version action** (`secrets.go:75-80`, `:142`, `:191`). Both are RFC3339 in UTC; a never-set timestamp serialises as `""`, not `"1970-…"` (`handler.go:807-812`). | ESO (`created_time`), CLI | **GAP** |

## 4. Check-and-set (CAS)

| ID | Preconditions | Request | Expected observable result | Depended on by | Covered? |
|---|---|---|---|---|---|
| SEC-CAS-01 | no such path | `PUT M/data/<p>` `{"data":{…},"options":{"cas":0}}` | 200, version 1 — `cas:0` is create-only and succeeds exactly once (`secrets.go:63-65`). **[observed]** | ESO push with CAS, CLI `kv put -cas=0` | **PARTIAL** — kernel `apply_test.go:329-333` asserts the *rejection* of `cas:0` against an existing secret; the create-only success path over HTTP is a GAP |
| SEC-CAS-02 | secret at version 1 | `PUT M/data/<p>` `{…,"options":{"cas":0}}` | 400 `{"errors":["check-and-set parameter did not match the current version"]}` — the exact Vault string (`secrets.go:64` → `handler.go:847-849`). **[observed]** | ESO (string-matches / surfaces the message), CLI, hvac | **PARTIAL** — kernel-level at `apply_test.go:329-333`; the **status code and error string over HTTP** are a GAP |
| SEC-CAS-03 | secret at version 2 | `PUT M/data/<p>` `{…,"options":{"cas":2}}` | 200, version 3 (`secrets.go:63-65`). **[observed]** | ESO push (`current_version` read → CAS write, E-06:85) | **PARTIAL** — `apply_test.go:325-328` |
| SEC-CAS-04 | secret at version 2 | `PUT M/data/<p>` `{…,"options":{"cas":1}}` | 400 with the same error string; **no version is created** — `current_version` is still 2 afterwards. | ESO (lost-update prevention) | **PARTIAL** — `apply_test.go:321-324` asserts the rejection but not that the version counter is unmoved |
| SEC-CAS-05 | `cas_required:true` on the path | `PUT M/data/<p>` `{"data":{…}}` with no `options` | 400 `{"errors":["check-and-set parameter required for this call"]}` — the exact Vault string (`secrets.go:60-62`). | ops enforcing safe rotation | **PARTIAL** — kernel `secrets_test.go:188-201`; HTTP status/string a GAP |
| SEC-CAS-06 | secret at version 1, N=8 concurrent clients | 8 simultaneous `PUT M/data/<p>` all with `"cas":1` | **Exactly one** returns 200; the other seven return 400 with the mismatch string. CAS is decided inside `Apply`, the serialized single writer, so two proposals cannot both pass (`secrets.go:58-65`, `fsm.go:59-75`). **[observed: 1 of 8 accepted]** | ESO with multiple replicas; any rotation script | **GAP** — this is the property CAS exists for and nothing asserts it |
| SEC-CAS-07 | P0-P3 | `PUT M/data/<p>` `{…,"options":{"cas":"1"}}` (CAS as a **string**) | 400 `{"errors":["malformed request body"]}` — unlike `versions`, `options.cas` accepts numbers only (`handler.go:834-836`). Pin it so the asymmetry with `versionList` is deliberate. **[observed]** | curl/ops | **GAP** — see Q5 |

## 5. max_versions trimming

| ID | Preconditions | Request | Expected observable result | Depended on by | Covered? |
|---|---|---|---|---|---|
| SEC-TRIM-01 | fresh path, no metadata written | 11 writes | `max_versions` defaults to **10** (`model.go:147`, `secrets.go:49-53`), so after write 11 exactly 10 versions remain and version 1 is gone. | ops carrying Vault intuitions over | **GAP** — the default is only exercised indirectly |
| SEC-TRIM-02 | `max_versions:3`, then 5 writes | `GET M/metadata/<p>` | 200; exactly 3 entries in `versions`; `current_version:5`; `oldest_version:3` (`secrets.go:84-96`). | CLI, ops | **PARTIAL** — kernel `secrets_test.go:139-161`; the **HTTP metadata body** after trimming is a GAP |
| SEC-TRIM-03 | as SEC-TRIM-02 | `GET M/data/<p>?version=1` | 404 `{"errors":[]}` — a trimmed version's data record is deleted, not hidden (`secrets.go:90-93`). **[observed]** | ops (the storage bound is real) | **PARTIAL** — `secrets_test.go:155-157`, kernel level only |
| SEC-TRIM-04 | as SEC-TRIM-02 | `GET M/data/<p>` | 200 — the current version is never trimmed. | all | **PARTIAL** — `secrets_test.go:158-160` |
| SEC-TRIM-05 | `max_versions:1` | 2 writes | Exactly one version survives; boundary case for the `>` in the trim loop (`secrets.go:85`). | ops | **GAP** |
| SEC-TRIM-06 | `max_versions:2`, versions 1,2 with **1 destroyed** | one more write | The destroyed version's tombstone counts toward the ceiling (`liveVersions` returns *all* map entries, `secrets.go:198-205`) and is the thing trimmed. Assert whichever semantics is intended — the helper's name says "live" and its body says "all". | ops | **GAP** — see Q6 |
| SEC-TRIM-07 | `max_versions:10`, 5 versions written | `PUT M/metadata/<p>` `{"max_versions":2}` | 204; **history is not retroactively trimmed** — the ceiling applies on the next write only (`secrets.go:84-96` runs inside `applyPutSecret`). Matches Vault. **[observed]** | ops | **GAP** |
| SEC-TRIM-08 | after any trim | `GET M/metadata/<p>` | `oldest_version` tracks the lowest surviving version and never goes stale (`secrets.go:94`). | ESO, CLI | **PARTIAL** — `secrets_test.go:152-154` |

## 6. Listing

| ID | Preconditions | Request | Expected observable result | Depended on by | Covered? |
|---|---|---|---|---|---|
| SEC-LIST-01 | secrets under `cluster-svc/apps/` and `cluster-svc/platform/` | `GET M/metadata/cluster-svc?list=true` | 200; `data.keys` = `["apps/","platform/"]` — immediate children only, directories with a **trailing slash** (`secrets.go:219-241`). | ESO `GetAllSecrets`/find, CLI `kv list` | **PARTIAL** — kernel `secrets_test.go:203-244`; not over HTTP |
| SEC-LIST-02 | as above | `GET M/metadata/cluster-svc/?list=true` (**trailing slash** — ESO's literal shape, E-06:86) | Identical result to SEC-LIST-01; `treePath` trims slashes (`handler.go:872-878`). **[observed]** | ESO | **GAP** |
| SEC-LIST-03 | as above | `LIST M/metadata/cluster-svc` (the real LIST verb) | Identical result — both the verb and `?list=true` are routed (`handler.go:104-105`, `:612-616`). **[observed]** | curl users, hvac | **GAP** |
| SEC-LIST-04 | P0-P2 | `GET M/metadata/?list=true` (mount root) | 200 with the top-level children. The root is special-cased because `treePath` refuses an empty path (`handler.go:658-663`). **[observed]** | CLI `kv list <mount>/`, ops | **GAP** |
| SEC-LIST-05 | prefix with no children | `GET M/metadata/nope/?list=true` | **404 `{"errors":[]}`** — an empty list is reported as absent, matching Vault (`kernel.go:301-303`). GoAPI decodes this as `(nil,nil)`. **[observed]** | ESO find, CLI | **GAP** |
| SEC-LIST-06 | siblings `cluster-lab` and `cluster-svc` exist | `GET M/metadata/cluster-svc?list=true` | `cluster-lab` never appears — prefix matching is component-wise, so `/secrets/cluster-svc` does not swallow `/secrets/cluster-svc-2` (`secrets.go:220-222`, `path.go:65-73`). | ESO, security | **PARTIAL** — `secrets_test.go:223-232` (kernel), `apply_test.go:355-358` (scope) |
| SEC-LIST-07 | leaf directory | `GET M/metadata/cluster-svc/apps?list=true` | `data.keys` = `["grafana","litellm"]` — leaves carry **no** trailing slash, and the list is sorted (`secrets.go:239`). | ESO, CLI | **PARTIAL** — `secrets_test.go:234-243` |
| SEC-LIST-08 | a metadata-only path exists (SEC-META-04) | `GET M/metadata/?list=true` | The metadata-only path **is listed** even though `GET .../data/…` on it 404s — the list scans `secret_meta` (`secrets.go:225`). **[observed]** | ESO find (it will then read and get NoSecret) | **GAP** |

## 7. Error, status and envelope shapes

These are the rows where a wrong *type* — not a wrong value — breaks a real
client. E-06:41-63 and `docs/07-dialect-roadmap.md:24-29` are the source.

| ID | Preconditions | Request | Expected observable result | Depended on by | Covered? |
|---|---|---|---|---|---|
| SEC-ERR-01 | P0-P3 | `GET M/data/nope/missing` | **404 with `{"errors":[]}` — an EMPTY array.** This exact shape is what GoAPI maps to "no secret, no error", which drives ESO's entire absent-secret path (`handler.go:585-590`). | ESO (the load-bearing one) | **COVERED** `handler_test.go:126-135` |
| SEC-ERR-02 | P0-P3 | any 200 response | The envelope always carries `request_id`,`lease_id`,`renewable`,`lease_duration`,`data`,`wrap_info`,`warnings`,`auth` (`handler.go:899-910`), and `Content-Type: application/json` (`handler.go:912-916`). | GoAPI decode, hvac | **GAP** — no test asserts the envelope keys or the content type |
| SEC-ERR-03 | P0-P3 | any error response | Body is exactly `{"errors":[<strings>]}` — never bare text, never an object (`handler.go:918-920`). | GoAPI `ResponseError`, hvac exception mapping | **PARTIAL** — implied by SEC-ERR-01; the non-empty-errors form is unasserted |
| SEC-ERR-04 | P0-P3 | `GET M/data/<p>` with **no** token | 403 `{"errors":["permission denied"]}` (`handler.go:566-569`). | ESO `Validate()`, CLI | **COVERED** `handler_test.go:235-237` |
| SEC-ERR-05 | P0-P3 | `GET M/data/<p>` with a syntactically valid but unknown token | 403 `{"errors":["permission denied"]}` — indistinguishable from the no-token case (`kernel.go:181-183`). | security | **COVERED** `handler_test.go:238-240` |
| SEC-ERR-06 | session whose `Expiry` has passed | `GET M/data/<p>` | 403 — expiry is evaluated lazily on read, with no sweeper (`kernel.go:189-191`). | ESO token cache reuse | **GAP** |
| SEC-ERR-07 | P0-P3 | `GET /v1/other-mount/data/x` | 404 `{"errors":["no handler for route"]}` — an unserved mount is a routing miss, not a permission question (`handler.go:153`, `:159-161`). **[observed]** | CLI (`403` gets a special hint; `404` means "assume KV v1") | **COVERED (status only)** `handler_test.go:243-245`; the body string is unasserted |
| SEC-ERR-08 | P0-P3 | `GET M/data` and `GET M/data/` (no path) | 404 `{"errors":["no handler for route"]}` — a secret needs a name (`handler.go:571-575`, `:872-878`). **[observed]** | ops | **GAP** |
| SEC-ERR-09 | P0-P3 | `GET M/data/<p>` with `Authorization: Bearer <token>` instead of `X-Vault-Token` | 200 — both header forms are accepted (`handler.go:880-888`). Tier B in E-06:199. **[observed]** | ops, future agents | **GAP** |
| SEC-ERR-10 | P0-P3 | any request carrying `X-Vault-Request: true`, `X-Vault-Namespace: foo`, `X-Vault-Inconsistent: …` | Accepted and ignored; no behaviour change (E-06:48-50). The harness already sends `X-Vault-Request` on every call (`handler_test.go:89`). | all GoAPI clients (sent unconditionally) | **PARTIAL** — `X-Vault-Request` is exercised implicitly; namespace/inconsistent are a GAP |
| SEC-ERR-11 | P0-P3 | any KV request | Response status is never 412 and never a 3xx redirect (E-06:61-62) — the GoAPI retry loop treats 412 as retryable and follows exactly one redirect. | GoAPI | **GAP** |
| SEC-ERR-12 | P0-P3 | `GET /v1/sys/internal/ui/mounts/<mount>/<path>` | 200; `data.path` = `"<mount>/"`, `data.type` = `"kv"`, `data.options.version` = the JSON **string** `"2"` (a number panics the CLI) (`handler.go:457-462`). | CLI — runs this preflight on **every** `kv` subcommand, even with `-mount=` | **COVERED** `handler_test.go:169-193` |
| SEC-ERR-13 | P0-P3 | `GET /v1/sys/internal/ui/mounts/<mount>` (bare mount, no subpath) | 200 with the same body — `mountOf` handles a path with no slash (`handler.go:890-895`). **[observed]** | CLI `kv list <mount>` | **GAP** |
| SEC-ERR-14 | P0-P3 | `GET /v1/sys/internal/ui/mounts/other/x` | 404 `{"errors":["no handler for route"]}` (`handler.go:452-456`). **[observed]** | CLI ("404 → assume KV v1") | **GAP** |
| SEC-ERR-15 | P0-P3 | `GET /v1/sys/internal/ui/mounts/<mount>/x` with **no** token | 403 `{"errors":["permission denied"]}` — the preflight is authenticated (`handler.go:447-451`; E-06:185). **[observed]** | CLI (special error hint on 403) | **GAP** |
| SEC-ERR-16 | P0-P3 | `GET /v1/auth/token/lookup-self` | 200; `data.ttl` a **JSON number**, `data.expire_time` key always present (RFC3339 or null), `data.type` = `"service"` (`handler.go:523-550`). | ESO (`ttl.(json.Number)` unchecked assertion), CLI `login` | **COVERED** `handler_test.go:139-165` |
| SEC-ERR-17 | P0-P3 | `GET /v1/sys/health` | 200; `initialized`/`sealed`/`standby` are JSON **booleans** with real semantics; `version` present (`handler.go:432-445`). | cert-manager (status code), inframonitor (asserts the booleans, E-06:262-268) | **COVERED** `handler_test.go:197-215` |

## 8. Absent vs error vs denied — the three-way distinction

The single most consequential contract in this dialect. Absent must never look
like an error, denied must never look like absent, and neither must ever look
like the other to a *client library*, not just to a human.

| ID | Preconditions | Request | Expected observable result | Depended on by | Covered? |
|---|---|---|---|---|---|
| SEC-ABS-01 | P0-P3 | read a path that has never existed | 404 + `{"errors":[]}` → GoAPI `(nil,nil)` → ESO `NoSecretError`. | ESO | **COVERED** `handler_test.go:126-135` |
| SEC-ABS-02 | secret exists, principal holds **no** binding covering it | `GET M/data/<p>` | **403**, not 404 — the caller must not learn whether the secret exists. Authorization is evaluated *before* existence (`kernel.go:211-224`). | security; ESO surfaces this as a sync error rather than an empty secret | **PARTIAL** — kernel-level at `fsm_test.go:130-136`, HTTP-level via the kind interop `forbidden` ExternalSecret (`test/kind/externalsecret.yaml`, `run.sh` result loop). No unit test. |
| SEC-ABS-03 | path does **not** exist, principal holds no binding covering it | `GET M/data/<p>` | **403** — identical to SEC-ABS-02. A denied read must not become a 404 just because the target is absent, or 404-vs-403 becomes an existence oracle (`kernel.go:211-217` runs first). | security | **GAP** — the oracle test |
| SEC-ABS-04 | secret exists but its only version is soft-deleted | `GET M/data/<p>` | 404 + `{"errors":[]}` — deleted reads exactly like absent (`kernel.go:228-234`). | ESO (treats them identically by design, E-06:53) | **COVERED** `handler_test.go:268-270` |
| SEC-ABS-05 | as SEC-ABS-04 | `GET M/metadata/<p>` | **200** — the history survives a soft delete even though the value does not. Absent-at-`/data` and absent-at-`/metadata` are different questions. **[observed]** | CLI `kv metadata get`, ops recovering a deleted secret | **GAP** |
| SEC-ABS-06 | mount name misspelled in a client config | `GET /v1/wrong-mount/data/<p>` | 404 `{"errors":["no handler for route"]}`. **Note:** because the body carries neither `data` nor `warnings`, GoAPI also decodes *this* as `(nil,nil)` — so a typo'd mount reads to ESO as "secret absent", not as a configuration error. Vault behaves the same way; record it as known-and-accepted rather than discovering it in an incident. | ESO operators | **PARTIAL** — status asserted `handler_test.go:243-245`; the *consequence* is undocumented |

## 9. Authorization

Reserved roles and their verbs: `kv-reader` = read+list, `kv-writer` = +write,
`kv-admin` = +delete, `domain-admin` = everything (`model.go:206-212`). Route →
verb mapping: read/metadata-read/list → `read`/`list` (`kernel.go:211`, `:260`,
`:288`); data write and metadata write → `write` (`kernel.go:343`, `:359`);
soft-delete and undelete → `write`; version **destroy** and whole-secret destroy
→ `delete` (`kernel.go:313-316`, `:331`).

**Observed role matrix** (all cells confirmed by probe against a principal bound
at `/secrets/roles`):

| Route | kv-reader | kv-writer | kv-admin |
|---|---|---|---|
| `GET /data/…` | 200 | 200 | 200 |
| `GET /metadata/…?list=true` | 200 | 200 | 200 |
| `GET /metadata/…` | 200 | 200 | 200 |
| `PUT /data/…` | 403 | 200 | 200 |
| `PUT /metadata/…` | 403 | 204 | 204 |
| `DELETE /data/…` (soft) | 403 | 204 | 204 |
| `PUT /undelete/…` | 403 | 204 | 204 |
| `PUT /destroy/…` (version) | 403 | **403** | 204 |
| `DELETE /metadata/…` (secret) | 403 | **403** | 204 |

| ID | Preconditions | Request | Expected observable result | Depended on by | Covered? |
|---|---|---|---|---|---|
| SEC-AZ-01 | principal holds `kv-reader` at `/secrets/cluster-svc` | read/list/metadata-read inside that scope | 200 | ESO (its production role) | **PARTIAL** — kernel `fsm_test.go:130-133`; HTTP via kind interop |
| SEC-AZ-02 | same | any write, delete, undelete, destroy inside scope | 403 `{"errors":["permission denied"]}` | ESO read-only stores | **GAP** at HTTP level |
| SEC-AZ-03 | principal holds `kv-writer` | `PUT /data`, `PUT /metadata`, `DELETE /data`, `PUT /undelete` | 200/204 | ESO PushSecret | **GAP** |
| SEC-AZ-04 | principal holds `kv-writer` | `PUT /destroy/<p>` and `DELETE /metadata/<p>` | **403** — irreversible destruction is a different authority from replacing a value (`kernel.go:312-316`). This is the security-load-bearing cell of the matrix. **[observed]** | security; also means an ESO PushSecret GC principal needs `kv-admin` for step 2 (see Q7) | **GAP** |
| SEC-AZ-05 | principal holds `kv-admin` | every KV route in scope | 200/204 throughout | ops | **GAP** |
| SEC-AZ-06 | binding scoped at `/secrets/cluster-svc` | read `/secrets/cluster-svc-2/x` | 403 — scopes are component-wise; a sibling is not a child (`path.go:65-73`). | security (E-01 K-4) | **PARTIAL** — `apply_test.go:355-358` (kernel), kind interop `forbidden` case |
| SEC-AZ-07 | binding scoped at `/secrets/cluster-svc` | `GET M/metadata/?list=true` (mount root) | 403 — listing the root needs `list` at `/secrets`, which the binding does not cover (`kernel.go:288-294`, `apply_test.go:356`). Enumeration is its own disclosure. | security | **GAP** |
| SEC-AZ-08 | binding with `NotAfter` in the past | any KV request in scope | 403 — a lapsed JIT grant simply stops being honoured, with no revocation step (`policy.go:71`). | PAM design | **PARTIAL** — `apply_test.go:359-360` (kernel, `HasAuthority` directly) |
| SEC-AZ-09 | binding with `ActivationRequired`, no live activation | any KV request in scope | 403; after a live activation, 200; after expiry, 403 again — re-checked on every call (`policy.go:76-99`). | PAM | **PARTIAL** — `activation_test.go` covers activation state, not the KV route |
| SEC-AZ-10 | ESO's attested workload identity | full kind run: in-scope secret syncs, out-of-scope refused, absent refused, impostor SA refused | 4 ExternalSecrets in the documented end states | ESO, end-to-end | **COVERED** `test/kind/externalsecret.yaml` + `test/kind/run.sh` result loop |
| SEC-AZ-11 | any principal | rotate a secret's value | ESO re-syncs the new value into the Kubernetes Secret within a refresh interval | ESO | **COVERED** `test/kind/run.sh` "live rotation" section |

## 10. Durability, audit and consistency

| ID | Preconditions | Request | Expected observable result | Depended on by | Covered? |
|---|---|---|---|---|---|
| SEC-DUR-01 | secrets written, node restarted | read them back | Values, version numbers and bindings all survive; the version counter does **not** restart or drift (the applied-index watermark exists precisely to stop replay double-counting, `fsm.go:40-46`, and `docs/16` §"a secret's version climbed on every restart" records the bug it fixed). | ops | **PARTIAL** — `fsm_test.go:92-136` asserts read + scope after restart, **not** the version counter |
| SEC-DUR-02 | any accepted or rejected KV op | inspect the audit chain | One audit record per op, carrying `Kind`, `Actor`, `AtSec`, `Subject` = the secret **path**, and `Accepted` — and **never the secret's values** (`apply.go:331-379`, esp. `:365-372`). Rejections are recorded, not dropped (`fsm.go:59-63`). | security, compliance | **GAP** for the KV ops specifically — nothing asserts that a `PutSecret` audit record excludes `Data` |
| SEC-DUR-03 | replay the same op sequence at the same log indices onto a fresh store | compare state | Byte-identical, including secret version history — `Apply` is pure (`apply.go:11-29`). | restore/backup | **COVERED** `apply_test.go:90-129` (`TestApplyIsDeterministicUnderReplay`, whose sequence includes two `PutSecret`s at `:97-98`) |
| SEC-DUR-04 | a rejected op (CAS mismatch, bad path) | inspect buckets before/after | No bucket changed — validation completes before the first write (`secrets.go:41-65`, `apply.go:27-29`). | correctness | **COVERED** `apply_test.go:276-306` (`TestRejectedOpWritesNothing`) |
| SEC-DUR-05 | non-leader node | any KV write | Currently surfaces as **400** with the raft error text (`node.go:173-175` → `handler.go:766-767`). Vault returns 503/standby. Decide and pin. | GoAPI retry loop (retries 5xx, not 400) | **GAP** — see Q8 |

---

## Summary of coverage

| Area | Scenarios | Covered | Partial | Gap |
|---|---|---|---|---|
| 1. Read/write (`SEC-RW-*`) | 14 | 1 | 3 | 10 |
| 2. Delete/undelete/destroy (`SEC-VER-*`) | 18 | 3 | 7 | 8 |
| 3. Metadata (`SEC-META-*`) | 9 | 0 | 1 | 8 |
| 4. CAS (`SEC-CAS-*`) | 7 | 0 | 5 | 2 |
| 5. max_versions (`SEC-TRIM-*`) | 8 | 0 | 4 | 4 |
| 6. List (`SEC-LIST-*`) | 8 | 0 | 3 | 5 |
| 7. Error/envelope shapes (`SEC-ERR-*`) | 17 | 7 | 2 | 8 |
| 8. Absent vs error vs denied (`SEC-ABS-*`) | 6 | 2 | 2 | 2 |
| 9. Authorization (`SEC-AZ-*`) | 11 | 2 | 4 | 5 |
| 10. Durability/audit (`SEC-DUR-*`) | 5 | 2 | 1 | 2 |
| **Total** | **103** | **17** | **32** | **54** |

Seventeen of 103 scenarios are covered; two of those seventeen (`SEC-AZ-10`,
`SEC-AZ-11`) live only in `test/kind/`, which runs by hand against a real
cluster rather than in `make test`.

"Partial" almost always means the same thing: the *semantics* are tested at the
kernel level in `internal/kernel/secrets_test.go`, and the *serialization* — the
status code, the envelope, the field types a client actually parses — is not.
Given that this package's stated purpose is "a pure serializer" whose failures
"only exist in the serialized bytes" (`handler_test.go:23-26`), that is exactly
the wrong side of the boundary to be testing on.

---

## Live bugs found

### B1 — a rejected `versions` list silently acts on the CURRENT version (data loss)

`versionList.UnmarshalJSON` (`handler.go:783-805`) exists specifically to reject
malformed version lists, and its comment says so: *"A destructive call that
quietly no-ops is the worst possible failure here, so this type accepts both
forms and rejects anything else outright."* The handler then throws that
rejection away:

```go
_ = json.NewDecoder(r.Body).Decode(&body) // handler.go:731 — an empty body means "the current version"
```

On a decode error `body.Versions` stays `nil`, and `nil` is the sentinel for
*"act on the current version"* (`secrets.go:114-117`). So a request the type
system correctly refused becomes a request to destroy the live secret.

Observed, all returning **204 success**:

| Request | Effect |
|---|---|
| `PUT M/destroy/<p>` `{"versions":["abc"]}` | current version **destroyed**; read → 404 |
| `PUT M/destroy/<p>` `{"versions":1}` (not an array) | current version **destroyed** |
| `PUT M/delete/<p>` `{` (truncated body) | current version soft-deleted |

`destroy` is irreversible. The existing test at `handler_test.go:253-279`
covers the two *accepted* encodings and never the rejected one, which is why the
guard has been inert since it was written.

**Suggested contract:** a body that is present but undecodable ⇒ 400
`{"errors":["…"]}`, no state change. An absent/empty body ⇒ current version, as
today. The distinction the current code cannot make is *"no versions field"* vs
*"a versions field I refused"*.

### B2 — an ESO metadata push silently clears `cas_required`

`writeMetadata` decodes into a struct whose `CASRequired` is a plain `bool`
(`handler.go:682-686`), so an absent `cas_required` decodes as `false`;
`applyPutSecretMeta` then assigns it unconditionally (`secrets.go:190`) while
`MaxVersions` is protected by a `> 0` guard on the line above
(`secrets.go:187-189`). The result is asymmetric, and the body that triggers it
is the exact body ESO sends (E-06:88):

```
PUT M/metadata/<p>  {"custom_metadata":{"managed-by":"external-secrets"}}
→ 204; GET M/metadata/<p> now reports cas_required:false, max_versions unchanged
```

So an operator sets `cas_required` to force safe rotation on a path, ESO later
tags the path, and the protection quietly disappears — with `max_versions`
surviving right next to it, which is what makes it read as a bug rather than a
policy. Whichever way it is resolved, **B2 and SEC-META-06/SEC-TRIM-06 must be
resolved together**: today `max_versions` is sticky and `cas_required` is not,
and only one of those can be the intended rule.

---

## Top 5 gaps by risk

1. **SEC-VER-* malformed-`versions` rejection (B1).** Irreversible loss of the
   live secret from a request that was already detected as invalid, reported as
   success. Highest severity, lowest cost to test.
2. **SEC-META-07 / cas_required clobbering (B2).** A protection silently
   removed by the primary consumer's normal operation.
3. **SEC-ABS-03 — denied-and-absent must be 403, not 404.** Nothing asserts
   that a caller without authority cannot use the 404-vs-403 split as an
   existence oracle over the whole secret tree. The code is correct today
   (`kernel.go:211-224` authorizes before it looks); only the guard is missing.
4. **SEC-AZ-04 — `kv-writer` must not destroy.** The `write`-vs-`delete` verb
   split (`kernel.go:312-316`) is the only thing standing between "rotate this
   secret" and "erase its history", and no test pins it. A refactor that
   collapsed the two verbs would pass every existing test.
5. **SEC-CAS-06 — concurrent CAS.** CAS exists to prevent lost updates under
   concurrency, and every existing CAS test is sequential. The property holds
   today (1 of 8 concurrent writers accepted), but nothing would notice if the
   check migrated out of `Apply` into the propose path, where it stops being
   serializable (`secrets.go:58-59` explains precisely why it must not).

Runners-up worth naming: SEC-META-01 (the whole `/metadata` read body is
unasserted, and ESO parses four of its fields), SEC-ERR-02 (the envelope keys
themselves), and SEC-DUR-02 (that secret *values* never reach the audit log).

---

## Questions for the maintainer

**Q1 — path grammar vs Vault paths (SEC-RW-13).** Signet applies the SPIFFE
segment grammar to KV paths, so `Apps/Thing` is **400 with a message naming the
offending byte**, where Vault would 404 or accept it. Three sub-questions: (a)
is 400 right, or should an ungrammatical path read as *absent* (404) so an ESO
`remoteRef` typo behaves like a missing secret rather than a hard error? (b)
should the error text echo the path back, given it is emitted pre-authorization?
(c) is there a documented migration story for an existing OpenBao tree that
contains uppercase or otherwise non-conforming paths? I could not find one in
docs 07 or E-06.

**Q2 — `max_versions: 0` cannot be cleared (SEC-META-06).** `secrets.go:187-189`
treats 0 as "unspecified", so a ceiling can be raised or lowered but never
removed. Is unlimited history intentionally unreachable through the API? If so
it belongs in the compat notes; Vault's `max_versions:0` means "fall back to the
mount default", which Signet has no equivalent of.

**Q3 — string-only secret values (SEC-RW-11) and the missing-`data`-key write
(SEC-RW-10).** `map[string]string` (`handler.go:833`, `op.go:141`) makes
`{"data":{"port":8080}}` a 400. That is defensible — but is it the *stated*
compat line? E-06 does not call it out, and hvac/curl users will hit it. Related:
a body with no `data` key currently succeeds and creates a version that reads
back as `data.data: null`, which ESO interprets as "no secret". Should a write
with no `data` field be a 400 instead?

**Q4 — `DELETE /data/<absent>` 404 vs `DELETE /metadata/<absent>` 204
(SEC-VER-15/16).** Both are "delete something that isn't there", and they answer
differently, because one path returns `ErrNotFound` from Apply
(`secrets.go:111-113`) and the other deliberately does not (`secrets.go:157-159`).
Which is the intended contract? Vault 204s both. The 404 is invisible to GoAPI
but not to hvac or curl.

**Q5 — `options.cas` accepts numbers only (SEC-CAS-07)** while `versions`
accepts numbers *and* strings, for the documented reason that the CLI sends
strings. Has anything been observed sending `cas` as a string? If yes it wants
the same tolerant decoder; if no, the asymmetry is fine and should be a comment.

**Q6 — `liveVersions` counts destroyed versions (SEC-TRIM-06).** The helper is
named `liveVersions` but returns every entry in the map including destroyed
tombstones (`secrets.go:198-205`), so destroying old versions does not free
budget under `max_versions` — instead the tombstones get trimmed first. I
believe this matches Vault, but the name asserts the opposite of the behaviour
and I did not want to assume which one is the intent.

**Q7 — ESO PushSecret GC needs two different roles.** ESO's cleanup is
`DELETE /data/<p>` then `DELETE /metadata/<p>` (E-06:89). The first needs
`write`, the second needs `delete` (`kernel.go:313-316`, `:331`), so a
PushSecret-capable ESO principal must hold `kv-admin` — which also grants
version-destroy across the whole scope. Is that the intended operational
guidance, or does the metadata delete want its own verb?

**Q8 — non-leader writes surface as 400 (SEC-DUR-05).** `node.go:173-175` wraps
the raft error and `writeKernelErr`'s default arm turns it into a 400
(`handler.go:766-767`). GoAPI retries 5xx but not 400, so a brief leadership
change becomes an immediate hard failure at the client instead of a retried one.
E-06:61-62 says never redirect and never 412 — but it does not say what a
standby should return. 503 seems right; confirm before this is pinned in tests.

**Q9 — the `handler_test.go:241-242` comment.** It says clients "branch
differently" on 403 vs 404 for a wrong mount. True for the CLI, but GoAPI
decodes *any* 404 lacking `data`/`warnings` as `(nil,nil)` — so for ESO a
misspelled mount is indistinguishable from an absent secret (SEC-ABS-06). Worth
recording as accepted Vault-inherited behaviour rather than leaving the comment
implying otherwise.

**Q10 — tree-prefix mapping.** `docs/07-dialect-roadmap.md:30-36` describes the
KV mapping as `<mount>/cluster-svc/apps/litellm` → `/clusters/svc/secrets/apps/litellm`,
but the implementation maps flatly to `<TreePrefix>/<rest>` = `/secrets/cluster-svc/apps/litellm`
(`handler.go:872-878`). The tests and the kind fixture use the flat form. Is doc
07 stale, or is the per-cluster form still planned? The answer changes what
SEC-AZ-06's scope boundaries look like.

---

## Notes on how to run these

`make test` / `make build` only — the tree is on NFS without `flock`, so bare
`go test` fails (`Makefile:10` rsyncs to a local-disk mirror; `README`/`docs/16:70`).
The HTTP-level scenarios belong next to `internal/dialect/vaultkv/handler_test.go`
and can reuse its `newServer`/`do` helpers (`:27-97`); the role matrix in §9 needs
one additional helper that mints a session for a principal holding a single
reserved role at a given scope, which the current harness does not expose.
`test/kind/run.sh` remains the release gate for anything that only fails against
a real client.
