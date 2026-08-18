# 08 — Test plan: RBAC / authorization core

**Status: Draft** (written 2026-08-18)
**Area under test:** `internal/kernel/{policy,path,model,apply,kernel}.go`
**Design sources:** [05-authorization](../05-authorization.md),
[13-kernel-data-model](../13-kernel-data-model.md),
[E-01 K-1/K-4](../explorations/E-01-threat-model.md),
[10-testing-strategy](../10-testing-strategy.md)

This is the security heart of Signet: every dialect, every credential, and every
secret read funnels through `HasAuthority` → `ScopeCovers`. A single wrong
`true` here is a domain compromise. The plan below enumerates every supported
scenario, marks what the tree already asserts, and names the gaps.

> **Build constraint.** This tree lives on NFS, which has no `flock`. Never run
> bare `go test` / `go build`. Use `make test` (verified green at the time of
> writing: `internal/kernel` ok, 7.742s) and `make build`.

---

## 0. The code under test, in one page

| Function | File:line | Contract |
|---|---|---|
| `ValidatePath` | [path.go:24-60](../../internal/kernel/path.go) | `/` or absolute; segments `[a-z0-9._-]+`; no `.`/`..`; no empty segment; no trailing slash; ≤1024 bytes; ≤64 segments |
| `ScopeCovers` | [path.go:65-73](../../internal/kernel/path.go) | `scope == "/"` ∨ `scope == path` ∨ `HasPrefix(path, scope+"/")` |
| `LoadBindings` | [policy.go:15-25](../../internal/kernel/policy.go) | prefix scan of `BucketBindings` on `"<subject>/"`; unmarshal failures silently skipped (line 19) |
| `HasAuthority` | [policy.go:33-73](../../internal/kernel/policy.go) | expiry → scope → role-verb → activation, first match wins |
| `roleVerbs` / `roleGrants` | [model.go:206-219](../../internal/kernel/model.go) | 5 roles, 6 verbs |
| `adminRoles` | [model.go:215](../../internal/kernel/model.go) | **declared, never referenced anywhere in the tree** (see D-06) |
| `applyPutBinding` | [apply.go:109-164](../../internal/kernel/apply.go) | scope validity → known role → non-empty ID/subject → subject exists → grantor holds `admin` at scope, *or* bootstrap |
| `bindingsEmpty` | [apply.go:306-313](../../internal/kernel/apply.go) | the bootstrap gate |
| `Kernel.authorize` | [kernel.go:471-485](../../internal/kernel/kernel.go) | wraps `HasAuthority` in a read tx; **does not** call `ValidatePath` |

Three structural facts shape everything below:

1. **`ScopeCovers` never validates its arguments.** Correctness of the algebra
   is entirely conditional on every caller having run `ValidatePath` first. Two
   of the five call sites do not (see D-02, D-03).
2. **There is no `DeleteBinding` / `RevokeBinding` Op.** `Apply`'s dispatch
   ([apply.go:30-75](../../internal/kernel/apply.go)) has no case for one, and
   `internal/op/op.go` defines none. A binding, once written, is permanent.
   This makes the *additivity* invariant named in
   [docs/10:12](../10-testing-strategy.md) ("removing a binding never adds
   rights") currently unexercisable, and leaves docs/13 F4's `--revoke-grants`
   cascade ([13:131](../13-kernel-data-model.md)) without a mechanism.
3. **`applyPutPrincipal` performs no authorization at all**
   ([apply.go:77-107](../../internal/kernel/apply.go)) and `Kernel.PutPrincipal`
   ([kernel.go:373-385](../../internal/kernel/kernel.go)) adds none. It is the
   only mutating admin-plane Op with no grantor check. See D-01.

### Fixtures assumed by every scenario

```
D0  empty domain (no principals, no bindings)
D1  D0 + principal root  @ /people/root      + grantorless binding domain-admin @ "/"
D2  D1 + principal lab   @ /people/labadmin  + binding domain-admin @ /clusters/lab   (grantor root)
D3  D2 + principal vic   @ /people/victim    (no bindings)
D4  D2 + principal peer  @ /people/peer      + binding domain-admin @ /clusters/lab-2 (grantor root)
D5  D1 + principal rdr   @ /people/reader    + binding kv-reader    @ /secrets/lab    (grantor root)
```

`bootstrap(t, s)` in [apply_test.go:79-84](../../internal/kernel/apply_test.go)
already builds D1. Fixtures D2–D5 should be helpers alongside it.

---

## A. Path grammar — `ValidatePath` (SP-01 … SP-30)

Preconditions: none; `ValidatePath` is pure. Input is the single string
argument. "Accept" = returns `nil`.

| ID | Input | Expected | Rationale | Coverage |
|---|---|---|---|---|
| SP-01 | `"/"` | accept | domain root, path.go:34 | COVERED [path_test.go:7](../../internal/kernel/path_test.go) |
| SP-02 | `"/people/mcarey"` | accept | ordinary | COVERED path_test.go:7 |
| SP-03 | `"/clusters/svc/apps/eso"` | accept | depth 4 | COVERED path_test.go:7 |
| SP-04 | `"/a.b_c-d/e"` | accept | full byte class in one segment | COVERED path_test.go:8 |
| SP-05 | `"/0/9z/z0"` | accept | digits, digit-leading segments | GAP |
| SP-06 | `"/..."` | **accept** | 3+ dots is not `.` or `..` (path.go:48) | GAP — and see Q-1 |
| SP-07 | `"/.a"`, `"/a."` | **accept** | leading/trailing dot | GAP — see Q-1 |
| SP-08 | `"/-"`, `"/_"`, `"/-a"` | **accept** | leading hyphen/underscore | GAP — see Q-2 |
| SP-09 | `""` | reject, `errors.Is(err, ErrEmptyPath)` | sentinel is exported (path.go:20) so callers can branch on it | GAP (path_test.go:31 asserts non-nil only) |
| SP-10 | `"people/mcarey"` | reject "must be absolute" | path.go:28 | COVERED path_test.go:18 |
| SP-11 | `" /a"` | reject "must be absolute" | leading space must not be trimmed | GAP |
| SP-12 | `"/people/"` | reject trailing slash | path.go:37 | COVERED path_test.go:19 |
| SP-13 | `"//"` | reject | falls to the trailing-slash arm, not the empty-segment arm | GAP |
| SP-14 | `"/people//mcarey"` | reject empty segment | path.go:45 | COVERED path_test.go:20 |
| SP-15 | `"/people/."` | reject relative segment | path.go:48 | COVERED path_test.go:21 |
| SP-16 | `"/people/../root"` | reject relative segment | path.go:48 | COVERED path_test.go:22 |
| SP-17 | `"/../a"` | reject | `..` in first position | GAP |
| SP-18 | `"/People/Mcarey"` | reject illegal byte | case-confusable (docs/13:55) | COVERED path_test.go:23 |
| SP-19 | `"/people/andré"` (NFC) | reject illegal byte | unicode-confusable | COVERED path_test.go:24 |
| SP-20 | `"/people/andré"` (NFD) | reject illegal byte | the *other* normalization of SP-19 must also be rejected, so no normalizer is ever needed | GAP |
| SP-21 | `"/people/has space"` | reject | path_test.go:25 | COVERED |
| SP-22 | `"/people/semi;colon"` | reject | path_test.go:26 | COVERED |
| SP-23 | `"/people/tab\tchar"` | reject | path_test.go:27 | COVERED |
| SP-24 | `"/people/star*"` | reject | path_test.go:28 | COVERED |
| SP-25 | `"/a\nb"`, `"/a\rb"` | reject | CR/LF would be log/audit injection into `AuditRecord.Subject` (apply.go:364) | GAP |
| SP-26 | `"/a\x00b"` | reject | NUL truncation in any C consumer / SPIFFE SAN | GAP |
| SP-27 | `"/%41"`, `"/%2e%2e"` | reject illegal byte `%` | no percent-decoding anywhere; two encodings must never denote one node | GAP |
| SP-28 | valid path of exactly 1024 bytes / exactly 1025 | accept / reject | boundary of `len(p) > MaxPathLen` (path.go:31) | GAP |
| SP-29 | valid path of exactly 64 segments / 65 | accept / reject | boundary of `len(segs) > MaxPathDepth` (path.go:41) | GAP |
| SP-30 | 5000-byte *relative* path | reject "must be absolute" (not the length error) | pins check order: absolute (line 28) precedes length (line 31) | GAP |

**Section A: 30 scenarios, 15 covered, 15 GAP.**

---

## B. Scope algebra — `ScopeCovers` (SC-01 … SC-32)

This is the section that decides whether Signet is a security product. It is
split into B.1 (both arguments valid — the supported contract) and B.2 (one
argument invalid — the failure modes that reach `ScopeCovers` because it does
not validate).

### B.1 — Both arguments pass `ValidatePath`

| ID | scope | path | Expected | Rationale | Coverage |
|---|---|---|---|---|---|
| SC-01 | `/` | `/` | true | root covers itself | COVERED [path_test.go:43](../../internal/kernel/path_test.go) |
| SC-02 | `/` | `/anything/at/all` | true | root covers everything | COVERED path_test.go:42 |
| SC-03 | `/clusters/lab` | `/clusters/lab` | true | exact match (reflexivity) | COVERED path_test.go:44 |
| SC-04 | `/clusters/lab` | `/clusters/lab/apps/runner` | true | inherits downward, 2 levels | COVERED path_test.go:45 |
| SC-05 | `/clusters/lab` | `/clusters/lab-2` | false | **the prefix-as-substring bug**, E-01 K-4 | COVERED path_test.go:47 |
| SC-06 | `/clusters/lab` | `/clusters/lab-2/apps/x` | false | same, with descent | COVERED path_test.go:48 |
| SC-07 | `/clusters/lab` | `/clusters` | false | parent is not covered by child | COVERED path_test.go:49 |
| SC-08 | `/clusters/lab/apps` | `/clusters/lab` | false | grandparent | COVERED path_test.go:50 |
| SC-09 | `/secrets/a` | `/secrets/ab` | false | 1-byte mid-component extension | COVERED path_test.go:51 |
| SC-10 | `/clusters/lab` | `/` | false | nothing but `/` covers `/` | GAP |
| SC-11 | `/a` | `/b` | false | disjoint siblings, no shared prefix | GAP |
| SC-12 | `/a/b` | `/a/c` | false | siblings at depth | GAP |
| SC-13 | `/a` | `/a.b` | false | `.` is *inside* the byte class — a boundary-looking byte that is not a boundary | GAP |
| SC-14 | `/a` | `/a_b` | false | same for `_` | GAP |
| SC-15 | `/a` | `/a-b` | false | same for `-`, minimal form of SC-05 | GAP |
| SC-16 | `/a` | `/a.` | false | trailing-dot sibling (valid path per SP-07) | GAP |
| SC-17 | `/secrets/appdata` | `/secrets/app` | false | longer scope, shorter path, shared mid-component prefix | GAP |
| SC-18 | `/secrets/app` | `/secrets/appdata` | false | the reverse | GAP |
| SC-19 | `/a` | `/a/b/c/d/e/f` | true | deep descent | GAP |
| SC-20 | depth-64 scope; identical depth-64 path / same but last segment differs | true / false | correctness at the depth ceiling | GAP |
| SC-21 | 1024-byte scope; identical 1024-byte path | true | correctness at the length ceiling (no truncating compare) | GAP |
| SC-22 | `/A` vs `/a`, and `/a` vs `/A/b` | false, false | case-sensitivity is deny-by-default even though `ValidatePath` would reject both | GAP |
| SC-23 | `/café` NFC vs `/café` NFD (raw bytes) | false in both directions | no normalization is performed, so the two byte strings are two nodes | GAP |
| SC-24 | `/a` | `/%61/b` | false | percent-encoding does not alias | GAP |

### B.2 — Unvalidated argument (the defect surface)

`ScopeCovers` is exported and is called from five places
([policy.go:43](../../internal/kernel/policy.go),
[issue.go:216](../../internal/kernel/issue.go), and three test sites). Its
`scope` argument is always a stored `Binding.Scope` (validated at write). Its
`path` argument is validated by every `Kernel` secrets method
(kernel.go:206/255/283/309/328/340/356) but **not** by `Kernel.Authorize` /
`Kernel.AuthorizeSign` ([pki.go:361-370](../../internal/kernel/pki.go)) and not
by `HasAuthority` itself.

| ID | scope | path | Actual today | Expected | Coverage |
|---|---|---|---|---|---|
| SC-25 | `""` | `/anything/at/all` | **`true`** | **`false`** | GAP — **D-02, the headline defect** |
| SC-26 | `""` | `""` | **`true`** (equality arm) | `false` | GAP — D-02 |
| SC-27 | `/` | `""` | **`true`** (root arm short-circuits before looking at `path`) | `false` | GAP — D-02 |
| SC-28 | `/` | `"relative/path"` | **`true`** | `false` | GAP — D-02 |
| SC-29 | `/a` | `/a/` | `true` | `false` (or: reject at the door) | GAP — D-03 |
| SC-30 | `/a` | `/a//b` | `true` | `false` | GAP — D-03 |
| SC-31 | `/a` | `/a/../../b` | **`true`** | `false` — a scope escape for any caller that uses `path` after the check | GAP — **D-03** |
| SC-32 | `/a` | `"/a\x00/b"` | `true` | `false` | GAP — D-03 |

**Section B: 32 scenarios, 9 covered, 23 GAP.**

**Conclusion of the exhaustive attack.** For inputs where *both* arguments pass
`ValidatePath`, I could construct no pair on which `ScopeCovers` returns `true`
incorrectly. Given a validated `scope` (no trailing slash, no empty segments)
and a validated `path`, `HasPrefix(path, scope+"/")` implies
`path == scope + "/" + rest` with `rest` non-empty and containing no empty
segment, which is exactly the component-wise prefix relation. The algebra is
correct **conditionally**. Every way to break it runs through an unvalidated
argument, which is why B.2 exists and why D-02/D-03 are rated as they are.

---

## C. Role → verb matrix (RV-01 … RV-38)

The full cross-product of [model.go:206-212](../../internal/kernel/model.go)
against the six verbs at [model.go:192-201](../../internal/kernel/model.go).
Preconditions: D1 + a principal holding exactly the row's role at `/x`; input
`HasAuthority(subject, verb, "/x", now)` with no expiry and no activation.

| ID | role | read | list | write | delete | admin | sign |
|---|---|---|---|---|---|---|---|
| RV-01…06 | `kv-reader` | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ |
| RV-07…12 | `kv-writer` | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| RV-13…18 | `kv-admin` | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| RV-19…24 | `pki-signer` | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| RV-25…30 | `domain-admin` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

Existing coverage of the 30 cells: `kv-reader`/read allow
([apply_test.go:359-360](../../internal/kernel/apply_test.go),
[activation_test.go:408](../../internal/kernel/activation_test.go)),
`kv-reader`/write deny (apply_test.go:361, activation_test.go:411),
`kv-writer`/write allow (activation_test.go:69). **4 of 30 cells asserted; 26
GAP.** A single table-driven test closes all 30 and is the cheapest high-value
work in this plan.

Structural invariants over the role table — these are the ones that survive
someone adding a sixth role:

| ID | Assertion | Why it matters | Coverage |
|---|---|---|---|
| RV-31 | `roleGrants("not-a-role", v)` is false ∀v | nil-map indexing must not become an allow | GAP |
| RV-32 | `roleGrants("", v)` is false ∀v | a binding with an empty role can only arrive via a corrupted store, but must be inert | GAP |
| RV-33 | `KnownRole(r)` ⇔ `r ∈ keys(roleVerbs)` | the write-time gate (apply.go:113) and the eval-time table must not drift | GAP |
| RV-34 | no `kv-*` role grants `VerbSign` | signing an identity is not writing a secret (model.go:198-200); `pki.go:182` gates issuance on `VerbSign` alone | GAP |
| RV-35 | no role outside `adminRoles` grants `VerbAdmin` | `VerbAdmin` *is* the delegation gate (apply.go:140); a new role that grants it silently becomes a granting role | GAP |
| RV-36 | ∀ `a ∈ adminRoles`, ∀ `q ∈ roleVerbs`: `verbs(q) ⊆ verbs(a)` | **the "grant a role stronger than yourself" guard.** `applyPutBinding` checks only that the grantor holds `admin` at the scope — it never compares verb sets. Today that is safe *only because* `domain-admin` is the sole admin role and holds every verb. A narrow admin role (say `pki-admin: {admin, sign}`) would immediately be able to grant `kv-admin`'s `delete`, which it does not hold | GAP — **D-05** |
| RV-37 | `adminRoles == {r : VerbAdmin ∈ verbs(r)}` | `adminRoles` is dead code (see D-06); this test is what makes the comment at model.go:214 true | GAP |
| RV-38 | `keys(roleVerbs)` is exactly the five roles named in [docs/13:236-239](../13-kernel-data-model.md) | doc/code drift on the reserved role set | GAP |

**Section C: 38 scenarios, 4 covered, 34 GAP.**

---

## D. `HasAuthority` composition (HA-01 … HA-20)

Preconditions as stated; input `HasAuthority(tx, subject, verb, path, nowSec)`.

| ID | Precondition | Input | Expected | Coverage |
|---|---|---|---|---|
| HA-01 | D3 (principal `vic`, no bindings) | any verb, any path | `false, nil` | GAP |
| HA-02 | D1 | subject `"no-such-id"` | `false, nil` (absence is denial, not an error) | GAP |
| HA-03 | D1 + `kv-reader@/s` + `pki-signer@/s` on one subject | read@/s, sign@/s | both `true` — rights are the **union** (docs/13:100) | GAP |
| HA-04 | as HA-03, with binding IDs chosen so scan order puts the non-matching one first | read@/s | `true` — the loop must not stop at the first non-match | GAP |
| HA-05 | D5, `NotAfter == 0` | read@/secrets/lab/app, now=1500 | `true` — 0 means no expiry (model.go:27) | COVERED apply_test.go:359 |
| HA-06 | binding with `NotAfter = 2000` | now = **2000** exactly | `false` — policy.go:40 is `>=`, so authority ends *at* T, not after it | GAP (boundary; apply_test.go:365 tests 2001) |
| HA-07 | same | now = **1999** | `true` | GAP (boundary; apply_test.go:364 tests 1500) |
| HA-08 | D2; `PutBinding` with `NotAfter` already in the past at `AtSec` | the write, then a check | write **accepted** today, authority never granted | GAP — see Q-6 |
| HA-09 | binding with `NotAfter = -1` | now = 0 | `false` (`0 >= -1`) | GAP |
| HA-10 | binding with `NotAfter = 0` | now = 0 and now = -1 | `true` both — `NotAfter==0` is "none", not "expired at epoch" | GAP |
| HA-11 | binding `ActivationRequired`, no activation | write@scope | `false` — eligibility ≠ possession (docs/13:196) | COVERED [activation_test.go:69](../../internal/kernel/activation_test.go) |
| HA-12 | + live activation | write@scope | `true` | COVERED activation_test.go:80 |
| HA-13 | + activation past `Expiry` | write@scope | `false` | COVERED activation_test.go:89 |
| HA-14 | two `ActivationRequired` bindings B1, B2; activation live for B1 only | verb only B2 grants | `false` — policy.go:67 matches on `a.Binding == b.ID` | GAP |
| HA-15 | activation in `pending` / `killed` | | `false` | COVERED activation_test.go:198 / :293 |
| HA-15b | activation in `denied` | | `false` | GAP |
| HA-16 | activation whose `Role`/`Scope` fields differ from the binding's | | the *binding's* role and scope govern; the activation's copies are display metadata only (model.go:73-74) | GAP |
| HA-17 | a `BucketBindings` value that is not valid JSON | any | binding silently skipped ([policy.go:19](../../internal/kernel/policy.go)); fails **closed** but silently | GAP — see Q-7 |
| HA-18 | principal `A` and principal `A/b`, each with a binding | `HasAuthority(A, …)` | must **not** see `A/b`'s bindings. `bindingKey` is `subject + "/" + id` (model.go:233) and `LoadBindings` prefix-scans `subject + "/"` (policy.go:17), so `A/b`'s key `A/b/<id>` falls inside `A`'s scan | GAP — see D-07 |
| HA-19 | store returns an error mid-scan | any | `(false, err)` — never `(true, err)` | GAP |
| HA-20 | D5 | read@`/secrets/lab` (the scope node itself) | `true` | COVERED apply_test.go:360 |

**Section D: 21 scenarios, 6 covered, 15 GAP.**

---

## E. Delegation only narrows, on binding creation (DN-01 … DN-23)

All scenarios: `Apply(tx, &op.PutBinding{...})`; "denied" means
`res.Err != nil` **and** no write occurred (the
[apply.go:29](../../internal/kernel/apply.go) all-validation-before-first-write
contract, spot-checked by
[apply_test.go:276-306](../../internal/kernel/apply_test.go)).

| ID | Precondition | Grantor / Scope / Role | Expected | Coverage |
|---|---|---|---|---|
| DN-01 | D1 | root, `/`, any role | accept | COVERED apply_test.go:82, :137 |
| DN-02 | D3 | lab, `/clusters/lab` | accept (equal scope) | COVERED apply_test.go:131-175 |
| DN-03 | D3 | lab, `/clusters/lab/apps/x` | accept (narrower) | COVERED apply_test.go:131-175 |
| DN-04 | D3 | lab, `/clusters` | deny (wider) | COVERED apply_test.go:131-175 |
| DN-05 | D4 | lab, `/clusters/lab-2` | deny (sibling — the substring trap at write time) | COVERED apply_test.go:131-175 |
| DN-06 | D3 | lab, `/` | deny | COVERED apply_test.go:131-175 |
| DN-07 | D1 + a principal holding **`kv-admin`@`/x`** | that principal, `/x`, `kv-reader` | **deny** — `kv-admin` has `delete` but not `admin` (model.go:209), so it is not a granting role | GAP |
| DN-08 | D1 + a principal whose `domain-admin`@`/x` binding has `ActivationRequired: true` and no live activation | that principal, `/x` | **deny** — eligibility to administer is not the power to grant. `HasAuthority` handles this at policy.go:49, but nothing asserts it for the *grant* path | GAP |
| DN-09 | D2 with lab's binding carrying `NotAfter = 2000` | lab, `/clusters/lab`, `AtSec = 2000` | deny — an expired admin cannot delegate | GAP |
| DN-10 | D2 | grantor `lab`, **subject `lab`**, `/clusters/lab`, `domain-admin`, `NotAfter: 0` | **accepted today.** If lab's own binding carries `NotAfter = T`, lab can self-grant an identical *non-expiring* binding before T — "JIT laundering" | GAP — **D-04**, Q-4 |
| DN-11 | D2 | grantor `lab`, subject `lab`, `/clusters` | deny | GAP |
| DN-12 | D3 | grantor `"ghost-id"` (no principal, no bindings) | deny — `HasAuthority` finds nothing | GAP (apply_test.go:287 covers a ghost *subject*, not a ghost *grantor*) |
| DN-13 | D1 | subject `"ghost"` | deny "subject does not exist" (apply.go:122) | COVERED apply_test.go:287 |
| DN-14 | D1 | role `"not-a-role"` | deny (apply.go:114) | COVERED apply_test.go:288 |
| DN-15 | D2 | scope ∈ {`/People/X`, `/a//b`, `/a/../b`, `/a/`, `a/b`, 65 segments, 1025 bytes} | deny at apply.go:110, **before** the grantor check | GAP (one sub-case per invalid form) |
| DN-16 | D2 | scope `""` | deny — this single check (apply.go:110 → path.go:21) is the only thing keeping SC-25 unreachable. It must be regression-locked explicitly, not incidentally | GAP — **D-02** |
| DN-17 | D2 | `ID: ""` | deny (apply.go:117) | GAP |
| DN-18 | D2 | `Subject: ""` | deny (apply.go:117) | GAP |
| DN-19 | D2 with lab's binding `NotAfter = 2000` | same Op applied with `AtSec = 1000` at wall-clock 3000 | accept — the verdict is a function of `o.AtSec` only (apply.go:140), never of a clock. Replay-determinism | GAP (implied by apply_test.go:90 but not asserted for authorization) |
| DN-20 | D2, a binding already written with ID `X` | same ID `X`, different role/scope | accepted, overwrites (`tx.Put`, apply.go:160). No prior-existence check | GAP — Q-8 |
| DN-21 | D2 | lab grants each of the 5 roles at `/clusters/lab` | all accept, since `domain-admin` ⊇ every role | GAP (the meaningful assertion is RV-36) |
| DN-22 | D1 → A@`/a` → B@`/a/b` → C@`/a/b/c` (three-hop chain) | C grants at `/a/b` | deny; and no reachable state lets C hold anything outside `/a/b/c` | GAP — **the property test is single-hop only** |
| DN-23 | D2, lab's binding has `NotAfter = 2000` | lab grants `vic` a binding with `NotAfter = 9999` (or 0) | accepted today — the grant outlives the grantor's own authority | GAP — Q-4 |

**Section E: 23 scenarios, 8 covered, 15 GAP.**

> **Methodological defect in the existing flagship test.**
> [apply_test.go:169](../../internal/kernel/apply_test.go) computes its
> expectation as `wantAllowed := ScopeCovers(delegated, scope)` — the function
> under test is its own oracle. `TestDelegationOnlyNarrows` therefore **cannot
> detect any `ScopeCovers` bug**; it only proves that `applyPutBinding` agrees
> with `ScopeCovers`, whatever `ScopeCovers` happens to do. It also never emits
> an invalid path, so the apply.go:110 validation arm is never taken. PROP-04
> and PROP-07 below replace the oracle with an independent segment-prefix
> reference implementation.

---

## F. Bootstrap exception (BS-01 … BS-10)

The grantorless door is `o.Grantor == "" && bindingsEmpty(tx)`
([apply.go:131-138](../../internal/kernel/apply.go)), plus a second copy in
`requireDomainAuthority` ([apply.go:276-286](../../internal/kernel/apply.go))
used by `PutIssuer` and `PutRolePolicy`.

| ID | Precondition | Input | Expected | Coverage |
|---|---|---|---|---|
| BS-01 | D0 | `PutBinding{Grantor: "", Scope: "/", Role: "domain-admin"}` | accept | COVERED apply_test.go:82 |
| BS-02 | D1 | a second `PutBinding{Grantor: ""}`, any subject/scope | deny (apply.go:137) | COVERED apply_test.go:260-272 |
| BS-03 | D0, then a **rejected** `PutBinding` (e.g. unknown role) | `PutBinding{Grantor: "", Scope: "/"}` | accept — a rejected Op leaves the bucket empty, so it must not consume the bootstrap window | GAP |
| BS-04 | D0 | `PutBinding{Grantor: "", Scope: "/clusters/lab"}` | **accepted today.** The domain now has no `/`-admin, and BS-02 forbids a second grantorless binding — the domain is permanently wedged | GAP — Q-3 |
| BS-05 | D0 | `PutBinding{Grantor: "", Scope: "/", ActivationRequired: true}` | **accepted today.** Nobody holds admin, and approving an activation requires admin at the scope (activation.go:287) — deadlock | GAP — Q-3 |
| BS-06 | D0 | `PutBinding{Grantor: "", Role: "kv-reader", Scope: "/"}` | **accepted today** → wedged | GAP — Q-3 |
| BS-07 | D0 | `PutBinding{Grantor: "", Scope: "/", NotAfter: AtSec - 1}` | **accepted today** → wedged the instant it is written | GAP — Q-3 |
| BS-08 | D1 (root's binding exists) | grantorless binding for a **different** subject | deny — `bindingsEmpty` scans the whole bucket with prefix `""` (apply.go:308), not per-subject | GAP |
| BS-09 | D1 | `PutIssuer{Grantor: ""}` / `PutRolePolicy{Grantor: ""}` | deny — the second bootstrap door closes on the same gate | GAP |
| BS-10 | D0 + principals but still no bindings | `PutIssuer{Grantor: ""}`, then `PutRolePolicy{Grantor: "", MinTier: 1}` for a tier-4 role | **accepted today** — trust anchors and role security floors can be set with no grantor as long as no binding exists yet | GAP — Q-3 |

**Section F: 10 scenarios, 2 covered, 8 GAP.**

---

## G. Privilege-escalation attempts (PE-01 … PE-24)

| ID | Attack | Expected | Coverage |
|---|---|---|---|
| PE-01 | Admin at `/clusters/lab` grants at `/clusters` | deny | COVERED (= DN-04) |
| PE-02 | …grants at `/` | deny | COVERED (= DN-06) |
| PE-03 | Grantor grants a role whose verb set exceeds their own | structurally impossible today; must stay so | GAP (= RV-36) — **D-05** |
| PE-04 | Self-grant at the same scope | accepted today | GAP — Q-4 |
| PE-05 | Self-grant at a wider scope | deny | COVERED (= DN-04) |
| PE-06 | **JIT laundering**: time-bounded admin self-grants an unbounded equivalent before expiry | accepted today | GAP — **D-04** |
| PE-07 | Grant to a principal that does not exist | deny | COVERED apply_test.go:287 |
| PE-08 | Binding whose scope fails path validation | deny | GAP (= DN-15/16) |
| PE-09 | **ESC1 via mapping rule**: subtree admin maps evidence onto a superior principal | deny | COVERED [apply_test.go:182-225](../../internal/kernel/apply_test.go) |
| PE-10 | **ESC1 via principal rename**: subtree admin issues `PutPrincipal{ID: <root's ID>, Path: "/clusters/lab/pwn"}`, re-homing the root principal into their own subtree, then maps evidence onto it (which now passes the apply.go:251 check) | must deny at the rename | GAP — **D-01, highest-severity finding** |
| PE-11 | Path squatting: create a principal at a path a superior admin intends to use, blocking them (apply.go:91) | should require authority over the path | GAP — D-01 |
| PE-12 | ID collision: `PutPrincipal` with an **existing ID** and a fresh path. Accepted; overwrites the principal record and leaves the old path-index entry dangling, so two paths resolve to one ID | deny, or tombstone the old name | GAP — D-01 |
| PE-13 | `op.ID` containing `/` collides binding keys: `(subject="a", id="b/c")` and `(subject="a/b", id="c")` both key `a/b/c` | IDs must be constrained (hex, no `/`) | GAP — D-07 |
| PE-14 | Approve an activation without admin at the binding's scope | deny | COVERED activation_test.go:206 |
| PE-15 | Approve your own activation request | deny | COVERED activation_test.go:152 |
| PE-16 | Activation widens scope or role | deny | COVERED activation_test.go:401 |
| PE-17 | **PAM bypass at issuance**: hold an `ActivationRequired` binding with no live activation and call `Kernel.Issue`. `filterRoles` ([issue.go:200-231](../../internal/kernel/issue.go)) checks `NotAfter`, `ScopeCovers`, tier, and AMR — but **never `ActivationRequired`** — so the gated role is embedded in an offline JWT/SSH cert | role must be absent | GAP — **D-08, second-highest finding** |
| PE-18 | Subtree admin defines a PKI role scoped outside their subtree (`applyPutPKIRole`, pki.go:75) | deny | GAP (no test exists for pki.go:75) |
| PE-19 | Subtree admin defines an SSH role scoped outside their subtree (pki.go:390) | deny | GAP |
| PE-20 | Subtree admin registers a trust anchor | deny (domain-wide authority, apply.go:210) | COVERED apply_test.go:217-224 |
| PE-21 | Non-root writes a `RolePolicy`, or root lowers a tier-4 role's `MinTier` to 1 (the K-2 downgrade) | first denies (issue.go:59); second is a governance event that must be audited | GAP |
| PE-22 | Dialect calls `Kernel.Authorize(s, verb, path)` with a client-controlled unvalidated `path` (`""`, `/a/../b`) | `Authorize` must validate before evaluating | GAP — **D-03** |
| PE-23 | Revoke a binding | **no Op exists.** Bindings are permanent | GAP — Q-5 |
| PE-24 | Revoking a grantor's admin does not cascade to grants they made (docs/13:124) | binding survives | GAP — untestable until PE-23 exists |

**Section G: 24 scenarios, 8 covered, 16 GAP.**

---

## H. Property-based tests (PROP-01 … PROP-18)

Randomized generation earns its place here because the interesting space is
*pairs of paths from randomly-shaped trees* — a space no hand-written table
samples densely enough. Each property states its invariant precisely.

**Generators.**
`genSegment()` → non-empty string over `[a-z0-9._-]`, length 1–8, biased toward
producing near-misses (`lab`, `lab-2`, `lab.2`, `lab_2`, `laboratory`, `la`).
`genPath(maxDepth)` → `/` or `"/" + join(segments, "/")`, depth 0–64.
`genTree(n)` → n nodes forming a random rooted tree; yields (ancestor,
descendant), (sibling, sibling), and (unrelated, unrelated) pairs by
construction, so expectations come from the tree shape, never from
`ScopeCovers`.

**Reference oracle** (must live in the test file, not in `path.go` — the point
is an independent second implementation):

```
refCovers(scope, path):
    if scope == "/": return true
    return segments(path)[:len(segments(scope))] == segments(scope)
        where segments(p) = strings.Split(strings.TrimPrefix(p, "/"), "/")
```

| ID | Invariant | Notes | Coverage |
|---|---|---|---|
| PROP-01 | ∀ valid `p`: `ScopeCovers(p, p)` — **reflexive** | | GAP |
| PROP-02 | ∀ valid `a,b`: `ScopeCovers(a,b) ∧ ScopeCovers(b,a) ⇒ a == b` — **antisymmetric** | this is the formal version of "never the reverse unless a == b" | GAP |
| PROP-03 | ∀ valid `a,b,c`: `ScopeCovers(a,b) ∧ ScopeCovers(b,c) ⇒ ScopeCovers(a,c)` — **transitive** | delegation chains rest on this | GAP |
| PROP-04 | ∀ valid `a,b`: `ScopeCovers(a,b) == refCovers(a,b)` — **differential** | the single highest-value property: defines the algebra independently of the implementation, and is the one test that would have caught a substring bug without being told about `lab-2` | GAP |
| PROP-05 | Fix a binding set B. Define `Auth(p) = {v : HasAuthority(subj, v, p)}`. Then `ScopeCovers(a,b) ⇒ Auth(a) ⊆ Auth(b)`; and for `a != b` with `ScopeCovers(a,b)` there exists a B witnessing `Auth(b) ⊋ Auth(a)` (bind at `b`) | **"every authority at `a` is available at `b`, and never the reverse unless `a == b`"**, stated exactly. Follows from PROP-03 | GAP |
| PROP-06 | `Auth_B(p) ⊆ Auth_{B ∪ {x}}(p)` for any additional binding `x` — **additive-only** | guards the docs/05:60 no-deny decision; would fail loudly the day someone adds a deny rule. Note: the *converse* form named in docs/10:12 ("removing a binding never adds rights") is unexercisable until an Op exists to remove one (Q-5) | GAP |
| PROP-07 | **Multi-hop delegation closure.** Random tree; random chain `root → A₁ → … → Aₖ` of grants at randomly chosen scopes; assert every accepted binding's scope is covered by its grantor's scope **using `refCovers`**, and that no principal transitively reaches a scope outside the subtree it was originally delegated | supersedes [apply_test.go:131-175](../../internal/kernel/apply_test.go), which is single-hop and self-oracled | PARTIAL (single-hop, self-oracled) |
| PROP-08 | The grammar admits at most one byte string per node: for accepted `p,q`: `p == q ⇔ segments(p) == segments(q)` | documents that no normalization is applied *and none is needed* | GAP |
| PROP-09 | ∀ byte `b ∈ 0..255` not in `[a-z0-9._-]`: `ValidatePath("/x" + b + "y")` rejects | 256 enumerated cases, cheap, closes the whole punctuation/control/high-bit class in one test | GAP |
| PROP-10 | Boundaries: random valid paths at byte length 1023/1024/1025 and depth 63/64/65 → accept/accept/reject and accept/accept/reject | | GAP |
| PROP-11 | `FuzzValidatePath`: never panics; every accepted input satisfies the grammar predicate; every accepted input has all bytes in `0x2d..0x7a`; `ValidatePath(p) == nil ⇒ ScopeCovers(p, p)` | docs/10:22 asks for fuzzing of every parser on the untrusted path; `ValidatePath` is one and has no fuzz target today | GAP |
| PROP-12 | `FuzzScopeCovers(a, b)`: never panics; if both pass `ValidatePath`, result equals `refCovers` | corpus seeded from the SC table | GAP |
| PROP-13 | ∀ `a ∈ adminRoles`, ∀ `q ∈ roleVerbs`: `verbs(q) ⊆ verbs(a)` | = RV-36, stated as a table property so it holds for future roles | GAP |
| PROP-14 | ∀ `r ∉ adminRoles`: `VerbAdmin ∉ verbs(r)` | = RV-35 | GAP |
| PROP-15 | For a binding set with no `ActivationRequired`: `t₂ > t₁ ⇒ Auth(t₂) ⊆ Auth(t₁)` — **authority is non-increasing in time** | catches a sign/`>=` inversion at policy.go:40. Deliberately excludes activations, which legitimately turn authority *on* | GAP |
| PROP-16 | For any binding set B and any activation set A: `Auth_{B,A}(p) ⊆ Auth_{B', ∅}(p)` where `B'` is B with every `ActivationRequired` forced false — **an activation never confers more than the binding would outright** | generalizes [activation_test.go:401](../../internal/kernel/activation_test.go) | GAP |
| PROP-17 | Over random accepted Op sequences: at most one accepted `PutBinding` has `Grantor == ""` | generalizes BS-02 | GAP |
| PROP-18 | After any accepted `PutPrincipal` sequence, `BucketPathIndex` is a bijection onto live principals | would catch PE-12 | GAP |

**Section H: 18 scenarios, 0 covered (1 partial).**

---

## I. Coverage summary

| Section | Scenarios | Covered | GAP |
|---|---|---|---|
| A. Path grammar (SP) | 30 | 15 | 15 |
| B. Scope algebra (SC) | 32 | 9 | 23 |
| C. Role/verb matrix (RV) | 38 | 4 | 34 |
| D. `HasAuthority` (HA) | 21 | 6 | 15 |
| E. Delegation narrows (DN) | 23 | 8 | 15 |
| F. Bootstrap (BS) | 10 | 2 | 8 |
| G. Escalation (PE) | 24 | 8 | 16 |
| H. Properties (PROP) | 18 | 1 (partial) | 17 |
| **Total** | **196** | **53** | **143** |

**≈27% of the supported authorization surface is asserted today.** The covered
27% is not arbitrary — it is the set of scenarios someone thought about
adversarially (the `lab-2` substring case, the ESC1 mapping case, bootstrap
single-use, activation semantics). The gap is concentrated in the mechanical
cross-products (role × verb, path × path) and in the escalation paths that run
*around* `applyPutBinding` rather than through it.

---

## J. Suspected defects

Ordered by risk. Each is a code-reading finding, not an observed failure; each
should be confirmed by writing the cited scenario before any fix.

### D-01 — `PutPrincipal` is unauthorized; a subtree admin can re-home a superior principal into their own subtree (ESC1) — **CRITICAL**

`applyPutPrincipal` ([apply.go:77-107](../../internal/kernel/apply.go)) has no
grantor field and no authority check; `Kernel.PutPrincipal`
([kernel.go:373-385](../../internal/kernel/kernel.go)) adds none. It is the only
mutating admin-plane Op without one. Worse, it checks the **path** index for
collisions (apply.go:89-93) but never checks whether the **ID** already belongs
to a different principal — so a `PutPrincipal` naming an existing ID with a new,
free path is an unauthenticated *rename*.

Attack (PE-10), against fixture D2:

1. `labadmin` proposes `PutPrincipal{ID: <root's ID>, Path: "/clusters/lab/pwn", Type: "human"}`.
   Path is free → accepted. The root principal's record now says its path is
   inside labadmin's subtree.
2. `labadmin` proposes `PutMapping{Principal: <root's ID>, …}`. The K-1 guard at
   [apply.go:251](../../internal/kernel/apply.go) asks
   `HasAuthority(labadmin, admin, target.Path)` — and `target.Path` is now
   `/clusters/lab/pwn`. **Accepted.**
3. Any workload matching that rule logs in as the root principal, which holds
   `domain-admin` at `/`.

This is exactly the ESC1 shape that
[E-01 K-1](../explorations/E-01-threat-model.md) rates HIGH and that
`TestMappingRulesObeyDelegationNarrows` was written to prevent — reached by
mutating the *input* to the guard rather than the guard itself.

**Mitigating factor today:** `PutPrincipal` is reachable only from the local
`signet genesis` CLI ([main.go:233](../../cmd/signet/main.go),
[main.go:517](../../cmd/signet/main.go)); no dialect exposes it. That makes it a
latent defect rather than a remote one — but the kernel's own charter principle
5 ([kernel.go:34-36](../../internal/kernel/kernel.go)) says authorization lives
inside the kernel method precisely so that a future caller cannot forget it, and
docs/14's control-plane API is the caller that will.

**Fix shape:** require a grantor holding `admin` over both the new path *and*
(for an existing ID) the principal's current path; reject a `PutPrincipal` whose
ID exists with a different path unless it is an explicit, audited rename.

### D-08 — Offline credentials ignore `ActivationRequired`: PAM bypass at issuance — **HIGH**

`filterRoles` ([issue.go:200-231](../../internal/kernel/issue.go)) iterates the
subject's bindings and filters on `NotAfter` (line 212), `ScopeCovers` (216),
`MinTier` (222), and `RequiredAMR` (225). It never consults
`b.ActivationRequired`. `HasAuthority` does (policy.go:49-70), so the online KV
path is correct — but an `ActivationRequired` role is embedded into any JWT or
SSH certificate minted by `Kernel.Issue` with no live activation.

That inverts the central PAM claim at
[docs/13:196](../13-kernel-data-model.md) ("`HasAuthority` skips a binding with
`activation_required` unless a live activation references it") for exactly the
credential class that a relying party accepts *without asking anyone* — the
offline half, where the guard matters most (issue.go:17-21). It is also a
K-2-adjacent downgrade: standing access smuggled into an offline token.

Scenario PE-17. Fix: add the same activation check to `filterRoles`, and extend
PROP-16 to cover the issuance path, not just `HasAuthority`.

### D-02 — `ScopeCovers("", path)` returns `true` for every absolute path — **HIGH (latent)**

[path.go:65-73](../../internal/kernel/path.go): with `scope == ""`, the first
two arms fall through and `strings.HasPrefix(path, ""+"/")` is true for every
absolute path. **An empty scope is silently a root scope** — the single most
dangerous default an authorization function can have.

Today the only writer of `Binding.Scope` is `applyPutBinding`, which validates
via `ValidatePath` (apply.go:110 → path.go:21), so no stored binding can carry
`""`. The invariant is real but it is held up by one line in a different file,
with no test asserting the connection. Any of the following breaks it: a new Op
that writes a binding, a store-level corruption (which `LoadBindings` swallows
silently, policy.go:19 — a partially-decoded binding is dropped, but a binding
whose JSON simply omits `"scope"` unmarshals cleanly to `""`), or a future
caller computing a scope from a request.

Scenarios SC-25…SC-28, DN-16. Fix: make `ScopeCovers` fail closed on any
`scope` that does not pass `ValidatePath` — it is a two-line guard on the
hottest security path in the product.

### D-03 — `Kernel.Authorize` / `AuthorizeSign` accept unvalidated paths; `ScopeCovers` then honors traversal — **MEDIUM–HIGH (latent)**

`Kernel.Authorize` ([pki.go:361-364](../../internal/kernel/pki.go)) and
`AuthorizeSign` (pki.go:367-370) are the exported "for dialects that must refuse
before doing work" entry points, and neither calls `ValidatePath`. Every secrets
method in kernel.go does; these two do not. Consequently
`ScopeCovers("/a", "/a/../../b")` → `true` (SC-31), as do the doubled-slash and
NUL variants.

No current dialect passes client-controlled input here — vaultkv passes literal
`"/"` (handler.go:173/232/254) or a stored `a.Scope` (handler.go:363), sshca
passes a validated `role.Scope` (handler.go:82) — so this is a live footgun
rather than a live bug. The blast radius is any future dialect that authorizes a
path and then uses that same path against a non-kernel resource (a filesystem, a
proxied URL, an SSH principal), where `..` is not inert the way a flat KV key is.

Scenario PE-22. Fix: `ValidatePath` at the top of `authorize` (kernel.go:471),
which covers both exported wrappers at once.

### D-04 — JIT laundering: an admin can self-grant an unbounded copy of a time-bounded authority — **MEDIUM**

`applyPutBinding` places no constraint on the grantor being the subject
(DN-10/PE-04), and none on the new binding's `NotAfter` relative to the
grantor's own (DN-23/PE-06). So a `domain-admin` at `/clusters/lab` whose
binding expires at T can, at T−1, propose an identical binding for themselves
with `NotAfter: 0`. The delegation invariant is preserved in the **scope**
dimension and silently violated in the **time** dimension: docs/13:147 says a
JIT grant "stops being minted after T", and this makes that false.

The same applies to a grant *to someone else* outliving the grantor's authority.
docs/13:124 explicitly decides against cascade ("revoking a delegated admin does
not silently invalidate every grant they made"), which makes DN-23 arguably
intended — but a grant that outlives its grantor's *scheduled, known-in-advance*
expiry is a different case from one that outlives an *unplanned* revocation.
See Q-4.

### D-05 — Nothing compares the granted role's verb set to the grantor's — **MEDIUM (latent)**

`applyPutBinding` gates on `HasAuthority(grantor, VerbAdmin, scope)`
([apply.go:140](../../internal/kernel/apply.go)) and nothing else. There is no
check that `verbs(o.Role) ⊆ verbs(grantor's role)`. This is safe **only** because
`domain-admin` is the sole role granting `VerbAdmin` and it holds all six verbs.
Adding any narrower admin role — the natural next step, e.g. `pki-admin:
{admin, sign}` for a delegated CA operator — instantly permits granting `delete`
to someone by an admin who does not hold it. RV-36/PROP-13 is the regression
that makes this structural rather than incidental.

### D-06 — `adminRoles` is dead code; the documented control is not the implemented one — **LOW (correctness-of-belief)**

[model.go:214-215](../../internal/kernel/model.go) declares
`adminRoles = {"domain-admin"}` with the comment "adminRoles may create bindings
(subject to delegation-only-narrows)". Grep confirms **zero references** in the
tree. The actual gate is `VerbAdmin` in the `roleVerbs` table. A maintainer
adding a role to `adminRoles` would change nothing; one removing `domain-admin`
from it would revoke nothing. Either delete it or wire it into
`applyPutBinding` and lock the relationship with RV-37.

### D-07 — Binding keys are `subject + "/" + id` with no constraint on either component — **LOW**

`bindingKey` ([model.go:233](../../internal/kernel/model.go)) and
`LoadBindings`' prefix scan ([policy.go:17](../../internal/kernel/policy.go))
assume `op.ID` contains no `/`. Nothing enforces it: `applyPutPrincipal` checks
only `o.ID != ""` (apply.go:84) and `applyPutBinding` only `o.ID != ""`
(apply.go:116). A principal with ID `alice/x` has its bindings collected by
`LoadBindings(alice)` (HA-18), and `(subject="a", id="b/c")` collides with
`(subject="a/b", id="c")` (PE-13). Not currently reachable — IDs come from
`newID()` (kernel.go:503-509, 32 hex chars) — but the invariant is unstated and
untested. `activationKey` (activation.go:62) has the identical shape.

---

## K. Recommended ordering

1. **Confirm D-01 and D-08 with the two scenarios PE-10 and PE-17.** These are
   the two findings that would change the product's security claims. Write the
   tests first; they are expected to *fail*.
2. **PROP-04 + PROP-09 + the RV table.** Three tests, ~120 lines total, take
   `ScopeCovers`, the byte grammar, and the role matrix from sampled to
   exhaustive. PROP-04 in particular removes the self-oracle problem at
   apply_test.go:169.
3. **SC-25…SC-32 and D-02/D-03 guards.** Cheap, and they convert two
   "safe because a different file validates" arguments into local invariants.
4. **DN-07…DN-23 and BS-03…BS-10.** The write-path escalation cases.
5. **PROP-07 (multi-hop) and PROP-11/12 (fuzz).** The long-tail coverage
   docs/10 already committed to.

---

## L. Questions for the maintainer

**Q-1 — Are `/...`, `/a.`, and `/.a` intended to be legal path segments?**
`ValidatePath` excludes exactly `"."` and `".."` (path.go:48) but accepts any
other all-dot segment, so `/...` and `/....` are valid nodes. Some filesystem
and URL normalizers collapse or reject these; if a Signet path is ever handed to
one, two paths could converge. SPIFFE's grammar permits them. Decide and pin
with SP-06/SP-07 either way.

**Q-2 — Should a segment be allowed to start with `-` or `_`?**
`/-a` and `/_` are accepted. Principal paths serialize into SPIFFE IDs and, in
the X.509 dialect, adjacent to DNS SANs where a leading hyphen is illegal. Is
the SPIFFE URI SAN the only serialization target, or does a path segment ever
need to be DNS-safe?

**Q-3 — What is a well-formed bootstrap binding?**
`applyPutBinding` permits a grantorless binding with *any* scope, *any* role,
`ActivationRequired: true`, or an already-expired `NotAfter` (BS-04…BS-07). Each
wedges the domain permanently, since BS-02 then forbids a second one and nobody
holds admin. Should bootstrap require `Scope == "/"`, a role in `adminRoles`,
`ActivationRequired == false`, and `NotAfter == 0`? Relatedly (BS-10): should
the `requireDomainAuthority` bootstrap door (apply.go:276-286) be gated on the
same "no bindings yet" condition, or on a narrower "genesis is in progress"
signal — today a grantorless `PutRolePolicy` can set any role's security floor
as long as no binding exists yet.

**Q-4 — Is self-granting intended, and may a grant outlive its grantor's own
expiry?** (D-04.) Two sub-questions: (a) should `o.Grantor == o.Subject` be
refused, or refused only when it would extend `NotAfter`? (b) should
`o.NotAfter` be clamped to the grantor's binding's `NotAfter`, the way an
activation is clamped to its binding's (activation.go:177-178)? The activation
path already implements exactly this "JIT-on-JIT" clamp; the binding path does
not, and it is not obvious that the asymmetry is deliberate.

**Q-5 — Is the absence of a binding-removal Op deliberate for the MVP?**
No `DeleteBinding`/`RevokeBinding` exists. This blocks the *additivity*
invariant named in docs/10:12, the `grantor`-indexed quarantine and
`--revoke-grants` cascade in docs/13:129-131, and scenario PE-23/PE-24. Is
revocation intended to be expressed purely as JIT expiry for now (which would be
worth stating in docs/13), or is the Op simply not built yet?

**Q-6 — Should `applyPutBinding` reject a `NotAfter` already in the past at
`o.AtSec`?** (HA-08.) Today it writes a binding that can never be honored. Fine
as a no-op, but an operator who fat-fingers a timestamp gets a silent success.

**Q-7 — Should `LoadBindings` surface an unmarshalable binding rather than skip
it?** [policy.go:19](../../internal/kernel/policy.go) drops it silently. That
fails closed (authority is lost, not gained), which is the right direction — but
it also means a corrupted or partially-migrated store degrades authorization
invisibly. Should it return an error, or at minimum increment a metric?

**Q-8 — Is `PutBinding` with an existing ID meant to be an overwrite?**
(DN-20.) `applyPutBinding` does not check for prior existence and `tx.Put`
replaces (apply.go:160). With random IDs this never happens, but the Op is
declaratively re-appliable and restore replays it — worth stating whether
"update a binding in place" is a supported operation or an accident.

**Q-9 — Does the `Activation.Role`/`Activation.Scope` pair
([model.go:73-74](../../internal/kernel/model.go)) have any authority, or is it
display metadata?** `HasAuthority` consults only `a.Binding == b.ID`
(policy.go:67), so the binding governs entirely. HA-16 proposes locking that in;
confirm it is the intent, because a reader of the struct could reasonably assume
otherwise.
