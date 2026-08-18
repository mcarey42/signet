# 07 — Test plan: privileged access management (JIT / PAM activation)

**Status: Draft** · Area owner: kernel · Feature shipped in milestone 5b
(`docs/13-kernel-data-model.md:187`).

## 1. What is under test

The split between being **eligible** for an authority and **holding** it, and
everything that turns the first into the second for a bounded window.

| Component | File | Role in the feature |
|---|---|---|
| Activation lifecycle | `internal/kernel/activation.go:101` (`applyRequestActivation`), `:213` (`applyActivationAction`) | All state-dependent validation, inside `Apply` |
| Clamping | `internal/kernel/activation.go:167` (`clampExpiry`) | `min(requested, MaxActivationSec, NotAfter)` |
| Step-up | `internal/kernel/activation.go:183` (`checkStepUp`) | AMR set + auth freshness |
| Enforcement | `internal/kernel/policy.go:33` (`HasAuthority`), esp. `:49`–`:70` | An `activation_required` binding is skipped unless a live activation names it |
| Data model | `internal/kernel/model.go:18` (`Binding`), `:69` (`Activation`), `:90` (`Live`) | The six PAM fields and the four activation states |
| Write vocabulary | `internal/op/op.go:294` (`RequestActivation`), `:320` (`ActivationAction`) | Ops carry every nondeterministic input |
| Service API | `internal/kernel/activation.go:324` (`Eligible`), `:362` (`RequestActivation`), `:383` (`DecideActivation`), `:392` (`Activations`), `:404` (`PendingActivations`) | Propose-time checks and read models |
| HTTP surface | `internal/dialect/vaultkv/handler.go:148`–`:151`, handlers at `:295`, `:309`, `:347`, `:370` | `/v1/pam/{eligible,activate,pending,decide}` |
| CLI | `cmd/signet/pam.go:36` | `signet pam eligible\|activate\|pending\|approve\|deny\|kill` |

The four semantics this plan exists to hold down are stated in
`docs/13-kernel-data-model.md:173`–`:185` and restated as built behaviour at
`:195`–`:216`; the honest limit on step-up is at `:218`.

## 2. How to run

The tree is on NFS without `flock`. **Never** run bare `go test` / `go build`.

```
make test                       # unit layer, incl. internal/kernel/activation_test.go
make test-pam                   # end-to-end: builds, then test/pam/run.sh against a live node
```

New unit scenarios belong in `internal/kernel/activation_test.go` (helpers
`bindPAM` `:23`, `requestAct` `:38`, `decide` `:46`, `withTx` `:52`). New
end-to-end scenarios belong in `test/pam/run.sh`, which is wired into the
`test-pam` target in `Makefile`.

## 3. Fixture vocabulary

Referenced by every scenario below. Times are the integer seconds the tests
already use; `T0 = 1000`.

**Principals** — `alice` (subject, holds nothing outright), `bob` (second
approver, or a stranger where noted), `carol` (`domain-admin` at `/`), `dave`
(`domain-admin` at `/clusters` only), `eve` (exists, holds nothing anywhere).

**Bindings** (all `Subject: alice` unless stated):

| Fixture | Shape |
|---|---|
| `B-plain` | `kv-admin @ /secrets`, no PAM fields (held outright) |
| `B-jit` | `kv-admin @ /secrets`, `NotAfter: 1500`, no PAM fields |
| `B-pam` | `kv-admin @ /secrets`, `activation_required` |
| `B-pam-max` | as `B-pam` + `max_activation_sec: 600` |
| `B-pam-jit` | as `B-pam` + `not_after: 1500` |
| `B-appr` | as `B-pam` + `approval_required` |
| `B-appr2` | as `B-appr` + `min_approvers: 2` |
| `B-step` | as `B-pam` + `step_up_amr: ["hwk"]`, `step_up_max_age_sec: 300` |
| `B-narrow` | `kv-reader @ /secrets/app`, `activation_required` |
| `B-admin-pam` | `domain-admin @ /`, `activation_required`, `max_activation_sec: 600` |

**Status column**: `COVERED` (a named existing assertion proves it), `PARTIAL`
(the path is exercised but the property is not asserted), `GAP` (nothing tests
it), `BUG` (tested here and found wrong — see §14).

---

## 4. A — Eligibility versus possession (PAM-E)

The load-bearing group. If any of these fail the feature is decorative.

### PAM-E-01 — an unactivated binding confers nothing
- **Pre:** `B-pam` only.
- **Input:** `HasAuthority(alice, write, /secrets/app, T0)`.
- **Expect:** `false`. `policy.go:49`–`:51` refuses to short-circuit and `:65`–`:70` finds no live activation.
- **Status:** COVERED — `internal/kernel/activation_test.go:69`; end-to-end `test/pam/run.sh:70`–`:71`.

### PAM-E-02 — an active activation confers exactly the binding's authority
- **Pre:** `B-pam`; `PAM-A-01` performed at `T0`.
- **Input:** `HasAuthority(alice, write, /secrets/app, T0)`.
- **Expect:** `true`.
- **Status:** COVERED — `activation_test.go:80`; e2e `test/pam/run.sh:93`.

### PAM-E-03 — authority ends at expiry with nothing sweeping it
- **Pre:** as PAM-E-02, activation expiry `1600`.
- **Input:** `HasAuthority(...)` at `1599`, `1600`, `1601`; no intervening write of any kind.
- **Expect:** `true`, `false`, `false`. `Live` is `Expiry > nowSec` (`model.go:91`), so the boundary is exclusive, and no record is mutated at expiry.
- **Status:** PARTIAL — `activation_test.go:89` checks only `T0+3601`. The **exact boundary** `now == Expiry` is a GAP (verified correct by probe, but unasserted).

### PAM-E-04 — expiry needs no store write to take effect
- **Pre:** as PAM-E-02.
- **Input:** after expiry, `loadActivation(alice, act-1)`.
- **Expect:** the record is still `state: active` with a past `Expiry`. Nothing demotes it; `Live` decides. This is the "no sweep" claim of `docs/13:197`.
- **Status:** GAP. Worth asserting explicitly, because a future "tidy-up" that flips expired records to `killed` would silently change the audit meaning of `killed`.

### PAM-E-05 — an ordinary non-PAM binding is untouched by any of this
- **Pre:** `B-plain` for `bob`.
- **Input:** `HasAuthority(bob, write, /secrets/app, T0)`.
- **Expect:** `true`, with no activation record consulted (`policy.go:49`–`:51`).
- **Status:** COVERED — `activation_test.go:100`.

### PAM-E-06 — a PAM binding and a plain binding coexist without contaminating each other
- **Pre:** `alice` holds `B-plain` at `/secrets/public` (`kv-reader`) **and** `B-pam` at `/secrets`.
- **Input:** `HasAuthority(alice, read, /secrets/public/x, T0)` and `HasAuthority(alice, write, /secrets/app, T0)`.
- **Expect:** `true` and `false`. The loop in `policy.go:39`–`:71` must not let the plain binding satisfy the PAM one, nor let the PAM one suppress the plain one.
- **Status:** PARTIAL — the e2e fixture has both (`test/pam/run.sh:47`–`:50`) but only asserts the negative half.

### PAM-E-07 — an expired *binding* is skipped before activation is even considered
- **Pre:** `B-pam-jit` with a live activation created at `T0` (expiry clamped to `1500`).
- **Input:** `HasAuthority(alice, write, /secrets/app, 1501)`.
- **Expect:** `false` via `policy.go:40`–`:42` (binding expiry), independently of the activation's own clamp.
- **Status:** COVERED — `activation_test.go:128`.

---

## 5. B — Activation without approval (PAM-A)

### PAM-A-01 — request on a non-approval PAM binding activates immediately
- **Pre:** `B-pam`.
- **Input:** `RequestActivation{Subject: alice, Binding: B-pam, Reason: "incident 42", ForSeconds: 3600, AtSec: T0}`.
- **Expect:** record written with `state: active`, `Expiry: 4600`, `Role/Scope` copied from the binding (`activation.go:150`–`:158`).
- **Status:** COVERED — `activation_test.go:77`.

### PAM-A-02 — the record carries the reason
- **Pre/Input:** as PAM-A-01.
- **Expect:** `Activation.Reason == "incident 42"`, and the audit record's subject is `activation <id>: <reason>` (`apply.go:346`–`:347`).
- **Status:** GAP at the unit layer (no assertion on `Reason` anywhere); PARTIAL e2e — `test/pam/run.sh:124` only verifies the chain still verifies, not that the reason is in it.

### PAM-A-03 — a request with no reason is refused
- **Pre:** `B-pam`.
- **Input:** `Kernel.RequestActivation(..., reason: "")`.
- **Expect:** refused before proposing (`activation.go:366`–`:369`).
- **Status:** COVERED e2e — `test/pam/run.sh:75`. GAP at unit layer.

### PAM-A-04 — Apply itself does **not** require a reason
- **Pre:** `B-pam`.
- **Input:** `applyRequestActivation` with `Reason: ""` directly.
- **Expect (today):** accepted. The check lives only at the service layer, contradicting `docs/13:192` ("enforced inside `Apply`, not in a caller that could be bypassed"). See Q1.
- **Status:** GAP — confirmed by probe.

### PAM-A-05 — activating a binding held outright is refused
- **Pre:** `B-plain`.
- **Input:** request against `B-plain`.
- **Expect:** error from `activation.go:111`–`:114`; no record written.
- **Status:** COVERED — `activation_test.go:352`.

### PAM-A-06 — activating a binding that does not exist is refused
- **Pre:** none.
- **Input:** request with `Binding: "no-such-binding"`.
- **Expect:** error from `activation.go:106`–`:110`.
- **Status:** COVERED — `activation_test.go:363`.

### PAM-A-07 — activating another principal's binding is refused
- **Pre:** `B-pam` on `alice`.
- **Input:** `Kernel.RequestActivation` as a session for `bob`, naming `alice`'s binding ID.
- **Expect:** refused — `findBinding` is scoped to the requester (`activation.go:85`–`:95`), and the service sets `Subject: s.Principal` (`activation.go:375`), so `bob` cannot even name it.
- **Status:** GAP. This is the cross-principal case and nothing asserts it.

### PAM-A-08 — a request against an already-expired eligibility is refused
- **Pre:** `B-pam-jit` (`NotAfter: 1500`).
- **Input:** request at `AtSec: 1500` and at `1600`.
- **Expect:** both refused by `activation.go:116`–`:120` (note `>=`: exactly at `NotAfter` is already too late).
- **Status:** GAP — the expiry check on the *request* path is untested (only the approve path is, PAM-P-06).

---

## 6. C — Activation with approval (PAM-P)

### PAM-P-01 — a request on an approval-required binding stays pending and confers nothing
- **Pre:** `B-appr`.
- **Input:** request at `T0`; then `HasAuthority(alice, write, /secrets/app, T0)`.
- **Expect:** `state: pending`, `Expiry: 0`, authority `false`.
- **Status:** COVERED — `activation_test.go:187`; e2e `test/pam/run.sh:82`.

### PAM-P-02 — one qualified approval activates when `min_approvers` is unset
- **Pre:** `B-appr`, pending request, `carol` = `domain-admin @ /`.
- **Input:** `ActivationAction{Verb: approve, Actor2: carol, AtSec: 1020}`.
- **Expect:** `state: active`, `DecidedBy: carol`, `Approvals: [carol]`, `need` defaults to 1 (`activation.go:298`–`:301`).
- **Status:** COVERED — `activation_test.go:223`; e2e `test/pam/run.sh:92`.

### PAM-P-03 — `min_approvers: 2` is not satisfied by one approval
- **Pre:** `B-appr2`, pending request, `carol` approves at `1010`.
- **Input:** `HasAuthority(alice, write, /secrets/app, 1015)`.
- **Expect:** `false`; record still `pending` with `Approvals: [carol]`.
- **Status:** COVERED — `activation_test.go:385`.

### PAM-P-04 — two distinct qualified approvers activate it
- **Pre:** as PAM-P-03; `bob` = `domain-admin @ /`.
- **Input:** `bob` approves at `1030`.
- **Expect:** `state: active`; authority `true` at `1035`.
- **Status:** COVERED — `activation_test.go:391`.

### PAM-P-05 — the same principal cannot supply two approvals
- **Pre:** as PAM-P-03.
- **Input:** `carol` approves a second time at `1020`.
- **Expect:** error from `activation.go:249`–`:255`; `Approvals` unchanged (length 1).
- **Status:** COVERED — `activation_test.go:388`. GAP on the *side effect*: nothing asserts `len(Approvals)` stayed 1 after the refusal.

### PAM-P-06 — approval after eligibility lapsed denies **and records why**
- **Pre:** `B-appr` with `NotAfter: 2000`; pending request from `T0`.
- **Input:** `carol` approves at `2001`.
- **Expect:** error to the approver **and** the record moved to `denied` with `KillReason` containing "expired" (`activation.go:274`–`:283`).
- **Status:** COVERED — `activation_test.go:244`–`:254`. GAP on `DecidedBy`/`DecidedAt` being set to the approver and the decision time.

### PAM-P-07 — approval after the binding was deleted denies and records why
- **Pre:** `B-appr`, pending request, binding removed from the store.
- **Input:** `carol` approves at `1010`.
- **Expect:** error, record `denied`, `KillReason: "the underlying eligibility was removed while this request was pending"` (`activation.go:264`–`:272`).
- **Status:** PARTIAL — `activation_test.go:270` asserts only that approval errored, not the recorded state or reason. **Also unreachable in production: there is no binding-deletion Op** (see Q2 / §14 F5).

### PAM-P-08 — an approver without admin authority at the binding's scope is refused
- **Pre:** `B-appr` (`scope /secrets`), pending request; `dave` = `domain-admin @ /clusters`.
- **Input:** `dave` approves.
- **Expect:** error from `activation.go:287`–`:295`; state stays `pending`, `Approvals` empty.
- **Status:** COVERED — `activation_test.go:216`.

### PAM-P-09 — an approver with a *narrower* admin scope than the binding is refused
- **Pre:** `B-appr` at `/secrets`; `bob` = `domain-admin @ /secrets/app` (strictly inside).
- **Input:** `bob` approves.
- **Expect:** refused — `HasAuthority(bob, admin, "/secrets")` is false because `ScopeCovers("/secrets/app", "/secrets")` is false (`path.go:65`). Delegation only narrows, and approving is granting.
- **Status:** GAP. The existing test uses a disjoint scope, which is the easy case.

### PAM-P-10 — nobody approves their own request, including a domain admin
- **Pre:** `alice` holds `domain-admin @ /` outright **and** `B-appr`; pending request.
- **Input:** `alice` approves her own request at `1010`.
- **Expect:** error containing "Separation of duties"; state `pending`; `Approvals` empty (`activation.go:244`–`:248`). Asserted on the record, not on `HasAuthority` — `alice` legitimately has write here through the other binding.
- **Status:** COVERED — `activation_test.go:152`, incl. the message and both side-effect assertions; e2e `test/pam/run.sh:87`.

### PAM-P-11 — the self-approval check precedes the authority check
- **Pre:** `alice` holds `domain-admin @ /` (so she *would* pass `HasAuthority`); pending request.
- **Input:** `alice` approves.
- **Expect:** the *self* refusal, not the authority refusal. Ordering matters for the error an operator reads.
- **Status:** COVERED implicitly by PAM-P-10's message assertion (`activation_test.go:167`).

### PAM-P-12 — an approver who is eligible-but-not-activated for admin cannot approve
- **Pre:** `B-appr` on `alice` at `/secrets`; `bob` holds `B-admin-pam` (`domain-admin @ /`, activation required) with **no** live activation.
- **Input:** `bob` approves.
- **Expect:** refused — `HasAuthority` at `activation.go:287` walks the same eligibility-is-not-possession path.
- **Status:** GAP. This is PAM applied to the approver, and nothing tests it.

### PAM-P-13 — an approver whose own admin authority is itself an active activation *can* approve
- **Pre:** as PAM-P-12, but `bob`'s `B-admin-pam` has a live activation.
- **Input:** `bob` approves.
- **Expect:** accepted. Decide whether this is intended (Q6) — it is the current behaviour by construction.
- **Status:** GAP.

### PAM-P-14 — approval on a record that is not pending is refused
- **Pre:** an activation in each of `active`, `denied`, `killed`.
- **Input:** `approve`.
- **Expect:** error `"... is <state>, not pending"` (`activation.go:238`–`:240`) for all three; no mutation.
- **Status:** GAP (only reached incidentally by PAM-O-02).

### PAM-P-15 — approving an activation that does not exist
- **Pre:** none.
- **Input:** `approve` with an unknown `ID`.
- **Expect:** `"activation: no such activation <id>"` (`activation.go:218`–`:220`).
- **Status:** GAP.

### PAM-P-16 — an unknown verb is refused
- **Input:** `ActivationAction{Verb: "revoke"}`.
- **Expect:** `"activation: unknown verb"` (`activation.go:308`).
- **Status:** GAP. Reachable from the wire: `handler.go:388` passes `body.verb` through unvalidated.

---

## 7. D — Expiry clamping (PAM-C)

The rule is `expiry = min(now + requested, now + max_activation_sec, not_after)`
with `requested <= 0` meaning "the maximum" (`activation.go:167`–`:181`).

### PAM-C-01 — requested below the max is honoured
- **Pre:** `B-pam-max` (`max 600`).
- **Input:** request `ForSeconds: 300` at `T0`.
- **Expect:** `Expiry == 1300`.
- **Status:** GAP. Every existing clamp test asks for *more* than allowed; nothing proves a modest request is honoured at all. (It is, on the no-approval path — but see PAM-C-06.)

### PAM-C-02 — requested above the max is clamped to the max
- **Pre:** `B-pam-max`.
- **Input:** `ForSeconds: 86400` at `T0`.
- **Expect:** `Expiry == 1600`.
- **Status:** COVERED — `activation_test.go:136`.

### PAM-C-03 — no max on the binding falls back to the domain default
- **Pre:** `B-pam` (`max_activation_sec` unset).
- **Input:** `ForSeconds: 86400` at `T0`.
- **Expect:** `Expiry == T0 + DefaultMaxActivationSec` = `1000 + 14400` (`activation.go:47`, `:169`–`:171`).
- **Status:** GAP.

### PAM-C-04 — `ForSeconds: 0` means the maximum, not zero
- **Pre:** `B-pam-max`.
- **Input:** `ForSeconds: 0` (this is what `signet pam activate` sends when `-for` is omitted, `cmd/signet/pam.go:145`).
- **Expect:** `Expiry == 1600`, i.e. the full 600s — *not* an instantly-dead window.
- **Status:** GAP, and it is the CLI's default path.

### PAM-C-05 — a negative `ForSeconds` is treated as "maximum", not as time travel
- **Input:** `ForSeconds: -3600`.
- **Expect:** clamped to the max by `forSeconds <= 0` (`activation.go:172`). Never `Expiry < now`.
- **Status:** GAP. Reachable from the wire (`handler.go:318` takes a raw signed int64).

### PAM-C-06 — the approval path must honour the requested duration **(BUG)**
- **Pre:** `B-appr` with `max_activation_sec: 3600`.
- **Input:** request `ForSeconds: 600` at `T0`; `carol` approves at `1010`.
- **Expect:** `Expiry == 1610` (a 600s window).
- **Actual:** `Expiry == 4610` (a 3600s window). `activation.go:304` calls `clampExpiry(b, 0, o.AtSec)` — the requested duration is discarded, and `Activation` (`model.go:69`–`:87`) has no field in which to have remembered it.
- **Status:** **BUG** — see §14 F1. Verified.

### PAM-C-07 — JIT-on-JIT: the activation may not outlive its eligibility
- **Pre:** `B-pam-jit` (`NotAfter: 1500`).
- **Input:** request `ForSeconds: 100000` at `T0`.
- **Expect:** `Expiry == 1500`; authority false at `1501` (`activation.go:176`–`:179`).
- **Status:** COVERED — `activation_test.go:113`.

### PAM-C-08 — JIT-on-JIT on the approval path
- **Pre:** `B-appr` + `NotAfter: 1500`; pending request from `T0`.
- **Input:** `carol` approves at `1400`.
- **Expect:** `Expiry == 1500` (100s), not `1400 + max`.
- **Status:** GAP. The clamp is shared code so it should hold, but the approval path's clamp has no test of its own at all.

### PAM-C-09 — the window is measured from the *decision*, not the request
- **Pre:** `B-appr`, `max 600`; request at `T0`.
- **Input:** approve at `5000`.
- **Expect:** `Expiry == 5600`. A request that sits in a queue for an hour still yields a full window from approval (`activation.go:304` passes `o.AtSec`).
- **Status:** GAP. Worth pinning: the alternative (measuring from request) is a defensible design and the choice should be a test, not an accident.

### PAM-C-10 — a zero/negative `max_activation_sec` falls back to the default
- **Pre:** `B-pam` with `max_activation_sec: -1`.
- **Expect:** `DefaultMaxActivationSec`, via `maxSec <= 0` (`activation.go:169`).
- **Status:** GAP. `applyPutBinding` (`apply.go:109`) does not validate the field, so a negative value is storable.

---

## 8. E — Kill and deny (PAM-K)

### PAM-K-01 — kill ends access immediately
- **Pre:** `B-pam` with a live activation; `carol` = `domain-admin @ /`.
- **Input:** `kill` at `1020`.
- **Expect:** `state: killed`, `DecidedBy: carol`, `DecidedAt: 1020`, `KillReason` = the supplied reason; `HasAuthority` false at `1030`.
- **Status:** COVERED — `activation_test.go:279`; e2e `test/pam/run.sh:114`–`:115`. GAP on the `DecidedBy`/`KillReason` fields being recorded.

### PAM-K-02 — kill does not touch eligibility
- **Pre:** as PAM-K-01, after the kill.
- **Input:** a fresh request at `1040`.
- **Expect:** accepted — the binding was never modified.
- **Status:** COVERED — `activation_test.go:297`; e2e `test/pam/run.sh:116`.

### PAM-K-03 — a pending request may be killed
- **Pre:** `B-appr`, pending.
- **Input:** `kill`.
- **Expect:** accepted (`activation.go:224` admits both `active` and `pending`); a later `approve` then fails with "is killed, not pending".
- **Status:** GAP.

### PAM-K-04 — killing an already-decided activation is refused
- **Pre:** an activation in `killed` and one in `denied`.
- **Input:** `kill`.
- **Expect:** `"activation: <id> is already <state>"` (`activation.go:224`–`:226`); no mutation, so the original `DecidedBy` is not overwritten by a second actor.
- **Status:** GAP.

### PAM-K-05 — deny leaves a pending request dead and recorded
- **Pre:** `B-appr`, pending.
- **Input:** `deny` by `carol` with a reason at `1010`.
- **Expect:** `state: denied`, `DecidedBy: carol`, `KillReason` = reason; authority stays false; a later `approve` fails.
- **Status:** GAP. **Deny has no test anywhere** — not in `activation_test.go`, not in `test/pam/run.sh`, though it is a first-class CLI verb (`cmd/signet/pam.go:48`).

### PAM-K-06 — denying a non-pending activation is refused
- **Input:** `deny` on an `active` record.
- **Expect:** `"is active, not pending"` (`activation.go:231`–`:233`).
- **Status:** GAP.

### PAM-K-07 — a stranger may not kill someone else's activation **(BUG)**
- **Pre:** `B-pam` on `alice`, live activation; `eve` holds nothing anywhere.
- **Input:** `ActivationAction{Verb: kill, Actor2: eve}`.
- **Expect:** refused for want of admin authority at the binding's scope.
- **Actual:** accepted. `activation.go:222`–`:228` performs **no authority check at all**, and `handler.go:370`–`:395` performs none either (its comment at `:386` asserts the opposite).
- **Status:** **BUG** — see §14 F2. Verified.

### PAM-K-08 — a stranger may not deny someone else's pending request **(BUG)**
- **Pre:** `B-appr` on `alice`, pending; `eve` holds nothing.
- **Input:** `deny` by `eve`.
- **Expect:** refused.
- **Actual:** accepted; the record is written `denied` with `DecidedBy: eve`.
- **Status:** **BUG** — see §14 F2. Verified. Note the double harm: denial of service against the request, plus a false attribution written into durable state and the audit chain.

### PAM-K-09 — the subject may release their own activation early
- **Pre:** `B-pam` on `alice`, live activation.
- **Input:** `kill` by `alice`.
- **Expect (today):** accepted. Self-release is a legitimate PAM feature and should stay legal even after PAM-K-07 is fixed — an authority check that only admits admins would remove it (Q3).
- **Status:** GAP — currently works only as a side effect of the missing check.

### PAM-K-10 — kill on an expired-but-still-`active` record
- **Pre:** an activation whose `Expiry` has passed but whose state is still `active` (see PAM-E-04).
- **Input:** `kill` at `Expiry + 100`.
- **Expect:** accepted today (state is `active`), producing a `killed` record for a window that had already closed. Decide whether that is the wanted audit story (Q4).
- **Status:** GAP.

---

## 9. F — Listings: `Eligible` and the pending queue (PAM-L)

### PAM-L-01 — `Eligible` distinguishes held, eligible, pending, and ACTIVE
- **Pre:** `alice` holds `B-plain` at `/secrets/public`, `B-pam` (no activation), `B-appr` (pending), `B-narrow` (live activation).
- **Input:** `Kernel.Eligible(alice)` at `T0`.
- **Expect:** four entries; `Held` true for the first and last only; `Activation` populated only for the pending and active ones (`activation.go:334`–`:351`); CLI renders `held` / `eligible` / `pending` / `ACTIVE` (`cmd/signet/pam.go:104`–`:115`).
- **Status:** PARTIAL — e2e greps for `ACTIVE` (`test/pam/run.sh:98`) and for `eligible .*kv-admin` (`test/pam/run.sh:116`). No unit test of `Eligible` exists **at all**; `pending` and `held` rendering are untested.

### PAM-L-02 — an expired binding held outright shows as not held
- **Pre:** `B-jit` (`NotAfter: 1500`).
- **Input:** `Eligible(alice)` at `1600`.
- **Expect:** entry present, `Held: false` (`activation.go:345`–`:346`).
- **Status:** GAP.

### PAM-L-03 — a killed or denied activation does not appear against its binding
- **Pre:** `B-pam` with one `killed` and one `denied` record.
- **Input:** `Eligible(alice)`.
- **Expect:** `Activation: nil`, `Held: false` — only `pending` or `Live` records are indexed (`activation.go:337`–`:341`).
- **Status:** GAP.

### PAM-L-04 — an expired activation does not appear either
- **Pre:** `B-pam`, activation `active` with `Expiry` in the past.
- **Expect:** `Activation: nil`, `Held: false`. Note the consequence: the operator sees "eligible" with no trace of the window they just held; `Activations()` (`activation.go:392`) is the history view and **is not exposed over HTTP** (Q5).
- **Status:** GAP.

### PAM-L-05 — `Eligible` returns a stable order
- **Expect:** sorted by `Binding.Scope` (`activation.go:355`). Two bindings at the same scope have an unspecified relative order — the sort is not total, and `sort.Slice` is not stable.
- **Status:** GAP; see Q7.

### PAM-L-06 — the pending queue is filtered to what the caller could decide
- **Pre:** pending requests at `/secrets` (from `alice`) and at `/clusters` (from someone else); caller is `dave`, `domain-admin @ /clusters`.
- **Input:** `GET /v1/pam/pending`.
- **Expect:** only the `/clusters` request. `handler.go:361`–`:366` filters by `Authorize(admin, a.Scope)`.
- **Status:** GAP. The e2e test has exactly one pending request and one admin (`test/pam/run.sh:85`), so the filter is never exercised as a filter.

### PAM-L-07 — the kernel's `PendingActivations` is deliberately unfiltered
- **Input:** `Kernel.PendingActivations(ctx)`.
- **Expect:** every pending request in the domain, regardless of caller (`activation.go:404`–`:417`) — the filtering contract belongs to the dialect. Pin this so a future dialect author cannot mistake the kernel call for a safe one.
- **Status:** GAP.

### PAM-L-08 — the queue is ordered oldest-first
- **Expect:** ascending `RequestedAt` (`activation.go:415`), while `Activations()` is newest-first (`activation.go:399`). Opposite orders on two adjacent APIs; pin both.
- **Status:** GAP.

### PAM-L-09 — a caller sees their own pending request in the queue but cannot act on it
- **Pre:** `alice` is `domain-admin @ /` and has her own pending request at `/secrets`.
- **Input:** `GET /v1/pam/pending`, then `approve`.
- **Expect (today):** her own request is listed (the filter at `handler.go:361` has no self-exclusion), and approving it fails with the separation-of-duties error. Decide whether the queue should hide it (Q8) — listing an item that can only ever fail is a UX trap in the one place operators must not be confused.
- **Status:** GAP.

### PAM-L-10 — the pending filter honours the caller's *own* activated authority
- **Pre:** `bob` is eligible-only for `domain-admin @ /`, with a live activation.
- **Expect:** the queue is populated for him while the activation is live and empty after it expires — the filter calls the same `HasAuthority`.
- **Status:** GAP.

---

## 10. G — Step-up (PAM-S)

### PAM-S-01 — a missing required AMR factor refuses the request
- **Pre:** `B-step` (`step_up_amr: ["hwk"]`).
- **Input:** request at `T0` with `SessionAMR: ["pwd"]`.
- **Expect:** error naming the missing factor and the ones held (`activation.go:197`–`:202`); no record written.
- **Status:** COVERED — `activation_test.go:331`.

### PAM-S-02 — stale authentication refuses the request
- **Pre:** `B-step` (`step_up_max_age_sec: 300`).
- **Input:** request at `2000` with `SessionAMR: ["pwd","hwk"]`, `SessionAuthTime: 1000`.
- **Expect:** error containing "Re-authenticate" (`activation.go:203`–`:208`).
- **Status:** COVERED — `activation_test.go:336`.

### PAM-S-03 — the right factor, recently, is accepted
- **Input:** request at `1100` with `["pwd","hwk"]`, `authTime 1000`.
- **Expect:** accepted.
- **Status:** COVERED — `activation_test.go:344`.

### PAM-S-04 — `SessionAuthTime: 0` is treated as stale, not as "never expires"
- **Pre:** `B-step`.
- **Input:** `SessionAMR: ["hwk"]`, `SessionAuthTime: 0`, at `T0`.
- **Expect:** refused by the explicit `authTime == 0` clause (`activation.go:203`). The zero value must fail closed.
- **Status:** GAP — and this is exactly the clause a refactor would drop.

### PAM-S-05 — the freshness boundary is exact
- **Pre:** `B-step` (`max age 300`), `authTime 1000`.
- **Input:** requests at `1300` and `1301`.
- **Expect:** accepted, then refused (`nowSec - authTime > StepUpMaxAgeSec`).
- **Status:** GAP.

### PAM-S-06 — `step_up_amr` with no max age checks factors only
- **Pre:** `B-pam` + `step_up_amr: ["hwk"]`, no `step_up_max_age_sec`.
- **Input:** `["hwk"]`, `authTime` far in the past.
- **Expect:** accepted (`activation.go:203` guard is `> 0`).
- **Status:** GAP.

### PAM-S-07 — an empty `step_up_amr` skips step-up entirely, even with a max age set
- **Pre:** `B-pam` + `step_up_max_age_sec: 300`, no `step_up_amr`.
- **Input:** any request with a stale `authTime`.
- **Expect (today):** accepted — `checkStepUp` returns at `activation.go:184`–`:186` before the freshness test ever runs. A binding that asks only for freshness silently asks for nothing. See Q9.
- **Status:** GAP.

### PAM-S-08 — multiple required factors need all of them
- **Pre:** `step_up_amr: ["hwk","otp"]`.
- **Input:** `SessionAMR: ["hwk"]`.
- **Expect:** refused, error naming `["otp"]` only.
- **Status:** GAP.

### PAM-S-09 — the requester cannot assert their own AMR over the wire
- **Pre:** `B-step`.
- **Input:** `POST /v1/pam/activate` with an extra `amr` / `session_amr` field in the body.
- **Expect:** ignored — the body struct at `handler.go:315`–`:319` has three fields, and the facts come from the session (`handler.go:326`, `activation.go:376`–`:377`).
- **Status:** GAP at the HTTP layer.

### PAM-S-10 — step-up is unreachable end-to-end today
- **Observation:** every session-minting path sets AMR to a fixed value — `"genesis"` (`cmd/signet/main.go:280`, `:300`, `:439`), `"operator"` (`cmd/signet/main.go:688`), or the attestation verifier's name (`kernel.go:133`). There is no re-authentication endpoint and no way to add a factor to a live session, so a binding carrying `step_up_amr` can never be activated by any real client.
- **Expect:** either an e2e test proving a step-up binding *can* be satisfied, or an explicit note in `docs/13:218` that the field is unusable pending E-05.
- **Status:** GAP (documentation partially acknowledges the crypto limit at `docs/13:218`, but not the reachability one).

---

## 11. H — Containment: what an activation must never widen (PAM-N)

### PAM-N-01 — an activation does not widen the role
- **Pre:** `B-narrow` (`kv-reader`), live activation.
- **Input:** `HasAuthority(alice, write, /secrets/app/x, 1010)`.
- **Expect:** `false`.
- **Status:** COVERED — `activation_test.go:411`.

### PAM-N-02 — an activation does not widen the scope
- **Input:** `HasAuthority(alice, read, /secrets/other, 1010)`.
- **Expect:** `false`.
- **Status:** COVERED — `activation_test.go:414`; e2e via the `/v1/trust/bundle` probe at `test/pam/run.sh:106`.

### PAM-N-03 — an activation does not confer the *approver's* authority
- **Pre:** `B-narrow` on `alice`; `carol` (`domain-admin @ /`) approves.
- **Input:** `HasAuthority(alice, admin, /, ...)`.
- **Expect:** `false`. What is conferred is the binding, never the granter's reach.
- **Status:** GAP (e2e `test/pam/run.sh:106` covers the shape of this but for a non-approval binding).

### PAM-N-04 — an activation on one binding does not activate another
- **Pre:** `alice` holds two PAM bindings, `B-pam` and `B-narrow`; only `B-pam` is activated.
- **Expect:** authority at `/secrets` yes, at `/secrets/app` (via `B-narrow`'s role) still gated — the match in `policy.go:67` is by binding ID.
- **Status:** GAP.

### PAM-N-05 — a live activation must not launder into a standing grant **(BUG / design)**
- **Pre:** `alice` holds `B-admin-pam` (`domain-admin @ /`, activation required, `max 600`); activation live at `1010`.
- **Input:** `PutBinding{Grantor: alice, Subject: alice, Role: kv-admin, Scope: /secrets}` with no `not_after` and no `activation_required`.
- **Expect:** something that prevents the elevated window from minting an authority that outlives it — refusal, or automatic inheritance of the activation's expiry.
- **Actual:** accepted; `alice` then has `write @ /secrets` **forever**, long after the 600s window closes. `applyPutBinding`'s narrowing check (`apply.go:139`–`:147`) asks only "does the grantor have admin here *now*", with no propagation of `NotAfter` or of the PAM flags.
- **Status:** **BUG / open design question** — §14 F3, Q10. Verified. It falsifies the "kill ends the access, nothing to sweep" story of `docs/13:196`–`:198` for any activation that includes `admin`.

### PAM-N-06 — rewriting the binding under a live activation
- **Pre:** `B-narrow` (`kv-reader @ /secrets/app`) with a live activation; an admin re-`PutBinding`s the **same binding ID** as `domain-admin @ /`, still `activation_required`.
- **Input:** `HasAuthority(alice, admin, /, 1010)`.
- **Actual:** `true` — the live activation now confers the *new* role and scope, while the `Activation` record still reads `kv-reader @ /secrets/app` (`Role`/`Scope` are snapshotted at `activation.go:152`). The audit trail and the enforced authority disagree.
- **Status:** GAP / suspected design hole — §14 F4, Q11. Verified.

### PAM-N-07 — an approved activation whose binding became held-outright while pending
- **Pre:** `B-appr` pending; the binding is rewritten with `activation_required: false`.
- **Input:** `carol` approves.
- **Actual:** accepted; an `active` activation now exists over a binding that needs none. Harmless in authority terms (already held) but inconsistent with the request path, which refuses exactly this shape (`activation.go:111`–`:114`).
- **Status:** GAP. Verified.

### PAM-N-08 — stacking a second activation while one is live
- **Pre:** `B-pam` with a live activation.
- **Input:** a second `RequestActivation` at `1100`.
- **Expect:** error naming the live one and its expiry (`activation.go:143`–`:147`).
- **Status:** COVERED — `activation_test.go:307`; e2e `test/pam/run.sh:103`.

### PAM-N-09 — stacking on a *pending* request
- **Pre:** `B-appr` with a pending request.
- **Input:** a second request.
- **Expect:** error "still pending a decision" (`activation.go:138`–`:141`) — a distinct branch from PAM-N-08 and untested.
- **Status:** GAP.

### PAM-N-10 — a new activation is allowed once the old one has expired
- **Pre:** `B-pam`, activation expired at `1600`.
- **Input:** request at `1601`.
- **Expect:** accepted — `Live` is false, so neither guard fires.
- **Status:** GAP (the kill variant is covered at `activation_test.go:297`; the expiry variant is not).

### PAM-N-11 — a denied request does not block a fresh one
- **Pre:** `B-appr` with a `denied` record.
- **Input:** a new request.
- **Expect:** accepted.
- **Status:** GAP.

---

## 12. I — Ordering, concurrency, and replay (PAM-O)

The structural claim: **every state-dependent check is inside `Apply`**
(`apply.go:23`–`:26`, `:68`–`:71`), `Apply` runs inside one bolt write
transaction per Raft entry (`internal/fsm/fsm.go:57`–`:69`), and Raft applies
entries one at a time in log order. So the interleavings below are *not*
races in the store; each proposal sees the committed effect of its predecessor.
What remains at risk is (a) checks that live *outside* `Apply`, and (b) the
clock, which `Apply` cannot read and therefore cannot sanity-check.

### PAM-O-01 — two approvals proposed concurrently **(handled by construction)**
- **Pre:** `B-appr2` (`min_approvers: 2`), pending; `carol` and `bob` both `POST /v1/pam/decide` simultaneously.
- **Expect:** serialized. The second `Apply` reads the `Approvals` list the first wrote, so the duplicate-approver check (`activation.go:249`) and the count (`activation.go:298`–`:302`) are both evaluated against committed state. Two approvals from the *same* principal racing each other: the first appends, the second is refused.
- **Status:** handled by construction; GAP as a test. A deterministic two-entry-in-order test through `fsm` would pin it against a future refactor that moves any check to propose time.

### PAM-O-02 — kill racing an approval **(handled by construction)**
- **Pre:** `B-appr` pending; `kill` and `approve` proposed at once.
- **Expect:** whichever commits first wins. Kill-then-approve → approve fails "is killed, not pending" (`activation.go:238`). Approve-then-kill → the activation is briefly live and then killed; both records exist in the audit chain.
- **Status:** handled by construction; GAP as a test.

### PAM-O-03 — a request racing the deletion of its binding **(handled by construction, unreachable in practice)**
- **Expect:** `findBinding` at `activation.go:102` runs in the same serialized transaction, so the request either sees the binding or does not. The approve path re-reads it (`activation.go:260`).
- **Reality:** **there is no Op that deletes a binding** — no `DeleteBinding` kind in `op.go:29`–`:51`, no `tx.Delete(store.BucketBindings, ...)` outside `activation_test.go:267`. The only production way to end eligibility is `not_after`, or overwriting the binding by ID. The race is therefore untestable end-to-end today, and revocation-by-deletion is itself a missing feature (Q2).
- **Status:** GAP (blocked on a revocation path existing).

### PAM-O-04 — replay of a `RequestActivation` through Raft **(handled by construction)**
- **Pre:** an applied `RequestActivation`; the entry is replayed (restart before the applied-index advanced, or a backup-segment restore).
- **Expect:** identical state. Two mechanisms, either sufficient: `fsm.go:44` skips entries at or below the applied index; and even without it, the stacking guard (`activation.go:134`–`:148`) refuses using the *op's own* `AtSec`, so `Live(o.AtSec)` re-evaluates identically, and the record's key/content are byte-identical anyway.
- **Status:** handled by construction; GAP as a test. Worth an explicit "apply the same op twice, assert the store is unchanged" case, because `Apply` purity is a docs/15 contract.

### PAM-O-05 — replay of an `ActivationAction` **(handled by construction)**
- **Expect:** the second application finds the record no longer `pending` and refuses (`activation.go:238`), leaving `Approvals` at length 1 rather than double-counting the same approver twice. The duplicate-approver check is a second line of defence.
- **Status:** handled by construction; GAP as a test. This is the highest-value replay case: a double-counted approval would silently satisfy `min_approvers: 2` with one human.

### PAM-O-06 — clock movement between propose and apply **(genuine gap)**
- **Pre:** `AtSec` is stamped by the leader at propose time (`kernel.go:58`–`:60`) and `Apply` never reads a clock.
- **Risk:** nothing bounds `AtSec` against the store's own notion of time. A leader whose clock jumps **backwards** can approve a request whose eligibility has already expired (`activation.go:274` compares `o.AtSec` to `b.NotAfter`). A leader whose clock jumps **forwards** produces an activation that is dead on arrival, or an eligibility check that refuses a still-valid binding.
- **Expect:** a sanity bound — e.g. reject an Op whose `AtSec` is more than N seconds behind the last applied entry's `AtSec` (the store already carries `term`/`index` per write, `store.go:88`–`:92`). `docs/10-testing-strategy.md:20` already names **clock-skew bounds (TIME-1)** as a required property; PAM is the sharpest instance of it.
- **Status:** **GAP — genuine, not by construction.** See Q12.

### PAM-O-07 — a follower's clock disagrees at read time **(genuine gap)**
- **Pre:** activation with `Expiry: 1600`; node A's clock reads 1590, node B's reads 1610.
- **Actual:** `HasAuthority` is called with `k.now().Unix()` at each node (`kernel.go:474`), so the same activation is live on A and dead on B. Reads are served from any node's local store; only writes go through the leader.
- **Expect:** documented and bounded (this is inherent to time-based expiry), but the boundary should be a named test with an explicit skew budget.
- **Status:** GAP.

### PAM-O-08 — `Actor2` is trusted over `Header.Actor` **(genuine gap)**
- **Input:** `ActivationAction{Header.Actor: eve, Actor2: carol, Verb: approve}` applied directly.
- **Actual:** accepted, recorded as `Approvals: [carol]`. `Apply` uses `o.Actor2` for the self-approval check (`activation.go:244`), the duplicate check (`:250`), the authority check (`:287`) and the recorded approver (`:297`), and never compares it to `Header.Actor`. The two are only equal because `DecideActivation` sets both (`activation.go:386`).
- **Expect:** `Apply` should reject `Actor2 != Header.Actor`, or the field should be removed in favour of `Header.Actor`. As it stands the identity that separation-of-duties turns on is validated nowhere inside the serialized writer — precisely the placement `docs/13:192` claims to avoid.
- **Status:** **GAP.** Verified. See Q13.

### PAM-O-09 — `Subject` is trusted over `Header.Actor` on the request path
- **Input:** `RequestActivation{Header.Actor: eve, Subject: alice, SessionAMR: ["hwk"], SessionAuthTime: <now>}` applied directly against a `B-step` binding.
- **Actual:** accepted — `eve` obtains an activation for `alice`, asserting `alice`'s step-up facts. Only `Kernel.RequestActivation` (`activation.go:375`) binds `Subject` to the session's principal.
- **Expect:** same remedy as PAM-O-08.
- **Status:** **GAP.** Verified.

### PAM-O-10 — proposals against a stale leader
- **Pre:** a partitioned/old leader.
- **Expect:** `Propose` fails at `internal/fsm/node.go:167` rather than applying locally; `pamActivate`'s read-back at `handler.go:331` sees only committed state.
- **Status:** GAP; general to the FSM rather than PAM-specific, but PAM's read-after-write in `handler.go:331`–`:343` is the one place a dialect assumes its own write is already visible locally.

---

## 13. J — Dialect and CLI surface (PAM-X)

### PAM-X-01 — every `/v1/pam/*` route requires a session
- **Input:** each of the four routes with no token and with a garbage token.
- **Expect:** `403 permission denied` (`handler.go:296`, `:310`, `:348`, `:371`). What a principal is eligible for is itself sensitive (`handler.go:145`–`:147`).
- **Status:** GAP.

### PAM-X-02 — `activate` returns the resulting state
- **Input:** `POST /v1/pam/activate` on `B-pam` and on `B-appr`.
- **Expect:** `data.state` = `active` with a non-zero `expiry`, versus `pending` with `expiry: 0`; CLI prints the two different explanations (`cmd/signet/pam.go:167`–`:179`).
- **Status:** PARTIAL — e2e prints but does not assert (`test/pam/run.sh:80`).

### PAM-X-03 — a malformed body is rejected cleanly
- **Input:** non-JSON, and `for_seconds` as a string.
- **Expect:** `400 malformed request body` (`handler.go:320`, `:382`), never a 500.
- **Status:** GAP.

### PAM-X-04 — `decide` with an unknown verb
- **Input:** `{"verb":"revoke"}`.
- **Expect:** a 400 carrying the kernel's "unknown verb" message. Note it reaches `Apply` and therefore consumes a Raft entry and an audit record before being rejected.
- **Status:** GAP.

### PAM-X-05 — `signet pam activate` requires `-binding` and `-reason`
- **Expect:** local refusals with the long-form explanation (`cmd/signet/pam.go:135`–`:143`).
- **Status:** COVERED for `-reason` — `test/pam/run.sh:75`. GAP for `-binding`.

### PAM-X-06 — `signet pam approve|deny|kill` require `-subject` and `-id`
- **Expect:** local refusal (`cmd/signet/pam.go:229`–`:231`).
- **Status:** GAP.

### PAM-X-07 — the audit chain records request, approval, deny and kill
- **Expect:** one `RequestActivation` record whose subject is `activation <id>: <reason>` and one `ActivationAction` record per decision, both with the acting principal (`apply.go:346`–`:350`); chain verifies.
- **Status:** PARTIAL — `test/pam/run.sh:124` verifies the chain but never inspects the entries. Nothing asserts the reason survives into the audit record, which is the stated purpose of requiring one (`cmd/signet/pam.go:22`–`:24`). Note the `ActivationAction` record does **not** name the subject principal, only the activation ID.

### PAM-X-08 — refused activations are still audited
- **Pre:** any refusal above (self-approval, stacking, step-up).
- **Expect:** an audit record with `accepted: false` and the error text (`apply.go:331`–`:334`, `fsm.go:58`–`:62`). Failed elevation attempts are the interesting ones.
- **Status:** GAP.

### PAM-X-09 — a genesis config carrying every PAM field round-trips
- **Input:** a `GenesisConfig` binding with all six PAM fields (`cmd/signet/main.go:104`–`:117`).
- **Expect:** the stored `Binding` matches field for field.
- **Status:** PARTIAL — `test/pam/run.sh:47`–`:50` sets three of six; `min_approvers`, `step_up_amr` and `step_up_max_age_sec` are never exercised end-to-end.

### PAM-X-10 — there is no runtime way to create a PAM binding
- **Observation:** `PutBindingSpec` (`kernel.go:397`) carries every PAM field, but no CLI or HTTP route reaches it — grep finds the flags only in the genesis config struct. PAM bindings can be created **only** at genesis.
- **Status:** GAP / product limitation. See Q14.

---

## 14. Suspected live bugs

All five were reproduced against the current tree in a local-disk mirror
(`make test` semantics, probe file kept out of the repo).

**F1 — the approval path throws away the requested duration.**
`activation.go:304` is `clampExpiry(b, 0, o.AtSec)`; `0` means "give the
maximum" (`activation.go:172`). A request for 10 minutes on a binding whose
`max_activation_sec` is an hour becomes an hour on approval. `Activation`
(`model.go:69`–`:87`) has no field carrying the requested duration, so the
information is destroyed at request time and cannot be recovered at approval
time. Observed: requested 600s → 3600s window. `test/pam/run.sh:80` asks for
`-for 10m` against `max_activation_sec: 3600` and silently receives an hour.
Severity: over-grant on exactly the bindings judged sensitive enough to need
approval. Fix touches the model (persist `ForSeconds`) plus `activation.go:304`.
Scenario PAM-C-06.

**F2 — `kill` and `deny` have no authorization at all.**
`activation.go:222`–`:235` checks only the current state; `handler.go:370`–`:395`
checks only that the caller has *a* session, while its comment at `:386` claims
"authority to decide is re-checked inside Apply". Only `approve` calls
`HasAuthority` (`activation.go:287`). Any authenticated principal — including one
holding no binding anywhere — can kill another principal's live activation
(denial of privileged access mid-incident) or deny their pending request, with
`DecidedBy` recorded as the attacker in durable state and in the audit chain.
The only obstacle is knowing the activation ID, which is obscurity, not
authorization. Scenarios PAM-K-07, PAM-K-08; interacts with PAM-K-09 (self-release
must survive the fix).

**F3 — an activation that includes `admin` launders into a standing grant.**
While a `domain-admin` activation is live, the holder can `PutBinding` themselves
a permanent binding with no `not_after` and no `activation_required`; it survives
the window's expiry and any kill. `applyPutBinding` (`apply.go:139`–`:147`) asks
only whether the grantor has admin *now* and propagates neither `NotAfter` nor
the PAM flags. This is arguably inherent to "admin means admin", but it directly
falsifies the claim at `docs/13:196`–`:198` that an expiring or killed activation
ends the access "with nothing to sweep". At minimum it needs a stated position;
better, a binding minted under an activation should inherit that activation's
expiry as an upper bound. Scenario PAM-N-05.

**F4 — a binding rewrite silently re-points a live activation.**
`PutBinding` writes by `subject/id` (`apply.go:160`), so re-using a binding ID
replaces role and scope in place. A live activation keyed on that ID then confers
the **new** authority, while the `Activation` record continues to display the
role and scope snapshotted at request time (`activation.go:152`). Enforcement and
audit disagree, and the operator-facing `pam eligible` output shows the old
values. Widening still requires admin at the new scope, so this is a record-integrity
bug rather than a direct escalation — but the record is the product here.
Scenario PAM-N-06.

**F5 — eligibility cannot be revoked.**
There is no binding-deletion Op (`op.go:29`–`:51`). `docs/13:200` and
`activation.go:258`–`:272` describe revoking eligibility while a request is
pending as a supported flow, and `activation_test.go:259` tests it by deleting
the record straight out of the store — a path no production caller can take.
Today the only ways to end eligibility are `not_after` and overwriting the
binding by ID. Scenario PAM-P-07, PAM-O-03.

Two lesser findings, recorded but not called bugs: `Apply` accepts an empty
reason (PAM-A-04) and accepts `Subject`/`Actor2` values unrelated to the header's
actor (PAM-O-08, PAM-O-09) — in both cases the real check lives in the service
layer, which the docs explicitly say is the wrong place for it.

---

## 15. Coverage summary

| Group | Scenarios | Covered | Partial | Gap | Bug |
|---|---|---|---|---|---|
| A — eligibility vs possession (PAM-E) | 7 | 4 | 2 | 1 | — |
| B — activation without approval (PAM-A) | 8 | 4 | 1 | 3 | — |
| C — approval (PAM-P) | 16 | 9 | 1 | 6 | — |
| D — clamping (PAM-C) | 10 | 2 | — | 7 | 1 |
| E — kill and deny (PAM-K) | 10 | 2 | — | 6 | 2 |
| F — listings (PAM-L) | 10 | — | 1 | 9 | — |
| G — step-up (PAM-S) | 10 | 3 | — | 7 | — |
| H — containment (PAM-N) | 11 | 3 | — | 7 | 1 |
| I — ordering & concurrency (PAM-O) | 10 | — | — | 10 | — |
| J — dialect & CLI (PAM-X) | 10 | — | 4 | 6 | — |
| **Total** | **102** | **27** | **9** | **62** | **4** |

(The four `BUG` rows are counted once each, in the group where they are
specified; F5 is recorded as a GAP under PAM-P-07 / PAM-O-03 since the missing
feature is what blocks the test.)

Of the 102, **27 are proven today** (a further 9 partially) by `internal/kernel/activation_test.go`
(16 tests) and `test/pam/run.sh` (8 steps) — a genuinely good spine covering
every one of the four documented semantics. The gaps cluster in five places:
the entire `Eligible`/pending read model, the `deny` verb, the approval path's
clamping, everything about ordering and identity inside `Apply`, and the HTTP
surface.

### Top 5 gaps by risk

1. **Authorization on `kill`/`deny` (F2, PAM-K-07/08)** — a live authorization
   hole reachable from any valid session, plus false attribution in the audit
   chain. Highest severity, cheapest fix.
2. **The approval path's expiry (F1, PAM-C-06)** — silent over-grant on the
   most sensitive class of binding; no test in the tree would notice.
3. **Identity fields trusted inside `Apply` (PAM-O-08/09)** — separation of
   duties, the feature's central claim, turns on a field the serialized writer
   never validates against the header.
4. **Replay of an `ActivationAction` (PAM-O-05)** — safe today, by two
   independent mechanisms, and untested. A double-counted approval would satisfy
   `min_approvers: 2` with one human; this is the invariant most worth pinning
   before either mechanism is refactored.
5. **The `Eligible`/pending read model (PAM-L-01..10)** — zero unit coverage of
   the operator's entire view of their own privileges, including the queue filter
   that is the only thing preventing one principal from enumerating another's.

---

## 16. Questions for the maintainer

1. **Q1 — where does the reason requirement belong?** It is enforced at
   `activation.go:366` (service) but not in `Apply`, while `docs/13:192` says
   these checks live in `Apply` "not in a caller that could be bypassed". Move it,
   or state that non-empty-reason is a UX rule rather than an invariant?
2. **Q2 — is revocation of eligibility in scope for the MVP?** Without a
   binding-deletion Op, `not_after` is the only revocation, and the
   "removed while pending" semantic (`docs/13:200`) is untestable in production.
3. **Q3 — may a subject release their own activation early?** It works today only
   because `kill` is unauthorized (F2). If it is intended, the fix for F2 must
   admit `Actor2 == a.Subject` explicitly.
4. **Q4 — should `kill` be legal on an expired-but-`active` record?** It is
   today, producing a `killed` record for a window that had already closed.
5. **Q5 — should activation *history* be reachable over HTTP?** `Activations()`
   exists (`activation.go:392`) but no route exposes it, so `pam eligible` shows
   nothing about a window once it lapses, and the record-keeping the feature
   exists for is only readable via the audit log.
6. **Q6 — may an approver's admin authority itself be an activation?** It can
   today. Requiring approvers to hold admin *outright* would be defensible, and
   is a one-line change at `activation.go:287`.
7. **Q7 — `Eligible`'s sort is by scope only** (`activation.go:355`), which is
   not a total order; two bindings at the same scope come back in unspecified
   order. Add role/ID as a tiebreak?
8. **Q8 — should the pending queue hide the caller's own requests?** They are
   listed today and can only ever fail to be approved (PAM-L-09).
9. **Q9 — `step_up_max_age_sec` without `step_up_amr` is silently inert**
   (`activation.go:184`). Should a freshness-only requirement be honoured, or
   should `applyPutBinding` reject the combination?
10. **Q10 — what should a binding minted *during* an activation inherit?**
    (F3.) Nothing, the activation's expiry, or a refusal?
11. **Q11 — should binding IDs be re-writable at all?** (F4.) Re-`PutBinding`ing
    an ID silently re-points every live activation over it. Making bindings
    immutable — new ID for a new shape — would close this and simplify the
    activation record's meaning.
12. **Q12 — what is the clock-skew budget?** `docs/10:20` names TIME-1 as a
    required property; PAM has no bound on `AtSec` at all (PAM-O-06/07).
13. **Q13 — keep `Actor2` and `Subject` as separate fields?** If they must always
    equal `Header.Actor`, `Apply` should enforce it or the fields should go.
14. **Q14 — how are PAM bindings created after genesis?** `PutBindingSpec`
    supports every field but nothing reaches it from the CLI or the API
    (PAM-X-10), so PAM policy is genesis-only today.
15. **Q15 — is `min_approvers` meaningful without `approval_required`?** Set
    alone, it is silently ignored and the activation goes live immediately
    (verified). Reject the combination at `applyPutBinding`?
