# 05 — Test plan: trust bundles and the multi-domain fabric

**Status: Draft** · Area owner: trust
Covers `internal/trust` (bundle, state, fabric), `internal/kernel/trust.go`,
`cmd/signet/trust.go`, the `/v1/trust/*` routes in
`internal/dialect/vaultkv/handler.go`, and the ceremony half of
`cmd/signet/ca.go` that feeds a bundle.

Design source of truth: [`docs/02-trust-topology.md`](../02-trust-topology.md),
particularly "Anchors, issuers, and the two trust flows" (02:200–348) and
"Sibling power over a sibling" (02:164–198).

---

## 0. What this plan is for

A trust bundle is the only artifact in Signet that a consumer is *told* not to
trust on its face. Everything it is worth comes from what it refuses. So the
negative cases below are not the tail of this plan — they are the plan, and the
positive cases exist mostly to prove the refusals are scoping rather than
breakage.

Three claims in docs/02 are load-bearing and each gets its own block of
scenarios:

1. **Publishing is a root ceremony.** An issuing key may mint leaves; it may not
   say who is trusted (`internal/trust/bundle.go:5–28`, docs/02:311–324).
2. **One artifact, two anchor selections.** The same signed bundle serves a
   cascade consumer (root anchor) and a pinned consumer (one issuer anchor);
   selection is the consumer's local choice (docs/02:205–231,
   `bundle.go:315–331`).
3. **A valid path is not proof that a domain vouched.** Under a shared
   organizational root a sibling's issuer reaches the same anchor, so the chain
   must additionally run only through issuers *that domain published*
   (docs/02:164–198, `fabric.go:159–171`, `fabric.go:231–257`).

Claim 3 is currently **not true of the shipping binary**. See
[§10 Suspected live bugs](#10-suspected-live-bugs), BUG-1, which is
demonstrated end to end below and which the existing fabric test misses for an
ordering reason.

### Conventions

| Field | Meaning |
|---|---|
| **ID** | Stable. Never renumber; retire an ID rather than reuse it. |
| **Pre** | Preconditions — the fixture state assumed before the input. |
| **Input** | The exact call or command. Library scenarios name the Go call; ceremony scenarios name the CLI invocation. |
| **Expect** | The required outcome. For refusals, the error must be *specific* — a generic failure passes the assertion but fails review. |
| **Covered** | `file:line` of the existing test, or **GAP**. |

Negative scenarios are marked **⊘**. All builds and test runs go through
`make test` / `make build` / `make test-trust` / `make test-fabric` — the tree
is on NFS without `flock`, so bare `go test` fails (`Makefile:1–6`).

### Standard fixtures

Named once so scenarios can refer to them.

- **F-CASCADE** — one org root `Example Root CA`; issuers `home issuer`,
  `gcp issuer` beneath it; domains `home.example.net`, `gcp.example.net`. This
  is `test/fabric/run.sh:37–69`, and `mkCA` in
  `internal/trust/bundle_test.go:29–55`.
- **F-SOVEREIGN** — additionally `AWS Root CA` (self-signed, unrelated) with
  `aws issuer` beneath it, domain `aws.example.net`
  (`test/fabric/run.sh:38–41`).
- **F-CONSUMER** — a `trust.State` file holding one `DomainState` per domain
  (`state.go:19–36`), built by `signet trust fetch` or `State.Peer`.
- **F-NODE** — a genesis'd node with an installed issuer, serving
  (`test/trust/run.sh:40–59`).

---

## 1. TB — Bundle authoring: the root ceremony

`Build` (`bundle.go:141–156`), `Sign` (`bundle.go:159–184`), `caBundle`
(`cmd/signet/trust.go:81–174`).

| ID | Scenario | Pre | Input | Expect | Covered |
|---|---|---|---|---|---|
| TB-01 | The ceremony runs where the root key is | F-CASCADE root dir with `root.crt` + `root.key`, ≥1 cert in `root/issuers/` | `signet ca bundle -root root -domain home.example.net -out b.json -max-age 720h` | Exit 0; `b.json` written; stdout names domain, epoch, anchor count, max age; the root fingerprint is printed as the thing consumers must pin (`cmd/signet/trust.go:163–173`) | `test/trust/run.sh:52–54` |
| TB-02 | The bundle carries a root anchor, one issuer anchor per issuer, and the full issuer set | as TB-01 with 2 issuers | decode `b.json` payload | `anchors` = 1×`root` + 2×`issuer`; `issuers` = 2 entries; each `spki` = `sha256:` + base64url(SHA-256 of SPKI) (`bundle.go:134–137`) | `bundle_test.go:106–124` (library); **GAP** at CLI level — no assertion on the emitted artifact's shape |
| TB-03 | Metadata is complete: epoch, issued-at, max-age | as TB-01 | decode payload | `version=1`, `epoch≥1`, `issued_at` ≈ now, `max_age_sec=2592000` (`bundle.go:151–155`) | **GAP** |
| TB-04 | The epoch advances at the only place that can publish | TB-01 run once (`root/bundle.epoch` = 1) | re-run `ca bundle` with no `-epoch` | epoch 2; `root/bundle.epoch` updated (`cmd/signet/trust.go:132–140,159–161`) | Implicitly `test/trust/run.sh:138` (epoch 2 published); **GAP** on the epoch-file mechanics and on epoch surviving a lost node |
| TB-05 | A hardware-held root signs the same artifact | `root.ref` present, no `root.key`, SoftHSM token | `signet ca bundle -root root -seal 'pkcs11:...' ...` | Bundle verifies identically; `openRoot` takes the seal path (`cmd/signet/trust.go:530–547`) | **GAP** — `make test-hsm` covers the seal, not the bundle ceremony |
| TB-06 ⊘ | A bundle with no anchors would tell a consumer to trust nothing | — | `Build(domain, 1, 1h, nil, nil, now)` | error "a bundle with no anchors" (`bundle.go:145–147`) | `bundle_test.go:308–310` |
| TB-07 ⊘ | A bundle with no max-age can never be detected as stale | — | `Build(domain, 1, 0, anchors, nil, now)` | error "max-age must be positive" (`bundle.go:148–150`) | `bundle_test.go:311–313` |
| TB-08 ⊘ | A bundle that does not name its domain | — | `Build("", 1, 1h, anchors, nil, now)` | error "must name its domain" (`bundle.go:142–144`) | `bundle_test.go:314–316` |
| TB-09 ⊘ | A ceremony with an empty issuer directory | `root/issuers/` empty | `signet ca bundle -root root -domain d -out b.json` | Refusal naming the directory: anchors with no path-building material (`cmd/signet/trust.go:111–116`) | **GAP** |
| TB-10 ⊘ | Bundles are ECDSA-signed; another key type is refused at signing | RSA root signer | `Sign(p, rsaSigner)` | error "bundles are signed with ECDSA" (`bundle.go:164–167`) | **GAP** |
| TB-11 | Issuer file naming makes re-signing replace rather than accumulate | issuer signed twice with the same key | two `ca sign-issuer` runs, then `ca bundle` | one entry per key in `root/issuers/` (files named by SPKI, `cmd/signet/ca.go:394–405`); the bundle does not carry duplicates | **GAP** |
| TB-12 ⊘ | **The bundle for domain D publishes only D's issuers** | F-CASCADE: org root has signed both `home issuer` and `gcp issuer`, so both are recorded in `org-root/issuers/` (`cmd/signet/ca.go:399–404`) | `signet ca bundle -root org-root -domain gcp.example.net -out gcp.json` | gcp's bundle must publish **only** `gcp issuer`, as both an issuer anchor and in `issuers` | **GAP — and currently FAILS.** Measured: the emitted bundle carries `anchors: [root Example Root CA, issuer home issuer, issuer gcp issuer]`, `issuers: [home issuer, gcp issuer]`. `readIssuerDir` reads the whole directory with no `-domain` filter (`cmd/signet/trust.go:107–128`). See BUG-1. |

---

## 2. TV — Consumer verification of a bundle

`Verify` (`bundle.go:215–311`). The ordering is contractual: signer identity,
then integrity, then domain, then rollback, then freshness (`bundle.go:210–214`).

| ID | Scenario | Pre | Input | Expect | Covered |
|---|---|---|---|---|---|
| TV-01 | A bundle signed by the pinned root is accepted | F-CASCADE bundle, epoch 1 | `Verify(b, {PinnedSPKI: fp(root), Domain: "home.example.net", Now: now})` | Payload returned; `Domain`, `Epoch`, anchors, issuers intact | `bundle_test.go:112` |
| TV-02 | Verification is over the exact transmitted bytes | as TV-01 | re-marshal the decoded payload and compare to `base64decode(b.Payload)` | Byte-identical is *not* required of a verifier; the verifier must sign/check `raw` and never a re-serialization (`bundle.go:108–121`, `bundle.go:225–232,259`) | **GAP** — assert that a payload with reordered JSON keys still verifies (proves `raw` is used), and that a re-marshal round trip is never substituted |
| TV-03 | Accepting the same epoch again is allowed (idempotent refresh) | `LastEpoch=5` | `Verify` a bundle of epoch 5 | Accepted — `p.Epoch < opts.LastEpoch` is the refusal (`bundle.go:284`) | **GAP** (relied on by `trust fetch` re-runs) |
| TV-04 ⊘ | **Impostor root with the same common name** | real root `CN=Example Root CA`; attacker root, same CN, different key; attacker signs a well-formed bundle for the same domain | `Verify(forged, {PinnedSPKI: fp(realRoot)})` | Refusal: "not signed by the pinned key" (`bundle.go:268–272`). The CN must play no part | `bundle_test.go:154–164`; CLI: `test/trust/run.sh:102–106` |
| TV-05 ⊘ | **Tampered payload** — an extra issuer spliced in | valid bundle | mutate the decoded payload, re-base64, keep the original signature | Refusal: "signature does not verify" (`bundle.go:260–264`) | `bundle_test.go:167–184`; CLI (`max_age_sec` bumped): `test/trust/run.sh:108–117` |
| TV-06 ⊘ | Tampering that only reorders/renames anchors | valid bundle | swap `role` on two anchors, keep signature | Same refusal as TV-05 | **GAP** — proves the *whole* payload is signed, not a digest of selected fields |
| TV-07 ⊘ | **An unpinned read** | valid bundle | `Verify(b, {PinnedSPKI: "", ...})` | Refusal: "no pinned key was supplied … a bundle vouches for itself" (`bundle.go:216–220`). Must not fall back to the anchors it contains | `bundle_test.go:242–248`; CLI: `test/trust/run.sh:118–119` |
| TV-08 ⊘ | A bundle carrying no signatures at all | payload valid, `signatures: []` | `Verify` with a pin | Refusal: "carries no signatures" (`bundle.go:221–223`) | **GAP** |
| TV-09 ⊘ | Signed by the pinned key, but that key is not among the bundle's anchors | payload anchors only the issuer; root signs | `Verify(b, {PinnedSPKI: fp(root)})` | Refusal: "does not contain that key as an anchor" (`bundle.go:245–250`) | `bundle_test.go:288–302` |
| TV-10 ⊘ | **A bundle for a different domain** | bundle built for `home.example.net` | `Verify(b, {PinnedSPKI: fp(root), Domain: "aws.example.net"})` | Refusal naming both domains: "Trust domains are kept separate" (`bundle.go:275–280`). Never merged | `bundle_test.go:230–238`; CLI: `test/trust/run.sh:120–121` |
| TV-11 ⊘ | **A replayed older epoch at the consumer** | consumer has accepted epoch 5 (issuer b withdrawn); attacker serves the epoch-4 bundle that still lists b | `Verify(old, {LastEpoch: 5})` | Refusal: "Refusing to move backwards" (`bundle.go:284–289`) | `bundle_test.go:188–202`; CLI against real state: `test/trust/run.sh:149–150` |
| TV-12 ⊘ | **A stale bundle fails closed** | bundle with `max_age 1h` | `Verify(b, {Now: issued+2h})` | Refusal: "went stale at …", naming issued-at and max age (`bundle.go:296–304`). Not a warning | `bundle_test.go:206–216` |
| TV-13 ⊘ | **Clock skew must NOT extend life past max-age** | bundle with `max_age 1s` | `Verify(b, {Now: issued+2s, Skew: 5m})` | Refusal "went stale" — skew applies only to the future-dated check (`bundle.go:291–309`, and the reasoning at `bundle.go:199–207`) | `bundle_test.go:393–411`; with a real clock and the real binary: `test/trust/run.sh:127–132`. **This was a live bug** (docs/16:119–126) |
| TV-14 | Skew still does its actual job | bundle issued now | `Verify(b, {Now: now-30s, Skew: 5m})` | Accepted — a slightly slow clock must not read a fresh bundle as future-dated | `bundle_test.go:413–417` |
| TV-15 ⊘ | A bundle timestamped in the future | valid bundle | `Verify(b, {Now: issued-24h, Skew: 5m})` | Refusal: "is in the future" (`bundle.go:305–309`) | `bundle_test.go:219–226` |
| TV-16 ⊘ | An unknown format version | payload with `version: 2`, correctly signed | `Verify` with the right pin | Refusal: "format version 2 and this build understands 1" (`bundle.go:233–237`) | **GAP** — verified by probe to behave correctly, but nothing asserts it |
| TV-17 ⊘ | Malformed envelope: payload not base64, or not JSON | hand-built bundle | `Verify` | Distinct refusals (`bundle.go:225–232`), not a panic | **GAP** — candidate for `go test -fuzz` per docs/10:23–26 |
| TV-18 ⊘ | Signer's anchor certificate holds a non-ECDSA key | payload anchor is an RSA cert whose SPKI matches the pin | `Verify` | Refusal: "bundles are ECDSA-signed" (`bundle.go:255–258`) | **GAP** |
| TV-19 ⊘ | **An issuer-signed, issuer-anchored bundle** | payload anchors only `home issuer` (role `issuer`), signed by that issuer's key; consumer pinned to the issuer's SPKI | `Verify(b, {PinnedSPKI: fp(homeIssuer)})` | Per `bundle.go:5–18` and docs/02:311–324 this must be **refused**: an issuing key may not declare the trust set | **GAP — and currently ACCEPTED.** `Verify` requires only that the signer be *an* anchor (`bundle.go:245–250`), not the *root* anchor. See BUG-6 |
| TV-20 ⊘ | An unbounded max-age | payload with `max_age_sec` = 100 years, correctly signed | `Verify` 50 years later | Design question: FED-1 requires fail-closed on staleness (docs/02:394–396). Nothing caps `MaxAgeSec` at build (`bundle.go:148–150`) or at verify | **GAP** — measured: accepted. See Q-4 |

---

## 3. TA — Anchor selection and path building

`SelectAnchor` (`bundle.go:315–331`), `Pool` (`bundle.go:343–367`). This is
claim 2: **two anchor selections from one artifact**.

| ID | Scenario | Pre | Input | Expect | Covered |
|---|---|---|---|---|---|
| TA-01 | Cascade selection: the root anchor | verified payload with 1 root + 2 issuer anchors | `p.SelectAnchor(RoleRoot, "")` | The root anchor; `SPKI == fp(root)` | `bundle_test.go:115–121` |
| TA-02 | Pinned selection: one named issuer anchor | as TA-01 | `p.SelectAnchor(RoleIssuer, "issuer a")` | That issuer's anchor, not the root | `bundle_test.go:133–136`, `bundle_test.go:369–383` |
| TA-03 | **One artifact serves both** | one bundle, two consumers | both selections against the *same* verified payload | Both succeed; the artifact is not re-issued per consumer (docs/02:292–309) | `bundle_test.go:106–150`; end to end with two state files and two `-out` anchors: `test/trust/run.sh:79–85` |
| TA-04 | Cascade accepts leaves from every issuer beneath the anchor | cascade `Pool` | verify `leaf under a` and `leaf under b` | Both verify | `bundle_test.go:126–130`; with `openssl`: `test/trust/run.sh:88–91` |
| TA-05 ⊘ | Pinned rejects the sibling issuer's leaf — the subdivision is real | pinned-to-`issuer a` `Pool` | verify `leaf under b` | Refused: the chain never reaches the anchor | `bundle_test.go:145–149`; `openssl -partial_chain`: `test/trust/run.sh:98–99` |
| TA-06 ⊘ | Pinned rejects a *parent-minted replacement* of the same issuer | root mints `issuer a′` with the same subject and constraints, different key | verify a leaf under `a′` against the `issuer a` pinned pool | Refused — an anchor is a specific public key (docs/02:220–226). This is the DB-1 mitigation and the whole reason pinned mode exists | **GAP — the single most valuable uncovered positive claim in docs/02** |
| TA-07 | The full issuer set is present so paths build without discovery | verified payload | `p.Pool(anchor)` | `intermediates` contains every non-revoked published issuer (`bundle.go:355–365`); a leaf verifies with no network fetch (docs/02:298–299) | `bundle_test.go:122–130` |
| TA-08 ⊘ | Asking for an issuer anchor by a name the domain does not publish | verified payload | `p.SelectAnchor(RoleIssuer, "issuer z")` | Refusal naming the issuer and explaining that pinning isolates to exactly that issuer (`bundle.go:325–329`) | **GAP** |
| TA-09 ⊘ | Asking for a root anchor in a bundle that publishes none | payload with issuer anchors only | `p.SelectAnchor(RoleRoot, "")` | Refusal: "publishes no root anchor" (`bundle.go:330`) | **GAP** |
| TA-10 ⊘ | Selecting a **withdrawn** issuer as an anchor | payload lists `issuer b` as an issuer anchor and also in `Revoked` | `p.SelectAnchor(RoleIssuer, "issuer b")`, then `Pool` on it | Must be refused, or the withdrawal is advisory for exactly the consumers most exposed to it | **GAP — and currently ACCEPTED.** Measured: the anchor is returned and a leaf from the withdrawn issuer verifies under it. `SelectAnchor` never consults `p.Revoked`. See BUG-3 |
| TA-11 | `Pool` carries the documented warning contract | — | code review + doc test | `Pool`'s doc comment must keep saying it is insufficient under a shared root and point at `VerifyCert` (`bundle.go:333–342`) | **GAP** (lint/doc assertion; cheap and prevents silent regression of docs/02:180–185) |

---

## 4. TR — Revocation state

`Payload.Revoked` (`bundle.go:103–105`), honoured in `Pool` (`bundle.go:351–359`),
in `VerifyCert` (`fabric.go:173–182,191–193`) and in
`trust fetch -issuers-out` (`cmd/signet/trust.go:444–464`).

| ID | Scenario | Pre | Input | Expect | Covered |
|---|---|---|---|---|---|
| TR-01 | Withdrawing an issuer is a root ceremony | F-CASCADE, epoch 1 published | `signet ca bundle -root root -domain d -out b2.json -revoke "sha256:…"` | epoch 2 written; stdout lists the revoked fingerprints (`cmd/signet/trust.go:146,166–168`) | `test/trust/run.sh:134–143` |
| TR-02 ⊘ | A revoked issuer does not help build a path | epoch-2 payload with `issuer b` revoked | `Pool(rootAnchor)` then verify a leaf under b | Refused; the surviving issuer's leaf still verifies | `bundle_test.go:252–284`; with `openssl`: `test/trust/run.sh:145–148` |
| TR-03 ⊘ | A revoked issuer is not accepted by `VerifyCert` even if the presenter supplies it | epoch-2 payload | `p.VerifyCert(leafUnderB, []{issuerB}, now)` | Refused — `published` excludes revoked SPKIs (`fabric.go:178–182`), and the supplied cert cannot re-add it | **GAP** — TR-02 covers `Pool`, not the `extra`-supplied path, which is the realistic one |
| TR-04 ⊘ | A revoked *anchor* is skipped | payload where an issuer anchor's SPKI is in `Revoked` | `p.VerifyCert(leaf, nil, now)` | That anchor is skipped (`fabric.go:191–193`); verification falls through to the root anchor or fails | **GAP** |
| TR-05 | `-issuers-out` writes the surviving set and says how many were dropped | epoch 2 fetched | `signet trust fetch … -issuers-out issuers.pem` | Withdrawn issuers omitted; stdout reports "N issuer(s) written … M withdrawn and omitted" (`cmd/signet/trust.go:444–464`) | `test/trust/run.sh:141–142` runs it; **GAP** on asserting the omission count / file contents |
| TR-06 ⊘ | **Revocation binds only consumers that build their own paths** | epoch 2 with `issuer b` withdrawn; two consumers: (a) uses `-issuers-out` and builds paths, (b) anchors on the root and accepts whatever chain a server presents | present a leaf under `issuer b` with `issuer b` in the presented chain | (a) refuses; (b) **accepts** — and the test asserts the acceptance, because that is the measured fact docs/02:338–343 records. Withdrawal complements expiry; it does not replace it | **GAP** — the fact is documented but nothing demonstrates it. This is one of the two named interop facts; see §8 |
| TR-07 ⊘ | Revocation cannot be undone by replaying the pre-revocation epoch | consumer at epoch 2 | serve epoch 1 | Refused (TV-11) | `test/trust/run.sh:149–150` |
| TR-08 ⊘ | Revocation cannot be undone by a *same-epoch* republication | consumer at epoch 2 (issuer b withdrawn) | serve a **different** root-signed bundle also numbered epoch 2, without the revocation | Should be refused: epoch must be content-monotonic | **GAP — and currently ACCEPTED** at both the consumer (`bundle.go:284` uses `<`) and the node (`kernel/trust.go:133` uses `<`). Reachable by operator error via `ca bundle -epoch N` (`cmd/signet/trust.go:88`). See BUG-5 |
| TR-09 | Revoking by fingerprint matches the SPKI form consumers compute | issuer cert on disk | derive `sha256:` + base64url(SHA-256(SPKI)) with `openssl`, pass to `-revoke` | The value matches `trust.Fingerprint` (`bundle.go:134–137`) and the revocation bites | `test/trust/run.sh:135–139` (the openssl pipeline is itself the cross-check) |

---

## 5. TS — Per-domain consumer state that survives restart

`State`/`DomainState` (`state.go:19–36`), `LoadState` (`state.go:39–59`), `Pin`
(`state.go:66–78`), `Accept` (`state.go:81–88`), `Save` (`state.go:94–110`).

| ID | Scenario | Pre | Input | Expect | Covered |
|---|---|---|---|---|---|
| TS-01 | Absent state file is an empty fabric, not an error | no file | `LoadState(path)` | Empty `Domains`, no error (`state.go:41–43`) | Implicit in `fabric_test.go:70–77`; **GAP** on the explicit assertion |
| TS-02 | The remembered epoch survives a restart | pinned + `Accept(7)` + `Save` | `LoadState` again | `LastEpoch == 7` (`state.go:81–88`) | `bundle_test.go:321–341` |
| TS-03 | The stored **bundle** survives a restart, so verification needs no re-fetch | `Peer()` then `Save` | `LoadState`, then `VerifyLeaf` | The leaf verifies from stored state alone (`state.go:33–35`, `fabric.go:118–131`) | `fabric_test.go:310–334` |
| TS-04 ⊘ | The remembered epoch cannot be walked backwards through `Accept` | `LastEpoch=7` | `Accept(domain, 3, now)` | Still 7 (`state.go:83`) | `bundle_test.go:342–346` |
| TS-05 ⊘ | Re-pinning a domain to a different key is refused | pinned to `sha256:AAA` | `Pin(domain, "sha256:BBB")` | Refusal naming both fingerprints and the state file, telling the operator to confirm out of band and delete the file (`state.go:66–77`) | `bundle_test.go:347–349` |
| TS-06 | Re-pinning to the *same* key is a no-op | pinned to X | `Pin(domain, X)` | No error, no change | **GAP** (the idempotent refresh path) |
| TS-07 ⊘ | A corrupt state file refuses rather than starting blank | truncated/garbage JSON at the path | `LoadState(path)` | Error explaining that starting from a blank slate would reopen the rollback this file prevents (`state.go:48–53`) | **GAP** |
| TS-08 | State is written atomically | — | `Save()`, inspect | Written via `path + ".tmp"` then `os.Rename` (`state.go:105–109`); mode `0600`, dir `0700` | **GAP** — assert the mode bits and that no partial file is observable |
| TS-09 | Several domains are held separately and never merged | F-CASCADE + F-SOVEREIGN, three `Peer` calls | inspect `State.Domains` | Three independent `DomainState`s, each with its own pin, epoch and bundle (`state.go:24–36`, `fabric.go:11–20`) | `fabric_test.go:137–144`, `183–253`; CLI view: `test/fabric/run.sh:85–93` |
| TS-10 | `DomainNames` is stable | several domains | `DomainNames()` | Sorted (`state.go:113–120`) — output of `signet trust peers` must not reorder run to run | **GAP** |
| TS-11 ⊘ | Two domains pinned to different roots do not contaminate one another | F-SOVEREIGN | `Pin("aws…", awsFp)` after `Pin("home…", orgFp)` | Independent; neither pin is disturbed | Implicit in `fabric_test.go:189–203`; **GAP** on the direct assertion |
| TS-12 | `trust fetch` records state only after the anchor selection succeeds | fetch with `-anchor issuer -anchor-name "nope"` | run it | Selection fails (`cmd/signet/trust.go:406–409`) before `st.Save()` (`:410`) — but note `verifyBundle(..., record=true)` has already mutated the in-memory state via `Peer` (`:508–515`). Assert the on-disk epoch is unchanged | **GAP** — ordering is fragile; see Q-6 |

---

## 6. TN — Publication to a running node, and serving

`PutTrustBundle` (`kernel/trust.go:30–56`), `applyPutTrustBundle`
(`kernel/trust.go:121–145`), `TrustBundle` (`kernel/trust.go:61–93`), routes
(`handler.go:125,129–130,165–195,419–430`), CLI (`cmd/signet/trust.go:204–277`).

> **There is no Go test anywhere outside `internal/trust` that touches the trust
> path.** A grep for `TrustBundle` / `trust.` across `internal/**/*_test.go` and
> `cmd/**/*_test.go` returns nothing. Everything in this section is covered, if
> at all, only by `test/trust/run.sh`.

| ID | Scenario | Pre | Input | Expect | Covered |
|---|---|---|---|---|---|
| TN-01 | Publishing over the API needs no restart | F-NODE serving; bundle epoch 1 | `signet trust install -addr http://… -token <admin> -bundle b.json` | 200; `{"domain":…, "epoch":…}` (`handler.go:194`); the node keeps serving throughout — expiry must not be an outage (`handler.go:126–128`) | `test/trust/run.sh:56–59` |
| TN-02 | Publishing offline against a stopped node's data dir | node stopped | `signet trust install -data-dir node-a -bundle b.json` | Stored; actor resolved from `-actor` (`cmd/signet/trust.go:230–248`) | **GAP** |
| TN-03 ⊘ | Neither `-addr` nor `-data-dir` | — | `signet trust install -bundle b.json` | Refusal explaining both modes (`cmd/signet/trust.go:218–222`) | **GAP** |
| TN-04 ⊘ | `-addr` without `-token` | — | `signet trust install -addr … -bundle b.json` | Refusal: needs admin authority at `/` (`cmd/signet/trust.go:254–256`) | **GAP** |
| TN-05 ⊘ | A session with no admin authority at `/` | non-admin token | `PUT /v1/trust/bundle` | 403 "publishing a trust bundle needs admin authority at /" (`handler.go:171–176`) | **GAP — highest-value uncovered authorization check in this area** |
| TN-06 ⊘ | No session at all | no token | `PUT /v1/trust/bundle` | 403 "permission denied" (`handler.go:166–170`) | **GAP** |
| TN-07 ⊘ | **A bundle from a root this node does not chain to** | F-NODE whose issuer chains to `root`; a bundle signed by an impostor root of the same CN | `signet trust install -addr … -bundle evil.json` | 400; the node re-verifies against `rootPin` — the root its *own* issuer chains to, a fact it knows independently of the bundle (`kernel/trust.go:36–51`, `:96–111`). An admin session is permission to publish, not to redefine trust (`handler.go:182–184`) | `test/trust/run.sh:122–123` |
| TN-08 ⊘ | **Walking the node itself back to an older epoch** | node holds epoch 2 | `signet trust install -addr … -bundle bundle1.json` | Refused inside `Apply`, so it holds against every path into the log including a replayed proposal from a node that has been offline (`kernel/trust.go:126–140`) | `test/trust/run.sh:151–152` |
| TN-09 ⊘ | Rollback is refused inside `Apply`, not only at the API | — | craft an `op.PutTrustBundle` with a lower epoch and apply it directly | `op.Result{Err: …}` naming both epochs (`kernel/trust.go:133–138`) | **GAP** — the shell test exercises the API path only, so the *reason* the check lives in `Apply` is untested |
| TN-10 ⊘ | A same-epoch republication at the node | node holds epoch 2 | publish a different epoch-2 bundle | Currently accepted (`kernel/trust.go:133` uses `<`). See TR-08 / BUG-5 | **GAP** |
| TN-11 | A published bundle is served byte for byte | epoch 1 installed | `GET /v1/trust/bundle` | Response bytes identical to the file; `Content-Type: application/json`; no re-encoding, which would break the signature (`handler.go:425–429`) | `test/trust/run.sh:80–85` fetches it; **GAP** on the byte-identity assertion |
| TN-12 | The GET is unauthenticated on purpose | no token | `GET /v1/trust/bundle` | 200. Requiring a credential would invert the bootstrap (`handler.go:120–125`) | Implicit at `test/trust/run.sh:80`; **GAP** on the explicit no-token assertion |
| TN-13 ⊘ | Fetching a domain with no bundle | fresh node | `GET /v1/trust/bundle` | 404 with the "publish one with `signet ca bundle`" guidance (`kernel/trust.go:76–81`, `:86–91`; `handler.go:421–424`) | **GAP** |
| TN-14 ⊘ | `?domain=` selects; the empty case is ambiguous | a node holding bundles for two domains | `GET /v1/trust/bundle` with no query | `TrustBundle("")` returns whichever key sorts first (`kernel/trust.go:66–70`, `store.go:139–141` scans in key order), and `trust fetch` never sends `?domain=` (`cmd/signet/trust.go:388`). Must be either deterministic-and-documented or an error | **GAP — see BUG-4** |
| TN-15 ⊘ | A node accepts a *sibling domain's* bundle | F-CASCADE; node for `home.example.net`, admin token | publish `gcp-bundle.json` (signed by the same org root) | Should be refused: a node stores its own domain's trust set. `PutTrustBundle` passes **no `Domain`** to `Verify` (`kernel/trust.go:42–46`), so the org-root signature is sufficient and the bundle is stored under `gcp.example.net` (`kernel/trust.go:141`) | **GAP — see BUG-4** |
| TN-16 ⊘ | A node with no CA installed cannot check a bundle at all | genesis'd, no `ca install` | `signet trust install -addr …` | Refusal: "this node holds no certificate authority … Install an issuer first" (`kernel/trust.go:108–110`) | **GAP** |
| TN-17 | The publication is audited with domain and epoch | bundle published | read the audit log | Subject is `"<domain> epoch <n>"` (`kernel/apply.go:343–344`) | **GAP** |
| TN-18 ⊘ | Oversized body | 8 MB body | `PUT /v1/trust/bundle` | Truncated at 4 MB and refused as unparseable, not OOM (`handler.go:177`) | **GAP** |

---

## 7. FB — The multi-domain fabric

`VerifyLeaf`/`VerifyLeafWith` (`fabric.go:91–150`), `VerifyCert`
(`fabric.go:172–227`), `chainUsesPublishedIssuers` (`fabric.go:231–257`),
`Peer` (`fabric.go:282–307`), `SharesRootWith`/`Sovereignty`
(`fabric.go:320–349`).

### 7.1 Federation links

| ID | Scenario | Pre | Input | Expect | Covered |
|---|---|---|---|---|---|
| FB-01 | Federating with three domains, bundles held separately | F-CASCADE + F-SOVEREIGN | three `Peer(pin, raw, now)` calls | Three links; each verified against its own pin; nothing merged (`fabric.go:11–20`) | `fabric_test.go:189–203,240–243`; CLI: `test/fabric/run.sh:85–93` |
| FB-02 ⊘ | **A peer may describe only itself** | — | `Peer(awsPin, awsBundle)` | Filed under `aws.example.net` — the domain comes from the *verified payload*, never from the caller (`fabric.go:288–291,299–305`). `home.example.net` must not appear | `fabric_test.go:271–286` |
| FB-03 ⊘ | A peer bundle signed by a key the consumer did not pin | aws bundle, org pin | `Peer(orgPin, awsBundle)` | Refused before anything is stored (`fabric.go:292–298`) | **GAP** |
| FB-04 ⊘ | A peer refresh that tries to move the pin | domain pinned to X | `Peer(Y, bundleSignedByY)` | `Verify` passes under Y, then `Pin` refuses (`fabric.go:299–301`, `state.go:68–74`) and nothing is stored | **GAP** — assert that the stored bundle and epoch are untouched after the failure |
| FB-05 | A refresh advances the epoch and replaces the stored bundle | epoch 1 stored | `Peer(pin, epoch2Raw)` | `LastEpoch=2`, `Bundle` replaced verbatim, `UpdatedAt` set (`fabric.go:302–306`) | `test/trust/run.sh:141–143`; **GAP** at library level |
| FB-06 ⊘ | A stale stored bundle stops verifying on its own | link established with a 1 h bundle | `VerifyLeaf(leaf, "", now+2h)` | Refused "went stale" with no re-fetch and no explicit expiry sweep — the bundle is re-verified on every use (`fabric.go:124–131`, `:261–274`) | `fabric_test.go:290–306` |
| FB-07 | The stored bundle is re-verified with the *caller's* clock | — | `VerifyLeaf(leaf, "", t)` for several `t` | `verifyStored` passes `Now: now`, `Skew: 5m` (`fabric.go:266–269`) | Implicit in FB-06; **GAP** on skew at this layer |

### 7.2 Namespace scoping

| ID | Scenario | Pre | Input | Expect | Covered |
|---|---|---|---|---|---|
| FB-10 | An identity is accepted by its own domain | F-CASCADE fabric | `VerifyLeaf(gcpLeaf, "", now)` | `Identity{Domain: "gcp.example.net", URI: "spiffe://gcp.example.net/workload/api", Anchor, AnchorRole}` (`fabric.go:146–149`) | `fabric_test.go:152–174`; CLI: `test/fabric/run.sh:107–114` |
| FB-11 ⊘ | Federating with gcp gives gcp no authority over home's namespace | F-CASCADE fabric | `VerifyLeaf(gcpIssuerSigned("spiffe://home.example.net/people/root"), "", now)` | Refused. Under cascade the chain is valid; the **namespace check** is what refuses it (`fabric.go:135–140`) — in cascade mode it is the only thing doing the work (`fabric.go:22–38`) | `fabric_test.go:176–178` |
| FB-12 ⊘ | A domain does not govern its DNS-looking children | — | `BelongsTo("prod.aws.example.net", "aws.example.net")` | `false` — suffix matching would recreate transitive trust one string comparison at a time (`fabric.go:74–83`) | `fabric_test.go:338–348` |
| FB-13 ⊘ | **An unfederated domain is refused, not looked up** | fabric without `azure.example.net` | `VerifyLeaf(azureLeaf, "", now)` | Refusal listing the domains this consumer *does* federate with (`fabric.go:111–116`) | `fabric_test.go:194–197`; CLI: `test/fabric/run.sh:175–185` |
| FB-14 ⊘ | A domain pinned but with no bundle stored | `Pin` called, no `Peer` | `VerifyLeaf(leaf, "", now)` | Refusal telling the operator to run `signet trust fetch` (`fabric.go:118–122`) | **GAP** |
| FB-15 ⊘ | A caller may not relabel a certificate that names its own domain | fabric with home | `VerifyLeaf(gcpIdentityLeaf, "home.example.net", now)` | Refusal: "The certificate's own name wins" (`fabric.go:104–109`) | `fabric_test.go:257–267` |
| FB-16 | `domainHint` is used only when the certificate carries no spiffe URI | leaf with no URI SAN | `VerifyLeaf(leaf, "home.example.net", now)` | Verified as home; `Identity.URI` empty, `CN` populated (`fabric.go:98–103,146–149`) | **GAP** |
| FB-17 ⊘ | A certificate with no spiffe URI and no hint | leaf with no URI SAN | `VerifyLeaf(leaf, "", now)` | Refusal: "does not say which trust domain it belongs to. Pass the domain explicitly" (`fabric.go:69–71`) | **GAP** |
| FB-18 ⊘ | A spiffe URI with no host | leaf with `spiffe:///workload/api` | `TrustDomainOf(cert)` | Refusal: "names no trust domain" (`fabric.go:64–66`) | **GAP** |
| FB-19 ⊘ | A certificate carrying **two** spiffe URIs in different domains | leaf with `spiffe://home…/x` and `spiffe://gcp…/x` | `VerifyLeaf(leaf, "", now)` | Measured: the *first* URI wins (`fabric.go:60–68`) and the cert verifies as a home identity, while a verifier reading the second SAN would call it a gcp identity. Either refuse multi-domain URI SANs, or document the first-wins rule as contractual | **GAP** — see Q-3 |
| FB-20 ⊘ | Trust-domain comparison is exact and case-sensitive | leaf with `spiffe://GCP.example.net/x` | `VerifyLeaf(leaf, "", now)` | Refused at the state lookup (`fabric.go:111–116`) — fail-closed, but assert it rather than inherit it | **GAP** |

### 7.3 Sibling impersonation — the substance of the feature

Design: docs/02:164–198. Implementation rationale: `fabric.go:159–171`.

| ID | Scenario | Pre | Input | Expect | Covered |
|---|---|---|---|---|---|
| FB-30 | **Precondition: the forged chain really is valid** | F-CASCADE; `home issuer` mints `spiffe://gcp.example.net/workload/api` | build a path with gcp's root anchor pool plus home's issuer as an intermediate | The chain **verifies**. Without this the refusal below proves nothing about *why* | `fabric_test.go:102–115`; with `openssl`: `test/fabric/run.sh:149–154` |
| FB-31 ⊘ | **The bundle refuses it anyway** | as FB-30 | `p.VerifyCert(forged, []{homeIssuer}, now)` | Refusal naming the offending intermediate and explaining that under a shared root a valid path is not proof the domain vouched (`fabric.go:242–246`) | `fabric_test.go:88–127` |
| FB-32 ⊘ | The same attack through the relying party's real entry point | F-CASCADE fabric | `fab.VerifyLeafWith(forged, []{homeIssuer}, "", now)` | Same refusal, wrapped as "domain %q does not vouch for this certificate" (`fabric.go:142–145`) | `fabric_test.go:131–148` |
| FB-33 ⊘ | **…with the intermediates supplied the way a TLS peer supplies them** | as FB-32 | present the chain via `-chain` / a TLS handshake rather than as a library argument | Same refusal (`cmd/signet/trust.go:681–697`) | `test/fabric/run.sh:156–157` |
| FB-34 | The genuine article still verifies even when extra certs are supplied | F-CASCADE | `p.VerifyCert(realGcpLeaf, []{homeIssuer}, now)` | Accepted — the refusal is scoping, not breakage | `fabric_test.go:122–126` |
| FB-35 ⊘ | **The forged issuer is one the org root signed for a real sibling domain** | F-CASCADE built by the **real CLI**: `ca sign-issuer` for home and gcp, then `ca bundle -domain gcp.example.net` | `signet trust check -cert <home-minted gcp identity> -state consumer.json` | Refused | **GAP — and currently ACCEPTED, with no intermediates supplied at all.** `test/fabric/run.sh` misses this because its forging CA is created at `run.sh:137–140`, *after* the bundles are published at `run.sh:71–74`; the unit test misses it because `bundleFor` (`fabric_test.go:47–68`) hand-picks one issuer. See BUG-1 — **top risk in this document** |
| FB-36 ⊘ | An unpublished, unrelated intermediate under the same root | rogue CA signed by the org root *after* publication | `trust check -cert forged.crt -chain rogue-ca.crt` | Refused | `test/fabric/run.sh:133–157` |
| FB-37 | A leaf minted **directly by the org root** is accepted by every domain that anchors on it | F-CASCADE | `p.VerifyCert(rootMintedGcpLeaf, nil, now)` | **Accepted** — chain length 2, so `chain[1:len-1]` is empty (`fabric.go:236`). This is DB-1: within one org the parent *is* all-powerful (docs/02:142–154). Assert it explicitly so the boundary between "parent power (expected)" and "sibling power (refused)" is a test, not a memory | **GAP** — measured as accepted |
| FB-38 ⊘ | **Presenting an anchor certificate as the leaf** | any fabric | `signet trust check -cert <the domain's own issuer or root cert> -domain d -state …` | A clean refusal | **GAP — and currently PANICS**: `panic: runtime error: slice bounds out of range [1:0]` at `fabric.go:236`. Go returns a length-1 chain when the presented cert is itself in the root pool (`crypto/x509/verify.go:597`). Reachable by any peer that can hand a certificate to a Signet verifier. See BUG-2 |
| FB-39 | The caller is told *which* anchor the chain terminated at | pinned and cascade consumers | `VerifyLeaf` | `Identity.Anchor` / `AnchorRole` populated, so a caller can tell a cascade result from a pinned one rather than assuming (`fabric.go:46–48,146–149`); anchors are tried most-specific-first (`fabric.go:186–190`) | `fabric_test.go:171–173` asserts `Domain` only; **GAP** on `AnchorRole` |
| FB-40 ⊘ | `VerifyCert` with an expired leaf | leaf past `NotAfter` | `p.VerifyCert(leaf, nil, now)` | Refused by `cert.Verify` with `CurrentTime: now` (`fabric.go:208–212`) | **GAP** |

### 7.4 Sovereignty

| ID | Scenario | Pre | Input | Expect | Covered |
|---|---|---|---|---|---|
| FB-50 ⊘ | A sovereign domain is separated by **arithmetic**, not policy | F-SOVEREIGN | `VerifyLeafWith(homeMintedAwsIdentity, []{homeIssuer, orgRoot}, "", now)` | Refused even when handed the *entire* organizational chain — there is no path from aws's root to anything the org signed (docs/02:187–192) | `fabric_test.go:216–226`; CLI: `test/fabric/run.sh:159–173` |
| FB-51 | Sovereignty is a property of the fabric, not of one bundle | F-SOVEREIGN, only home federated | `Sovereignty("home.example.net")` | `"sovereign"` — nothing shared *yet*. From one bundle a domain's own root and its parent's are indistinguishable (`fabric.go:309–318`) | `fabric_test.go:231–236` |
| FB-52 | Federating a second org-rooted domain makes the shared root visible | add gcp | `Sovereignty("home.example.net")`, `SharesRootWith("home.example.net")` | `"shared root"`; `["gcp.example.net"]` (`fabric.go:320–349`) | `fabric_test.go:240–249` |
| FB-53 | aws stays sovereign regardless of who else joins | as FB-52 | `Sovereignty("aws.example.net")` | `"sovereign"` | `fabric_test.go:250–252` |
| FB-54 | A domain with no stored bundle reports `unknown` | pinned, no bundle | `Sovereignty(d)` | `"unknown"` (`fabric.go:342–344`) | **GAP** |
| FB-55 | `signet trust peers` names the standing, epoch, staleness and shared-root set | F-CASCADE + F-SOVEREIGN state | `signet trust peers -state s.json` | Table with `DOMAIN STANDING EPOCH STATUS SHARES ROOT WITH`; the shared-root caveat printed when any domain shares (`cmd/signet/trust.go:623–651`) | `test/fabric/run.sh:93` runs it; **GAP** — output is not asserted |
| FB-56 | `trust peers` marks a stale bundle `STALE` without refusing to list it | expired stored bundle | `signet trust peers` | `STATUS = STALE` (`cmd/signet/trust.go:628–635`) | **GAP** |
| FB-57 ⊘ | `trust peers` on an empty fabric | no state file | `signet trust peers` | Refusal explaining that the pin must come from somewhere other than the domain being pinned, and naming the state path (`cmd/signet/trust.go:617–622`) | **GAP** |

---

## 8. IX — The two measured interop facts

These are the facts docs/02:326–343 and docs/16:113–118 record as *measured,
not assumed*. They are tests precisely because they are surprising, and they
must be re-run whenever the anchor modes or the fetch output change.

| ID | Scenario | Pre | Input | Expect | Covered |
|---|---|---|---|---|---|
| IX-01 | **Go accepts a non-self-signed trust anchor** | pinned-to-`issuer a` anchor + leaf under a | `leaf.Verify({Roots: poolContainingIntermediate})` | Accepted — any certificate in Go's root pool is a valid anchor. The pinned mode works in Go | `bundle_test.go:362–384` |
| IX-02 ⊘ | **OpenSSL refuses the same anchor without `-partial_chain`** | same anchor written by `trust fetch -out` | `openssl verify -CAfile c-pinned/anchor.crt leaf-a.crt` | **Fails.** Same bundle, same anchor, opposite result, for reasons unrelated to the certificates | **GAP** — `test/trust/run.sh:96` only runs the `-partial_chain` *success* case. The failure without the flag is the actual finding and is asserted nowhere |
| IX-03 | OpenSSL accepts it **with** `-partial_chain` | as IX-02 | `openssl verify -partial_chain -CAfile c-pinned/anchor.crt leaf-a.crt` | Accepted | `test/trust/run.sh:96–97` |
| IX-04 | The operator is warned at the moment of choosing | — | `signet trust fetch -anchor issuer -anchor-name …` | stdout names Go, OpenSSL and "others vary; test yours", and says to anchor on the root instead if consumers cannot be configured (`cmd/signet/trust.go:416–430`) | **GAP** — the warning text is a contract with the operator and should be asserted |
| IX-05 | Cross-verifier anchor matrix | pinned anchor + leaf | run through Go, OpenSSL, LibreSSL, pyca, rustls-webpki | Record accept/reject per verifier, as docs/10:19–21 already requires for name constraints | **GAP** — the natural home is the E-02 harness |
| IX-06 ⊘ | **Revocation binds only consumers that build their own paths** | epoch 2 with `issuer b` withdrawn | (a) `openssl verify -CAfile anchor.crt -untrusted issuers.pem leaf-b.crt` where `issuers.pem` came from `-issuers-out`; (b) the same verification with `issuer b` supplied by the *presenter* instead | (a) **fails**; (b) **succeeds** — and the test asserts (b)'s success, because that is the documented limit of bundle revocation (docs/02:338–343, `cmd/signet/trust.go:444–447`) | (a) `test/trust/run.sh:147–148`; (b) **GAP** — the half that makes the fact a fact |
| IX-07 | A bundle is readable outside Go | published bundle | decode `payload` with `python3 -c "base64.b64decode(...)"` and parse as JSON | Succeeds — the payload is a base64 *string*, not a Go `[]byte` that would be double-encoded (`bundle.go:116–120`) | `test/trust/run.sh:108–115` does exactly this as a side effect; **GAP** on the explicit assertion |
| IX-08 | SPKI fingerprints agree between Signet and OpenSSL | issuer cert | `openssl x509 -noout -pubkey \| openssl pkey -pubin -outform der \| openssl dgst -sha256 -binary \| base64 \| tr '+/' '-_' \| tr -d '='` vs `trust.Fingerprint` | Identical (`bundle.go:134–137`) | `test/trust/run.sh:135–139` (used, not asserted); **GAP** on a direct comparison |

---

## 9. Coverage summary

**98 scenarios.** Counting a scenario as covered only when an existing test
asserts its stated expectation:

| Section | Total | Covered | Partial | GAP |
|---|---:|---:|---:|---:|
| TB — authoring ceremony | 12 | 4 | 1 | 7 |
| TV — consumer verification | 20 | 10 | 0 | 10 |
| TA — anchors and pools | 11 | 5 | 0 | 6 |
| TR — revocation | 9 | 4 | 1 | 4 |
| TS — consumer state | 12 | 5 | 2 | 5 |
| TN — node publication & serving | 18 | 3 | 2 | 13 |
| FB — fabric | 34 | 16 | 3 | 15 |
| IX — interop | 8 | 3 | 2 | 3 |
| **Total** | **98** | **50** | **11** | **37** |

Shape of the coverage: `internal/trust`'s *library* surface is genuinely well
tested — the bundle format, the refusals, and the fabric's namespace scoping
each have a named test that says what it stops. Two areas are close to bare:

- **The node and HTTP layer has no Go tests at all.** `PutTrustBundle`,
  `applyPutTrustBundle`, `TrustBundle` and both `/v1/trust/bundle` routes are
  exercised only by `test/trust/run.sh`, which is not run by `make test`.
  Authorization (TN-05, TN-06) is untested anywhere.
- **The ceremony CLI is untested as an artifact producer.** Nothing asserts
  what `signet ca bundle` actually emits, which is how BUG-1 survived a passing
  fabric test.

---

## 10. Suspected live bugs

All six were reproduced. BUG-1 and BUG-2 were reproduced against a binary from
`make build`; the rest against `internal/trust` in a local-disk copy of the
tree. No repository file was modified.

### BUG-1 — `ca bundle` publishes every sibling's issuer, so the sibling-impersonation defence is vacuous in real deployments · **critical**

`recordIssuerCopy` files *every* issuer the root signs into `<root>/issuers/`
(`cmd/signet/ca.go:394–405`). `caBundle` then reads that whole directory and
publishes all of it — as issuer **anchors** and in the `issuers` set — with no
filter by `-domain` (`cmd/signet/trust.go:107–128`).

Under cascade, one org root signs every domain's issuer. So every domain's
bundle publishes every sibling's issuer, and `chainUsesPublishedIssuers`
(`fabric.go:231–257`) — the entire defence described in docs/02:164–198 and
`fabric.go:159–171` — finds the sibling's issuer in `published` and passes.

Reproduced with the real binary: an org root signs `home issuer` and
`gcp issuer`; `signet ca bundle -root org-root -domain gcp.example.net` emits

```
anchors: [('root','Example Root CA'), ('issuer','home issuer'), ('issuer','gcp issuer')]
issuers: ['home issuer', 'gcp issuer']
```

and then, against a consumer state pinned to the org root and holding that
bundle:

```
$ signet trust check -cert forged.crt -state consumer.json     # no -chain needed
accepted
  identity: spiffe://gcp.example.net/workload/api
  domain:   gcp.example.net
  anchor:   issuer "home issuer"
```

The attacker does not even need to supply intermediates — home's issuer is an
issuer *anchor* in gcp's bundle, and anchors are tried most-specific-first
(`fabric.go:188–190`).

**Why both existing tests miss it.** `test/fabric/run.sh` forges with a
`rogue-ca` created at `run.sh:137–140`, *after* the bundles are published at
`run.sh:71–74` — so the rogue issuer is genuinely absent from the bundle and
the refusal is real but incidental. The comment at `run.sh:76–78` ("Each
domain's bundle must publish only its own issuer") describes an intent the code
does not implement. `TestCascadeSiblingCannotImpersonateViaSuppliedIntermediate`
misses it because `bundleFor` (`fabric_test.go:47–68`) hand-picks the issuer
list the CLI would not have produced.

**Fix direction** (maintainer's call — see Q-1): `ca bundle` should select
issuers by the domain being published, e.g. from the issuer certificate's DNS
name constraints or SANs (`ca sign-issuer -domains` already records the
binding), or issuer directories should be per-domain. **Regression tests:
TB-12 and FB-35.**

### BUG-2 — reachable panic when the presented certificate is itself an anchor · **high**

`chainUsesPublishedIssuers` slices `chain[1 : len(chain)-1]` (`fabric.go:236`).
Go returns a chain of length 1 when the leaf is already in the root pool
(`crypto/x509/verify.go:591–598`), so the slice is `chain[1:0]` and panics.

```
$ signet trust check -cert gcp-issuer.crt -domain gcp.example.net -state consumer.json
panic: runtime error: slice bounds out of range [1:0]
  …trust.chainUsesPublishedIssuers …/internal/trust/fabric.go:236
  …trust.(*Payload).VerifyCert
```

Reached through `VerifyLeafWith`, which is the relying-party entry point — so
any peer that can hand a certificate to a Signet verifier can crash it. A
length-1 chain should be treated as "the presented certificate *is* the anchor"
and handled deliberately (accept or refuse), never sliced.
**Regression test: FB-38.**

### BUG-3 — `SelectAnchor` ignores `Revoked` · **medium**

`SelectAnchor` (`bundle.go:315–331`) never consults `p.Revoked`. A consumer can
therefore pin a withdrawn issuer as its anchor, and `Pool` will add it to
`roots` unconditionally (`bundle.go:344–349`) — the revocation filter applies
only to `intermediates` (`bundle.go:351–359`). Measured: the withdrawn issuer's
leaves still verify. `trust fetch` filters `-issuers-out` by revocation
(`cmd/signet/trust.go:444–455`) but not the anchor it writes to `-out`
(`:435–440`). The consumers most exposed to a compromised issuer — those pinned
to it — are the ones the withdrawal does not reach.
**Regression test: TA-10.**

### BUG-4 — a node accepts and may serve another domain's bundle · **medium**

`PutTrustBundle` verifies with **no `Domain`** in `VerifyOptions`
(`kernel/trust.go:42–46`), so the only requirement is a signature from the root
this node's issuer chains to (`kernel/trust.go:96–111`). Under a shared org root
that is satisfied by every sibling domain's bundle, which is then stored under
the sibling's key (`kernel/trust.go:141`).

`TrustBundle("")` returns whichever domain sorts first
(`kernel/trust.go:66–70`, scanning in key order per `store.go:139–141`), and
`trust fetch` never sends `?domain=` (`cmd/signet/trust.go:388`). So an admin at
`/` on one node can cause consumers that omit `-domain` to fetch a different
domain's trust set. The consumer's own scoping limits the damage (`Peer` files
by verified payload domain, `fabric.go:288–291`), but the result is at minimum a
silent trust-set substitution and a denial of service on the intended domain.
Also: `op.PutTrustBundle.Domain` is set by the proposer
(`kernel/trust.go:53`) and `applyPutTrustBundle` trusts it rather than
re-deriving it from the bundle (`kernel/trust.go:121–141`).
**Regression tests: TN-14, TN-15.**

### BUG-5 — epoch is not content-monotonic · **medium-low**

Both rollback checks use strict `<`: `bundle.go:284` at the consumer and
`kernel/trust.go:133` in `Apply`. Two *different* root-signed bundles numbered
epoch N are therefore interchangeable, last-writer-wins. Measured: a second
epoch-1 bundle re-adding a withdrawn issuer is accepted by `State.Peer` and the
withdrawn issuer's leaves verify again. `ca bundle -epoch N`
(`cmd/signet/trust.go:88`) makes reusing an epoch a one-flag operator error.
Either refuse a same-epoch bundle whose bytes differ from the stored one, or
document same-epoch replacement as intended.
**Regression tests: TR-08, TN-10.**

### BUG-6 — an issuing key can sign a bundle · **low (documented invariant violated)**

`bundle.go:5–28` and docs/02:311–324 state the invariant plainly: an issuing key
is authorized to mint leaves, not to declare the trust set, "if issuers could
sign bundles, a single compromised node could publish one adding its own
anchor". `Verify` enforces only that the signer appears as *an anchor*
(`bundle.go:245–250`), not that it is the **root** anchor. Measured: a bundle
anchored on `home issuer` (role `issuer`) and signed by that issuer's key
verifies and federates for any consumer pinned to that issuer.

Consumers that pin a root are unaffected, and `PutTrustBundle` independently
enforces the root pin at the node (`kernel/trust.go:36–51`). So the exposure is
limited to consumers bootstrapped with an issuer fingerprint — but that is
exactly the pinned mode docs/02:220–231 recommends. **Regression test: TV-19.**

---

## 11. Top gaps by risk

Ranked by (blast radius if wrong) × (likelihood of silent regression).

1. **FB-35 / TB-12 — the CLI-produced bundle's issuer set.** The sibling
   defence is the headline claim of milestone 4c and it does not hold for
   artifacts Signet itself produces (BUG-1). The gap is not "an untested edge";
   it is that both existing tests build the fixture by hand and never look at
   what the ceremony emits.
2. **FB-38 — presenting an anchor as a leaf.** A remote, unauthenticated panic
   in the relying-party path (BUG-2). Trivial input, total loss of the verifier.
3. **TN-05 / TN-06 — authorization on `PUT /v1/trust/bundle`.** The only thing
   standing between a valid session and republishing a domain's trust set is
   `Authorize(VerbAdmin, "/")` at `handler.go:173`, and nothing tests it. The
   kernel's root-pin re-check is a strong second line, but a regression here
   would be invisible until someone tried it.
4. **TA-06 — pinned mode refusing a parent-minted replacement.** This is the
   entire justification for the pinned anchor mode (docs/02:220–226) and the
   DB-1 mitigation. Nothing asserts it. If it silently stopped holding, the
   mode would still *look* correct in every existing test.
5. **IX-02 / IX-06 — the negative halves of both interop facts.** Each fact is
   currently evidenced only by its positive half: `-partial_chain` succeeding,
   and path-building consumers refusing a withdrawn issuer. The findings are
   "OpenSSL refuses *without* the flag" and "a chain-accepting consumer does
   *not* notice" — neither is asserted, so both could silently become false and
   docs/02:326–343 would quietly become wrong.

Runners-up worth scheduling: **TA-10** (BUG-3), **TN-14/15** (BUG-4),
**TS-07** (corrupt state must not fail open to a blank slate), **TV-17**
(fuzz the envelope parser — docs/10:23–26 already asks for this).

---

## 12. Questions for the maintainer

**Q-1 — How should `ca bundle` decide which issuers belong to a domain?**
(Blocks BUG-1 / TB-12.) `ca sign-issuer -domains` already records the binding,
and the issuer certificate carries DNS name constraints. Options: filter
`readIssuerDir` by the issuer's permitted DNS subtrees against `-domain`;
per-domain issuer subdirectories (`<root>/issuers/<domain>/`); or an explicit
`-issuer` list at ceremony time. The first is the most automatic and the least
forgiving of an operator who never set `-domains`. Which is intended?

**Q-2 — Should a domain's bundle publish sibling issuers as issuer *anchors*?**
Even with Q-1 resolved for the `issuers` set, the anchor list is built from the
same directory (`cmd/signet/trust.go:117–122`). Is an issuer anchor for another
domain ever meaningful, or should anchors be strictly `{root} ∪ {this domain's
issuers}`?

**Q-3 — Multi-SAN identity: first-wins, or refuse?** `TrustDomainOf` returns
the first `spiffe://` URI (`fabric.go:60–68`). A certificate with two spiffe
URIs in different trust domains verifies as the first and would be read as the
second by any verifier that iterates differently. Signet's own issuer roles
constrain `allowed_uri_prefixes`, but a parent or a compromised sibling is not
bound by that. Refuse multi-domain URI SANs, or make first-wins contractual and
documented?

**Q-4 — Is there a ceiling on `max_age`?** `Build` accepts any positive
duration (`bundle.go:148–150`) and nothing caps it at verify. A 100-year bundle
was accepted 50 years on. FED-1 requires fail-closed on staleness
(docs/02:394–396); an unbounded max-age makes that a matter of publisher
discipline. Should there be a hard ceiling, a warning at ceremony time, or is
this deliberately the publisher's choice?

**Q-5 — Is same-epoch replacement intended?** (BUG-5.) Should epoch be a strict
content counter — same epoch, same bytes, or refuse — or is last-writer-wins at
a given epoch acceptable because only the root can produce either bundle?

**Q-6 — What is the intended durability contract for `trust fetch`?**
`verifyBundle(record=true)` mutates state via `Peer` (`cmd/signet/trust.go:508–515`)
before `SelectAnchor` runs (`:406`) and before `st.Save()` (`:410`). A failed
anchor selection therefore leaves the accepted epoch unwritten, so a subsequent
fetch of an *older* bundle would be accepted. Should the epoch be persisted as
soon as the bundle verifies, independently of whether the requested anchor
exists?

**Q-7 — Should `Verify` require the signer to be the *root* anchor?** (BUG-6.)
The package doc says only the root may sign. Enforcing
`anchor.Role == RoleRoot` would make the invariant true in the library rather
than only at the node — but would break any deliberate use of a bundle anchored
solely on an issuer (a pinned consumer's private view, say). Is such a bundle a
supported shape?

**Q-8 — Should `GET /v1/trust/bundle` with no `?domain=` be an error when a
node holds more than one?** (BUG-4 / TN-14.) The current "return whichever is
present" (`kernel/trust.go:66–70`) is convenient for the one-domain case that
`handler.go` assumes, and ambiguous otherwise. Related: should `trust fetch`
send `?domain=` when the operator passed `-domain`?

**Q-9 — Where should the algorithm policy be tested?** docs/02:350–380 makes
"which algorithms are currently acceptable" ride the bundle epoch, and
`Payload.Algorithms` exists (`bundle.go:102`) but is never populated by `Build`
(`bundle.go:151–155`) nor consulted by `Verify`. Is this E-12 work with no test
obligation yet, or should this plan carry placeholder scenarios (downgrade
protection, AND-signature over the policy) now?

**Q-10 — Does `rootPin` need to handle a node with several issuers under
different roots?** It returns the first issuer's root fingerprint
(`kernel/trust.go:101–106`), iterating a map, so the result is not stable across
calls. Single-root-per-node is presumably the invariant — should it be asserted
rather than assumed?
