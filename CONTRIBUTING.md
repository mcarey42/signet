# Contributing

Signet is pre-1.0 and the design is still moving. Issues and discussion are
more useful than large pull requests right now — check before building
something substantial, so neither of us wastes the effort.

**Security issues do not go here.** See [SECURITY.md](SECURITY.md).

## Building

```sh
make build        # the static binary
make test         # unit and integration
make test-race    # the same under the race detector
make vet
```

The end-to-end suites (`test-trust`, `test-fabric`, `test-pam`, `test-audit`)
each stand up real nodes and take a minute or two. `make test-hsm` needs
SoftHSM2 and `pkcs11-tool`:

```sh
brew install softhsm opensc          # macOS
apt install softhsm2 opensc          # Debian/Ubuntu
```

## What a change needs

**A test that fails before your fix and passes after.** Not a test that
exercises the code — one that would have caught the bug. Name it after the
failure it prevents rather than after the function it calls, so that when it
breaks in two years the failure message explains itself.

**A reason in the comment, not a restatement of the code.** The convention here
is that comments explain *why*, especially where a decision looks arbitrary or
where a simpler-looking alternative is wrong. `git log` is full of examples.

**Verification against something external where that is possible.** Certificate
work should be checked with `openssl`, SSH with `sshd`, Vault compatibility
with the real `bao` CLI. Checking our own output with our own verifier proves
much less, and this project has the scars to prove it.

## Things worth knowing before you start

**Everything that decides anything happens inside `Apply`.** Authorization,
validation, narrowing — all of it, under the serialized writer. A check in an
HTTP handler is an early refusal for a better error message, never the
enforcement. Several real bugs came from a handler comment claiming an
invariant that `Apply` did not implement.

**`Apply` must be pure.** No wall clock, no randomness, no I/O beyond the
transaction. Anything nondeterministic is resolved at propose time and carried
in the `Op`. There is a test that replays a log onto a fresh store and compares
bytes; it exists to catch exactly this.

**Determinism and idempotence are different properties.** Raft replays
committed entries; the applied-index watermark is what stops them applying
twice. It is also, quietly, what keeps the barrier's nonces unique — see
`internal/store/barrier.go`.

**Op kind tags are never reused.** A retired tag stays retired. The log is
forever, and a tag that changes meaning makes old entries decode into something
else.

**Dependencies are a decision, not a default.** There are three, and adding a
fourth needs an argument in the pull request. Metrics, JOSE, JWKS and the audit
chain are hand-rolled for this reason.

## Commit messages

Explain what changed and why it was wrong before. If a fix was found by a
particular attack or a particular real client, say so — that context is what
makes the history worth reading.

Sign your work if you like, but it is not required.

## Licence

Contributions are under [Apache-2.0](LICENSE), the same as the project.
