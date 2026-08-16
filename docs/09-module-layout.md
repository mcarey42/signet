# 09 — Module layout & dependency budget

**Status: Open** (principles Decided; concrete layout pending first code)

## Principles (Decided)

- **Modular monolith**: one repo, one server binary, strict internal
  boundaries. Dialects import the kernel; the kernel imports nothing above
  storage; nothing imports a dialect.
- **Dependency budget** (server): one Raft library, one embedded KV store,
  Go stdlib for crypto/TLS/X.509/HTTP/JSON. Every additional dependency needs
  a written exception in this doc (candidate exceptions so far: an ASN.1
  helper if stdlib gaps bite; XML-DSig if/when SAML lands).
- **Never hand-rolled**: crypto primitives, consensus, TLS.
- Agents share the kernel's client libraries from the same repo; native shims
  live in `agents/shims/<platform>/` with their own build chains.

## Sketch (to be validated by first vertical slice)

```
signet/
  cmd/signet/           # single entrypoint: server | agent | cli subcommands
  kernel/
    graph/              # identity graph + resource tree
    policy/             # role bindings, scoped eval, freshness ladder
    keys/               # key hierarchy, seal interface, signing
                        # REQ (E-01 DB-3): PKCS#11/TPM/KMS-resident signing as
                        # a first-class backend; keys separated by function
                        # (intermediate CA / session / role / KV data key)
    attest/             # evidence verifier plugin interface + verifiers
    issue/              # the one decision path: attest/session -> claims -> mint
  consensus/            # hashicorp/raft glue: FSM, transport, bootstrap/recover
  store/                # bbolt (raft.db/state.db) + barrier encryption
  backup/               # generations: writer/restorer + targets (s3, gcs, file)
  dialects/
    oidc/  vaultkv/  sshca/  acme/  x509/
  agents/
    core/               # session mgmt, renewal loop, IPC server
    keystore/           # tpm, secure-enclave, cng behind one interface
    shims/              # (v2+) pam/, credprovider/, macos-authz/
  internal/wire/        # shared client lib (agents, cli)
```

## Footprint targets (Draft)

- Server binary ≤ ~40 MB static; idle RSS ≤ ~100 MB single-node.
- Agent idle RSS ≤ ~30 MB.
- Cold start to serving ≤ 2 s on Celeron-class hardware.

## Open questions

- One binary for server+agent (k3s-style) vs separate lean agent binary for
  workstation distribution. Leaning one for ops simplicity; measure size.
- Go module layout: single module vs kernel as separate module for external
  reuse. Start single; split only on demand.
