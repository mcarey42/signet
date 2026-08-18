# 17 — Performance

**Status: measured 2026-08-18** (Apple M5, single node, local disk).

Numbers first, opinions second. Everything here comes from
`internal/kernel/bench_test.go` and the `/metrics` endpoint, not from reasoning
about the code.

## What a request actually costs

From a live node doing 25 secret writes and 26 reads:

| Stage | Mean |
|---|---|
| Authorization decision | **5.4 µs** |
| Raft propose → commit → apply | **17.5 ms** |
| Apply into the store | 8.8 ms |

An authorization decision is **0.03%** of a write. Consensus and the fsync
underneath it are the entire cost. That is worth stating plainly because it
determines where optimization effort is *not* worth spending.

## The authorization path

| Case | Cost |
|---|---|
| `ScopeCovers` alone | 11 ns |
| 1 binding | 1.5 µs |
| 512 bindings, match on the first | **2.4 µs** |
| 512 bindings, match on the last | 667 µs |
| 512 bindings, denied | 629 µs |

Cost is **linear in bindings examined**, at roughly 1.3 µs each. The breakdown
of that per-binding cost:

| Component | Cost | Share |
|---|---|---|
| JSON unmarshal | 936 ns | ~62% |
| bbolt read + AES-GCM open | 571 ns | ~38% |

**JSON, not cryptography, is the dominant term.** Any future optimization here
should start with the encoding, not with the barrier.

### Fix applied: stream, do not materialize

`HasAuthority` originally called `LoadBindings`, which decrypted and
unmarshalled *every* binding before examining any of them — so a principal with
512 grants paid 667 µs even when the very first grant answered the question. It
now scans with early exit, which made that case **2.4 µs, a ~280× improvement**,
and left it essentially independent of how much authority the principal holds.

A denial is still O(n) and always will be: to say no you must genuinely look at
everything. At ~1.3 µs per binding that is fine to four figures of bindings, and
if it ever is not, the fix is a scope index or a cheaper encoding — not threads.

## On concurrency

The question "do we need multi-threading to serve requests quickly" already has
an answer, and it is mostly no:

- **Requests are already concurrent.** `net/http` is goroutine-per-request.
- **Reads are already concurrent.** bbolt readers take a consistent snapshot
  and do not block each other. Measured: 79.6 µs → 24.2 µs across 8 cores
  (3.3×, sub-linear but real).
- **Writes serialize, and must.** One Raft leader, one bbolt writer. That is
  what consensus *is*; a thread pool cannot make a quorum agree faster.

So the useful levers are batching proposals, and reducing per-binding decode
cost — not parallelism that already exists. `signet_requests_in_flight` is
exposed so that this stays a measured claim rather than an assumed one.

## Metrics

Off by default; `-metrics-listen 127.0.0.1:9101` serves Prometheus text at
`/metrics` on its own listener, so it can be bound to a management interface
rather than exposed wherever the API is.

Implemented in `internal/metrics` with no third-party dependency: atomic
counters and fixed-bucket histograms, allocation-free on the hot path. Labels
are fixed at registration and route labels come from the ServeMux *pattern*
(`GET /v1/secrets/data/{path...}`), never the concrete path — a metric label
per secret name would be a memory leak with a remote trigger.

Exposed: `signet_authz_duration_seconds`, `signet_authz_bindings_scanned`,
`signet_authz_activations_scanned`, `signet_authz_{allowed,denied}_total`,
`signet_propose_duration_seconds`, `signet_apply_duration_seconds`,
`signet_store_{read,write}_duration_seconds`, `signet_request_duration_seconds`
and `signet_requests_total` by route, and `signet_requests_in_flight`.

One behaviour worth knowing when reading these: a request with an invalid token
increments no authorization counter at all, because session lookup fails before
any authorization decision is reached. `signet_authz_denied_total` counts
*authenticated* principals who were refused, which is the more interesting
signal anyway.

## Not yet measured

- Multi-node consensus (there is only one voter today).
- Certificate issuance and signing throughput.
- Behaviour at O(10k) principals; the design envelope is O(1k) (docs/03).
- Memory under sustained load, and GC pressure from the JSON path above.
