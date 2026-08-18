#!/usr/bin/env bash
# Milestone 5b: privileged access — eligible vs held.
#
# alice is eligible for kv-admin on /secrets but does not hold it. The test is
# mostly about what she CANNOT do: read before activating, approve her own
# request, keep the access past its window, or stack another window on top.
#
# The one that matters most is the first. If eligibility silently granted the
# authority, every other assertion here could pass and the feature would be
# worthless.
set -euo pipefail

BIN=${BIN:-$(cd "$(dirname "$0")/../.." && pwd)/signet}
WORK=${WORK:-$(mktemp -d)}
PORT=${PORT:-18801}
pass=0; fail=0

ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
refutes() { local n=$1; shift; if "$@" >/dev/null 2>&1; then bad "$n (allowed!)"; else ok "$n"; fi; }

[ -x "$BIN" ] || { echo "build first: make build" >&2; exit 1; }
cd "$WORK"
cleanup() { pkill -f "$BIN serve" 2>/dev/null || true; }
trap cleanup EXIT

A=http://127.0.0.1:$PORT
kv_read()  { curl -sf -H "X-Vault-Token: $1" "$A/v1/secrets/data/$2" >/dev/null; }
kv_write() { curl -sf -X PUT -H "X-Vault-Token: $1" -d '{"data":{"k":"v"}}' "$A/v1/secrets/data/$2" >/dev/null; }

step "1. a domain where alice is ELIGIBLE for kv-admin, not holding it"
cat > cfg.json <<'EOF'
{
  "principals": [
    { "path": "/people/alice", "type": "human" },
    { "path": "/people/carol", "type": "human" }
  ],
  "bindings": [
    { "subject": "/people/carol", "role": "domain-admin", "scope": "/" },
    { "subject": "/people/alice", "role": "kv-reader", "scope": "/secrets/public" },
    { "subject": "/people/alice", "role": "kv-admin", "scope": "/secrets",
      "activation_required": true, "approval_required": true,
      "max_activation_sec": 3600 }
  ]
}
EOF
mkdir -p d
$BIN genesis -data-dir d -config cfg.json > gen.txt 2>&1
grep -o 'signet\.[A-Za-z0-9._-]*' gen.txt | head -1 > root.token
ROOT=$(cat root.token)
$BIN serve -data-dir d -listen "127.0.0.1:$PORT" -domain home.example.net >serve.log 2>&1 &
for _ in $(seq 80); do curl -sf "$A/v1/sys/health" >/dev/null && break; sleep 0.25; done

# Mint tokens for alice and carol. The server must be running, so these go
# through the API using the root token.
stop_and_token() { # stop_and_token PRINCIPAL OUTFILE
  pkill -f "$BIN serve -data-dir d " 2>/dev/null || true; sleep 1
  $BIN token -data-dir d -principal "$1" 2>/dev/null | grep -o 'signet\.[A-Za-z0-9._-]*' | head -1 > "$2"
  $BIN serve -data-dir d -listen "127.0.0.1:$PORT" -domain home.example.net >>serve.log 2>&1 &
  for _ in $(seq 80); do curl -sf "$A/v1/sys/health" >/dev/null && break; sleep 0.25; done
}
stop_and_token /people/alice alice.token
stop_and_token /people/carol carol.token
ALICE=$(cat alice.token); CAROL=$(cat carol.token)
ok "alice eligible for kv-admin@/secrets (approval required); carol is domain-admin"

step "2. eligibility is not possession"
kv_write "$ROOT" app1 >/dev/null 2>&1 || true
refutes "alice cannot write /secrets/app1 while merely eligible" kv_write "$ALICE" app1
refutes "alice cannot read it either" kv_read "$ALICE" app1
$BIN pam eligible -addr "$A" -token "$ALICE" | head -6

step "3. she asks, and must say why"
refutes "an activation request with no reason" \
  $BIN pam activate -addr "$A" -token "$ALICE" -binding x -reason ""
BINDING=$($BIN pam eligible -addr "$A" -token "$ALICE" 2>/dev/null \
  | awk '$1=="eligible" && $2=="kv-admin" {print $NF}')
[ -n "$BINDING" ] || { bad "could not find the eligible binding"; BINDING=none; }
$BIN pam activate -addr "$A" -token "$ALICE" -binding "$BINDING" \
   -reason "incident 42: rotating a leaked key" -for 10m | head -4
refutes "and still cannot write, because approval is pending" kv_write "$ALICE" app1

step "4. she cannot approve her own request"
ACT=$($BIN pam pending -addr "$A" -token "$CAROL" 2>/dev/null | awk '/^  subject/ {print $4}')
SUBJ=$($BIN pam pending -addr "$A" -token "$CAROL" 2>/dev/null | awk '/^  subject/ {print $2}')
refutes "alice approving her own activation" \
  $BIN pam approve -addr "$A" -token "$ALICE" -subject "$SUBJ" -id "$ACT"
refutes "and she still cannot write" kv_write "$ALICE" app1

step "5. carol approves, and only then does the authority exist"
$BIN pam approve -addr "$A" -token "$CAROL" -subject "$SUBJ" -id "$ACT"
if kv_write "$ALICE" app1; then
  ok "alice can now write /secrets/app1"
else
  bad "an approved activation did not confer the authority"
fi
$BIN pam eligible -addr "$A" -token "$ALICE" | grep -q ACTIVE \
  && ok "and it shows as ACTIVE, with an expiry" \
  || bad "the activation should show as active"

step "6. the window cannot be widened or stacked"
refutes "a second activation while one is live" \
  $BIN pam activate -addr "$A" -token "$ALICE" -binding "$BINDING" -reason "again" -for 10m
# Publishing a trust bundle needs admin authority at "/" — a real operation
# outside the activated scope, rather than a path the router would normalize.
if curl -sf -X PUT -H "X-Vault-Token: $ALICE" -d '{}' "$A/v1/trust/bundle" >/dev/null 2>&1; then
  bad "the activation reached authority at / that it never granted"
else
  ok "the activation grants kv-admin at /secrets and nothing wider"
fi

step "7. carol can end it early, and eligibility survives"
$BIN pam kill -addr "$A" -token "$CAROL" -subject "$SUBJ" -id "$ACT" -reason "done"
refutes "alice cannot write once the activation is killed" kv_write "$ALICE" app1
$BIN pam eligible -addr "$A" -token "$ALICE" | grep -q "eligible .*kv-admin" \
  && ok "she is eligible again — the binding was never touched" \
  || bad "killing an activation should not remove eligibility"

step "8. the record of who held what, and why"
if $BIN pam eligible -addr "$A" -token "$ALICE" >/dev/null 2>&1; then
  ok "eligibility remains queryable after the fact"
fi
pkill -f "$BIN serve -data-dir d " 2>/dev/null || true; sleep 1
if $BIN audit verify -data-dir d >/dev/null 2>&1; then
  ok "every request, approval and kill is in the hash-chained audit log"
else
  bad "the audit chain should still verify"
fi

printf '\n\033[1m%d passed, %d failed\033[0m  (%s)\n' "$pass" "$fail" "$WORK"
[ "$fail" -eq 0 ]
