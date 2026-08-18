#!/usr/bin/env bash
# Milestone 5a: anchored audit.
#
# home does work and publishes signed checkpoints of its audit chain; aws
# witnesses them. Then home's history is rewritten the way someone holding the
# node actually would -- rolled back to a genuine earlier state, keys and all,
# and re-run differently -- and we watch what each layer does about it.
#
# The point of the script is the ORDER of those results:
#   the local hash chain says the rewritten log is FINE, because it is
#   the witness says it is not, because it remembers
#
# A second, cruder rewrite (wipe the node and start over) is covered at the end,
# because it fails differently: the audit key changes, and that is evidence too.
set -euo pipefail

BIN=${BIN:-$(cd "$(dirname "$0")/../.." && pwd)/signet}
WORK=${WORK:-$(mktemp -d)}
PORT=${PORT:-18601}
pass=0; fail=0

ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
refutes() { local n=$1; shift; if "$@" >/dev/null 2>&1; then bad "$n (accepted!)"; else ok "$n"; fi; }

[ -x "$BIN" ] || { echo "build first: make build" >&2; exit 1; }
cd "$WORK"
cleanup() { pkill -f "$BIN serve" 2>/dev/null || true; }
trap cleanup EXIT

HOME_PORT=$PORT
AWS_PORT=$((PORT+1))

start() { # start DIR PORT DOMAIN
  $BIN serve -data-dir "$1" -listen "127.0.0.1:$2" -domain "$3" -node-id "$3" > "$1.log" 2>&1 &
  for _ in $(seq 80); do curl -sf "http://127.0.0.1:$2/v1/sys/health" >/dev/null && return 0; sleep 0.25; done
  return 1
}
stop() { pkill -f "$BIN serve -data-dir $1 " 2>/dev/null || true; sleep 1; }
work() { # work PORT TOKEN N -- do N ordinary writes
  for i in $(seq "$3"); do
    curl -s -X PUT -H "X-Vault-Token: $2" -d "{\"data\":{\"k\":\"v$i\"}}" \
      "http://127.0.0.1:$1/v1/secrets/data/app$i" >/dev/null
  done
}

step "1. two domains"
for d in home aws; do
  mkdir -p "$d"
  $BIN genesis -data-dir "$d" > "$d/gen.txt" 2>&1
  grep -o 'signet\.[A-Za-z0-9._-]*' "$d/gen.txt" | head -1 > "$d/token"
done
start home $HOME_PORT home.example.net
start aws $AWS_PORT aws.example.net
ok "home and aws running, each with its own audit chain"

step "2. home does some work, then is witnessed by aws"
work $HOME_PORT "$(cat home/token)" 5
$BIN audit witness -subject "http://127.0.0.1:$HOME_PORT" -subject-token "$(cat home/token)" \
   -witness "http://127.0.0.1:$AWS_PORT" -witness-token "$(cat aws/token)"
BEFORE_COUNT=$(curl -s "http://127.0.0.1:$AWS_PORT/v1/audit/witnessed?domain=home.example.net" \
   | python3 -c "import json,sys;print(json.load(sys.stdin)['count'])")
ok "aws holds home's chain at $BEFORE_COUNT entries"

step "3. more work, and a second witnessing that must verify by replay"
# Before that work, take a copy of home exactly as it stands. This is the
# attacker's restore point later: keys, seal, audit key and all. Wiping a node
# is the easy attack to catch (the audit key changes); rolling one back to a
# genuine earlier state keeps every key intact, so nothing about the node looks
# new. That is the case worth testing.
cp -R home home-backup
work $HOME_PORT "$(cat home/token)" 4
$BIN audit witness -subject "http://127.0.0.1:$HOME_PORT" -subject-token "$(cat home/token)" \
   -witness "http://127.0.0.1:$AWS_PORT" -witness-token "$(cat aws/token)"
ok "the extension was accepted only after aws replayed the new entries itself"

# Save the head aws has committed to, as the evidence it will hold against.
WITNESSED=$(curl -s "http://127.0.0.1:$AWS_PORT/v1/audit/witnessed?domain=home.example.net" \
   | python3 -c "import json,sys;print(json.load(sys.stdin)['count'])")

step "4. home's local chain verifies, as it should"
stop home
if $BIN audit verify -data-dir home >/dev/null 2>&1; then
  ok "hash chain intact over $WITNESSED entries"
else
  bad "the honest chain should verify"
fi

step "5. the attack: home is rolled back and given a different history"
# The realistic rewrite. Not "edit one record and hope" -- restore a genuine
# earlier state of the node and carry on differently, so the log is internally
# perfect, signed by the same key, and describes events that never happened.
rm -rf home
mv home-backup home
start home $HOME_PORT home.example.net
work $HOME_PORT "$(cat home/token)" 9   # a divergent history, longer than the real one
ok "home rolled back to its state at $BEFORE_COUNT entries, then re-run differently"
ok "every key survived the rollback: same seal, same audit key, same token"

step "6. what each layer says about the rewritten log"
stop home
if $BIN audit verify -data-dir home >/dev/null 2>&1; then
  ok "the LOCAL hash chain says the rewritten log is intact -- and it is right"
else
  bad "a rebuilt chain is internally consistent and should verify locally"
fi
printf '       \033[2m(this is the limit of chaining: it proves nobody edited an entry,\n'
printf '        not that the entries are the ones that ever happened)\033[0m\n'

start home $HOME_PORT home.example.net
refutes "the WITNESS refuses it: the entries after $BEFORE_COUNT are not the ones it verified" \
  $BIN audit witness -subject "http://127.0.0.1:$HOME_PORT" -subject-token "$(cat home/token)" \
     -witness "http://127.0.0.1:$AWS_PORT" -witness-token "$(cat aws/token)"

step "7. the evidence aws now holds"
$BIN audit witnessed -addr "http://127.0.0.1:$AWS_PORT" || true
AFTER=$(curl -s "http://127.0.0.1:$AWS_PORT/v1/audit/witnessed?domain=home.example.net" \
   | python3 -c "import json,sys;print(json.load(sys.stdin)['count'])")
if [ "$AFTER" = "$WITNESSED" ]; then
  ok "aws kept the head it verified ($WITNESSED entries) and was not talked out of it"
else
  bad "aws moved to the rewritten history"
fi
if curl -s "http://127.0.0.1:$AWS_PORT/v1/audit/witnessed?domain=home.example.net" | grep -q conflict; then
  ok "the conflict is stored as durable evidence, not just returned once"
else
  bad "the conflict should be persisted"
fi

step "8. a witness cannot be reset by simply asking again"
refutes "re-presenting the rewritten history a second time" \
  $BIN audit witness -subject "http://127.0.0.1:$HOME_PORT" -subject-token "$(cat home/token)" \
     -witness "http://127.0.0.1:$AWS_PORT" -witness-token "$(cat aws/token)"

step "9. the cruder rewrite: a node wiped and started again"
# Rebuilding from nothing is easier to catch, and worth catching separately: the
# checkpoint key does not survive, so the domain stops being able to prove it is
# the same domain. That is recorded as evidence rather than shrugged off.
mkdir -p gcp
$BIN genesis -data-dir gcp > gcp/gen.txt 2>&1
grep -o 'signet\.[A-Za-z0-9._-]*' gcp/gen.txt | head -1 > gcp/token
start gcp $((PORT+2)) gcp.example.net
work $((PORT+2)) "$(cat gcp/token)" 3
$BIN audit witness -subject "http://127.0.0.1:$((PORT+2))" -subject-token "$(cat gcp/token)" \
   -witness "http://127.0.0.1:$AWS_PORT" -witness-token "$(cat aws/token)" >/dev/null
ok "gcp witnessed by aws"

stop gcp
rm -rf gcp && mkdir -p gcp
$BIN genesis -data-dir gcp > gcp/gen2.txt 2>&1
grep -o 'signet\.[A-Za-z0-9._-]*' gcp/gen2.txt | head -1 > gcp/token
start gcp $((PORT+2)) gcp.example.net
work $((PORT+2)) "$(cat gcp/token)" 6
refutes "a domain rebuilt from nothing cannot pass itself off as the original" \
  $BIN audit witness -subject "http://127.0.0.1:$((PORT+2))" -subject-token "$(cat gcp/token)" \
     -witness "http://127.0.0.1:$AWS_PORT" -witness-token "$(cat aws/token)"
if curl -s "http://127.0.0.1:$AWS_PORT/v1/audit/witnessed?domain=gcp.example.net" \
   | grep -q "different key"; then
  ok "and the changed checkpoint key is recorded as the reason"
else
  bad "the key change should be recorded as evidence"
fi

printf '\n\033[1m%d passed, %d failed\033[0m  (%s)\n' "$pass" "$fail" "$WORK"
[ "$fail" -eq 0 ]
