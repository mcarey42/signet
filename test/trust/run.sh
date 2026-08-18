#!/usr/bin/env bash
# Milestone 4b end to end: one offline root, two signing nodes, one signed trust
# bundle, and two consumers that choose different anchors from it.
#
# The interesting assertions are the negative ones — a forged bundle, a tampered
# payload, a replayed epoch, a withdrawn issuer — because a trust artifact is
# only worth as much as what it refuses.
#
# Verification here is done with openssl, not with Signet's own code. Checking
# our certificates with our own verifier would prove considerably less.
set -euo pipefail

BIN=${BIN:-$(cd "$(dirname "$0")/../.." && pwd)/signet}
WORK=${WORK:-$(mktemp -d)}
PORT=${PORT:-18251}
pass=0; fail=0

ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
# refutes NAME CMD... — the command must fail, and its message must be legible.
refutes() { local n=$1; shift; if "$@" >/dev/null 2>&1; then bad "$n (accepted!)"; else ok "$n"; fi; }

[ -x "$BIN" ] || { echo "build first: make build && cp \$(make -s binpath) ./signet" >&2; exit 1; }
cd "$WORK"
cleanup() { pkill -f "$BIN serve" 2>/dev/null || true; }
trap cleanup EXIT

step "1. an offline root, used a handful of times and then put away"
$BIN ca init-root -out root -common-name "Example" -ttl 8760h >/dev/null
PIN=$($BIN trust pin -root root 2>/dev/null)
ok "root created; consumers will pin ${PIN:0:24}..."

step "2. two signing nodes, each generating its key where that key lives"
cat > cfg.json <<'EOF'
{ "pki_roles": [ { "name": "srv", "scope": "/pki/server",
    "allowed_domains": ["a.example.net","b.example.net"],
    "allow_subdomains": true, "max_ttl_seconds": 86400 } ] }
EOF
for n in a b; do
  mkdir -p "node-$n"
  $BIN genesis -data-dir "node-$n" -config cfg.json > "node-$n/gen.txt" 2>&1
  grep -o 'signet\.[A-Za-z0-9._-]*' "node-$n/gen.txt" | head -1 > "node-$n/token"
  $BIN ca request -data-dir "node-$n" -out "issuer-$n.csr" -common-name "issuer $n" >/dev/null
  # -trust-domain records which domain's bundle this issuer belongs in. Its DNS
  # constraint ($n.example.net) and the trust domain (home.example.net) are
  # different things, so the association is recorded rather than inferred.
  $BIN ca sign-issuer -root root -csr "issuer-$n.csr" -out "issuer-$n.crt" \
      -domains "$n.example.net" -trust-domain home.example.net -ttl 4380h >/dev/null
  $BIN ca install -data-dir "node-$n" -cert "issuer-$n.crt" -root-cert root/root.crt \
      -node-id "node-$n" >/dev/null
done
ok "issuer a and issuer b certified by the one root"

step "3. publish the bundle (a root ceremony, because only the root may say who is trusted)"
$BIN ca bundle -root root -domain home.example.net -out bundle.json -max-age 720h >/dev/null
ok "epoch 1 published"

$BIN serve -data-dir node-a -listen "127.0.0.1:$PORT" -node-id node-a >serve.log 2>&1 &
for _ in $(seq 60); do curl -sf "http://127.0.0.1:$PORT/v1/sys/health" >/dev/null && break; sleep 0.25; done
$BIN trust install -addr "http://127.0.0.1:$PORT" -token "$(cat node-a/token)" -bundle bundle.json >/dev/null
ok "published to a running node over the API (no restart, so expiry is not an outage)"

step "4. real leaves from each node"
for n in a b; do
  p=$PORT
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
     -keyout "leaf-$n.key" -out "leaf-$n.csr" -subj "/CN=host.$n.example.net" 2>/dev/null
  if [ "$n" = b ]; then
    $BIN serve -data-dir node-b -listen "127.0.0.1:$((PORT+1))" -node-id node-b >serve-b.log 2>&1 &
    for _ in $(seq 60); do curl -sf "http://127.0.0.1:$((PORT+1))/v1/sys/health" >/dev/null && break; sleep 0.25; done
    p=$((PORT+1))
  fi
  CSR=$(python3 -c "import json;print(json.dumps(open('leaf-$n.csr').read()))")
  curl -s -X POST -H "X-Vault-Token: $(cat node-$n/token)" \
     -d "{\"csr\":$CSR,\"common_name\":\"host.$n.example.net\",\"ttl\":\"1h\"}" \
     "http://127.0.0.1:$p/v1/pki/sign/srv" \
   | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['certificate'])" > "leaf-$n.crt"
done
ok "leaves issued by each node's own issuer"

step "5. two consumers, one artifact, different anchors"
$BIN trust fetch -url "http://127.0.0.1:$PORT" -pin "$PIN" -domain home.example.net \
   -state c-cascade/trust.json -anchor root \
   -out c-cascade/anchor.crt -issuers-out c-cascade/issuers.pem >/dev/null
$BIN trust fetch -url "http://127.0.0.1:$PORT" -pin "$PIN" -domain home.example.net \
   -state c-pinned/trust.json -anchor issuer -anchor-name "issuer a" \
   -out c-pinned/anchor.crt >/dev/null

# Cascade trusts the root, so both issuers' leaves verify.
openssl verify -CAfile c-cascade/anchor.crt -untrusted c-cascade/issuers.pem leaf-a.crt >/dev/null 2>&1 \
  && ok "cascade consumer accepts node a's leaf" || bad "cascade should accept node a"
openssl verify -CAfile c-cascade/anchor.crt -untrusted c-cascade/issuers.pem leaf-b.crt >/dev/null 2>&1 \
  && ok "cascade consumer accepts node b's leaf" || bad "cascade should accept node b"

# Pinned trusts one issuer. -partial_chain because OpenSSL otherwise refuses a
# non-self-signed anchor outright: a real difference between verifiers, not a
# certificate problem. See docs/02 and docs/16.
openssl verify -partial_chain -CAfile c-pinned/anchor.crt leaf-a.crt >/dev/null 2>&1 \
  && ok "pinned consumer accepts its own issuer's leaf" || bad "pinned should accept node a"
refutes "pinned consumer refuses the sibling issuer's leaf (subdivision is real)" \
  openssl verify -partial_chain -CAfile c-pinned/anchor.crt leaf-b.crt

step "6. what the bundle refuses"
$BIN ca init-root -out evil -common-name "Example" -ttl 8760h >/dev/null
# The impostor copies the real root's issuer records wholesale — certificates
# and their trust-domain sidecars — so its bundle is well formed in every
# respect except the one that matters: who signed it.
mkdir -p evil/issuers && cp root/issuers/* evil/issuers/
$BIN ca bundle -root evil -domain home.example.net -out evil.json >/dev/null
refutes "a bundle from an impostor root with the same name" \
  $BIN trust verify -bundle evil.json -pin "$PIN"

python3 - <<'PY'
import json, base64
b = json.load(open('bundle.json'))
p = json.loads(base64.b64decode(b['payload']))
p['max_age_sec'] = 999999999
b['payload'] = base64.b64encode(json.dumps(p).encode()).decode()
json.dump(b, open('tampered.json', 'w'))
PY
refutes "a payload altered in transit" \
  $BIN trust verify -bundle tampered.json -pin "$PIN"
refutes "a bundle read with no pin at all" \
  $BIN trust verify -bundle bundle.json -pin ""
refutes "a bundle claiming a domain the consumer did not ask for" \
  $BIN trust verify -bundle bundle.json -pin "$PIN" -domain aws.example.net
refutes "a node asked to publish a bundle from a root it does not chain to" \
  $BIN trust install -addr "http://127.0.0.1:$PORT" -token "$(cat node-a/token)" -bundle evil.json

# Staleness, with a real clock rather than an injected one. This caught a live
# bug: skew tolerance was extending every bundle's life past its max age.
$BIN ca bundle -root root -domain home.example.net -out stale.json -max-age 2s >/dev/null
$BIN trust verify -bundle stale.json -pin "$PIN" >/dev/null 2>&1 \
  && ok "a fresh short-lived bundle is accepted" || bad "fresh bundle should be accepted"
sleep 3
refutes "the same bundle once past its max age (skew must not extend it)" \
  $BIN trust verify -bundle stale.json -pin "$PIN"

step "7. withdraw an issuer, then try to undo it by replay"
FP_B=$(openssl x509 -in issuer-b.crt -noout -pubkey \
      | openssl pkey -pubin -outform der 2>/dev/null \
      | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=')
$BIN ca bundle -root root -domain home.example.net -out bundle2.json -max-age 720h \
   -revoke "sha256:$FP_B" >/dev/null
$BIN trust install -addr "http://127.0.0.1:$PORT" -token "$(cat node-a/token)" -bundle bundle2.json >/dev/null
$BIN trust fetch -url "http://127.0.0.1:$PORT" -pin "$PIN" -state c-cascade/trust.json \
   -anchor root -out c-cascade/anchor.crt -issuers-out c-cascade/issuers.pem >/dev/null
ok "epoch 2 published and refreshed, issuer b withdrawn"

openssl verify -CAfile c-cascade/anchor.crt -untrusted c-cascade/issuers.pem leaf-a.crt >/dev/null 2>&1 \
  && ok "the surviving issuer's leaf still verifies" || bad "issuer a should survive"
refutes "the withdrawn issuer's leaf no longer builds a path" \
  openssl verify -CAfile c-cascade/anchor.crt -untrusted c-cascade/issuers.pem leaf-b.crt
refutes "replaying epoch 1 at a consumer that has seen epoch 2" \
  $BIN trust verify -bundle bundle.json -pin "$PIN" -state c-cascade/trust.json
refutes "walking the node itself back to epoch 1" \
  $BIN trust install -addr "http://127.0.0.1:$PORT" -token "$(cat node-a/token)" -bundle bundle.json

printf '\n\033[1m%d passed, %d failed\033[0m  (%s)\n' "$pass" "$fail" "$WORK"
[ "$fail" -eq 0 ]
