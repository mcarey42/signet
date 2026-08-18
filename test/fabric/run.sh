#!/usr/bin/env bash
# Milestone 4c: the multi-domain fabric.
#
#   Example Root CA (offline)
#     |- home.example.net   subordinate: its issuer is signed by the org root
#     |- gcp.example.net    subordinate: likewise
#   AWS Root CA (offline, separate)
#     '- aws.example.net    sovereign: its own root, federated as an equal
#
# One consumer federates with all three and holds their bundles separately.
# The assertions that matter are the impersonation attempts, because the whole
# question a fabric answers is "who is allowed to say who someone is".
#
# In particular this demonstrates the milestone's finding: under cascade, home
# and gcp share a root, so home CAN build a valid chain for a gcp identity. What
# stops it is that gcp's bundle publishes only gcp's issuer.
set -euo pipefail

BIN=${BIN:-$(cd "$(dirname "$0")/../.." && pwd)/signet}
WORK=${WORK:-$(mktemp -d)}
PORT=${PORT:-18301}
pass=0; fail=0

ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
step() { printf '\n\033[1m%s\033[0m\n' "$1"; }
refutes() { local n=$1; shift; if "$@" >/dev/null 2>&1; then bad "$n (accepted!)"; else ok "$n"; fi; }

[ -x "$BIN" ] || { echo "build first: make build" >&2; exit 1; }
cd "$WORK"
cleanup() { pkill -f "$BIN serve" 2>/dev/null || true; }
trap cleanup EXIT

# domain -> port
port_of() { case $1 in home) echo $PORT;; gcp) echo $((PORT+1));; aws) echo $((PORT+2));; esac; }

step "1. two roots: one organizational, one sovereign"
$BIN ca init-root -out org-root -common-name "Example" -ttl 8760h >/dev/null
$BIN ca init-root -out aws-root -common-name "AWS" -ttl 8760h >/dev/null
ORG_PIN=$($BIN trust pin -root org-root 2>/dev/null)
AWS_PIN=$($BIN trust pin -root aws-root 2>/dev/null)
ok "org root and a separate aws root, neither knowing about the other"

step "2. three domains, each with its own issuer and its own node"
for d in home gcp aws; do
  root=org-root; [ "$d" = aws ] && root=aws-root
  fqdn="$d.example.net"
  mkdir -p "node-$d"
  cat > "cfg-$d.json" <<EOF
{ "pki_roles": [ { "name": "id", "scope": "/pki/server",
    "allowed_domains": ["$fqdn"], "allow_subdomains": true,
    "allowed_uri_prefixes": ["spiffe://$fqdn/"], "max_ttl_seconds": 86400 } ] }
EOF
  $BIN genesis -data-dir "node-$d" -config "cfg-$d.json" > "node-$d/gen.txt" 2>&1
  grep -o 'signet\.[A-Za-z0-9._-]*' "node-$d/gen.txt" | head -1 > "node-$d/token"
  $BIN ca request -data-dir "node-$d" -out "$d.csr" -common-name "$d issuer" >/dev/null
  $BIN ca sign-issuer -root "$root" -csr "$d.csr" -out "$d-issuer.crt" \
      -domains "$fqdn" -ttl 4380h >/dev/null
  $BIN ca install -data-dir "node-$d" -cert "$d-issuer.crt" \
      -root-cert "$root/root.crt" -node-id "node-$d" >/dev/null
  $BIN serve -data-dir "node-$d" -listen "127.0.0.1:$(port_of "$d")" -node-id "node-$d" \
      > "$d.log" 2>&1 &
done
for d in home gcp aws; do
  for _ in $(seq 80); do
    curl -sf "http://127.0.0.1:$(port_of "$d")/v1/sys/health" >/dev/null && break; sleep 0.25
  done
done
ok "home and gcp subordinate to the org root; aws standing on its own"

# Create the rogue sibling issuer BEFORE the bundles are published. The
# original ordering created it afterwards, which is exactly why this test
# missed that `ca bundle` was publishing every sibling's issuer into every
# domain's bundle -- the defence it asserts was vacuous and the test could not
# tell.
openssl ecparam -name prime256v1 -genkey -noout -out rogue.key 2>/dev/null
openssl req -new -key rogue.key -out rogue-ca.csr -subj "/CN=home rogue issuer" 2>/dev/null
$BIN ca sign-issuer -root org-root -csr rogue-ca.csr -out rogue-ca.crt \
   -domains home.example.net -ttl 4380h >/dev/null

step "3. each domain publishes its own bundle"
for d in home gcp; do
  $BIN ca bundle -root org-root -domain "$d.example.net" -out "$d-bundle.json" -max-age 720h >/dev/null
done
$BIN ca bundle -root aws-root -domain aws.example.net -out aws-bundle.json -max-age 720h >/dev/null
# The org root signed home's and gcp's issuers both, so its issuer directory
# holds both. Each domain's bundle must publish only its own issuer -- that is
# what makes the issuer list load-bearing rather than decorative.
for d in home gcp aws; do
  $BIN trust install -addr "http://127.0.0.1:$(port_of "$d")" \
     -token "$(cat node-$d/token)" -bundle "$d-bundle.json" >/dev/null
done
ok "three bundles published, one per domain"

# Assert on what the bundles actually CONTAIN, not just that publishing worked.
# The property is no CROSS-DOMAIN leakage: a domain may publish several of its
# own issuers (the rogue CA above is a legitimately-constrained second home
# issuer, which is the point of the attack), but a sibling's issuer appearing
# here is what makes the whole defence vacuous.
check_no_leak() { # check_no_leak DOMAIN FOREIGN_SUBSTRING
  names=$(python3 -c "
import json,base64
p=json.loads(base64.b64decode(json.load(open('$1-bundle.json'))['payload']))
print(','.join(sorted(i['name'] for i in p['issuers'])))")
  case "$names" in
    *"$2"*) bad "$1.example.net publishes [$names] — a $2 issuer here makes the defence vacuous" ;;
    *)      ok  "$1.example.net publishes no $2 issuer ($names)" ;;
  esac
}
check_no_leak home gcp
check_no_leak gcp home

step "4. one consumer federates with all three"
S=consumer/trust.json
for d in home gcp; do
  $BIN trust fetch -url "http://127.0.0.1:$(port_of "$d")" -pin "$ORG_PIN" \
     -domain "$d.example.net" -state "$S" >/dev/null
done
$BIN trust fetch -url "http://127.0.0.1:$(port_of aws)" -pin "$AWS_PIN" \
   -domain aws.example.net -state "$S" >/dev/null
$BIN trust peers -state "$S"

step "5. genuine identities"
issue() { # issue DOMAIN SPIFFE_PATH OUTFILE  -- returns a leaf from that domain's node
  local d=$1 path=$2 out=$3
  openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
     -keyout "$out.key" -out "$out.csr" -subj "/CN=api.$d.example.net" 2>/dev/null
  local csr; csr=$(python3 -c "import json;print(json.dumps(open('$out.csr').read()))")
  curl -s -X POST -H "X-Vault-Token: $(cat node-$d/token)" \
     -d "{\"csr\":$csr,\"common_name\":\"$path.$d.example.net\",\"ttl\":\"1h\",\"uri_sans\":\"spiffe://$d.example.net/$path\"}" \
     "http://127.0.0.1:$(port_of "$d")/v1/pki/sign/id" \
   | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['data']['certificate'] if 'data' in d else '')" > "$out.crt"
  [ -s "$out.crt" ]
}
for d in home gcp aws; do
  issue "$d" "workload/api" "leaf-$d" || { bad "issuing a $d identity"; continue; }
  if $BIN trust check -cert "leaf-$d.crt" -state "$S" >/dev/null 2>&1; then
    ok "$d.example.net vouches for its own workload"
  else
    bad "$d should vouch for its own workload"
  fi
done

step "6. impersonation across a SHARED root (home -> gcp)"
# home asks its own node for a gcp identity. The node refuses: an issuer's role
# bounds what it may assert, which is the primary, issuer-side control (E-02).
csr_out=cross
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
   -keyout $csr_out.key -out $csr_out.csr -subj "/CN=impostor" 2>/dev/null
CSR=$(python3 -c "import json;print(json.dumps(open('$csr_out.csr').read()))")
RESP=$(curl -s -X POST -H "X-Vault-Token: $(cat node-home/token)" \
   -d "{\"csr\":$CSR,\"common_name\":\"api.gcp.example.net\",\"ttl\":\"1h\",\"uri_sans\":\"spiffe://gcp.example.net/workload/api\"}" \
   "http://127.0.0.1:$(port_of home)/v1/pki/sign/id")
if echo "$RESP" | grep -q '"certificate"'; then
  bad "home's node minted a gcp identity (issuer-side control failed)"
  echo "$RESP" | python3 -c "import json,sys;print(json.load(sys.stdin)['data']['certificate'])" > forged.crt
else
  ok "home's node refuses to mint a gcp identity (issuer-side control holds)"
fi

# The verifier-side test needs a certificate genuinely signed by home's issuer
# but naming a gcp identity. home's issuing key lives sealed inside its node, so
# we mint the equivalent with a standalone CA that the org root also signed --
# the same shape as a compromised sibling.
cat > forge.cnf <<'EOF'
[v3]
subjectAltName=URI:spiffe://gcp.example.net/workload/api
EOF
openssl x509 -req -in $csr_out.csr -CA rogue-ca.crt -CAkey rogue.key -CAcreateserial \
   -out forged.crt -days 1 -extfile forge.cnf -extensions v3 2>/dev/null
ok "forged a gcp identity from a sibling issuer the org root signed"

# It chains to the org root, which is gcp's anchor. Prove that first.
if openssl verify -CAfile org-root/root.crt -untrusted rogue-ca.crt forged.crt >/dev/null 2>&1; then
  ok "the forgery DOES chain to the shared org root (so the chain is valid)"
else
  bad "precondition: the forgery should chain to the org root"
fi

refutes "yet gcp's bundle refuses it, because that issuer is not one gcp publishes" \
  $BIN trust check -cert forged.crt -chain rogue-ca.crt -state "$S"

step "7. impersonation against a SOVEREIGN domain (home -> aws)"
cat > forge-aws.cnf <<'EOF'
[v3]
subjectAltName=URI:spiffe://aws.example.net/workload/api
EOF
openssl x509 -req -in $csr_out.csr -CA rogue-ca.crt -CAkey rogue.key -CAcreateserial \
   -out forged-aws.crt -days 1 -extfile forge-aws.cnf -extensions v3 2>/dev/null
refutes "aws refuses it, and no chain to aws's root exists at all" \
  $BIN trust check -cert forged-aws.crt -chain rogue-ca.crt -state "$S"
# The difference worth naming: even handed the whole org chain, aws cannot be
# reached. Under cascade the equivalent forgery is stopped by policy; here it is
# stopped by arithmetic.
cat rogue-ca.crt org-root/root.crt > org-chain.pem
refutes "aws refuses it even given the entire organizational chain" \
  $BIN trust check -cert forged-aws.crt -chain org-chain.pem -state "$S"

step "8. an unfederated domain is not looked up"
openssl ecparam -name prime256v1 -genkey -noout -out out.key 2>/dev/null
openssl req -new -key out.key -out out.csr -subj "/CN=outsider" 2>/dev/null
cat > out.cnf <<'EOF'
[v3]
subjectAltName=URI:spiffe://azure.example.net/workload/api
EOF
openssl x509 -req -in out.csr -CA rogue-ca.crt -CAkey rogue.key -CAcreateserial \
   -out outsider.crt -days 1 -extfile out.cnf -extensions v3 2>/dev/null
refutes "an identity from a domain this consumer does not federate with" \
  $BIN trust check -cert outsider.crt -state "$S"

printf '\n\033[1m%d passed, %d failed\033[0m  (%s)\n' "$pass" "$fail" "$WORK"
[ "$fail" -eq 0 ]
