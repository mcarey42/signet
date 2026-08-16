#!/usr/bin/env bash
# Interop test: unmodified External Secrets Operator reading from Signet.
#
# This is the goal criterion from the charter, run against real software: a real
# kind cluster, the real ESO Helm chart, and the same ExternalSecret shape the
# homelab uses in production. It is the seed of the conformance harness in
# docs/10 — the bug-compatibility details it exercises (404-with-empty-errors,
# ttl-as-JSON-number, mount preflight) are precisely the ones that only fail
# against a real client.
#
#   ./test/kind/run.sh          run everything
#   ./test/kind/run.sh clean    delete the cluster
set -euo pipefail

CLUSTER=${CLUSTER:-signet-test}
CTX="kind-${CLUSTER}"
IMAGE=${IMAGE:-signet:dev}
MOUNT=secrets-home-solcore-dot-net
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
BUILD=${BUILD_DIR:-${TMPDIR:-/tmp}signet-build}

k() { kubectl --context "$CTX" "$@"; }
say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

if [[ ${1:-} == clean ]]; then
	kind delete cluster --name "$CLUSTER"
	exit 0
fi

say "build the linux binary and image"
# The source tree may live on a filesystem without flock, so build from a mirror.
rsync -a --delete --exclude '.git' --exclude '._*' "$ROOT"/ "$BUILD"/
(cd "$BUILD" && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o signet-linux ./cmd/signet)
docker build -q -t "$IMAGE" "$BUILD" >/dev/null
echo "image: $(docker images "$IMAGE" --format '{{.Repository}}:{{.Tag}} {{.Size}}')"

say "create the cluster"
kind get clusters 2>/dev/null | grep -qx "$CLUSTER" || kind create cluster --name "$CLUSTER" --wait 120s
kind load docker-image "$IMAGE" --name "$CLUSTER"

say "pin the cluster's signing keys (out of band)"
# Signet never discovers verification keys from a request. They are fetched
# here, from the cluster's OIDC discovery endpoint, and mounted as a file.
k apply -f "$HERE/signet.yaml" >/dev/null 2>&1 || true
k get --raw /openid/v1/jwks > "$BUILD/jwks.json"
k -n signet delete configmap signet-jwks --ignore-not-found >/dev/null
k -n signet create configmap signet-jwks --from-file=jwks.json="$BUILD/jwks.json" >/dev/null
echo "issuer: $(k get --raw /.well-known/openid-configuration | python3 -c 'import sys,json;print(json.load(sys.stdin)["issuer"])')"

say "deploy signet"
k apply -f "$HERE/signet.yaml"
# Always start from a fresh domain. The data directory is an emptyDir, so
# replacing the pod re-runs genesis and issues new bootstrap tokens — without
# this, a re-run would read stale (possibly revoked) tokens from an old log.
k -n signet rollout restart deploy/signet
k -n signet rollout status deploy/signet --timeout=180s
# Drop the consumer namespace too. A SecretStore caches its readiness, so one
# left over from a previous domain would stay NotReady against tokens that no
# longer exist — recreating it is what makes the run reproducible.
k delete ns demo --ignore-not-found --wait >/dev/null 2>&1 || true

say "collect the root token from the genesis log"
# Only the operator token is bootstrapped. ESO gets no token at all — it
# authenticates as its Kubernetes workload identity.
POD=$(k -n signet get pod -l app=signet -o jsonpath='{.items[0].metadata.name}')
LOG=$(k -n signet logs "$POD" -c genesis)
ROOT_TOKEN=$(awk '/root token:/{print $3}' <<<"$LOG")
[[ -n $ROOT_TOKEN ]] || { echo "could not parse the root token"; exit 1; }
echo "root=${ROOT_TOKEN:0:16}...  (no ESO token: it attests instead)"

say "seed secrets through the API"
k -n signet port-forward svc/signet 8300:8200 >/dev/null 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
until curl -sf localhost:8300/v1/sys/health >/dev/null 2>&1; do sleep 0.25; done
curl -sf -X PUT -H "X-Vault-Token: $ROOT_TOKEN" \
	-d '{"data":{"master-key":"sk-litellm-REAL","runpod-api-key":"rp-REAL"}}' \
	"localhost:8300/v1/$MOUNT/data/cluster-svc/apps/litellm" >/dev/null
# Out of scope for the ESO workload — the negative test needs a real secret to
# be denied, not merely a missing one.
curl -sf -X PUT -H "X-Vault-Token: $ROOT_TOKEN" -d '{"data":{"top":"secret"}}' \
	"localhost:8300/v1/$MOUNT/data/cluster-main/apps/forbidden" >/dev/null
kill $PF 2>/dev/null || true; trap - EXIT

say "install External Secrets Operator (upstream chart, unmodified)"
helm repo add external-secrets https://charts.external-secrets.io >/dev/null 2>&1 || true
helm repo update >/dev/null
helm --kube-context "$CTX" upgrade --install external-secrets external-secrets/external-secrets \
	-n external-secrets --create-namespace --set installCRDs=true --wait --timeout 8m >/dev/null
echo "ESO $(helm --kube-context "$CTX" -n external-secrets list -f external-secrets -o json | python3 -c 'import sys,json; print(json.load(sys.stdin)[0]["app_version"])')"

say "apply SecretStore + ExternalSecrets"
k apply -f "$HERE/externalsecret.yaml"
sleep 20

say "results"
k -n demo get externalsecret -o custom-columns=\
'NAME:.metadata.name,READY:.status.conditions[0].status,REASON:.status.conditions[0].reason'
echo
fail=0
got=$(k -n demo get secret litellm-secret -o jsonpath='{.data.LITELLM_MASTER_KEY}' 2>/dev/null | base64 -d || true)
if [[ $got == "sk-litellm-REAL" ]]; then
	echo "PASS  in-scope secret synced: LITELLM_MASTER_KEY=$got"
else
	echo "FAIL  in-scope secret: got '${got:-<none>}'"; fail=1
fi
for name in forbidden missing impostor; do
	ready=$(k -n demo get externalsecret "$name" -o jsonpath='{.status.conditions[0].status}' 2>/dev/null)
	if [[ $ready == "False" ]]; then
		echo "PASS  $name correctly refused"
	else
		echo "FAIL  $name should not have synced (ready=$ready)"; fail=1
	fi
done

say "install cert-manager and issue a certificate from Signet's CA"
helm repo add jetstack https://charts.jetstack.io >/dev/null 2>&1 || true
helm repo update >/dev/null
helm --kube-context "$CTX" upgrade --install cert-manager jetstack/cert-manager \
	-n cert-manager --create-namespace --set crds.enabled=true --wait --timeout 8m >/dev/null
k apply -f "$HERE/certificate.yaml"
for _ in $(seq 1 40); do
	[[ $(k -n demo get certificate demo-tls -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null) == "True" ]] && break
	sleep 3
done
k -n demo get certificate -o custom-columns=\
'NAME:.metadata.name,READY:.status.conditions[?(@.type=="Ready")].status,MESSAGE:.status.conditions[?(@.type=="Ready")].message' | cut -c1-110
echo
if [[ $(k -n demo get certificate demo-tls -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}') == "True" ]]; then
	k -n demo get secret demo-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > "$BUILD/issued.crt"
	subject=$(openssl x509 -in "$BUILD/issued.crt" -noout -subject 2>/dev/null)
	echo "PASS  cert-manager obtained a certificate from Signet: $subject"
	# Verify it against the CA Signet published, using a different TLS stack.
	k -n signet port-forward svc/signet 8300:8200 >/dev/null 2>&1 &
	PF=$!
	until curl -sf localhost:8300/v1/sys/health >/dev/null 2>&1; do sleep 0.25; done
	curl -sf "localhost:8300/v1/pki-home-solcore-dot-net/ca_chain" > "$BUILD/chain.pem"
	kill $PF 2>/dev/null || true
	if openssl verify -CAfile "$BUILD/chain.pem" "$BUILD/issued.crt" >/dev/null 2>&1; then
		echo "PASS  the issued certificate verifies against Signet's published chain (openssl)"
	else
		echo "FAIL  the issued certificate does not verify against the published chain"; fail=1
	fi
else
	echo "FAIL  cert-manager could not obtain a certificate"; fail=1
fi
forbidden=$(k -n demo get certificate forbidden-tls -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
if [[ $forbidden != "True" ]]; then
	echo "PASS  the out-of-scope certificate was refused by the signing role"
else
	echo "FAIL  a certificate outside the role's domains was issued"; fail=1
fi

say "live rotation"
k -n signet port-forward svc/signet 8300:8200 >/dev/null 2>&1 &
PF=$!
trap 'kill $PF 2>/dev/null || true' EXIT
until curl -sf localhost:8300/v1/sys/health >/dev/null 2>&1; do sleep 0.25; done
curl -sf -X PUT -H "X-Vault-Token: $ROOT_TOKEN" \
	-d '{"data":{"master-key":"sk-ROTATED-v2","runpod-api-key":"rp-REAL"}}' \
	"localhost:8300/v1/$MOUNT/data/cluster-svc/apps/litellm" >/dev/null
kill $PF 2>/dev/null || true; trap - EXIT
for _ in $(seq 1 30); do
	[[ $(k -n demo get secret litellm-secret -o jsonpath='{.data.LITELLM_MASTER_KEY}' | base64 -d) == "sk-ROTATED-v2" ]] && break
	sleep 2
done
if [[ $(k -n demo get secret litellm-secret -o jsonpath='{.data.LITELLM_MASTER_KEY}' | base64 -d) == "sk-ROTATED-v2" ]]; then
	echo "PASS  rotation propagated to the Kubernetes Secret"
else
	echo "FAIL  rotation did not propagate"; fail=1
fi

say $([[ $fail == 0 ]] && echo "ALL CHECKS PASSED" || echo "FAILURES ABOVE")
exit $fail
