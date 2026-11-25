#!/usr/bin/env bash
# Live e2e orchestrator. Creates ONE kind cluster, installs Kyverno once, then
# runs every e2e/tests/*.sh against it and aggregates the result.
#
#   ./e2e/run.sh                 # full suite (what CI runs)
#   ./e2e/run.sh deprecated-apis # only e2e/tests/deprecated-apis.sh
#
# Adding live coverage for a policy = drop a new e2e/tests/<name>.sh that
# sources ../lib.sh; no change here or to the workflow is needed.
#
# Env: CLUSTER_NAME (kyverno-e2e), NODE_IMAGE (kindest/node:v1.31.9 — keep it
# pinned to a GKE-supported version), KEEP_CLUSTER=1 to skip teardown.
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-kyverno-e2e}"
NODE_IMAGE="${NODE_IMAGE:-kindest/node:v1.31.9}"
export E2E_CTX="kind-${CLUSTER_NAME}"
DIR="$(cd "$(dirname "$0")" && pwd)"

log() { printf '\n== %s\n' "$*"; }

cleanup() {
  [[ "${KEEP_CLUSTER:-0}" == 1 ]] || kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for bin in docker kind kubectl helm; do
  command -v "$bin" >/dev/null || { echo "missing required tool: $bin" >&2; exit 1; }
done

# Select which test files to run (all by default, or those named as args).
tests=()
if [[ $# -gt 0 ]]; then
  for name in "$@"; do tests+=("$DIR/tests/${name%.sh}.sh"); done
else
  for t in "$DIR"/tests/*.sh; do tests+=("$t"); done
fi
for t in "${tests[@]}"; do
  [[ -f "$t" ]] || { echo "no such test: $t" >&2; exit 1; }
done

log "Creating kind cluster ($NODE_IMAGE)"
kind create cluster --name "$CLUSTER_NAME" --image "$NODE_IMAGE" --wait 120s

log "Installing Kyverno"
helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null 2>&1 || true
helm repo update kyverno >/dev/null
helm install kyverno kyverno/kyverno -n kyverno --create-namespace \
  --kube-context "$E2E_CTX" --wait --timeout 5m >/dev/null

failed=()
for t in "${tests[@]}"; do
  log "Running $(basename "$t")"
  bash "$t" || failed+=("$(basename "$t")")
done

log "Suite result"
if [[ ${#failed[@]} -eq 0 ]]; then
  echo "All ${#tests[@]} test file(s) passed."
else
  printf 'FAILED (%d/%d): %s\n' "${#failed[@]}" "${#tests[@]}" "${failed[*]}"
  exit 1
fi
