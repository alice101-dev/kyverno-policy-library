#!/usr/bin/env bash
# Live e2e suite for the exec policies (block-pod-exec, block-kubectl-cp).
#
# `kyverno test` cannot simulate CONNECT subresource admission, so this script
# IS their test suite: it spins up a kind cluster, installs Kyverno, and
# asserts allow/deny behavior of real `kubectl exec` / `kubectl cp` calls.
#
#   ./e2e/exec-policies.sh
#
# Env overrides: CLUSTER_NAME (kyverno-e2e), NODE_IMAGE (kindest/node:v1.31.9,
# keep it pinned to a GKE-supported version), KEEP_CLUSTER=1 to skip teardown.
set -uo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-kyverno-e2e}"
NODE_IMAGE="${NODE_IMAGE:-kindest/node:v1.31.9}"
CTX="kind-${CLUSTER_NAME}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DENY_MARKER="blocked due to the following policies"
PASS=0 FAIL=0

log() { printf '\n== %s\n' "$*"; }
ok()  { PASS=$((PASS + 1)); printf 'PASS: %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf 'FAIL: %s\n' "$*"; }

expect_allow() {
  local desc="$1" out; shift
  if out="$("$@" 2>&1)"; then ok "$desc"; else bad "$desc — expected success, got: $out"; fi
}

expect_deny() {
  local desc="$1" out; shift
  if out="$("$@" 2>&1)"; then
    bad "$desc — expected denial, but command succeeded"
  elif grep -q "$DENY_MARKER" <<<"$out"; then
    ok "$desc"
  else
    bad "$desc — failed for the wrong reason: $out"
  fi
}

# First check of each phase: webhook reconfiguration is asynchronous, so poll
# until the policy actually bites before running the rest of the assertions.
wait_until_denied() {
  local desc="$1" out; shift
  for _ in $(seq 1 15); do
    if ! out="$("$@" 2>&1)" && grep -q "$DENY_MARKER" <<<"$out"; then
      ok "$desc"
      return
    fi
    sleep 2
  done
  bad "$desc — never denied"
}

apply_policy() {
  kubectl --context "$CTX" apply -f "$1" >/dev/null
  kubectl --context "$CTX" wait --for=condition=Ready clusterpolicy "$2" --timeout=60s >/dev/null
}

remove_policy() {
  kubectl --context "$CTX" delete clusterpolicy "$1" --ignore-not-found >/dev/null
  sleep 5 # let the webhook deregister before the next phase
}

cleanup() {
  [[ "${KEEP_CLUSTER:-0}" == 1 ]] || kind delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for bin in docker kind kubectl helm; do
  command -v "$bin" >/dev/null || { echo "missing: $bin" >&2; exit 1; }
done

log "Creating kind cluster ($NODE_IMAGE)"
kind create cluster --name "$CLUSTER_NAME" --image "$NODE_IMAGE" --wait 120s

log "Installing Kyverno"
helm repo add kyverno https://kyverno.github.io/kyverno/ >/dev/null 2>&1 || true
helm repo update kyverno >/dev/null
helm install kyverno kyverno/kyverno -n kyverno --create-namespace \
  --kube-context "$CTX" --wait --timeout 5m >/dev/null

log "Starting test pods"
kubectl --context "$CTX" run testpod --image=busybox:1.37 --restart=Never -- sleep 3600 >/dev/null
kubectl --context "$CTX" -n kube-system run testpod-sys --image=busybox:1.37 --restart=Never -- sleep 3600 >/dev/null
kubectl --context "$CTX" wait --for=condition=Ready pod/testpod --timeout=180s >/dev/null
kubectl --context "$CTX" -n kube-system wait --for=condition=Ready pod/testpod-sys --timeout=180s >/dev/null
TMPFILE="$(mktemp)" && echo e2e >"$TMPFILE"

log "Phase A: block-kubectl-cp — plain exec stays allowed, cp/tar denied"
apply_policy "$REPO_ROOT/policies/block-kubectl-cp/policy.yaml" block-kubectl-cp
wait_until_denied "manual tar exec denied" kubectl --context "$CTX" exec testpod -- tar --help
expect_allow "plain exec still allowed" kubectl --context "$CTX" exec testpod -- ls /
expect_deny "kubectl cp denied" kubectl --context "$CTX" cp "$TMPFILE" testpod:/tmp/e2e
remove_policy block-kubectl-cp

log "Phase B: block-pod-exec — all exec denied, system namespaces exempt"
apply_policy "$REPO_ROOT/policies/block-pod-exec/policy.yaml" block-pod-exec
wait_until_denied "exec denied" kubectl --context "$CTX" exec testpod -- ls /
expect_deny "kubectl cp denied (rides exec)" kubectl --context "$CTX" cp "$TMPFILE" testpod:/tmp/e2e
expect_allow "exec in kube-system still allowed (exclusion)" \
  kubectl --context "$CTX" -n kube-system exec testpod-sys -- ls /
remove_policy block-pod-exec

rm -f "$TMPFILE"
log "Results: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
