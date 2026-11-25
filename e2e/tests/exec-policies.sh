#!/usr/bin/env bash
# Live e2e for block-pod-exec and block-kubectl-cp.
#
# kubectl exec/attach (and kubectl cp, which is exec running tar) are CONNECT
# subresource admissions that `kyverno test` cannot simulate — this is their
# only automated gate. Runs against the shared cluster from e2e/run.sh.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/../lib.sh"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"

e2e_log "Fixtures: test pods in a normal namespace and in kube-system"
kc run testpod --image=busybox:1.37 --restart=Never -- sleep 3600 >/dev/null
kc -n kube-system run testpod-sys --image=busybox:1.37 --restart=Never -- sleep 3600 >/dev/null
kc wait --for=condition=Ready pod/testpod --timeout=180s >/dev/null
kc -n kube-system wait --for=condition=Ready pod/testpod-sys --timeout=180s >/dev/null
TMPFILE="$(mktemp)" && echo e2e >"$TMPFILE"
cleanup() {
  kc delete pod testpod --ignore-not-found --wait=false >/dev/null 2>&1
  kc -n kube-system delete pod testpod-sys --ignore-not-found --wait=false >/dev/null 2>&1
  rm -f "$TMPFILE"
}
trap cleanup EXIT

e2e_log "Phase A: block-kubectl-cp — plain exec stays allowed, cp/tar denied"
apply_policy "$REPO_ROOT/policies/block-kubectl-cp/policy.yaml" block-kubectl-cp
wait_until_denied "manual tar exec denied" kc exec testpod -- tar --help
expect_allow "plain exec still allowed" kc exec testpod -- ls /
expect_deny "kubectl cp denied" kc cp "$TMPFILE" testpod:/tmp/e2e
remove_policy block-kubectl-cp

e2e_log "Phase B: block-pod-exec — all exec denied, system namespaces exempt"
apply_policy "$REPO_ROOT/policies/block-pod-exec/policy.yaml" block-pod-exec
wait_until_denied "exec denied" kc exec testpod -- ls /
expect_deny "kubectl cp denied (rides exec)" kc cp "$TMPFILE" testpod:/tmp/e2e
expect_allow "exec in kube-system still allowed (exclusion)" \
  kc -n kube-system exec testpod-sys -- ls /
remove_policy block-pod-exec

e2e_summary "exec-policies"
