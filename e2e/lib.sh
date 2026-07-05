#!/usr/bin/env bash
# Shared harness for live policy e2e tests. Sourced by every e2e/tests/*.sh.
#
# It does NOT manage the cluster — e2e/run.sh creates the kind cluster and
# installs Kyverno once, then runs each test file against it, passing the kube
# context in E2E_CTX. A test file therefore only: applies its policy, asserts
# real kubectl calls, removes its policy, and calls e2e_summary.
#
# To run a single test file standalone against a cluster that already has
# Kyverno:  E2E_CTX=kind-mycluster ./e2e/tests/<name>.sh
set -uo pipefail

: "${E2E_CTX:?E2E_CTX (kube context) must be set — run via e2e/run.sh}"

# Admission-denial marker in the API error for a blocking ClusterPolicy.
E2E_DENY_MARKER="${E2E_DENY_MARKER:-blocked due to the following policies}"

E2E_PASS=0
E2E_FAIL=0

# kubectl bound to the test cluster.
kc() { kubectl --context "$E2E_CTX" "$@"; }

e2e_log() { printf '\n-- %s\n' "$*"; }
e2e_ok()  { E2E_PASS=$((E2E_PASS + 1)); printf 'PASS: %s\n' "$*"; }
e2e_bad() { E2E_FAIL=$((E2E_FAIL + 1)); printf 'FAIL: %s\n' "$*"; }

# expect_allow <desc> <cmd...> — command must succeed.
expect_allow() {
  local desc="$1" out; shift
  if out="$("$@" 2>&1)"; then e2e_ok "$desc"; else e2e_bad "$desc — expected success, got: $out"; fi
}

# expect_deny <desc> <cmd...> — command must fail *because a policy blocked it*
# (not for some unrelated error).
expect_deny() {
  local desc="$1" out; shift
  if out="$("$@" 2>&1)"; then
    e2e_bad "$desc — expected denial, but command succeeded"
  elif grep -q "$E2E_DENY_MARKER" <<<"$out"; then
    e2e_ok "$desc"
  else
    e2e_bad "$desc — failed for the wrong reason: $out"
  fi
}

# wait_until_denied <desc> <cmd...> — webhook (de)registration is async, so
# poll until the policy actually blocks before asserting the rest. Use it for
# the first deny check after apply_policy.
wait_until_denied() {
  local desc="$1" out; shift
  local i
  for i in $(seq 1 15); do
    if ! out="$("$@" 2>&1)" && grep -q "$E2E_DENY_MARKER" <<<"$out"; then
      e2e_ok "$desc"
      return
    fi
    sleep 2
  done
  e2e_bad "$desc — never denied after 30s"
}

apply_policy() {
  kc apply -f "$1" >/dev/null
  kc wait --for=condition=Ready clusterpolicy "$2" --timeout=60s >/dev/null
}

remove_policy() {
  kc delete clusterpolicy "$1" --ignore-not-found >/dev/null
  sleep 5 # let the webhook deregister before the next test file runs
}

# Print the tally and exit nonzero on any failure. Call at the end of a test.
e2e_summary() {
  printf '\n== %s: %d passed, %d failed\n' "${1:-e2e}" "$E2E_PASS" "$E2E_FAIL"
  [[ $E2E_FAIL -eq 0 ]]
}
