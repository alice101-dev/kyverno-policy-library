#!/usr/bin/env bash
# Live e2e for disallow-deprecated-apis.
#
# `kyverno test` passes even when the webhook wiring is wrong: exact-GVK
# matching plus matchPolicy Equivalent made the API server convert valid
# current-version requests into the deprecated version and wrongly block them.
# That regression is invisible offline, so it is asserted here — a valid
# flowcontrol/v1 object MUST be admitted while its v1beta3 sibling is denied.
#
# Note on coverage: only rules for versions the cluster still serves can be
# exercised live (older removed versions are rejected by the API server before
# admission). On NODE_IMAGE v1.31.x that means the v1.32 rule (flowcontrol
# v1beta3, still served, removed in 1.32). Offline `kyverno test` covers every
# release; this fills the live gap.
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/../lib.sh"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"

apply_policy "$REPO_ROOT/policies/disallow-deprecated-apis/policy.yaml" disallow-deprecated-apis

e2e_log "Deprecated version denied; current versions of matched kinds admitted"

# Removed in v1.32, still served on v1.31 → reaches the webhook → must be denied.
wait_until_denied "flowcontrol/v1beta3 FlowSchema denied" kc apply -f - <<'EOF'
apiVersion: flowcontrol.apiserver.k8s.io/v1beta3
kind: FlowSchema
metadata:
  name: e2e-bad-v1beta3
spec:
  priorityLevelConfiguration:
    name: global-default
  matchingPrecedence: 9998
EOF

# Current version of the SAME group — the matchPolicy Equivalent regression
# would wrongly block this. Must be admitted.
expect_allow "flowcontrol/v1 FlowSchema admitted (no false positive)" kc apply -f - <<'EOF'
apiVersion: flowcontrol.apiserver.k8s.io/v1
kind: FlowSchema
metadata:
  name: e2e-good-v1
spec:
  priorityLevelConfiguration:
    name: global-default
  matchingPrecedence: 9999
EOF

# A current-version workload of another matched kind stays admitted.
expect_allow "apps/v1 Deployment admitted" kc apply -f - <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: e2e-web
  namespace: default
spec:
  replicas: 0
  selector:
    matchLabels: {app: e2e-web}
  template:
    metadata:
      labels: {app: e2e-web}
    spec:
      containers:
        - name: web
          image: nginx:1.27
EOF

kc delete flowschema e2e-good-v1 --ignore-not-found >/dev/null 2>&1
kc delete deployment e2e-web -n default --ignore-not-found >/dev/null 2>&1
remove_policy disallow-deprecated-apis

e2e_summary "deprecated-apis"
