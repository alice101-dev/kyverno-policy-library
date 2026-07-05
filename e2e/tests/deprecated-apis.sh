#!/usr/bin/env bash
# Live e2e for disallow-deprecated-apis.
#
# What this suite is for
# ----------------------
# `kyverno test` already asserts every rule's DENY logic offline (one bad
# fixture per removal release). What it CANNOT see is the webhook wiring: the
# policy matches kinds with a version wildcard and checks the version in CEL
# precisely so the API server (matchPolicy Equivalent) does not convert a valid
# current-version request into the deprecated one and wrongly block it. That
# false positive is invisible offline — it only appears against a live API
# server. So this suite's job is the wiring/false-positive dimension:
#
#   DENY  — deprecated versions that the cluster still serves are blocked.
#   ALLOW — a valid current-version object of EVERY matched group is admitted.
#
# Live-testability note
# ---------------------
# Only versions the API server still serves reach admission; anything removed
# in an earlier release is rejected by the API server itself before Kyverno
# runs (so it can't be asserted as a Kyverno deny). On NODE_IMAGE v1.31.x the
# only still-served deprecated versions are flowcontrol .../v1beta3 (FlowSchema
# and PriorityLevelConfiguration, removed in 1.32) — those are the deny cases.
# The allow cases below cover the current version of at least one kind from
# each of the seven removal-release rules (v1.16 → v1.32).
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DIR/../lib.sh"
REPO_ROOT="$(cd "$DIR/../.." && pwd)"

NS=e2e-deprecated
WORK="$(mktemp -d)"
# Manifests go through files (not heredoc-on-stdin) so wait_until_denied can
# safely re-read them across retries.
# Trailing X's only — BSD/macOS mktemp rejects a suffix after them; kubectl
# -f does not need a .yaml extension.
mkf() { local f; f="$(mktemp "$WORK/manifest.XXXXXX")"; cat >"$f"; printf '%s' "$f"; }

cleanup() {
  kc delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1
  kc delete priorityclass e2e-good-priority --ignore-not-found >/dev/null 2>&1
  kc delete storageclass e2e-good-sc --ignore-not-found >/dev/null 2>&1
  kc delete runtimeclass e2e-good-runtimeclass --ignore-not-found >/dev/null 2>&1
  kc delete flowschema e2e-good-fs-v1 --ignore-not-found >/dev/null 2>&1
  kc delete prioritylevelconfiguration e2e-good-plc-v1 --ignore-not-found >/dev/null 2>&1
  rm -rf "$WORK"
}
trap cleanup EXIT

apply_policy "$REPO_ROOT/policies/disallow-deprecated-apis/policy.yaml" disallow-deprecated-apis
kc create namespace "$NS" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# DENY: still-served deprecated versions (flowcontrol v1beta3, removed in 1.32)
# ---------------------------------------------------------------------------
e2e_log "Deprecated versions still served by the cluster are denied"

bad_fs="$(mkf <<'EOF'
apiVersion: flowcontrol.apiserver.k8s.io/v1beta3
kind: FlowSchema
metadata: {name: e2e-bad-fs-v1beta3}
spec:
  priorityLevelConfiguration: {name: global-default}
  matchingPrecedence: 9998
EOF
)"
# First deny after apply — poll until the webhook is actually live.
wait_until_denied "flowcontrol/v1beta3 FlowSchema denied" kc apply -f "$bad_fs"

bad_plc="$(mkf <<'EOF'
apiVersion: flowcontrol.apiserver.k8s.io/v1beta3
kind: PriorityLevelConfiguration
metadata: {name: e2e-bad-plc-v1beta3}
spec:
  type: Limited
  limited:
    nominalConcurrencyShares: 10
    limitResponse: {type: Reject}
EOF
)"
expect_deny "flowcontrol/v1beta3 PriorityLevelConfiguration denied" kc apply -f "$bad_plc"

# ---------------------------------------------------------------------------
# ALLOW: a valid current-version object from every matched removal-release rule
# must be admitted (no matchPolicy-Equivalent false positive).
# ---------------------------------------------------------------------------
e2e_log "Current-version objects of every matched group are admitted"

# v1.16 rule — apps group
expect_allow "apps/v1 Deployment admitted" kc apply -f "$(mkf <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: good-deploy, namespace: $NS}
spec:
  replicas: 0
  selector: {matchLabels: {app: good}}
  template:
    metadata: {labels: {app: good}}
    spec:
      containers: [{name: c, image: nginx:1.27}]
EOF
)"

# v1.22 rule — networking, rbac, scheduling, storage groups
expect_allow "networking.k8s.io/v1 Ingress admitted" kc apply -f "$(mkf <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: good-ingress, namespace: $NS}
spec:
  defaultBackend:
    service: {name: dummy, port: {number: 80}}
EOF
)"
expect_allow "rbac.authorization.k8s.io/v1 Role admitted" kc apply -f "$(mkf <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: good-role, namespace: $NS}
rules:
  - apiGroups: [""]
    resources: [pods]
    verbs: [get]
EOF
)"
expect_allow "scheduling.k8s.io/v1 PriorityClass admitted" kc apply -f "$(mkf <<'EOF'
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata: {name: e2e-good-priority}
value: 1000
EOF
)"
expect_allow "storage.k8s.io/v1 StorageClass admitted" kc apply -f "$(mkf <<'EOF'
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata: {name: e2e-good-sc}
provisioner: kubernetes.io/no-provisioner
EOF
)"

# v1.25 rule — batch, autoscaling, policy, node, discovery groups
expect_allow "batch/v1 CronJob admitted" kc apply -f "$(mkf <<EOF
apiVersion: batch/v1
kind: CronJob
metadata: {name: good-cron, namespace: $NS}
spec:
  schedule: "0 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers: [{name: c, image: busybox:1.37}]
EOF
)"
expect_allow "autoscaling/v2 HorizontalPodAutoscaler admitted" kc apply -f "$(mkf <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata: {name: good-hpa, namespace: $NS}
spec:
  scaleTargetRef: {apiVersion: apps/v1, kind: Deployment, name: good-deploy}
  minReplicas: 1
  maxReplicas: 3
  metrics:
    - type: Resource
      resource: {name: cpu, target: {type: Utilization, averageUtilization: 80}}
EOF
)"
expect_allow "policy/v1 PodDisruptionBudget admitted" kc apply -f "$(mkf <<EOF
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: good-pdb, namespace: $NS}
spec:
  minAvailable: 1
  selector: {matchLabels: {app: good}}
EOF
)"
expect_allow "node.k8s.io/v1 RuntimeClass admitted" kc apply -f "$(mkf <<'EOF'
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata: {name: e2e-good-runtimeclass}
handler: runc
EOF
)"
expect_allow "discovery.k8s.io/v1 EndpointSlice admitted" kc apply -f "$(mkf <<EOF
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata: {name: good-eps, namespace: $NS}
addressType: IPv4
endpoints:
  - addresses: ["10.0.0.1"]
ports:
  - {name: http, port: 80}
EOF
)"

# v1.27 rule — storage CSIStorageCapacity
expect_allow "storage.k8s.io/v1 CSIStorageCapacity admitted" kc apply -f "$(mkf <<EOF
apiVersion: storage.k8s.io/v1
kind: CSIStorageCapacity
metadata: {name: good-csc, namespace: $NS}
storageClassName: e2e-good-sc
EOF
)"

# v1.26 / v1.29 / v1.32 rules — flowcontrol group, current version
expect_allow "flowcontrol/v1 FlowSchema admitted (no false positive)" kc apply -f "$(mkf <<'EOF'
apiVersion: flowcontrol.apiserver.k8s.io/v1
kind: FlowSchema
metadata: {name: e2e-good-fs-v1}
spec:
  priorityLevelConfiguration: {name: global-default}
  matchingPrecedence: 9999
EOF
)"
expect_allow "flowcontrol/v1 PriorityLevelConfiguration admitted" kc apply -f "$(mkf <<'EOF'
apiVersion: flowcontrol.apiserver.k8s.io/v1
kind: PriorityLevelConfiguration
metadata: {name: e2e-good-plc-v1}
spec:
  type: Limited
  limited:
    nominalConcurrencyShares: 10
    limitResponse: {type: Reject}
EOF
)"

remove_policy disallow-deprecated-apis
e2e_summary "deprecated-apis"
