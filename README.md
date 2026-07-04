# Kyverno Policy Library — Policy as Code for Kubernetes

[![CI](https://github.com/alice101-dev/kyverno-policy-library/actions/workflows/ci.yml/badge.svg)](https://github.com/alice101-dev/kyverno-policy-library/actions/workflows/ci.yml)

**Policy as Code** for Kubernetes: cluster guardrails defined, versioned, and
unit-tested like software. The hardening my other repos apply *by hand*, turned
into **admission-time law** with [Kyverno](https://kyverno.io). A deployment that forgets a resource limit,
runs as root, or ships a `:latest` tag doesn't get a code-review comment — it
gets **rejected by the cluster**. Every policy is unit-tested with good and bad
fixtures, so the library is a real gate, not a pile of YAML.

## Policies

| Policy | Category | Rejects |
| --- | --- | --- |
| [`require-requests-limits`](policies/require-requests-limits/) | Resource Management | containers with no CPU/memory requests + limits |
| [`require-non-root`](policies/require-non-root/) | Pod Security | containers that can run as root (`runAsNonRoot` unset) |
| [`require-ro-rootfs`](policies/require-ro-rootfs/) | Pod Security | writable container root filesystems |
| [`require-runtimedefault-profiles`](policies/require-runtimedefault-profiles/) | Pod Security | pods without RuntimeDefault seccomp **and** AppArmor |
| [`disallow-privilege-escalation`](policies/disallow-privilege-escalation/) | Pod Security | containers with `allowPrivilegeEscalation` unset/true |
| [`require-drop-all-capabilities`](policies/require-drop-all-capabilities/) | Pod Security | containers that don't drop ALL Linux capabilities |
| [`disallow-automount-sa-token`](policies/disallow-automount-sa-token/) | Pod Security | pods that mount a Kubernetes API token they don't need |
| [`require-pod-anti-affinity`](policies/require-pod-anti-affinity/) | High Availability | workloads with no replica spreading (topology spread, or soft/hard anti-affinity) |
| [`disallow-latest-tag`](policies/disallow-latest-tag/) | Supply Chain | `:latest` / untagged images (not reproducible) |
| [`disallow-default-namespace`](policies/disallow-default-namespace/) | Multi-Tenancy | workloads in the un-governed `default` namespace |

Each folder holds the `ClusterPolicy` plus a `.test/` directory with the
fixtures and a `kyverno test` spec that asserts pass/fail per resource.

## Why this exists

My other repos each *practice* one of these rules:

- [gke-pgbouncer-hardened](https://github.com/alice101-dev/gke-pgbouncer-hardened) — non-root, read-only fs, no SA token
- [k8s-pdb-production-patterns](https://github.com/alice101-dev/k8s-pdb-production-patterns) — resource limits, restricted PSS
- [supply-chain-secure-build](https://github.com/alice101-dev/supply-chain-secure-build) — digest-pinned images, signature verification

A manifest is only as safe as the reviewer who reads it. This library makes the
rules **non-optional**: enforced on every apply, for every team, whether anyone
reviews the YAML or not.

## Try it

```bash
# Unit-test every policy against its fixtures (what CI runs)
kyverno test ./policies/

# Dry-run a policy against your own manifest
kyverno apply policies/require-non-root/policy.yaml --resource my-deployment.yaml
```

## Rolling out safely

Policies ship with `validationFailureAction: Enforce` (block). When introducing
them to a live cluster, flip to `Audit` first to see what *would* be rejected
without breaking deploys, fix the offenders, then switch back to `Enforce`:

```bash
kubectl apply -f policies/require-non-root/policy.yaml
kubectl get policyreport -A   # what currently violates the policy
```

## CI

Every push and pull request runs through [GitHub Actions](.github/workflows/ci.yml):

- **`kyverno test`** — every policy is exercised against its good/bad fixtures.
- **Gitleaks** — full-history secret scan.
