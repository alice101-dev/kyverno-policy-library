# Kyverno Policy Library — Policy as Code for Kubernetes

[![CI](https://github.com/alice101-dev/kyverno-policy-library/actions/workflows/ci.yml/badge.svg)](https://github.com/alice101-dev/kyverno-policy-library/actions/workflows/ci.yml)

**Policy as Code** for Kubernetes: cluster guardrails defined, versioned, and
unit-tested like software, enforced as **admission-time law** with
[Kyverno](https://kyverno.io). A deployment that forgets a resource limit,
runs as root, or ships a `:latest` tag doesn't get a code-review comment — it
gets **rejected by the cluster**. Every policy is unit-tested with good and bad
fixtures, so the library is a real gate, not a pile of YAML.

## Policies

| Policy | Category | Rejects |
| --- | --- | --- |
| [`require-requests-limits`](policies/require-requests-limits/) | Resource Management | containers with no CPU/memory requests + memory limit (incl. init containers) |
| [`require-non-root`](policies/require-non-root/) | Pod Security | containers that can run as root (`runAsNonRoot` unset or overridden, incl. init containers) |
| [`require-ro-rootfs`](policies/require-ro-rootfs/) | Pod Security | writable container root filesystems (incl. init containers) |
| [`require-runtimedefault-profiles`](policies/require-runtimedefault-profiles/) | Pod Security | pods without RuntimeDefault seccomp **and** AppArmor, or containers overriding them |
| [`disallow-privilege-escalation`](policies/disallow-privilege-escalation/) | Pod Security | containers with `allowPrivilegeEscalation` unset/true (incl. init containers) |
| [`require-drop-all-capabilities`](policies/require-drop-all-capabilities/) | Pod Security | containers that don't drop ALL Linux capabilities (incl. init containers) |
| [`disallow-automount-sa-token`](policies/disallow-automount-sa-token/) | Pod Security | pods that mount a Kubernetes API token they don't need |
| [`require-pod-anti-affinity`](policies/require-pod-anti-affinity/) | High Availability | workloads with no replica spreading (topology spread, or soft/hard anti-affinity) |
| [`disallow-latest-tag`](policies/disallow-latest-tag/) | Supply Chain | `:latest`, untagged, or port-only images — digest-pinned is fine (incl. init containers) |
| [`disallow-default-namespace`](policies/disallow-default-namespace/) | Multi-Tenancy | workloads in the un-governed `default` namespace |
| [`require-pod-probes`](policies/require-pod-probes/) | High Availability | containers with no liveness, readiness, or startup probe |
| [`restrict-external-ips`](policies/restrict-external-ips/) | Network Security | Services setting `externalIPs` (CVE-2020-8554 MITM vector) |
| [`restrict-nodeport`](policies/restrict-nodeport/) | Network Security | Services of type NodePort (host ports bypass NetworkPolicy) |
| [`no-loadbalancer-service`](policies/no-loadbalancer-service/) | Network Security | Services of type LoadBalancer (each one creates a billable cloud LB) |
| [`disallow-deprecated-apis`](policies/disallow-deprecated-apis/) | Best Practices | manifests pinned to API versions removed in Kubernetes 1.25–1.32 |
| [`prevent-bare-pods`](policies/prevent-bare-pods/) | Best Practices | Pods with no ownerReference (not managed by any controller) |
| [`require-container-port-names`](policies/require-container-port-names/) | Best Practices | containerPorts without a `name` |
| [`imagepullpolicy-always`](policies/imagepullpolicy-always/) | Supply Chain | mutable-tag images without `imagePullPolicy: Always` |
| [`block-images-with-volumes`](policies/block-images-with-volumes/) | Supply Chain | images built with VOLUME statements (silently bypass read-only rootfs) |

Each folder holds the `ClusterPolicy` plus a `.test/` directory with the
fixtures and a `kyverno test` spec that asserts pass/fail per resource.

### Validation style: CEL

Every rule is written in [CEL](https://kyverno.io/docs/policy-types/cluster-policy/validate/#common-expression-language-cel) —
Kubernetes' native validation language (Kyverno 1.11+), the same expressions
that power the built-in `ValidatingAdmissionPolicy`. Compared to the
declarative `pattern` style these policies started with, CEL buys:

- one loop over *all* containers, `initContainers` included (patterns silently
  skipped them);
- catching containers that override a compliant pod-level setting
  (`runAsNonRoot`, seccomp/AppArmor);
- explicit defaults for unset fields (`.?field.orValue(...)`) that match what
  the kubelet actually does at runtime;
- real string logic — e.g. a registry port (`registry:5000/app`) is not
  mistaken for an image tag.

Ephemeral containers are deliberately left out of the container loops so
`kubectl debug` keeps working.

The rules come in two forms, both CEL. Most are `ClusterPolicy` with
`validate.cel`; the newest additions (`no-loadbalancer-service`,
`require-container-port-names`, `block-images-with-volumes`) use the
next-generation `ValidatingPolicy` kind (Kyverno 1.14+) — same expressions,
K8s `ValidatingAdmissionPolicy`-style spec. `block-images-with-volumes` also
uses the `image.GetMetadata()` CEL library to inspect image configs from the
registry; its tests mock those lookups with a CLI `Context` file so CI stays
offline.

## Why this exists

A manifest is only as safe as the reviewer who reads it. This library makes the
rules **non-optional**: enforced on every apply, for every team, whether anyone
reviews the YAML or not.

It pairs with
[supply-chain-secure-build](https://github.com/alice101-dev/supply-chain-secure-build):
that repo *produces* trustworthy images (digest-pinned, signed); this one makes
the cluster *demand* them, rejecting `:latest` and untagged images at admission.

## Try it

```bash
# Unit-test every policy against its fixtures (what CI runs)
kyverno test ./policies/

# Dry-run a policy against your own manifest
kyverno apply policies/require-non-root/policy.yaml --resource my-deployment.yaml
```

> [!WARNING]
> Both commands above are **offline** — safe anywhere. But don't
> `kubectl apply` these policies straight onto a cluster that already runs
> workloads: they ship with `Enforce`, so every non-compliant Deployment gets
> **blocked at its next rollout, restart, or scale-up** (existing pods keep
> running — until they need to be recreated, e.g. by a node upgrade). On a
> busy cluster that can freeze deploys team-wide. Follow
> [Rolling out safely](#rolling-out-safely) instead: `Audit` first, fix the
> offenders, then `Enforce`.

## Rolling out safely

Policies ship with `validationFailureAction: Enforce` (block). When introducing
them to a live cluster, flip to `Audit` first to see what *would* be rejected
without breaking deploys, fix the offenders, then switch back to `Enforce`:

```bash
kubectl apply -f policies/require-non-root/policy.yaml
kubectl get policyreport -A   # what currently violates the policy
```

### System namespaces are excluded (GKE-safe)

These policies only govern **your** workloads. Every rule excludes the
namespaces the cluster itself depends on:

| Excluded namespaces | Why |
| --- | --- |
| `kube-system`, `kube-public`, `kube-node-lease` | Core components (kube-dns, konnectivity, metrics-server, ...) run as root with writable filesystems *by design*. |
| `kyverno` | A policy that blocks Kyverno's own pods would deadlock admission for the whole cluster. |
| `gke-*`, `gmp-*`, `config-management-*`, `cnrm-system` | GKE-managed add-ons (Managed Prometheus, Config Sync, Config Connector). |

Without these exclusions, a node upgrade or auto-repair — which recreates
system pods — could be blocked by the webhook and take down DNS, logging,
and metrics.

Two guarantees back this up:

- **Tested**: every policy's test suite includes a non-compliant pod in
  `kube-system` and asserts it is *skipped*, not rejected. Removing an
  exclusion fails CI.
- **Portable**: the exclusions live in the policies themselves, so they work
  regardless of how Kyverno was installed (`resourceFilters` and webhook
  `namespaceSelector` vary per install).

`ClusterPolicy` rules carry the list as an `exclude` block; `ValidatingPolicy`
rules express the same list as a `matchConditions` entry (that kind has no
`exclude`).

## CI

Every push and pull request runs through [GitHub Actions](.github/workflows/ci.yml):

- **`kyverno test`** — every policy is exercised against its good/bad fixtures.
- **Gitleaks** — full-history secret scan.

## References

- [Kyverno policy library](https://kyverno.io/policies/) — the official collection of ready-made policies.
- [Kyverno Playground](https://playground.kyverno.io/#/) — try a policy against a resource in the browser, no cluster needed.
