# Kyverno Policy Library — Policy as Code for Kubernetes

[![CI](https://github.com/alice101-dev/kyverno-policy-library/actions/workflows/ci.yml/badge.svg)](https://github.com/alice101-dev/kyverno-policy-library/actions/workflows/ci.yml)

**Policy as Code** for Kubernetes: cluster guardrails defined, versioned, and
unit-tested like software, enforced as **admission-time law** with
[Kyverno](https://kyverno.io). A deployment that forgets a resource limit,
runs as root, or ships a `:latest` tag doesn't get a code-review comment — it
gets **rejected by the cluster**. Every policy is unit-tested with good and bad
fixtures, so the library is a real gate, not a pile of YAML.

Without Policy as Code, every one of those controls exists only as a
convention — a wiki page, a review checklist, a Slack reminder. **The cluster
itself will accept anything RBAC lets through**: a root container one kernel
CVE away from owning its node, an unsigned image from a registry nobody
vetted, a `:latest` tag that silently changes meaning between rollouts, a
Service that quietly exposes an internal API to the internet, a `kubectl exec`
that tampers with a workload leaving no trace in git. None of that is exotic
misconfiguration — it is the **default behavior of a vanilla cluster**, and a
single missed line in code review is all it takes to ship it. Policy as Code
turns the conventions into versioned, tested, enforced rules: the difference
between *"we ask teams not to run as root"* and *"the API server refuses
root"*.

## Policies

| Policy | Category | Rejects |
| --- | --- | --- |
| [`require-non-root`](policies/require-non-root/) | Pod Security | containers that can run as root (`runAsNonRoot` unset or overridden, incl. init containers) |
| [`require-ro-rootfs`](policies/require-ro-rootfs/) | Pod Security | writable container root filesystems (incl. init containers) |
| [`require-runtimedefault-profiles`](policies/require-runtimedefault-profiles/) | Pod Security | pods without RuntimeDefault seccomp **and** AppArmor, or containers overriding them |
| [`disallow-privilege-escalation`](policies/disallow-privilege-escalation/) | Pod Security | containers with `allowPrivilegeEscalation` unset/true (incl. init containers) |
| [`require-drop-all-capabilities`](policies/require-drop-all-capabilities/) | Pod Security | containers that don't drop ALL Linux capabilities (incl. init containers) |
| [`disallow-automount-sa-token`](policies/disallow-automount-sa-token/) | Pod Security | pods that mount a Kubernetes API token they don't need |
| [`block-pod-exec`](policies/block-pod-exec/) | Pod Security | `kubectl exec`/`attach` sessions outside system namespaces — interactive access bypasses manifest review |
| [`block-kubectl-cp`](policies/block-kubectl-cp/) | Pod Security | `kubectl cp` (an exec running `tar`) — file exfiltration/tampering channel |
| [`restrict-external-ips`](policies/restrict-external-ips/) | Network Security | Services setting `externalIPs` (CVE-2020-8554 MITM vector) |
| [`restrict-nodeport`](policies/restrict-nodeport/) | Network Security | Services of type NodePort (host ports bypass NetworkPolicy) |
| [`no-localhost-service`](policies/no-localhost-service/) | Network Security | ExternalName Services pointing at `localhost` (Ingress-controller exploit) |
| [`no-loadbalancer-service`](policies/no-loadbalancer-service/) | Network Security | Services of type LoadBalancer (internet-facing by default, billable) |
| [`verify-image-signatures`](policies/verify-image-signatures/) | Supply Chain | images without a valid cosign signature from the release key |
| [`restrict-image-registries`](policies/restrict-image-registries/) | Supply Chain | images from registries outside the trusted allowlist (incl. init containers) |
| [`require-image-digests`](policies/require-image-digests/) | Supply Chain | images not pinned by `@sha256:` digest — tags are mutable (incl. init containers) |
| [`disallow-latest-tag`](policies/disallow-latest-tag/) | Supply Chain | `:latest`, untagged, or port-only images — digest-pinned is fine (incl. init containers) |
| [`imagepullpolicy-always`](policies/imagepullpolicy-always/) | Supply Chain | mutable-tag images without `imagePullPolicy: Always` |
| [`block-images-with-volumes`](policies/block-images-with-volumes/) | Supply Chain | images built with VOLUME statements (silently bypass read-only rootfs) |

The library also ships operational (non-security) guardrails not listed above:
[`require-requests-limits`](policies/require-requests-limits/),
[`require-pod-probes`](policies/require-pod-probes/),
[`require-pod-anti-affinity`](policies/require-pod-anti-affinity/),
[`disallow-default-namespace`](policies/disallow-default-namespace/),
[`disallow-deprecated-apis`](policies/disallow-deprecated-apis/),
[`prevent-bare-pods`](policies/prevent-bare-pods/),
[`restrict-jobs`](policies/restrict-jobs/), and
[`require-container-port-names`](policies/require-container-port-names/).

Each folder holds the policy plus a `.test/` directory with the fixtures and a
`kyverno test` spec that asserts pass/fail per resource — except the exec
policies (`block-pod-exec`, `block-kubectl-cp`): CONNECT subresource admission
cannot be simulated by `kyverno test`, so
[`e2e/exec-policies.sh`](e2e/exec-policies.sh) covers them against a live kind
cluster (real `kubectl exec`/`cp` calls, including the system-namespace
exemption).

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

One deliberate exception: [`verify-image-signatures`](policies/verify-image-signatures/)
uses the classic `verifyImages` rule type rather than CEL — it is the form
Kyverno's own CLI test suite exercises, and the CEL `ImageValidatingPolicy`
cosign attestor could not be validated under `kyverno test`. Its test verifies
real cosign signatures against `ghcr.io/kyverno/test-verify-image`, so it is
the one test that needs network access (fine in GitHub Actions).

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

# Live e2e for the exec policies — needs Docker; creates (and deletes) a
# throwaway local kind cluster
./e2e/exec-policies.sh
```

> [!WARNING]
> The commands above are **offline** or run against a throwaway local
> cluster — safe anywhere. But don't
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
  `kube-system` and asserts it is *skipped*, not rejected — the exec policies
  assert it live instead: their e2e suite execs into a `kube-system` pod and
  expects it allowed. Removing an exclusion fails CI.
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
- **Exec-policy e2e** ([e2e.yml](.github/workflows/e2e.yml)) — path-filtered:
  when `block-pod-exec`, `block-kubectl-cp`, or the e2e suite change, CI spins
  up a kind cluster, installs Kyverno, and asserts real `kubectl exec`/`cp`
  calls against live admission (CONNECT cannot be simulated offline).

## References

- [Kyverno policy library](https://kyverno.io/policies/) — the official collection of ready-made policies.
- [Kyverno Playground](https://playground.kyverno.io/#/) — try a policy against a resource in the browser, no cluster needed.
