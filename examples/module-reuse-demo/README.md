# `examples/module-reuse-demo/`

Showcase corpus for the **Module Reuse Advisor** — the catalogue rule class that detects directories whose resource cluster matches the shape of a popular community module on the Terraform Registry.

Open this directory as a workspace in VS Code with the [tf-analyze extension](../../vscode-extension/) installed and click the `📦 Module Reuse` button in the activity bar's speed strip.

## Layout

```
examples/module-reuse-demo/
├── README.md              (this file)
├── aws/
│   ├── prod-vpc/          → MOD-REUSE-AWS-VPC-001     (high confidence)
│   ├── staging-vpc/       → MOD-REUSE-AWS-VPC-001     (high confidence)
│   └── admin-net/         → bespoke; below threshold; rule does NOT fire
├── gcp/
│   ├── prod-network/      → MOD-REUSE-GCP-NETWORK-001 (high confidence)
│   └── shared-vpc-host/   → matches shape, but contains shared-VPC
│                            host-project resources — those are in the
│                            rule's exclusion list, so it does NOT fire
└── azure/
    ├── prod-aks/          → MOD-REUSE-AZURE-AKS-001   (high confidence)
    └── dev-aks/           → MOD-REUSE-AZURE-AKS-001   (medium confidence)
```

Five positive matches across three fingerprints, plus two negative cases (one below-threshold, one excluded). The negative cases are deliberate — the rule is conservative by design, and `admin-net/` + `shared-vpc-host/` exist to prove the conservatism mechanism.

## Expected output

```sh
python3 ../../scripts/detect.py --target . --show-info --format text \
  | grep MOD-REUSE
```

```
MOD-REUSE-AWS-VPC-001     aws/prod-vpc/main.tf:33      aws_vpc.this
MOD-REUSE-AWS-VPC-001     aws/staging-vpc/main.tf:18   aws_vpc.this
MOD-REUSE-AZURE-AKS-001   azure/dev-aks/main.tf:10     azurerm_kubernetes_cluster.dev
MOD-REUSE-AZURE-AKS-001   azure/prod-aks/main.tf:23    azurerm_kubernetes_cluster.this
MOD-REUSE-GCP-NETWORK-001 gcp/prod-network/main.tf:21  google_compute_network.vpc
```

Five findings — never six. If `admin-net/` ever fires the rule, the supporting-types threshold logic is broken (it's there to prevent telling small bespoke networks to "use the community module"). If `shared-vpc-host/` fires, the exclusion logic is broken (Shared-VPC topologies aren't covered by the community module).

## Confidence levels

The advisor emits a `confidence` field per finding. Confidence scales with how far the cluster overshoots the rule's `supporting.threshold` — `high` for ≥ threshold + 2, `medium` for threshold + 1, `low` for exactly threshold.

| Directory | Supporting types | Threshold | Overshoot | Confidence |
|---|---|---|---|---|
| `aws/prod-vpc/` | 5 of 9 | 3 | +2 | **high** |
| `aws/staging-vpc/` | 5 of 9 | 3 | +2 | **high** |
| `azure/prod-aks/` | 7 of 8 | 2 | +5 | **high** |
| `gcp/prod-network/` | 3 of 6 | 2 | +1 | **medium** |
| `azure/dev-aks/` | 2 of 8 | 2 | +0 | **low** |

The corpus is deliberately tuned so all three tiers (high / medium / low) appear in the panel — useful for screenshotting and for verifying the badge styling renders correctly. Each tier is rendered with a distinct colour badge in the VS Code Module Reuse Advisor.

## What this is NOT

- **Not deployable.** Resources reference made-up project IDs, hardcoded ARNs, and missing variables. `terraform validate` will fail. The point is the resource shape, not the values.
- **Not a security demo.** For that, see [`examples/terragoat/`](../terragoat/) (deliberately-vulnerable corpus) or [`examples/attack-graph-demo/`](../attack-graph-demo/) (multi-tier internet → crown-jewels path).
- **Not a fixture.** Single-rule fixtures live under [`fixtures/`](../../fixtures/) and are minimised for unit-test speed. This corpus is rich enough that the panel's grouped view has interesting structure to render.

## Why these three rules?

The first three Module Reuse Advisor rules cover the most-replicated community modules across AWS, GCP, and Azure:

- [`terraform-aws-modules/vpc/aws`](https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/latest)
- [`terraform-google-modules/network/google`](https://registry.terraform.io/modules/terraform-google-modules/network/google/latest)
- [`Azure/aks/azurerm`](https://registry.terraform.io/modules/Azure/aks/azurerm/latest)

Together they account for >80% of the "you're hand-rolling something the registry already provides" cases real engineers actually hit. Adding new fingerprints is pure catalogue work — see [`catalog/README.md` § registry_fingerprint](../../catalog/README.md).
