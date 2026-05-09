# `examples/attack-graph-demo/`

Showcase corpus for the **Attack Graph** — the engine's internet → crown-jewels reachability analysis. A multi-file, deliberately-misconfigured 3-tier AWS app modelled on the canonical "small startup that grew fast" architecture.

Open this directory as a workspace in VS Code with the [tf-analyze extension](../../vscode-extension/) installed and click the `🛤 Attack Graph` button in the activity bar's speed strip.

## The architecture (and the misconfigurations)

```
                                  INTERNET
                                      │
                                      ▼
                               ┌─────────────┐
                               │ public ALB  │  (alb security group: 0.0.0.0/0:443)
                               └──────┬──────┘
                                      │
                                      ▼
                               ┌─────────────┐
                               │   web EC2   │  (public IP, IMDSv1 enabled,
                               │             │   SSH from 0.0.0.0/0:22 also open)
                               └──────┬──────┘
                                      │ instance profile
                                      ▼
                               ┌─────────────┐
                               │   IAM role  │  (s3:* / secretsmanager:* /
                               │             │   rds:* on Resource = "*")
                               └──────┬──────┘
                                      │
                  ┌───────────────────┼────────────────────┐
                  ▼                   ▼                    ▼
           ┌────────────┐      ┌────────────┐      ┌────────────┐
           │ S3 bucket  │      │  Secrets   │      │   RDS      │
           │ (no SSE,   │      │ Manager    │      │  Postgres  │
           │  no logs)  │      │ (no KMS,   │      │ (unencryp- │
           │            │      │  no rotn)  │      │  ted)      │
           └────────────┘      └────────────┘      └────────────┘
              CROWN JEWEL         CROWN JEWEL         CROWN JEWEL
```

Each rung is a real misconfiguration the engine detects:

| Rung | Misconfig | Rule(s) that fire |
|---|---|---|
| ALB | no `access_logs` | `SEC-AWS-ALB-001` |
| EC2 | public IP + IMDSv1 default | `SEC-AWS-EC2-IMDSV1` |
| EC2 SG | SSH from `0.0.0.0/0` | `SEC-AWS-SG-*` |
| IAM role | wildcard `Resource = "*"` | `SEC-AWS-IAM-001` (grep + JSON-policy analysis) |
| S3 | no SSE / no public-block / no logging / no versioning | `SEC-AWS-S3-001`, `-LOGGING-001`, `-PUBLIC-BLOCK-001`, `ROB-AWS-S3-001` |
| Secrets Manager | `recovery_window_in_days = 0`, no KMS | `ROB-AWS-SECRETSMANAGER-001` |
| RDS | no `storage_encrypted`, no `deletion_protection` | `ROB-AWS-RDS-*` |

## Layout

```
examples/attack-graph-demo/
├── README.md       (this file)
├── providers.tf    (provider, default_tags, app_name var)
├── network.tf      (VPC, subnets, IGW, ALB, three security groups)
├── compute.tf      (public EC2, IAM instance profile)
├── iam.tf          (IAM role + the wildcard policy that's the pivot)
└── data.tf         (S3, Secrets Manager, RDS — three crown jewels)
```

Five files, ~270 lines of HCL total. Splitting across files keeps each one readable and lets the VS Code Findings panel group findings by file in a way that mirrors the architecture diagram above.

## Expected output

```sh
python3 ../../scripts/detect.py \
  --target . \
  --attack-graph \
  --format text \
  | head -3
```

```
# tf-analyze: 19 (D) · 4 CRITICAL · 13 HIGH · 8 MEDIUM · 2 LOW · 0 INFO
# attack graph: 19 nodes, critical path length 0
```

(Score will drift as the catalogue evolves; the node count is the stable contract.)

The graph itself:

| Metric | Value |
|---|---|
| Total nodes | **19** |
| Total edges | **13** |
| Internet-reachable nodes | **6** (the ALB, the EC2, three SGs, plus the synthetic `INTERNET` source node) |
| Crown jewels | **3** (S3 bucket, Secrets Manager secret, RDS instance) |
| Total findings | **27** |

In the VS Code Attack Graph panel you'll see:

- The synthetic `INTERNET` node at the top
- Edges from `INTERNET` to every internet-reachable node (the ALB, the EC2, and the SGs that allow `0.0.0.0/0` ingress)
- The IAM-instance-profile → IAM-role edge that links compute to identity
- The crown-jewel nodes coloured distinctly (red in the d3 view)

## Why the critical path length might read as 0

The BFS edge-traversal model the engine ships today traces **structural** relationships (instance → SG → instance, EC2 → instance-profile → role) but does *not* infer "role can call S3 because its policy lists `s3:*`" as a graph edge. The IAM → crown-jewel reachability is encoded as findings on the role (via `iam_json_policy_analysis`), not as edges in the graph.

Result: the IAM-pivot ↔ crown-jewel relationship is visible in the **findings list** but not in the BFS critical-path metric. This is a known limitation; the demo deliberately exercises both surfaces so the gap is observable.

## What this is NOT

- **Not deployable.** The `aws_db_instance.appdb` references a hard-coded password and the AMI ID is a long-deprecated stub. `terraform validate` will pass; `terraform apply` will fail or be expensive — don't try.
- **Not a real-world threat model.** Real attackers chain misconfigurations the catalogue doesn't yet model (SSRF in the web app, IMDS credential theft, lateral movement via VPC peering). The demo is the *static* shape of an attack-vulnerable architecture, not a live exploit.
- **Not exhaustive.** Some rules deliberately do not fire here so the demo stays focused — see [`examples/terragoat/`](../terragoat/) for the comprehensive OWASP-organised corpus.

## Running it as a standalone demo

```sh
# JSON output (consumed by the VS Code Attack Graph panel and d3 demo)
python3 scripts/detect.py \
  --target examples/attack-graph-demo \
  --attack-graph \
  --format json \
  > /tmp/attack-graph.json

# HTML report — drop in a browser to see the rendered SVG attack graph
python3 scripts/detect.py \
  --target examples/attack-graph-demo \
  --attack-graph \
  --format html \
  > /tmp/attack-graph.html
open /tmp/attack-graph.html
```

The HTML report's score banner, the urgency-coloured findings table, and the embedded SVG attack-graph are all driven from the same one-pass scan.
