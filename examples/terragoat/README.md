# `examples/terragoat/` — deliberately vulnerable Terraform corpus

A multi-cloud, OWASP-Top-10-organised corpus of intentionally insecure Terraform. It serves three jobs:

1. **Smoke test for the `tf-analyze` engine.** Running `python3 scripts/detect.py --target examples/terragoat` produces a known finding count (~70 at the time of writing). Drift in the count is a regression signal — the CI workflow gates on it.
2. **Calibration target for new rules.** When you write a new detector, drop a triggering snippet into the cloud + OWASP slot it belongs in. Re-run the corpus scan; your new rule ID appears alongside the existing ones with no spurious cross-talk.
3. **Live demo for first-time users.** Reports against the corpus are realistic-shaped (multi-cloud, multi-resource, OWASP-narrative-aware) rather than the isolated single-rule fixtures under `fixtures/`.

> **Naming.** "Terragoat" follows the convention popularised by Bridgecrew's [`terragoat`](https://github.com/bridgecrewio/terragoat) — an intentionally vulnerable IaC corpus used to exercise scanners. This corpus is independently authored, organised by OWASP Top 10 (2021) categories, and tailored to the rules `tf-analyze` ships today plus a clear roadmap for what's missing.

## Layout

```
examples/terragoat/
├── README.md          (this file — overview and how-to-run)
├── aws/               (10 OWASP-mapped .tf files + versions + README)
├── gcp/               (10 OWASP-mapped .tf files + versions + README)
└── azure/             (10 OWASP-mapped .tf files + versions + README)
```

Each cloud folder contains exactly **10 numbered files**, one per OWASP 2021 Top 10 category:

| File | OWASP 2021 |
|---|---|
| `01_broken_access_control.tf` | A01 — Broken Access Control |
| `02_cryptographic_failures.tf` | A02 — Cryptographic Failures |
| `03_injection.tf` | A03 — Injection |
| `04_insecure_design.tf` | A04 — Insecure Design |
| `05_security_misconfiguration.tf` | A05 — Security Misconfiguration |
| `06_vulnerable_components.tf` | A06 — Vulnerable and Outdated Components |
| `07_identification_auth.tf` | A07 — Identification and Authentication Failures |
| `08_data_integrity.tf` | A08 — Software and Data Integrity Failures |
| `09_logging_monitoring.tf` | A09 — Security Logging and Monitoring Failures |
| `10_ssrf.tf` | A10 — Server-Side Request Forgery |

Each file:
- Has a header comment with the OWASP category, the cloud, the vulnerability description, real-world impact, expected `tf-analyze` finding IDs, and a one-line fix summary.
- Is self-contained where practical (some Azure files share the demo resource group declared in `versions.tf`).
- Does **not** need to apply cleanly with `terraform apply` — it's a static-analysis corpus, not a deployable module.

## Coverage by cloud

| Cloud | Active catalogue rules exercised | Total findings | Notes |
|---|---|---|---|
| **GCP** | ~25 | ~54 | Densest coverage — the catalogue is GCP-first, and every active rule has a trigger here. |
| **AWS** | ~6 | ~12 | Catalogue has 3 active AWS rules; the rest of the corpus documents OWASP categories with anti-patterns that are not yet detected. Every "expected findings" block names the rule that *would* fire if/when added. |
| **Azure** | ~4 | ~6 | Catalogue has 1 active Azure rule + 4 stubs. The corpus documents what the stubs *should* detect once promoted to active. |
| **Total** | ~35 unique IDs | **~70** | Drift > ±5 should be investigated. CI gates at 65–75. |

## Running the corpus

```sh
# Whole corpus
python3 ../../scripts/detect.py --target . --format text

# Per cloud
python3 ../../scripts/detect.py --target gcp   --format text
python3 ../../scripts/detect.py --target aws   --format text
python3 ../../scripts/detect.py --target azure --format text

# Counts only — useful for spotting regressions
for c in gcp aws azure; do
  N=$(python3 ../../scripts/detect.py --target "$c" --format json \
        | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["findings"]))')
  echo "$c: $N findings"
done

# SARIF for IDE / CI integration
python3 ../../scripts/detect.py --target . --format sarif > terragoat.sarif

# HTML for sharing with non-CLI reviewers
python3 ../../scripts/detect.py --target . --format html > terragoat.html

# Including stubs (Azure mostly — rules with status: stub):
python3 ../../scripts/detect.py --target azure --include-stubs --format text
```

## Why split by cloud and OWASP category?

**Why per cloud:** AWS / GCP / Azure have non-overlapping resource types and IAM models. Mixing them in one file produces unrealistic Terraform that no real-world repo would resemble — and the per-resource detection rules need to see realistic-shaped HCL. Keeping each cloud in its own folder also lets reviewers focus on the cloud they actually run.

**Why per OWASP category:** OWASP categories are the universal vocabulary security reviewers know. A finding labelled "A05:2021 Security Misconfiguration" needs no further translation; "the GCS bucket is missing public_access_prevention" does. The OWASP framing also forces discipline when adding new rules — *why does this matter, in the language a security architect uses?* — which improves recommendation quality.

The two axes (cloud × OWASP) compose: 3 clouds × 10 categories = 30 files. Plus a `versions.tf` and `README.md` per cloud. This is enough to demonstrate every catalogue rule that exists today and to document the OWASP roadmap for every rule that doesn't.

## Why both `fixtures/` and this corpus?

- **`fixtures/`** are minimal one-rule-per-directory inputs used by `self_test.py`. A failing self-test pinpoints exactly which rule broke. Each fixture is one resource, sometimes two.
- **`examples/terragoat/`** is a representative *project* that exercises rules in combination — including `graph_check` rules that need ≥2 resources to fire, corpus-level rules (`CI-TEST-001`, `SEC-GCP-LOGGING-001`, `STK-GCP-GCS-LOGGING-001`) that need a directory rather than a file, and the OWASP narrative that frames "why does this matter".

Isolated fixtures alone miss interaction bugs. A project-shaped corpus alone loses diagnostic precision. Both serve.

## Adding to the corpus

When you add a new rule to the catalogue:

1. Identify the cloud (GCP/AWS/Azure) and the OWASP category.
2. Add a triggering snippet to the relevant `<cloud>/0N_*.tf` file.
3. Update the file's header comment under `Expected tf-analyze findings`.
4. Update the per-cloud README's rule list.
5. Re-run `python3 ../../scripts/detect.py --target . --format json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["findings"]))'` and confirm the count increased by 1 (or more if the new rule fires multiple times).
6. Bump the CI gate in `.github/workflows/ci.yml` if the new total falls outside 65–75.

If a rule applies cross-cloud (cloud-neutral, like `ROB-MOVED-001`), put the trigger in the GCP folder by default — it has the densest existing coverage, so per-cloud accounting stays simple.

## Catalogue expansion roadmap

Each cloud's README lists specific rules that *should* fire on the corpus but don't (because the catalogue doesn't cover them yet). These are ranked candidates for the next batch of rule additions:

- **AWS roadmap:** `SEC-AWS-IMDS-001`, `SEC-AWS-S3-PUBLIC-BLOCK-001`, `SEC-AWS-RDS-ENCRYPT-001`, `SEC-AWS-RDS-PUBLIC-001`, `SEC-AWS-LAMBDA-RUNTIME-001`, `SEC-AWS-CLOUDTRAIL-001`. See [`aws/README.md`](aws/README.md).
- **Azure roadmap:** Promote the four existing stubs (`SEC-AZURE-STORAGE-001`, `SEC-AZURE-KV-001`, `STK-AZURE-NSG-001`, `SEC-AZURE-MI-001`). See [`azure/README.md`](azure/README.md).

`python3 scripts/detect.py --new-rule SEC-AWS-IMDS-001` scaffolds the catalogue YAML + fixture skeleton — pair it with adjusting the existing `aws/10_ssrf.tf` trigger.
