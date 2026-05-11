# HCP Terraform Run Task integration

A Run Task is HashiCorp's webhook hook between `terraform plan` and
`terraform apply`. tf-analyze ships an opt-in Run Task server that:

1. Receives the plan-JSON URL from HCP Terraform
2. Downloads the plan artifact (no Terraform credentials required)
3. Runs `detect.py --plan-json plan.json --fail-on HIGH`
4. POSTs `passed` / `failed` + summary to HCP Terraform's callback URL

The server lives at [`integrations/run-task/`](../integrations/run-task/).

## Why a Run Task

Catalogue rules can run in two modes — **static** (HCL regex) and **plan**
(plan-JSON-resolved values). Plan mode catches violations that depend on
runtime values: a `var.encrypted = false` set in a tfvars file, an IAM
role name composed via `format()`, or a count that's only resolvable at
plan time. The Run Task is the only path that gets plan-JSON without
re-running Terraform with credentials.

## Quick start

### 1. Run the server

Locally (smoke test):

```bash
pip install -r integrations/run-task/requirements.txt
TFA_RUN_TASK_HMAC_KEY=dev-only-key \
  uvicorn integrations.run-task.server:app --port 8000
```

In production (Docker):

```bash
docker build -f integrations/run-task/Dockerfile \
  -t tf-analyze-run-task .
docker run -d -p 8000:8000 \
  -e TFA_RUN_TASK_HMAC_KEY="$(openssl rand -hex 32)" \
  -e TFA_RUN_TASK_FAIL_ON=HIGH \
  tf-analyze-run-task
```

The server only needs outbound HTTPS to `archivist.terraform.io` (HCP's
plan-JSON CDN) and the per-org callback host.

### 2. Register the Run Task in HCP Terraform

Settings → Run Tasks → **Create**:

| Field         | Value                                          |
|---------------|------------------------------------------------|
| Name          | `tf-analyze`                                   |
| Endpoint URL  | `https://<your-host>/runtask`                  |
| HMAC key      | Same value as `TFA_RUN_TASK_HMAC_KEY` above    |
| Description   | "Static + plan-time security analysis"         |

Click **Test** — HCP sends a probe; the server replies 200 with `status: passed`.

### 3. Attach to a workspace

Workspace → Settings → Run Tasks → Add **tf-analyze**, choose stage:

- **Pre-plan** — analyze HCL only (static)
- **Post-plan** *(recommended)* — full plan-JSON analysis
- **Pre-apply** — gate apply on findings

Choose enforcement:

- **Advisory** — failures show as warnings; apply proceeds
- **Mandatory** — failures block apply (CI-style gate)

## Configuration

Environment variables (server side):

| Var                        | Default | Meaning                                                      |
|----------------------------|---------|--------------------------------------------------------------|
| `TFA_RUN_TASK_HMAC_KEY`    | _empty_ | HMAC-SHA512 key. **Required** in production.                 |
| `TFA_RUN_TASK_FAIL_ON`     | `HIGH`  | Minimum urgency that returns `failed` to HCP.                |
| `TFA_RUN_TASK_FRAMEWORK`   | _empty_ | Optional. One of `cis` / `pci_dss` / `soc2` / `owasp_iac` / `all`. When set, the engine renders a compliance gap report alongside its findings and the run-task message gains a `compliance: <fw> <fail>/<total> controls failing.` line. Invalid values are logged and ignored. |
| `TFA_LOG_LEVEL`            | `INFO`  | Standard logging levels.                                     |

## Security

- HMAC signature is verified on every callback. Requests with mismatched
  `X-Tfc-Task-Signature` return 401.
- The server downloads plan-JSON over HTTPS using the per-run access
  token HCP supplies — there is no long-lived token to manage.
- Plan-JSON is read into a tempdir and deleted at the end of each request.
- No findings are persisted; if you need history, point HCP at an
  HTML-hosting endpoint and surface the `url` field in the callback.

## Local development

The Run Task server is a thin shim around `detect.py --plan-json`. To
debug the underlying analysis without the webhook layer:

```bash
terraform plan -out=plan.bin
terraform show -json plan.bin > plan.json
python3 scripts/detect.py --target . --plan-json plan.json --format json
```

The server's behaviour is exactly that, plus the HMAC-verified webhook
plumbing.

## Engine-crash handling (R30.10 + R30.12)

The server treats a crashed or hung `detect.py` differently than a
clean scan with zero findings, so an HCP Run Task callback never
reports a healthy "0 findings" outcome when the engine actually died.

### `SYN-SCAN-FAILED` synthetic finding

When the engine subprocess returns malformed JSON (parse error, empty
stdout, partial output from an OOM kill), the server constructs a
single synthetic finding with these fields:

```json
{
  "id": "SYN-SCAN-FAILED",
  "urgency": "CRITICAL",
  "title": "tf-analyze engine crashed",
  "section": "verification",
  "file": "(engine)",
  "line": 0,
  "recommendation": "The engine returned non-JSON. Check the run-task logs …",
  "context": "<captured stderr, first 2000 bytes>"
}
```

Plus the existing `_scan_failed: true` flag on the top-level dict for
backwards-compatibility with consumers that already special-cased it.

Downstream renderers (the dashboard, the Slack notifier, the HCP
callback body builder) handle the synthetic entry through their normal
"render each finding" pipeline — they do not need to know it's a
sentinel. The `id` value `SYN-SCAN-FAILED` is the canonical hook:
match on it if you want to differentiate engine failures from real
CRITICAL findings, e.g. for paging.

The `section: "verification"` is deliberate: the catalogue's
`_VALID_SECTIONS` includes `verification` (used by `--verify-fixed`
findings), and using a valid section value means downstream code that
validates `section` against the catalogue accepts the synthetic
entry cleanly. Prior to R30.12 this field was `"engine"`, which is
**not** a valid section — downstream renderers either rejected the
finding or quietly stripped it.

### Timeout discipline (R30.12)

The engine subprocess is invoked via `subprocess.Popen(...)` +
`proc.communicate(timeout=120)` + explicit `proc.kill()` in the
`TimeoutExpired` branch. The earlier `subprocess.run(..., timeout=120)`
shape would raise the timeout exception but **leave the child process
running** (Python ≤ 3.13 behaviour), so on a busy HCP Run Task worker
a series of timeouts accumulated zombie `detect.py` processes that
held file handles open. The new shape reaps the child reliably.

After a timeout, the server still emits a `SYN-SCAN-FAILED` finding
(exit code 124 by convention) so the HCP callback carries a clear
"engine timed out" signal rather than silence.
