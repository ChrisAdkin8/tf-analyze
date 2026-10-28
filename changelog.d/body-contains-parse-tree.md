## Rules read the setting, not the resource's text

Findings change: 33 rules that searched the raw text of a resource now
read the one setting they are about. Terragoat: azure 122 → 123, total
360 → 361 (`STK-AZURE-FUNCTION-001` now catches the Linux Function App
on .NET `"3.1"`).

- **Variables and locals are followed.** `ipv4_enabled = var.public`
  with `default = true` was missed by `SEC-GCP-SQL-PUBLIC-001`; the same
  held for every converted rule (`verify = var.x`, `member = var.who`,
  `enable_auto_scaling = local.x` …). These rules also run in plan /
  state mode now.
- **Lookalikes no longer fire**: the text in a `description`, a tag
  such as `node_version = "16"`, or a namespace *annotation* instead of
  the PSA label.
- **New kind `resource_has_block`**: a nested block at a path is present
  (`network_interface.access_config`), or present and empty with
  `empty: true` (`spec.egress {}`, `replication.auto {}`). `dynamic`
  blocks count; comments are not content.
- **Regexes that were wrong, fixed**:
  - `STK-GCP-CLOUDARMOR-001` fired whenever the default allow rule was
    written out — even on its own recommended fix. It now fires when no
    rule has `rate_limit_options`, as the title says.
  - `STK-AZURE-FUNCTION-001` / `STK-AZURE-WEBAPP-RUNTIME-001` only knew
    `v3.1`-style .NET and `"16"`-style Node values; Linux apps write
    `"3.1"` and `"16-lts"`, Windows apps `"~16"` and Java `"1.8"`. Each
    runtime has its own pattern, so a Python value can't match a Node
    list. The duplicate Python body match is gone.
  - `STK-AZURE-VM-IMG-EOL-001` also catches `2012-R2-Datacenter` (named
    in its description) and SKU variants such as `-gensecond`.
  - `SEC-GCP-SECRET-002` also catches the pre-v5 `automatic = true`.
  - `SEC-GCP-COMPUTE-PROJSSH-001` / `-OSLOGIN-001` accept `"false"` in
    any case, as GCP does.
  - `STK-GCP-CLOUDRUN-001` fires on 0 or above 1000, as described (it
    skipped 1100–1999 and fired on exactly 1000).
  - `SEC-AZURE-APPGW-002` also checks `ssl_profile.ssl_policy`.
  - `SEC-K8S-SECRET-002` also checks `binary_data`. A secret with no
    `type` but a `.dockerconfigjson` key now fires too.
- **Narrower than before** (by design): `SEC-K8S-RBAC-002` checks the
  subject's name only, not `kind = "Group"` (`system:masters` and
  `system:unauthenticated` are groups); `SEC-GCP-LOG-EXCLUSION-001`
  reads the exclusion `filter` only.
- **Stays a text match**: `SEC-K8S-SECRET-001` — it asks how a value is
  written in the source (a quoted literal, also inside `jsonencode`),
  which the parsed value no longer shows.
