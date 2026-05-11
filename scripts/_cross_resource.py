"""Cross-resource detection helpers — eighth seam in the modularisation.

Each `_graph_*` function takes a resource index + raw files map and
yields partial findings (id is filled in by the caller). These checks
express conditions that span multiple resources — e.g. "logging-target
bucket is itself public" or "KMS key in a different region from its
consumer". They produce **findings**, not graph edges — orthogonal to
the attack-graph build in `_attack_graph.py`.

The catalogue YAML wires each helper in via
`patterns: [{kind: graph_check, function: <name>}]`. The
`_GRAPH_CHECKS` registry below maps catalogue names → helper functions.

Scope rule — same as the seven prior seams:

  * Pure functions + immutable regex constants only.
  * No engine state. Each helper takes the resource index and the raw
    files map as parameters and returns a list of dicts.
  * Cross-seam edges into `_hcl` for the HCL primitives
    (`find_blocks`, `block_arg_value`, `block_has_arg`,
    `RESOURCE_START`-style regexes). `_hcl` is fully independent so
    this doesn't create a cycle.

Public surface
--------------

* ``_build_resource_index(all_files_text)`` — index every resource
  block by `<type>.<name>` → `{file, line, body, type, name}`.
* ``_graph_logging_target_public(index, files)`` — bucket logging.log_bucket
  references another bucket whose `public_access_prevention` is not
  `enforced`. Cross-bucket finding.
* ``_graph_gke_nodepool_secure_boot(index, files)`` — GKE node pool
  attached to a cluster whose `node_config` lacks
  `shielded_instance_config.enable_secure_boot = true`.
* ``_graph_kms_location_parity(index, files)`` — consumer in region R1
  uses a KMS key in a different region R2 (geo-residency drift).
* ``_graph_iam_member_breadth(index, files)`` — single IAM role bound
  to many principals (privilege concentration risk).
* ``_graph_azure_uami_orphan(index, files)`` — user-assigned managed
  identity declared but never attached to a compute resource.
* ``_graph_dynamodb_pitr(index, files)`` — DynamoDB table without
  point-in-time recovery.
* ``_graph_dynamodb_sse(index, files)`` — DynamoDB table without
  server-side encryption.
* ``_GRAPH_CHECKS`` — `{name: function}` registry that
  `detect_corpus` iterates over.

Names are preserved exactly; the re-export shim in `detect.py` maps
each one as a binding so existing callers (`detect_corpus`, the
catalogue's `graph_check` dispatch, `tests/test_attack_graph.py`)
need no migration.
"""

from __future__ import annotations

import re

from _hcl import (
    find_blocks,
    block_arg_value,
    block_has_arg,
    brace_walk,
)

# `RESOURCE_START` regex lives in detect.py — it's the pervasive
# resource-block header pattern used by every detection branch. Mirror
# the pattern locally so this module stays import-independent of the
# detect.py top-level module-load order. The two compiled regexes are
# semantically identical; binding identity is not part of the contract.
_RESOURCE_START = re.compile(
    r'^\s*resource\s+"([\w-]+)"\s+"([\w-]+)"\s*\{', re.MULTILINE
)


# ---- Graph-based checks ---------------------------------------------------
#
# A graph check is a function that takes a resource index plus the raw file
# map and yields zero or more partial findings (id is filled in by the
# caller). Graph checks are how we express conditions that span multiple
# resources, e.g. "logging target bucket is itself private".
#
# To add a new graph check:
#   1. Write the function below (signature: index, files -> list[finding]).
#   2. Register it in _GRAPH_CHECKS.
#   3. Reference it from a catalogue YAML via `kind: graph_check, function: <name>`.

def _build_resource_index(all_files_text: dict) -> dict:
    """Index every resource block by `<type>.<name>` → {file, line, body}."""
    idx: dict[str, dict] = {}
    for fp, text in all_files_text.items():
        for blk in find_blocks(text, _RESOURCE_START):
            btype, bname = blk["groups"]
            idx[f"{btype}.{bname}"] = {
                "file": str(fp),
                "line": blk["start_line"],
                "body": blk["body"],
                "type": btype,
                "name": bname,
            }
    return idx


_LOG_BUCKET_REF = re.compile(
    r'log_bucket\s*=\s*google_storage_bucket\.([\w-]+)\.name',
)


def _graph_logging_target_public(index: dict, all_files_text: dict) -> list[dict]:
    """A bucket's logging.log_bucket references a bucket lacking
    public_access_prevention = "enforced". The target accumulates audit logs
    for the source — leaking it via public access is a high-blast-radius bug.
    """
    out: list[dict] = []
    for addr, src in index.items():
        if src["type"] != "google_storage_bucket":
            continue
        m = _LOG_BUCKET_REF.search(src["body"])
        if not m:
            continue
        target_addr = f"google_storage_bucket.{m.group(1)}"
        target = index.get(target_addr)
        if not target:
            continue
        pap = block_arg_value(target["body"], "public_access_prevention")
        if pap != "enforced":
            out.append({
                "file": target["file"],
                "line": target["line"],
                "resource": target_addr,
                "context": (
                    f"logging target of {addr} (in {src['file']}:{src['line']}) "
                    f"is missing public_access_prevention=enforced"
                ),
            })
    return out


_NODEPOOL_CLUSTER_REF = re.compile(
    r'cluster\s*=\s*google_container_cluster\.([\w-]+)(?:\.\w+)?',
)
_SECURE_BOOT_RE = re.compile(r'enable_secure_boot\s*=\s*true')
_INTEGRITY_MON_RE = re.compile(r'enable_integrity_monitoring\s*=\s*true')


def _graph_gke_nodepool_secure_boot(index: dict, all_files_text: dict) -> list[dict]:
    """Every google_container_node_pool attached to a cluster must set
    `node_config.shielded_instance_config.enable_secure_boot = true` AND
    `enable_integrity_monitoring = true`. CIS GKE 6.5.5 requires both on
    every pool — leaving any pool unhardened nullifies the cluster-wide
    posture, since pods schedule across pools.
    """
    out: list[dict] = []
    for addr, np in index.items():
        if np["type"] != "google_container_node_pool":
            continue
        m = _NODEPOOL_CLUSTER_REF.search(np["body"])
        if not m:
            continue  # ambient/data-source cluster reference — out of scope
        body = np["body"]
        missing = []
        if not _SECURE_BOOT_RE.search(body):
            missing.append("enable_secure_boot")
        if not _INTEGRITY_MON_RE.search(body):
            missing.append("enable_integrity_monitoring")
        if missing:
            out.append({
                "file": np["file"],
                "line": np["line"],
                "resource": addr,
                "context": (
                    f"node pool attached to google_container_cluster.{m.group(1)} "
                    f"is missing: {', '.join(missing)}"
                ),
            })
    return out


_KEY_RING_REF = re.compile(
    r'key_ring\s*=\s*google_kms_key_ring\.([\w-]+)(?:\.\w+)?',
)
_KMS_KEY_REF = re.compile(
    r'kms_key_name\s*=\s*google_kms_crypto_key\.([\w-]+)(?:\.\w+)?',
)


def _graph_kms_location_parity(index: dict, all_files_text: dict) -> list[dict]:
    """A KMS-encrypted resource's location must match the key ring's
    location. KMS keys inherit `location` from the key ring; if the
    consuming resource (bucket, SQL instance, etc.) lives in a different
    region, the encrypt/decrypt path crosses regions, breaks regional
    durability guarantees, and quietly degrades to multi-region pricing.
    """
    out: list[dict] = []
    # First pass: for each crypto key, find the location of its key ring.
    key_ring_loc: dict[str, str | None] = {}
    for addr, blk in index.items():
        if blk["type"] != "google_kms_crypto_key":
            continue
        m = _KEY_RING_REF.search(blk["body"])
        if not m:
            continue
        ring_addr = f"google_kms_key_ring.{m.group(1)}"
        ring = index.get(ring_addr)
        if not ring:
            continue
        key_ring_loc[addr] = block_arg_value(ring["body"], "location")
    # Second pass: any resource referencing a crypto key must match.
    for addr, consumer in index.items():
        if consumer["type"] in {"google_kms_crypto_key", "google_kms_key_ring"}:
            continue
        m = _KMS_KEY_REF.search(consumer["body"])
        if not m:
            continue
        key_addr = f"google_kms_crypto_key.{m.group(1)}"
        ring_loc = key_ring_loc.get(key_addr)
        if not ring_loc:
            continue
        consumer_loc = (
            block_arg_value(consumer["body"], "location")
            or block_arg_value(consumer["body"], "region")
        )
        if not consumer_loc:
            continue
        if consumer_loc.lower() != ring_loc.lower():
            out.append({
                "file": consumer["file"],
                "line": consumer["line"],
                "resource": addr,
                "context": (
                    f"location {consumer_loc!r} does not match KMS key ring "
                    f"location {ring_loc!r} (via {key_addr})"
                ),
            })
    return out


_PROJECT_IAM_TYPES = {
    "google_project_iam_member",
    "google_project_iam_binding",
}
_RESOURCE_LEVEL_TYPES = {
    "google_storage_bucket_iam_member",
    "google_storage_bucket_iam_binding",
    "google_pubsub_topic_iam_member",
    "google_pubsub_subscription_iam_member",
    "google_secret_manager_secret_iam_member",
    "google_kms_crypto_key_iam_member",
    "google_bigquery_dataset_iam_member",
}


def _graph_iam_member_breadth(index: dict, all_files_text: dict) -> list[dict]:
    """A service account that already has resource-level IAM (e.g. on a
    specific bucket / topic) and ALSO has a project-level IAM binding is
    almost certainly over-privileged: the project-level grant supersedes
    the resource-level scoping, making the latter pointless. Either
    remove the project grant or remove the resource-level one.
    """
    out: list[dict] = []
    member_re = re.compile(r'member\s*=\s*"([^"]+)"')
    members_re = re.compile(r'members\s*=\s*\[([^\]]+)\]')
    project_grants: dict[str, list[dict]] = {}
    resource_grants: dict[str, list[dict]] = {}
    for addr, blk in index.items():
        members: set[str] = set()
        m = member_re.search(blk["body"])
        if m:
            members.add(m.group(1))
        m = members_re.search(blk["body"])
        if m:
            for tok in m.group(1).split(","):
                tok = tok.strip().strip('"')
                if tok:
                    members.add(tok)
        if blk["type"] in _PROJECT_IAM_TYPES:
            for mem in members:
                project_grants.setdefault(mem, []).append({"addr": addr, "blk": blk})
        elif blk["type"] in _RESOURCE_LEVEL_TYPES:
            for mem in members:
                resource_grants.setdefault(mem, []).append({"addr": addr, "blk": blk})
    for mem, project_list in project_grants.items():
        resource_list = resource_grants.get(mem)
        if not resource_list:
            continue
        for pg in project_list:
            out.append({
                "file": pg["blk"]["file"],
                "line": pg["blk"]["line"],
                "resource": pg["addr"],
                "context": (
                    f"member {mem} also has resource-level IAM at "
                    f"{', '.join(g['addr'] for g in resource_list)} — "
                    f"the project-level grant makes those redundant"
                ),
            })
    return out


_UAMI_PRINCIPAL_REF = re.compile(
    r'azurerm_user_assigned_identity\.([\w-]+)\.principal_id'
)


def _graph_azure_uami_orphan(index: dict, all_files_text: dict) -> list[dict]:
    """Detect azurerm_user_assigned_identity resources with no
    azurerm_role_assignment referencing their principal_id — an orphan
    identity that grants no permissions yet still widens the blast radius
    of a tenant compromise (an attacker who can assign roles can weaponise it).
    """
    out: list[dict] = []
    uamis = {k: v for k, v in index.items()
             if v["type"] == "azurerm_user_assigned_identity"}
    if not uamis:
        return out
    referenced: set[str] = set()
    for addr, res in index.items():
        if res["type"] != "azurerm_role_assignment":
            continue
        for m in _UAMI_PRINCIPAL_REF.finditer(res["body"]):
            referenced.add(m.group(1))
    for addr, res in uamis.items():
        if res["name"] not in referenced:
            out.append(
                {
                    "file": res["file"],
                    "line": res["line"],
                    "resource": addr,
                    "context": (
                        "UAMI has no azurerm_role_assignment binding — "
                        "orphan identity widens blast radius without granting intent"
                    ),
                }
            )
    return out


def _graph_dynamodb_pitr(index: dict, all_files_text: dict) -> list[dict]:
    """aws_dynamodb_table without point_in_time_recovery { enabled = true }.

    DynamoDB's PITR default is disabled. A table with no
    point_in_time_recovery block (or enabled = false) cannot be restored
    to an arbitrary second within the last 35 days, leaving accidental
    writes or deletes unrecoverable.
    """
    out: list[dict] = []
    for addr, res in index.items():
        if res["type"] != "aws_dynamodb_table":
            continue
        body = res["body"]
        pitr_m = re.search(r'(?m)^\s*point_in_time_recovery\s*\{', body)
        if not pitr_m:
            out.append({"file": res["file"], "line": res["line"], "resource": addr})
            continue
        # Round-30.13 follow-up — the R30.13 inventory missed two
        # walkers in this module (they live outside `detect.py` and
        # `_apply_fixes.py`). Migrating to the shared `brace_walk`
        # closes the consistency gap and gains quote-awareness on the
        # PITR block boundary.
        end_after = brace_walk(body, pitr_m.end() - 1)
        if end_after is None:
            out.append({"file": res["file"], "line": res["line"], "resource": addr})
            continue
        end = end_after - 1
        pitr_body = body[pitr_m.end():end]
        enabled = block_arg_value(pitr_body, "enabled")
        if not enabled or enabled.lower() != "true":
            out.append({"file": res["file"], "line": res["line"], "resource": addr})
    return out


def _graph_dynamodb_sse(index: dict, all_files_text: dict) -> list[dict]:
    """aws_dynamodb_table without a customer-managed KMS key for SSE.

    DynamoDB encrypts at rest by default using Amazon-owned keys, which
    cannot be audited, rotated, or revoked. Tables that lack a
    server_side_encryption block with kms_key_arn rely on these default
    keys instead of a customer-managed key (CMK).
    """
    out: list[dict] = []
    for addr, res in index.items():
        if res["type"] != "aws_dynamodb_table":
            continue
        body = res["body"]
        sse_m = re.search(r'(?m)^\s*server_side_encryption\s*\{', body)
        if not sse_m:
            out.append({"file": res["file"], "line": res["line"], "resource": addr})
            continue
        # Round-30.13 follow-up — see PITR walker above; same migration.
        end_after = brace_walk(body, sse_m.end() - 1)
        if end_after is None:
            out.append({"file": res["file"], "line": res["line"], "resource": addr})
            continue
        end = end_after - 1
        sse_body = body[sse_m.end():end]
        if not block_has_arg(sse_body, "kms_key_arn"):
            out.append({"file": res["file"], "line": res["line"], "resource": addr})
    return out


_GRAPH_CHECKS = {
    "logging_target_public": _graph_logging_target_public,
    "gke_nodepool_secure_boot": _graph_gke_nodepool_secure_boot,
    "kms_location_parity": _graph_kms_location_parity,
    "iam_member_breadth": _graph_iam_member_breadth,
    "azure_uami_orphan": _graph_azure_uami_orphan,
    "dynamodb_pitr": _graph_dynamodb_pitr,
    "dynamodb_sse": _graph_dynamodb_sse,
}

