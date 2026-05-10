"""Attack-graph build + render — sixth seam in the detect.py modularisation.

Builds a directed graph from internet-reachable resources to crown
jewels, scores each finding by how many crown-jewel paths it blocks
when fixed, propagates reachability through security groups, and
renders the graph as Mermaid (Markdown reports) or self-contained
HTML+SVG (the VS Code attack-graph webview).

Scope rule — same as the prior five seams (`_mitre`, `_versions`,
`_scoring`, `_hcl`, `_catalog`):

  * Pure functions + immutable regex/data constants only.
  * No engine state. The functions operate over the `resource_index`
    dict (built by `detect._build_resource_index`, which itself uses
    `_hcl.find_blocks`) and the `findings` list — both passed as
    parameters.
  * One cross-seam edge: `_apply_reachability_urgency` imports
    `_URGENCY_TIERS` from `_scoring` (same shape as
    `_catalog` ↔ `_hcl._parse_scalar`).

Public surface
--------------

Constants
~~~~~~~~~

* ``_CROWN_JEWEL_TYPES`` — Terraform resource types treated as crown
  jewels: relational/NoSQL/document DBs, secret stores, KMS keys,
  storage accounts/buckets, etc. Across AWS, GCP, Azure.
* ``_NODE_TYPE_MAP`` — resource type → display category
  (``compute``, ``iam``, ``storage``, ``secret``, ``key``,
  ``network``). Drives the HTML render's colour palette and the
  Mermaid classDef assignments.
* ``_INET_*`` — 9 regex constants used by ``_is_internet_reachable``
  to decide whether a single resource is directly internet-facing
  based on its HCL body.
* ``_EDGE_*`` — 14 regex constants used by ``build_attack_graph``
  to infer cross-resource references (IAM, KMS, security groups,
  Secrets Manager, GCS buckets, Azure managed identities + Key
  Vault + Storage + SQL, GCP service accounts).

Functions
~~~~~~~~~

* ``_is_internet_reachable(rtype, body)`` — True if a resource's HCL
  body indicates it is directly internet-reachable.
* ``build_attack_graph(resource_index, findings)`` — return
  ``{nodes, edges, critical_path, internet_node_id}``. Nodes carry
  ``internet_reachable`` + ``is_crown_jewel`` + ``on_critical_path``;
  edges carry ``label`` (``iam_profile``, ``role``, ``kms_key``,
  ``security_group``, ``service_account``, …). For very large repos
  the graph is pruned to a manageable size (critical path + reachable
  + crown jewels + immediate neighbours) so the HTML render stays
  usable.
* ``_score_fix_centrality(graph, findings)`` — for each finding's
  resource, simulate removal from the graph and count the drop in
  reachable crown jewels. Returns list sorted by impact (descending);
  ``impact = crowns_blocked * 10 + (5 if on_critical_path else 0) +
  (3 if internet_reachable else 0)``.
* ``_apply_reachability_urgency(findings, graph, entry_map)`` —
  mutates the findings list in place. Promotes findings on
  critical-path resources by one urgency tier (LOW → MEDIUM →
  HIGH → CRITICAL) and demotes findings on resources unreachable from
  INTERNET by one tier. Findings on internet-reachable nodes keep
  their default urgency.
* ``_mermaid_id(addr)`` — sanitise ``aws_iam_role.foo`` →
  ``aws_iam_role_foo`` for Mermaid node IDs.
* ``graph_to_mermaid(graph)`` — turn the graph dict into a
  Mermaid ```mermaid flowchart``` block.
* ``_render_graph_html(graph)`` — turn the graph dict into a
  self-contained HTML+JS attack-graph view (force-directed layout,
  draggable nodes, clickable sidebar). No external scripts.

Names are kept exactly as they appeared in `detect.py`; the re-export
shim in detect.py preserves each one as a binding so existing callers
(VS Code extension's `Show Attack Graph` command, the HTML report
renderer, `tests/test_attack_graph.py`) need no migration.
"""

from __future__ import annotations

import re

from _scoring import _URGENCY_TIERS


# ---- attack graph -------------------------------------------------------

_CROWN_JEWEL_TYPES: set[str] = {
    "aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance",
    "aws_secretsmanager_secret", "aws_kms_key", "aws_s3_bucket",
    "google_sql_database_instance", "google_secret_manager_secret",
    "google_kms_crypto_key", "google_storage_bucket",
    "azurerm_mssql_server", "azurerm_sql_server",
    "azurerm_key_vault", "azurerm_key_vault_secret", "azurerm_storage_account",
    # Azure — expanded crown jewels
    "azurerm_postgresql_server", "azurerm_postgresql_flexible_server",
    "azurerm_cosmosdb_account", "azurerm_service_bus_namespace",
    "azurerm_mysql_server", "azurerm_mysql_flexible_server",
}

_NODE_TYPE_MAP: dict[str, str] = {
    "aws_instance": "compute", "aws_lambda_function": "compute",
    "aws_ecs_task_definition": "compute", "aws_ecs_service": "compute",
    "google_compute_instance": "compute", "google_cloud_run_v2_service": "compute",
    "google_cloud_run_service": "compute", "google_container_cluster": "compute",
    "google_cloudfunctions_function": "compute", "google_cloudfunctions2_function": "compute",
    "azurerm_linux_virtual_machine": "compute",
    "azurerm_windows_virtual_machine": "compute", "azurerm_virtual_machine": "compute",
    "azurerm_app_service": "compute", "azurerm_linux_web_app": "compute",
    "azurerm_windows_web_app": "compute", "azurerm_kubernetes_cluster": "compute",
    "azurerm_function_app": "compute", "azurerm_linux_function_app": "compute",
    "aws_iam_role": "iam", "aws_iam_instance_profile": "iam", "aws_iam_policy": "iam",
    "google_service_account": "iam",
    "azurerm_user_assigned_identity": "iam", "azurerm_role_assignment": "iam",
    "aws_s3_bucket": "storage", "google_storage_bucket": "storage",
    "azurerm_storage_account": "storage",
    "aws_db_instance": "storage", "aws_rds_cluster": "storage",
    "google_sql_database_instance": "storage", "azurerm_mssql_server": "storage",
    "azurerm_postgresql_server": "storage", "azurerm_postgresql_flexible_server": "storage",
    "azurerm_mysql_server": "storage", "azurerm_cosmosdb_account": "storage",
    "aws_secretsmanager_secret": "secret",
    "google_secret_manager_secret": "secret",
    "azurerm_key_vault_secret": "secret",
    "aws_kms_key": "key", "google_kms_crypto_key": "key",
    "azurerm_key_vault_key": "key", "azurerm_key_vault": "key",
    "aws_security_group": "network", "aws_lb": "network", "aws_alb": "network",
    "google_compute_firewall": "network", "azurerm_network_security_group": "network",
    "azurerm_public_ip": "network",
}

# Internet-reachability detection regexes
_INET_EC2_PUBLIC_IP_RE  = re.compile(r'associate_public_ip_address\s*=\s*true')
_INET_RDS_PUBLIC_RE     = re.compile(r'publicly_accessible\s*=\s*true')
_INET_SQL_PUBLIC_IP_RE  = re.compile(r'ipv4_enabled\s*=\s*true')
_INET_SG_CIDR_RE        = re.compile(r'cidr_blocks\s*=\s*\[.*?"0\.0\.0\.0/0"', re.DOTALL)
_INET_SG_IPV6_RE        = re.compile(r'ipv6_cidr_blocks\s*=\s*\[.*?"::/0"', re.DOTALL)
_INET_CLOUDRUN_ALL_RE   = re.compile(r'ingress\s*=\s*"?INGRESS_TRAFFIC_ALL"?')
_INET_ALB_FACING_RE     = re.compile(r'(?:scheme|load_balancer_type)\s*=\s*"?internet-facing"?')
_INET_GCE_ACCESS_CFG_RE = re.compile(r'access_config\s*\{')
_INET_GKE_PRIVATE_RE    = re.compile(r'private_cluster_config\s*\{')
# Azure reachability
_INET_AZ_IP_RESTRICTION_RE = re.compile(r'ip_restriction\s*\{')

# Edge-inference regexes (HCL reference patterns between resources)
_EDGE_IAM_PROFILE_RE  = re.compile(
    r'iam_instance_profile\s*=\s*aws_iam_instance_profile\.([\w-]+)')
_EDGE_PROFILE_ROLE_RE = re.compile(
    r'\brole\s*=\s*aws_iam_role\.([\w-]+)(?:\.\w+)?')
_EDGE_KMS_KEY_ID_RE   = re.compile(
    r'kms_key_id\s*=\s*aws_kms_key\.([\w-]+)(?:\.\w+)?')
_EDGE_KMS_KEY_NAME_RE = re.compile(
    r'kms_key_name\s*=\s*google_kms_crypto_key\.([\w-]+)(?:\.\w+)?')
_EDGE_KMS_MASTER_RE   = re.compile(
    r'kms_master_key_id\s*=\s*(?:aws_kms_key|google_kms_crypto_key)\.([\w-]+)(?:\.\w+)?')
_EDGE_SECRET_ARN_RE   = re.compile(
    r'secrets_manager_secret_arn\s*=\s*aws_secretsmanager_secret\.([\w-]+)(?:\.\w+)?')
_EDGE_SG_REF_RE       = re.compile(
    r'(?:vpc_security_group_ids|security_groups)\s*=\s*\[[^\]]*aws_security_group\.([\w-]+)')
_EDGE_GCP_SA_RE       = re.compile(
    r'email\s*=\s*google_service_account\.([\w-]+)(?:\.\w+)?')
_EDGE_GCS_BUCKET_RE   = re.compile(
    r'\bbucket\s*=\s*google_storage_bucket\.([\w-]+)(?:\.\w+)?')
# Azure edge-inference (managed identity, Key Vault, storage, SQL)
_EDGE_AZ_MI_RE        = re.compile(
    r'identity_ids\s*=\s*\[[^\]]*azurerm_user_assigned_identity\.([\w-]+)')
_EDGE_AZ_KV_RE        = re.compile(
    r'key_vault_id\s*=\s*azurerm_key_vault\.([\w-]+)(?:\.\w+)?')
_EDGE_AZ_STORAGE_RE   = re.compile(
    r'storage_account_name\s*=\s*azurerm_storage_account\.([\w-]+)(?:\.\w+)?')
_EDGE_AZ_SQL_RE       = re.compile(
    r'server_name\s*=\s*azurerm_mssql_server\.([\w-]+)(?:\.\w+)?')
# GCP additional service-account references (Cloud Run, GKE, Cloud Functions)
_EDGE_GCP_SA_EMAIL_RE = re.compile(
    r'service_account_email\s*=\s*google_service_account\.([\w-]+)(?:\.\w+)?')
_EDGE_GCP_SA_NAME_RE  = re.compile(
    r'(?<!\w)service_account\s*=\s*google_service_account\.([\w-]+)(?:\.\w+)?')


def _is_internet_reachable(rtype: str, body: str) -> bool:
    """Return True if the resource type + body suggests it is directly internet-reachable."""
    if rtype == "aws_instance":
        return bool(_INET_EC2_PUBLIC_IP_RE.search(body))
    if rtype in {"aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance"}:
        return bool(_INET_RDS_PUBLIC_RE.search(body))
    if rtype == "google_sql_database_instance":
        return bool(_INET_SQL_PUBLIC_IP_RE.search(body))
    if rtype == "aws_security_group":
        return bool(_INET_SG_CIDR_RE.search(body) or _INET_SG_IPV6_RE.search(body))
    if rtype in {"google_cloud_run_v2_service", "google_cloud_run_service"}:
        return bool(_INET_CLOUDRUN_ALL_RE.search(body) or "ingress" not in body)
    if rtype in {"aws_lb", "aws_alb"}:
        return bool(_INET_ALB_FACING_RE.search(body))
    if rtype == "google_compute_instance":
        return bool(_INET_GCE_ACCESS_CFG_RE.search(body))
    if rtype == "google_container_cluster":
        return not bool(_INET_GKE_PRIVATE_RE.search(body))
    # Azure — public_ip resource is always internet-facing by definition
    if rtype == "azurerm_public_ip":
        return True
    # Azure web/function apps are public unless ip_restriction blocks are present
    if rtype in {
        "azurerm_app_service", "azurerm_linux_web_app",
        "azurerm_windows_web_app", "azurerm_function_app",
        "azurerm_linux_function_app",
    }:
        return not bool(_INET_AZ_IP_RESTRICTION_RE.search(body))
    return False


def build_attack_graph(resource_index: dict, findings: list[dict]) -> dict:
    """Build a directed attack-path graph from internet-reachable nodes to crown jewels.

    Returns a dict with keys: nodes, edges, critical_path, internet_node_id.
    Nodes carry: id, type, label, file, line, findings, internet_reachable,
    is_crown_jewel, on_critical_path.
    Edges carry: from, to, label.
    """
    # Index findings by resource address
    finding_by_resource: dict[str, list[str]] = {}
    for f in findings:
        res = f.get("resource", "")
        if res:
            finding_by_resource.setdefault(res, []).append(f["id"])

    # Build nodes for every resource
    nodes: dict[str, dict] = {}
    for addr, res in resource_index.items():
        rtype = res["type"]
        reachable = _is_internet_reachable(rtype, res["body"])
        nodes[addr] = {
            "id": addr,
            "type": _NODE_TYPE_MAP.get(rtype, "compute"),
            "label": addr,
            "file": res["file"],
            "line": res["line"],
            "findings": finding_by_resource.get(addr, []),
            "internet_reachable": reachable,
            "is_crown_jewel": rtype in _CROWN_JEWEL_TYPES,
            "on_critical_path": False,
        }

    # Synthetic internet entry node
    nodes["INTERNET"] = {
        "id": "INTERNET",
        "type": "internet",
        "label": "Internet",
        "file": "",
        "line": 0,
        "findings": [],
        "internet_reachable": True,
        "is_crown_jewel": False,
        "on_critical_path": False,
    }

    # Infer edges from HCL reference patterns
    edges: list[dict] = []

    def _add_edge(src: str, dst: str, label: str) -> None:
        if src in nodes and dst in nodes and src != dst:
            edges.append({"from": src, "to": dst, "label": label})

    for addr, res in resource_index.items():
        body = res["body"]
        rtype = res["type"]

        for m in _EDGE_IAM_PROFILE_RE.finditer(body):
            _add_edge(addr, f"aws_iam_instance_profile.{m.group(1)}", "iam_profile")
        if rtype == "aws_iam_instance_profile":
            for m in _EDGE_PROFILE_ROLE_RE.finditer(body):
                _add_edge(addr, f"aws_iam_role.{m.group(1)}", "role")
        elif rtype not in {"aws_iam_instance_profile"}:
            for m in _EDGE_PROFILE_ROLE_RE.finditer(body):
                _add_edge(addr, f"aws_iam_role.{m.group(1)}", "role")
        for m in _EDGE_KMS_KEY_ID_RE.finditer(body):
            _add_edge(addr, f"aws_kms_key.{m.group(1)}", "kms_key")
        for m in _EDGE_KMS_KEY_NAME_RE.finditer(body):
            _add_edge(addr, f"google_kms_crypto_key.{m.group(1)}", "kms_key")
        for m in _EDGE_KMS_MASTER_RE.finditer(body):
            if "aws_kms_key" in m.group(0):
                _add_edge(addr, f"aws_kms_key.{m.group(1)}", "kms_master_key")
            else:
                _add_edge(addr, f"google_kms_crypto_key.{m.group(1)}", "kms_master_key")
        for m in _EDGE_SECRET_ARN_RE.finditer(body):
            _add_edge(addr, f"aws_secretsmanager_secret.{m.group(1)}", "secret_ref")
        for m in _EDGE_SG_REF_RE.finditer(body):
            _add_edge(addr, f"aws_security_group.{m.group(1)}", "security_group")
        for m in _EDGE_GCP_SA_RE.finditer(body):
            _add_edge(addr, f"google_service_account.{m.group(1)}", "service_account")
        for m in _EDGE_GCS_BUCKET_RE.finditer(body):
            _add_edge(addr, f"google_storage_bucket.{m.group(1)}", "bucket_ref")
        # Azure edges
        for m in _EDGE_AZ_MI_RE.finditer(body):
            _add_edge(addr, f"azurerm_user_assigned_identity.{m.group(1)}", "managed_identity")
        for m in _EDGE_AZ_KV_RE.finditer(body):
            _add_edge(addr, f"azurerm_key_vault.{m.group(1)}", "key_vault_ref")
        for m in _EDGE_AZ_STORAGE_RE.finditer(body):
            _add_edge(addr, f"azurerm_storage_account.{m.group(1)}", "storage_ref")
        for m in _EDGE_AZ_SQL_RE.finditer(body):
            _add_edge(addr, f"azurerm_mssql_server.{m.group(1)}", "sql_server_ref")
        # GCP additional service account reference patterns
        for m in _EDGE_GCP_SA_EMAIL_RE.finditer(body):
            _add_edge(addr, f"google_service_account.{m.group(1)}", "service_account")
        for m in _EDGE_GCP_SA_NAME_RE.finditer(body):
            _add_edge(addr, f"google_service_account.{m.group(1)}", "service_account")

    # Connect internet-reachable nodes to INTERNET
    for addr, node in list(nodes.items()):
        if addr != "INTERNET" and node["internet_reachable"]:
            edges.append({"from": "INTERNET", "to": addr, "label": "internet"})

    # Propagate reachability: compute → SG (internet-reachable) → mark compute reachable
    sg_reachable = {
        e["to"] for e in edges
        if e["from"] == "INTERNET" and nodes.get(e["to"], {}).get("type") == "network"
    }
    for e in edges:
        if e["label"] == "security_group" and e["to"] in sg_reachable:
            src = e["from"]
            if src in nodes and not nodes[src]["internet_reachable"]:
                nodes[src]["internet_reachable"] = True
                edges.append({"from": "INTERNET", "to": src, "label": "internet (via sg)"})

    # BFS: shortest path from INTERNET to each crown jewel
    adj: dict[str, list[str]] = {}
    for e in edges:
        adj.setdefault(e["from"], []).append(e["to"])

    from collections import deque

    def _bfs(start: str, goal: str) -> list[str]:
        queue: deque[list[str]] = deque([[start]])
        visited: set[str] = {start}
        while queue:
            path = queue.popleft()
            if path[-1] == goal:
                return path
            for nbr in adj.get(path[-1], []):
                if nbr not in visited:
                    visited.add(nbr)
                    queue.append(path + [nbr])
        return []

    crown_jewels = [addr for addr, n in nodes.items() if n["is_crown_jewel"]]
    critical_path: list[str] = []
    for cj in crown_jewels:
        path = _bfs("INTERNET", cj)
        if path and (not critical_path or len(path) < len(critical_path)):
            critical_path = path

    for nid in critical_path:
        if nid in nodes:
            nodes[nid]["on_critical_path"] = True

    # Prune to a manageable size for large repos (keep relevant nodes + neighbors)
    node_list = list(nodes.values())
    if len(node_list) > 60:
        keep = set(critical_path)
        keep.update(addr for addr, n in nodes.items() if n["internet_reachable"])
        keep.update(addr for addr, n in nodes.items() if n["is_crown_jewel"])
        keep.add("INTERNET")
        # add immediate neighbors of keep set
        for e in edges:
            if e["from"] in keep:
                keep.add(e["to"])
            if e["to"] in keep:
                keep.add(e["from"])
        node_list = [n for n in node_list if n["id"] in keep]
        edges = [e for e in edges if e["from"] in keep and e["to"] in keep]

    return {
        "nodes": node_list,
        "edges": edges,
        "critical_path": critical_path,
        "internet_node_id": "INTERNET",
    }


def _score_fix_centrality(graph: dict, findings: list[dict]) -> list[dict]:
    """Rank findings by how many crown-jewel attack paths they block when fixed.

    For each finding's resource, remove that node from the graph and re-run BFS
    from INTERNET to each crown jewel.  The drop in reachable crown jewels is the
    primary 'crowns_blocked' score; secondary signals reward critical-path and
    internet-reachable nodes.  Returns a list sorted by impact (descending).
    """
    if not graph or not graph.get("nodes"):
        return []

    nodes_by_id = {n["id"]: n for n in graph["nodes"]}
    edges = graph["edges"]
    adj: dict[str, list[str]] = {}
    for e in edges:
        adj.setdefault(e["from"], []).append(e["to"])

    crown_jewels: frozenset[str] = frozenset(
        n["id"] for n in graph["nodes"] if n.get("is_crown_jewel")
    )

    def _reachable_crowns(exclude: str) -> int:
        visited: set[str] = set()
        queue = ["INTERNET"]
        count = 0
        while queue:
            cur = queue.pop(0)
            if cur in visited or cur == exclude:
                continue
            visited.add(cur)
            if cur in crown_jewels:
                count += 1
            for nxt in adj.get(cur, []):
                if nxt not in visited and nxt != exclude:
                    queue.append(nxt)
        return count

    baseline = _reachable_crowns("")
    if baseline == 0:
        return []

    results: list[dict] = []
    seen: set[str] = set()
    for f in findings:
        res = f.get("resource", "")
        if not res or res in seen or res not in nodes_by_id:
            continue
        seen.add(res)
        after = _reachable_crowns(res)
        blocked = baseline - after
        node = nodes_by_id[res]
        score = blocked * 10
        if node.get("on_critical_path"):
            score += 5
        if node.get("internet_reachable"):
            score += 3
        results.append({
            "finding_id": f["id"],
            "resource": res,
            "impact": score,
            "crowns_blocked": blocked,
            "on_critical_path": node.get("on_critical_path", False),
            "internet_reachable": node.get("internet_reachable", False),
        })

    return sorted(results, key=lambda x: (-x["impact"], x["finding_id"]))


def _apply_reachability_urgency(
    findings: list[dict],
    graph: dict,
    entry_map: dict[str, dict],
) -> None:
    """Promote findings on critical-path resources by one urgency tier;
    demote findings on resources unreachable from INTERNET by one tier."""
    critical_path_set = set(graph.get("critical_path", []))
    internet_reachable_set = {
        n["id"] for n in graph.get("nodes", []) if n.get("internet_reachable")
    }
    for f in findings:
        resource = f.get("resource", "")
        entry = entry_map.get(f["id"], {})
        base = entry.get("default_urgency", "MEDIUM")
        idx = _URGENCY_TIERS.index(base) if base in _URGENCY_TIERS else 1
        if resource and resource in critical_path_set:
            f["urgency"] = _URGENCY_TIERS[min(idx + 1, len(_URGENCY_TIERS) - 1)]
            f["on_critical_path"] = True
        elif resource and resource not in internet_reachable_set:
            f["urgency"] = _URGENCY_TIERS[max(idx - 1, 0)]
        else:
            f["urgency"] = base


def _mermaid_id(addr: str) -> str:
    """Sanitize a resource address for use as a Mermaid node ID."""
    return addr.replace(".", "_").replace("-", "_")


def graph_to_mermaid(graph: dict) -> str:
    """Convert an attack graph to a Mermaid flowchart string."""
    crit_set = set(graph.get("critical_path", []))
    lines = ["```mermaid", "flowchart LR"]
    lines += [
        "    classDef internet fill:#1a1a2e,color:#fff,stroke:#fff",
        "    classDef critical fill:#c0392b,color:#fff,stroke:#ff4444,stroke-width:3px",
        "    classDef crown fill:#6b0000,color:#ffd700,stroke:#ffd700",
        "    classDef reachable fill:#d35400,color:#fff",
        "    classDef iam fill:#6c5ce7,color:#fff",
        "    classDef storage fill:#27ae60,color:#fff",
        "    classDef secret fill:#e74c3c,color:#fff",
        "    classDef key fill:#e67e22,color:#fff",
        "    classDef network fill:#7f8c8d,color:#fff",
        "    classDef compute fill:#2980b9,color:#fff",
    ]

    for node in graph["nodes"]:
        nid = _mermaid_id(node["id"])
        lbl = node["label"].replace('"', "'")
        if node["is_crown_jewel"]:
            lbl = f"\U0001f451 {lbl}"
        if node["type"] == "internet":
            shape = f'((("{lbl}")))'
        elif node["type"] in {"secret", "key"}:
            shape = f'{{"{lbl}"}}'
        elif node["type"] == "storage":
            shape = f'[("{lbl}")]'
        else:
            shape = f'["{lbl}"]'
        lines.append(f"    {nid}{shape}")
        if node["id"] in crit_set:
            lines.append(f"    class {nid} critical")
        elif node["is_crown_jewel"]:
            lines.append(f"    class {nid} crown")
        elif node["internet_reachable"] and node["id"] != "INTERNET":
            lines.append(f"    class {nid} reachable")
        else:
            lines.append(f"    class {nid} {node['type']}")

    for edge in graph["edges"]:
        fid = _mermaid_id(edge["from"])
        tid = _mermaid_id(edge["to"])
        lbl = edge.get("label", "")
        f_crit = edge["from"] in crit_set
        t_crit = edge["to"] in crit_set
        arrow = "==>" if (f_crit and t_crit) else "-->"
        if lbl:
            lines.append(f'    {fid} {arrow}|"{lbl}"| {tid}')
        else:
            lines.append(f"    {fid} {arrow} {tid}")

    lines.append("```")
    return "\n".join(lines)


def _render_graph_html(graph: dict) -> str:
    """Return self-contained HTML+JS for an interactive force-directed attack graph."""
    import json as _json
    graph_json = _json.dumps(graph)

    return f"""<div style="margin-bottom:.5em">
  <span style="font-size:12px;color:#666">
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#1a1a2e;vertical-align:middle"></span> Internet &nbsp;
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#2980b9;vertical-align:middle"></span> Compute &nbsp;
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#6c5ce7;vertical-align:middle"></span> IAM &nbsp;
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#27ae60;vertical-align:middle"></span> Storage &nbsp;
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#e74c3c;vertical-align:middle"></span> Secret &nbsp;
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#e67e22;vertical-align:middle"></span> Key &nbsp;
    <span style="display:inline-block;width:12px;height:12px;border-radius:50%;background:#7f8c8d;vertical-align:middle"></span> Network &nbsp;
    <span style="border:2px solid #ff4444;display:inline-block;width:12px;height:12px;border-radius:50%;vertical-align:middle;background:#c0392b"></span> Critical path &nbsp;
    <span style="border:2px solid #ffd700;display:inline-block;width:12px;height:12px;border-radius:50%;vertical-align:middle;background:#6b0000"></span> Crown jewel
  </span>
</div>
<div id="ag-wrap" style="position:relative;width:100%;height:580px;background:#f8f9fa;border:1px solid #e0e0e0;border-radius:8px;overflow:hidden">
  <svg id="ag-svg" width="100%" height="100%" style="display:block;cursor:grab">
    <defs>
      <marker id="ag-arr" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
        <polygon points="0 0,8 3,0 6" fill="#aaa"/>
      </marker>
      <marker id="ag-arr-red" markerWidth="8" markerHeight="6" refX="7" refY="3" orient="auto">
        <polygon points="0 0,8 3,0 6" fill="#c0392b"/>
      </marker>
    </defs>
    <g id="ag-edges-g"></g>
    <g id="ag-nodes-g"></g>
  </svg>
  <div id="ag-sb" style="position:absolute;right:0;top:0;width:270px;height:100%;background:rgba(255,255,255,.97);border-left:1px solid #ddd;padding:14px;box-sizing:border-box;overflow-y:auto;display:none;font-size:13px">
    <button onclick="document.getElementById('ag-sb').style.display='none'"
      style="float:right;border:none;background:none;font-size:16px;cursor:pointer;color:#666">✕</button>
    <h4 id="ag-sb-title" style="margin:0 0 .6em;font-size:14px;word-break:break-all"></h4>
    <div id="ag-sb-body"></div>
  </div>
</div>
<script>
(function(){{
  var G={graph_json};
  var CRIT=new Set(G.critical_path);
  var svgEl=document.getElementById('ag-svg');
  var W=svgEl.parentElement.clientWidth||900, H=580;
  var NS='http://www.w3.org/2000/svg';
  var COLORS={{internet:'#1a1a2e',compute:'#2980b9',iam:'#6c5ce7',storage:'#27ae60',
               secret:'#e74c3c',key:'#e67e22',network:'#7f8c8d'}};
  // Compute pill dimensions for a node (resource name + type prefix, two lines)
  function pillDims(n){{
    var parts=n.label.split('.');
    var name=parts.length>1?parts[parts.length-1]:n.label;
    var typeStr=parts.length>1?parts.slice(0,-1).join('.'):'';
    var dispName=name.length>18?name.slice(0,16)+'…':name;
    var dispType=typeStr.length>24?typeStr.slice(0,22)+'…':typeStr;
    var twoLine=typeStr.length>0;
    // approximate char widths: name at 10px bold ~6.2px, type at 7.5px ~4.6px
    var pw=Math.max(dispName.length*6.2+24,twoLine?dispType.length*4.6+24:0,62);
    var ph=twoLine?36:26;
    return {{hw:pw/2,hh:ph/2,pw:pw,ph:ph,dispName:dispName,dispType:dispType,twoLine:twoLine}};
  }}
  // Clip line endpoint to the rectangular pill boundary of a node
  function clipPt(sx,sy,tx,ty,hw,hh){{
    var dx=sx-tx,dy=sy-ty,dist=Math.sqrt(dx*dx+dy*dy)||1;
    var nx=dx/dist,ny=dy/dist;
    var tc=Math.abs(nx)>1e-9?hw/Math.abs(nx):1e9;
    var tcc=Math.abs(ny)>1e-9?hh/Math.abs(ny):1e9;
    var t=Math.min(tc,tcc);
    return [tx+nx*t,ty+ny*t];
  }}
  // initialise node positions
  var TYPE_ORDER={{internet:0,compute:1,network:2,iam:3,storage:4,secret:5,key:6}};
  var nodes=G.nodes.map(function(n){{
    return Object.assign({{}},n,{{x:W/2,y:H/2,vx:0,vy:0}});
  }});
  var byId={{}};
  nodes.forEach(function(n){{byId[n.id]=n;}});
  var edges=G.edges.map(function(e){{
    return Object.assign({{}},e,{{s:byId[e.from],t:byId[e.to]}});
  }}).filter(function(e){{return e.s&&e.t;}});

  // Pill dims must be ready before tick() so collision resolution can use them
  nodes.forEach(function(n){{var d=pillDims(n);n._hw=d.hw;n._hh=d.hh;}});

  // Structured initial placement: one column per resource type, rows within each group.
  // This gives the physics a much better starting configuration than a random blob.
  (function(){{
    var groups={{}};
    nodes.forEach(function(n){{(groups[n.type]=groups[n.type]||[]).push(n);}});
    var types=Object.keys(groups).sort(function(a,b){{
      return (TYPE_ORDER[a]!==undefined?TYPE_ORDER[a]:5)-(TYPE_ORDER[b]!==undefined?TYPE_ORDER[b]:5);
    }});
    var nc=types.length||1;
    types.forEach(function(t,ti){{
      var g=groups[t];
      g.forEach(function(n,i){{
        n.x=W*(ti+0.5)/nc+(Math.random()-.5)*18;
        n.y=H*(i+0.5)/g.length+(Math.random()-.5)*10;
      }});
    }});
  }})();

  // force tick: Coulomb repulsion + Hooke spring + pill collision resolution + gravity
  var REP=4000,SL=140,SK=0.04,GV=0.008,DMP=0.82,CPAD=14;
  function tick(){{
    var i,j,a,b,dx,dy,d,f,fx,fy,nx2,ny2,hwS,hhS,sep,push;
    for(i=0;i<nodes.length;i++){{
      for(j=i+1;j<nodes.length;j++){{
        a=nodes[i];b=nodes[j];
        dx=a.x-b.x;dy=a.y-b.y;d=Math.sqrt(dx*dx+dy*dy)||1;
        f=REP/(d*d);fx=f*dx/d;fy=f*dy/d;
        a.vx+=fx;a.vy+=fy;b.vx-=fx;b.vy-=fy;
      }}
    }}
    edges.forEach(function(e){{
      dx=e.t.x-e.s.x;dy=e.t.y-e.s.y;d=Math.sqrt(dx*dx+dy*dy)||1;
      f=SK*(d-SL);fx=f*dx/d;fy=f*dy/d;
      e.s.vx+=fx;e.s.vy+=fy;e.t.vx-=fx;e.t.vy-=fy;
    }});
    // Pill collision: if two nodes are closer than their combined pill extents (+padding),
    // push them apart with a force proportional to the overlap. The minimum separation
    // in direction (nx2,ny2) is derived from the ellipse-approximated Minkowski sum of
    // the two pill bounding boxes.
    for(i=0;i<nodes.length;i++){{
      for(j=i+1;j<nodes.length;j++){{
        a=nodes[i];b=nodes[j];
        dx=a.x-b.x;dy=a.y-b.y;d=Math.sqrt(dx*dx+dy*dy)||1;
        nx2=dx/d;ny2=dy/d;
        hwS=a._hw+b._hw+CPAD;
        hhS=a._hh+b._hh+CPAD;
        sep=hwS*hhS/Math.sqrt(hhS*hhS*nx2*nx2+hwS*hwS*ny2*ny2);
        if(d<sep){{
          push=(sep-d)*0.55;
          a.vx+=push*nx2;a.vy+=push*ny2;
          b.vx-=push*nx2;b.vy-=push*ny2;
        }}
      }}
    }}
    nodes.forEach(function(n){{
      n.vx+=GV*(W/2-n.x);n.vy+=GV*(H/2-n.y);
      n.vx*=DMP;n.vy*=DMP;n.x+=n.vx;n.y+=n.vy;
      n.x=Math.max(n._hw+8,Math.min(W-n._hw-8,n.x));
      n.y=Math.max(n._hh+8,Math.min(H-n._hh-8,n.y));
    }});
  }}
  for(var _i=0;_i<400;_i++)tick();

  // SVG helpers
  function svgEl2(tag,attrs,parent){{
    var e=document.createElementNS(NS,tag);
    Object.keys(attrs).forEach(function(k){{e.setAttribute(k,attrs[k]);}});
    if(parent)parent.appendChild(e);
    return e;
  }}

  var egG=document.getElementById('ag-edges-g');
  var ndG=document.getElementById('ag-nodes-g');

  // draw edges clipped to pill boundaries so arrowheads land at the node border
  var lineEls=edges.map(function(e){{
    var isCrit=CRIT.has(e.from)&&CRIT.has(e.to);
    var p1=clipPt(e.t.x,e.t.y,e.s.x,e.s.y,e.s._hw,e.s._hh);
    var p2=clipPt(e.s.x,e.s.y,e.t.x,e.t.y,e.t._hw,e.t._hh);
    var line=svgEl2('line',{{
      x1:p1[0],y1:p1[1],x2:p2[0],y2:p2[1],
      stroke:isCrit?'#c0392b':'#bbb',
      'stroke-width':isCrit?'2.5':'1.2',
      'marker-end':isCrit?'url(#ag-arr-red)':'url(#ag-arr)'
    }},egG);
    var lbl=null;
    if(e.label){{
      lbl=svgEl2('text',{{
        x:(e.s.x+e.t.x)/2,y:(e.s.y+e.t.y)/2,
        'font-size':'8.5','fill':'#aaa','text-anchor':'middle','pointer-events':'none'
      }},egG);
      lbl.textContent=e.label;
    }}
    return {{line:line,lbl:lbl,e:e}};
  }});

  // draw nodes as pill-shaped rectangles with two-line labels
  var nodeEls=nodes.map(function(n){{
    var d=pillDims(n);
    var g=svgEl2('g',{{'transform':'translate('+n.x+','+n.y+')','style':'cursor:pointer'}},ndG);
    var fill=n.on_critical_path?'#c0392b':n.is_crown_jewel?'#6b0000':
             n.internet_reachable&&n.id!=='INTERNET'?'#d35400':
             (COLORS[n.type]||'#2980b9');
    var stroke=n.is_crown_jewel?'#ffd700':'rgba(0,0,0,.18)';
    var sw=n.is_crown_jewel?'2.5':'1';
    svgEl2('rect',{{x:-d.hw,y:-d.hh,width:d.pw,height:d.ph,rx:d.hh,
      fill:fill,stroke:stroke,'stroke-width':sw}},g);
    // primary label: resource name, bold
    var nameEl=svgEl2('text',{{'text-anchor':'middle','fill':'#fff','pointer-events':'none'}},g);
    var ns1=document.createElementNS(NS,'tspan');
    ns1.setAttribute('x','0');
    ns1.setAttribute('dy',d.twoLine?'-3':'4');
    ns1.setAttribute('font-size','10');
    ns1.setAttribute('font-weight','600');
    ns1.textContent=d.dispName;
    nameEl.appendChild(ns1);
    if(d.twoLine){{
      var ns2=document.createElementNS(NS,'tspan');
      ns2.setAttribute('x','0');
      ns2.setAttribute('dy','13');
      ns2.setAttribute('font-size','7.5');
      ns2.setAttribute('fill','rgba(255,255,255,0.62)');
      ns2.textContent=d.dispType;
      nameEl.appendChild(ns2);
    }}
    g.addEventListener('click',function(){{showSb(n);}});
    return {{g:g,n:n}};
  }});

  function redraw(){{
    lineEls.forEach(function(el){{
      var p1=clipPt(el.e.t.x,el.e.t.y,el.e.s.x,el.e.s.y,el.e.s._hw,el.e.s._hh);
      var p2=clipPt(el.e.s.x,el.e.s.y,el.e.t.x,el.e.t.y,el.e.t._hw,el.e.t._hh);
      el.line.setAttribute('x1',p1[0]);el.line.setAttribute('y1',p1[1]);
      el.line.setAttribute('x2',p2[0]);el.line.setAttribute('y2',p2[1]);
      if(el.lbl){{
        el.lbl.setAttribute('x',(el.e.s.x+el.e.t.x)/2);
        el.lbl.setAttribute('y',(el.e.s.y+el.e.t.y)/2);
      }}
    }});
    nodeEls.forEach(function(el){{
      el.g.setAttribute('transform','translate('+el.n.x+','+el.n.y+')');
    }});
  }}

  // animation cool-down
  var alpha=1;
  function animate(){{
    if(alpha>0.005){{
      tick();tick();tick();redraw();
      alpha*=0.96;
      requestAnimationFrame(animate);
    }}
  }}
  animate();

  // drag
  var dragging=null,dragOX=0,dragOY=0;
  svgEl.addEventListener('mousedown',function(ev){{
    var rect=svgEl.getBoundingClientRect();
    var mx=ev.clientX-rect.left,my=ev.clientY-rect.top;
    nodes.forEach(function(n){{
      if(Math.abs(n.x-mx)<n._hw+4&&Math.abs(n.y-my)<n._hh+4){{
        dragging=n;dragOX=mx-n.x;dragOY=my-n.y;
      }}
    }});
    if(dragging)ev.preventDefault();
  }});
  svgEl.addEventListener('mousemove',function(ev){{
    if(!dragging)return;
    var rect=svgEl.getBoundingClientRect();
    dragging.x=ev.clientX-rect.left-dragOX;
    dragging.y=ev.clientY-rect.top-dragOY;
    dragging.vx=0;dragging.vy=0;
    redraw();
  }});
  svgEl.addEventListener('mouseup',function(){{dragging=null;}});
  svgEl.addEventListener('mouseleave',function(){{dragging=null;}});

  // sidebar
  function showSb(n){{
    document.getElementById('ag-sb-title').textContent=n.label;
    var html='<b>Type:</b> '+n.type+'<br>';
    if(n.file)html+='<b>File:</b> <code style="font-size:11px">'+n.file+'</code>:'+n.line+'<br>';
    if(n.is_crown_jewel)html+='<span style="color:#8b0000;font-weight:600">&#128081; Crown Jewel</span><br>';
    if(n.on_critical_path)html+='<span style="color:#c0392b;font-weight:600">&#9888; On Critical Attack Path</span><br>';
    if(n.internet_reachable&&n.id!=='INTERNET')html+='<span style="color:#d35400">&#127760; Internet-reachable</span><br>';
    if(n.findings&&n.findings.length){{
      html+='<br><b>Findings:</b><ul style="margin:.3em 0;padding-left:1.2em">';
      n.findings.forEach(function(f){{html+='<li><code>'+f+'</code></li>';}});
      html+='</ul>';
    }}else{{html+='<br><i style="color:#999">No findings on this resource</i>';}}
    document.getElementById('ag-sb-body').innerHTML=html;
    document.getElementById('ag-sb').style.display='block';
  }}
}})();
</script>"""
