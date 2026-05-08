#!/usr/bin/env python3
"""Auto-scaffold `fixtures/<RULE-ID>_clean/main.tf` from each rule's `fix_hcl`.

A clean fixture is a positive control: a correctly-configured Terraform file
that the rule must NOT fire on. For `resource_arg` and `resource_missing_arg`
rules, the catalogue's `fix_hcl` field already encodes the correct shape — we
just need to wrap it in a directory and verify the rule stays silent.

Skips rules whose `fix_hcl` is not stand-alone HCL (e.g. policy-document
fragments, grep-pattern snippets, dependency-based resources that need
unrelated context to scan cleanly).

Run:  python3 scripts/gen_clean_fixtures.py [--write]
Without --write the script previews what it would create.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CATALOG_DIR = REPO_ROOT / "catalog"
FIXTURES_DIR = REPO_ROOT / "fixtures"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from detect import load_yaml  # type: ignore  # noqa: E402

# Pattern kinds that scan a single resource and whose fix_hcl is a usable
# stand-alone Terraform block.
SCANNABLE_KINDS = {
    "resource_arg",
    "resource_missing_arg",
    "resource_absent",
    "resource_present",
    "resource_body_contains",
    "hcl_attr",
}

# Pattern kinds whose fix_hcl is not a stand-alone fixture (snippet, doc
# fragment, or whole-corpus shape that needs hand-curated context).
NON_SCANNABLE_KINDS = {
    "grep",
    "graph_check",
    "intent_gap",
    "firewall_open_port",
    "iam_policy_analysis",
    "providers_version_missing",
    "submodule_version_missing",
    "variable_unused",
    "variable_type",
    "variable_missing_validation",
    "variable_missing_description",
    "tfstate_in_repo",
    "templatefile_sensitive_leak",
    "remote_state_present",
    "removed_block_present",
}


def is_standalone_tf(fix_hcl: str) -> bool:
    """Heuristic: must start with `resource "` or `data "` or `module "`.

    Anything else (a `statement { ... }` policy fragment, a tfvars line,
    a `terraform { ... }` block fragment) cannot be parsed in isolation.
    """
    if not fix_hcl or not fix_hcl.strip():
        return False
    head = fix_hcl.lstrip().split("\n", 1)[0]
    return bool(re.match(r'^(resource|data|module)\s+"', head))


def rule_is_eligible(entry: dict) -> tuple[bool, str]:
    if entry.get("status") in ("deprecated", "stub"):
        return False, "status not active"
    fix_hcl = entry.get("fix_hcl") or ""
    if not fix_hcl.strip():
        return False, "no fix_hcl"
    kinds = {p.get("kind") for p in (entry.get("patterns") or [])}
    if not kinds & SCANNABLE_KINDS:
        return False, f"non-scannable kinds: {sorted(kinds)}"
    if not is_standalone_tf(fix_hcl):
        return False, "fix_hcl is not a stand-alone resource/data/module block"
    return True, ""


def render_fixture(rule_id: str, title: str, fix_hcl: str) -> str:
    return (
        f"# Auto-generated clean fixture for {rule_id}.\n"
        f"# {title}\n"
        f"# This is a CORRECT configuration; {rule_id} must NOT fire here.\n"
        f"# Edit by hand if the rule needs additional context.\n"
        f"\n"
        f"{fix_hcl.rstrip()}\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--write",
        action="store_true",
        help="Actually create the fixture files (default: dry-run preview).",
    )
    args = ap.parse_args()

    created = 0
    skipped: list[tuple[str, str]] = []
    already: list[str] = []

    for yml in sorted(CATALOG_DIR.glob("*.yaml")):
        try:
            entry = load_yaml(yml.read_text())
        except Exception as e:
            print(f"  WARN: cannot parse {yml.name}: {e}", file=sys.stderr)
            continue
        rule_id = entry.get("id") or yml.stem
        clean_dir = FIXTURES_DIR / f"{rule_id}_clean"
        if clean_dir.exists():
            already.append(rule_id)
            continue
        ok, reason = rule_is_eligible(entry)
        if not ok:
            skipped.append((rule_id, reason))
            continue
        body = render_fixture(rule_id, entry.get("title", ""), entry["fix_hcl"])
        if args.write:
            clean_dir.mkdir(parents=True, exist_ok=True)
            (clean_dir / "main.tf").write_text(body)
        created += 1
        if not args.write:
            print(f"  WOULD CREATE: {clean_dir.relative_to(REPO_ROOT)}")

    print()
    print(f"Already exist:        {len(already)}")
    print(f"To create:            {created}")
    print(f"Skipped:              {len(skipped)}")
    if not args.write:
        print()
        print("Re-run with --write to materialise the fixtures.")
    if skipped and "-v" in sys.argv:
        print()
        print("Skipped reasons:")
        for rid, reason in skipped:
            print(f"  {rid}: {reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
