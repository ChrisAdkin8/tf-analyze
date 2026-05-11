"""Catalogue load + validate — fifth seam in the detect.py modularisation.

This module owns the catalogue's lifecycle: parsing the YAML files,
validating their schema, and loading active entries (skipping stubs
and deprecated rules) into the dict-list that detect.py and every
external caller consumes.

Scope rule — same as `_versions.py`, `_scoring.py`, `_hcl.py`:

  * Pure functions and immutable validation constants only.
  * No engine state. The `_USE_HCL2` toggle, the var-resolution
    layer, the runtime catalogue index — all stay in `detect.py`.
  * I/O is allowed when it's the gateway between the filesystem and
    a structured Python value (file → YAML → dict, same shape as
    `_hcl._read_normalized`).

Public surface
--------------

Constants (validation domain)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* ``_VALID_SECTIONS`` — the catalogue section names a rule may declare.
* ``_VALID_URGENCIES`` — the urgency tiers a rule's ``default_urgency``
  may declare. Includes ``INFO`` (zero score weight per
  ``_scoring._RISK_WEIGHTS``).
* ``_VALID_BLAST_RADIUS`` — the blast-radius keywords a rule may declare.
* ``_VALID_STATUS`` — the lifecycle status values (``active``,
  ``deprecated``, ``stub``, ``experimental``).
* ``_VALID_FIX_DISRUPTIONS`` — the ``fix_disruption`` values a rule may
  declare; HTML/SARIF renderers join on these so the validator must
  reject typos at load time.
* ``_REQUIRED_FIELDS`` — tuple of field names every catalogue entry
  must populate.

Functions
~~~~~~~~~

* ``load_yaml(text)`` — minimal stdlib YAML parser scoped to the
  catalogue's shallow structure. Avoids the PyYAML dependency on the
  user's PATH; matches a few specific shapes (block scalars with
  ``|``, list items with inline mappings, top-level key-value pairs).
* ``validate_catalog_entry(data, source)`` — schema validation. Returns
  a list of human-readable error strings (empty = valid). Includes
  CWE / D3FEND / OWASP-IaC shape checks so SARIF output stays
  consumable by downstream taxonomies.
* ``_load_project_config(target)`` — parse a workspace's
  ``.tf-analyze.yaml`` if present. Returns ``{}`` on missing file or
  any parse error (with a stderr warning).
* ``load_catalog(catalog_dir, include_stubs=False, strict=False,
  extra_rules_dir=None)`` — load every ``*.yaml`` in ``catalog_dir``,
  validate, and return active entries. ``strict=True`` aborts via
  ``sys.exit(2)`` on any error; default is permissive so a stale
  catalogue entry doesn't break every CI run. ``extra_rules_dir``
  pulls in ``CUSTOM-*`` rules from a workspace directory.

Why this seam pays off
----------------------

* `load_yaml` is consumed not just by detect.py but by
  `scripts/gen_rule_docs.py`, `scripts/self_test.py`,
  `scripts/check_attack_drift.py`, `scripts/test_schema.py`, and
  several test helpers — all of which currently import via the
  `detect` namespace. Those callers can migrate to
  `from _catalog import load_yaml` at their leisure; the re-export
  shim in `detect.py` keeps the existing path working in the meantime.
* `validate_catalog_entry` is the single source of truth for what a
  catalogue rule must look like. Pulling it out of the monolith makes
  it cheap to add new optional fields (`nist_csf:`, `slsa:`, etc.) in
  R30.1 without diff-conflict pressure across the whole engine.

Names are preserved; ``detect.py`` re-imports them all under their
original identifiers so existing call sites and tests need no
migration.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from _hcl import _parse_scalar


# ---- Validation domain --------------------------------------------------

_VALID_SECTIONS = {
    "security", "robustness", "dry", "style", "simplicity",
    "ops", "cicd", "module", "module-reuse", "stack", "verification",
}
_VALID_URGENCIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_VALID_BLAST_RADIUS = {
    "single-resource", "module", "environment", "infrastructure-wide",
}
_VALID_STATUS = {"active", "deprecated", "stub", "experimental"}
_VALID_FIX_DISRUPTIONS = {"none", "plan_required", "forces_replacement"}
_REQUIRED_FIELDS = (
    "id", "title", "section", "default_urgency", "blast_radius",
    "patterns", "recommendation", "verification",
)


# ---- Minimal YAML loader -----------------------------------------------
# Avoid PyYAML dependency. Catalogue YAML is shallow and well-formed.

def load_yaml(text: str) -> dict:
    """Tiny YAML parser for the catalogue subset we control."""
    root: dict = {}
    stack: list[tuple[int, object]] = [(-1, root)]
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw = lines[i]
        # Strip comments outside of strings (catalogue values don't contain `#`)
        line = raw.split("#", 1)[0] if not raw.lstrip().startswith("- ") else raw
        if not line.strip():
            i += 1
            continue
        indent = len(line) - len(line.lstrip())
        # Pop stack to current depth.
        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1]
        stripped = line.strip()
        # Block scalar (`key: |` followed by indented body)
        if re.match(r"^[A-Za-z_][\w-]*:\s*\|\s*$", stripped):
            key = stripped.split(":", 1)[0]
            i += 1
            body_lines = []
            base_indent = None
            while i < len(lines):
                bl = lines[i]
                if not bl.strip():
                    body_lines.append("")
                    i += 1
                    continue
                bi = len(bl) - len(bl.lstrip())
                if base_indent is None:
                    base_indent = bi
                if bi < base_indent:
                    break
                body_lines.append(bl[base_indent:])
                i += 1
            if isinstance(parent, dict):
                parent[key] = "\n".join(body_lines).rstrip() + "\n"
            continue
        # List item
        if stripped.startswith("- "):
            value = stripped[2:].strip()
            if isinstance(parent, list):
                if ":" in value and not value.startswith("'") and not value.startswith('"'):
                    # Inline mapping start: `- key: val`
                    item: dict = {}
                    k, v = value.split(":", 1)
                    item[k.strip()] = _parse_scalar(v.strip())
                    parent.append(item)
                    stack.append((indent, item))
                else:
                    parent.append(_parse_scalar(value))
            i += 1
            continue
        # `key:` (mapping or container)
        if ":" in stripped:
            key, _, rest = stripped.partition(":")
            key = key.strip()
            rest = rest.strip()
            if rest == "":
                # Container — peek at next non-empty line to decide list vs dict.
                # Skip blank lines AND comment-only lines during peek.
                j = i + 1
                while j < len(lines):
                    peeked = lines[j].strip()
                    if peeked == "" or peeked.startswith("#"):
                        j += 1
                        continue
                    break
                if j < len(lines) and lines[j].lstrip().startswith("- "):
                    container: object = []
                else:
                    container = {}
                if isinstance(parent, dict):
                    parent[key] = container
                stack.append((indent, container))
            else:
                if isinstance(parent, dict):
                    parent[key] = _parse_scalar(rest)
            i += 1
            continue
        i += 1
    return root


# ---- Schema validation --------------------------------------------------

def validate_catalog_entry(data: dict, source: str) -> list[str]:
    """Return a list of human-readable schema errors. Empty list = valid.

    `source` is the catalogue YAML file path used in error messages.
    """
    errs: list[str] = []
    if not isinstance(data, dict):
        return [f"{source}: top-level YAML is not a mapping"]
    for f in _REQUIRED_FIELDS:
        if data.get(f) in (None, "", []):
            errs.append(f"{source}: missing required field '{f}'")
    section = data.get("section")
    if section is not None and section not in _VALID_SECTIONS:
        errs.append(
            f"{source}: section '{section}' not in {sorted(_VALID_SECTIONS)}"
        )
    urgency = data.get("default_urgency")
    if urgency is not None and urgency not in _VALID_URGENCIES:
        errs.append(
            f"{source}: default_urgency '{urgency}' not in "
            f"{sorted(_VALID_URGENCIES)}"
        )
    blast = data.get("blast_radius")
    if blast is not None and blast not in _VALID_BLAST_RADIUS:
        errs.append(
            f"{source}: blast_radius '{blast}' not in "
            f"{sorted(_VALID_BLAST_RADIUS)}"
        )
    status = data.get("status")
    if status is not None and status not in _VALID_STATUS:
        errs.append(
            f"{source}: status '{status}' not in {sorted(_VALID_STATUS)}"
        )
    pats = data.get("patterns")
    if isinstance(pats, list):
        for i, p in enumerate(pats):
            if not isinstance(p, dict):
                errs.append(f"{source}: patterns[{i}] is not a mapping")
                continue
            if not p.get("kind"):
                errs.append(f"{source}: patterns[{i}] missing 'kind'")
    elif pats is not None:
        errs.append(f"{source}: 'patterns' must be a list")
    narrative = data.get("narrative")
    if narrative is not None and not isinstance(narrative, str):
        errs.append(f"{source}: 'narrative' must be a string if present")
    test_template = data.get("test_template")
    if test_template is not None and not isinstance(test_template, str):
        errs.append(f"{source}: 'test_template' must be a string if present")
    fix_hcl = data.get("fix_hcl")
    if fix_hcl is not None and not isinstance(fix_hcl, str):
        errs.append(f"{source}: 'fix_hcl' must be a string if present")
    # `fix_hcl_minimal` (R30.10): preferred by `--apply-fixes` when present.
    # Stripped-down form of `fix_hcl` — just the attribute or nested block
    # the patcher needs to insert/replace, with no surrounding resource
    # declaration. Falls back to `fix_hcl` when absent.
    fix_hcl_minimal = data.get("fix_hcl_minimal")
    if fix_hcl_minimal is not None and not isinstance(fix_hcl_minimal, str):
        errs.append(f"{source}: 'fix_hcl_minimal' must be a string if present")
    fix_disruption = data.get("fix_disruption")
    if fix_disruption is not None and fix_disruption not in _VALID_FIX_DISRUPTIONS:
        errs.append(
            f"{source}: fix_disruption '{fix_disruption}' not in "
            f"{sorted(_VALID_FIX_DISRUPTIONS)}"
        )
    fix_disruption_note = data.get("fix_disruption_note")
    if fix_disruption_note is not None and not isinstance(fix_disruption_note, str):
        errs.append(f"{source}: 'fix_disruption_note' must be a string if present")
    pci_dss = data.get("pci_dss")
    if pci_dss is not None:
        if not isinstance(pci_dss, list) or not all(isinstance(x, str) for x in pci_dss):
            errs.append(f"{source}: 'pci_dss' must be a list of strings if present")
    soc2_cc = data.get("soc2_cc")
    if soc2_cc is not None:
        if not isinstance(soc2_cc, list) or not all(isinstance(x, str) for x in soc2_cc):
            errs.append(f"{source}: 'soc2_cc' must be a list of strings if present")
    # CWE — Common Weakness Enumeration. Items are bare numeric IDs as
    # strings (e.g. "CWE-732") so SARIF taxonomies can emit them
    # verbatim. Validate the shape so typos (`cwe-732`, `732`,
    # `CWE 732`) fail catalogue load rather than silently producing
    # broken SARIF output.
    cwe = data.get("cwe")
    if cwe is not None:
        if not isinstance(cwe, list) or not all(isinstance(x, str) for x in cwe):
            errs.append(f"{source}: 'cwe' must be a list of strings if present")
        else:
            for item in cwe:
                if not re.fullmatch(r"CWE-\d+", item):
                    errs.append(
                        f"{source}: cwe item {item!r} must match the form 'CWE-<digits>'"
                    )
    # D3FEND — defensive techniques (the ATT&CK counterpart). Items
    # are D3FEND IDs of the form D3-<token> (e.g. D3-MFA, D3-EAR).
    # No comparable IaC scanner emits these today; the field is a
    # deliberate differentiator.
    d3fend = data.get("d3fend")
    if d3fend is not None:
        if not isinstance(d3fend, list) or not all(isinstance(x, str) for x in d3fend):
            errs.append(f"{source}: 'd3fend' must be a list of strings if present")
        else:
            for item in d3fend:
                if not re.fullmatch(r"D3-[A-Z]{2,8}", item):
                    errs.append(
                        f"{source}: d3fend item {item!r} must match the form 'D3-<2-8 uppercase letters>'"
                    )
    # OWASP IaC Security Cheat Sheet mapping. Items are textual labels of
    # the form `Develop and Distribute / Secrets Detection`. The cheat
    # sheet's three sections — `Develop and Distribute`, `Deploy`,
    # `Runtime` — appear before the `/`. Validate the shape so a typo
    # (`Devleop and Distribute / …`) fails CI rather than silently
    # creating a singleton column in the compliance output.
    owasp_iac = data.get("owasp_iac")
    if owasp_iac is not None:
        if not isinstance(owasp_iac, list) or not all(isinstance(x, str) for x in owasp_iac):
            errs.append(f"{source}: 'owasp_iac' must be a list of strings if present")
        else:
            valid_sections = {"Develop and Distribute", "Deploy", "Runtime"}
            for item in owasp_iac:
                if " / " not in item:
                    errs.append(
                        f"{source}: owasp_iac item {item!r} must be of the "
                        f"form '<Section> / <Item label>' (sections: "
                        f"{sorted(valid_sections)})"
                    )
                    continue
                section = item.split(" / ", 1)[0]
                if section not in valid_sections:
                    errs.append(
                        f"{source}: owasp_iac item {item!r} has unknown "
                        f"section {section!r}; expected one of "
                        f"{sorted(valid_sections)}"
                    )
    # ---- R30.1 multi-framework taxonomy fields ----
    # Five new optional list-of-string fields with per-field regex
    # validators. Catalogue YAMLs add the fields opportunistically;
    # `_compliance_gap_report` dispatches against them when
    # `--compliance-framework <name>` selects the corresponding mode.
    # First-pass shape rules:
    #   * nist_csf — `<Function>.<Category>-<sub#>`, e.g. PR.AC-1.
    #     Functions: GV, ID, PR, DE, RS, RC.
    #   * nist_800_53 — `<Family>-<n>` or `<Family>-<n>(<enh>)`, e.g.
    #     AC-2(7), SC-12, IA-5(1). Family is 2 uppercase letters.
    #   * csa_ccm — `<Domain>-<nn>`, e.g. IAM-09 or DSI-04. Domain is
    #     2-4 uppercase letters.
    #   * slsa — bare keyword: L1, L2, L3, L4, source, build, deps.
    #   * owasp (namespaced) — items use category-prefix form so a
    #     single field can serve 5 OWASP sub-modes. Accepted prefixes:
    #     A01..A10 (Top 10), API01..API10 (API Top 10), CICD-SEC-1..10
    #     (OWASP CICD), LLM01..LLM10 (LLM Top 10), K01..K10 (Kubernetes
    #     Top 10), ASVS-V<major>.<minor>.<sub> (ASVS controls).
    nist_csf = data.get("nist_csf")
    if nist_csf is not None:
        if not isinstance(nist_csf, list) or not all(isinstance(x, str) for x in nist_csf):
            errs.append(f"{source}: 'nist_csf' must be a list of strings if present")
        else:
            for item in nist_csf:
                if not re.fullmatch(r"(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d+", item):
                    errs.append(
                        f"{source}: nist_csf item {item!r} must match the form "
                        f"'<Function>.<Category>-<sub>' where Function ∈ "
                        f"{{GV,ID,PR,DE,RS,RC}} (e.g. PR.AC-1, DE.CM-1)"
                    )
    nist_800_53 = data.get("nist_800_53")
    if nist_800_53 is not None:
        if not isinstance(nist_800_53, list) or not all(isinstance(x, str) for x in nist_800_53):
            errs.append(f"{source}: 'nist_800_53' must be a list of strings if present")
        else:
            for item in nist_800_53:
                if not re.fullmatch(r"[A-Z]{2}-\d+(?:\(\d+\))?", item):
                    errs.append(
                        f"{source}: nist_800_53 item {item!r} must match the form "
                        f"'<Family>-<num>' or '<Family>-<num>(<enh>)' "
                        f"(e.g. AC-2, AC-2(7), SC-12)"
                    )
    csa_ccm = data.get("csa_ccm")
    if csa_ccm is not None:
        if not isinstance(csa_ccm, list) or not all(isinstance(x, str) for x in csa_ccm):
            errs.append(f"{source}: 'csa_ccm' must be a list of strings if present")
        else:
            for item in csa_ccm:
                if not re.fullmatch(r"[A-Z]{2,4}-\d{2}", item):
                    errs.append(
                        f"{source}: csa_ccm item {item!r} must match the form "
                        f"'<Domain>-<NN>' where Domain is 2-4 uppercase letters "
                        f"(e.g. IAM-09, DSI-04)"
                    )
    slsa = data.get("slsa")
    if slsa is not None:
        if not isinstance(slsa, list) or not all(isinstance(x, str) for x in slsa):
            errs.append(f"{source}: 'slsa' must be a list of strings if present")
        else:
            for item in slsa:
                if not re.fullmatch(r"L[1-4]|source|build|deps", item):
                    errs.append(
                        f"{source}: slsa item {item!r} must be one of "
                        f"L1..L4, 'source', 'build', or 'deps'"
                    )
    owasp = data.get("owasp")
    if owasp is not None:
        if not isinstance(owasp, list) or not all(isinstance(x, str) for x in owasp):
            errs.append(f"{source}: 'owasp' must be a list of strings if present")
        else:
            # Namespaced — first match wins. ASVS items are versioned.
            _OWASP_ITEM_RE = re.compile(
                r"^(?:"
                r"A(?:0[1-9]|10)"                         # A01..A10
                r"|API(?:0[1-9]|10)"                       # API01..API10
                r"|CICD-SEC-(?:[1-9]|10)"                  # CICD-SEC-1..10
                r"|LLM(?:0[1-9]|10)"                       # LLM01..LLM10
                r"|K(?:0[1-9]|10)"                         # K01..K10
                r"|ASVS-V\d+\.\d+\.\d+"                    # ASVS-V<m>.<n>.<sub>
                r")$"
            )
            for item in owasp:
                if not _OWASP_ITEM_RE.match(item):
                    errs.append(
                        f"{source}: owasp item {item!r} must match one of "
                        f"A01..A10, API01..API10, CICD-SEC-1..10, "
                        f"LLM01..LLM10, K01..K10, or ASVS-V<m>.<n>.<s>"
                    )
    fid = data.get("id")
    fname = Path(source).stem
    if fid and fid != fname:
        errs.append(
            f"{source}: id '{fid}' does not match filename stem '{fname}'"
        )
    fingerprint = data.get("fingerprint")
    if fingerprint is not None:
        if not isinstance(fingerprint, dict):
            errs.append(f"{source}: 'fingerprint' must be a mapping if present")
        else:
            req = fingerprint.get("required")
            if not isinstance(req, list) or not req:
                errs.append(f"{source}: fingerprint.required must be a non-empty list")
            else:
                for i, r in enumerate(req):
                    if not isinstance(r, dict) or not r.get("type"):
                        errs.append(f"{source}: fingerprint.required[{i}] needs 'type'")
            sup = fingerprint.get("supporting")
            if sup is not None:
                if not isinstance(sup, dict):
                    errs.append(f"{source}: fingerprint.supporting must be a mapping")
                elif sup.get("types") is not None and not isinstance(sup.get("types"), list):
                    errs.append(f"{source}: fingerprint.supporting.types must be a list")
    return errs


# ---- Project config + catalogue load ------------------------------------

def _load_project_config(target: Path) -> dict:
    """Read .tf-analyze.yaml from target directory.

    Returns {} on missing file or any parse error (with a warning to stderr).
    """
    cfg_path = target / ".tf-analyze.yaml"
    if not cfg_path.exists():
        return {}
    try:
        return load_yaml(cfg_path.read_text()) or {}
    except Exception as e:
        print(f"WARN: cannot parse {cfg_path}: {e}", file=sys.stderr)
        return {}


def load_catalog(
    catalog_dir: Path,
    include_stubs: bool = False,
    strict: bool = False,
    extra_rules_dir: Path | None = None,
) -> list[dict]:
    """Load catalogue YAMLs with schema validation.

    Stubs (status: stub) are excluded by default — their patterns may be
    incomplete and would produce false positives in normal scans. Pass
    include_stubs=True only when validating that the stub itself parses.

    Validation errors print to stderr as 'ERROR:' lines and the offending
    entry is skipped. With strict=True, a single error aborts the load
    via sys.exit(2). Default is non-strict so a stale catalogue entry
    doesn't break every CI run.

    If extra_rules_dir is set and is a directory, custom rules are loaded
    from *.yaml files there. Custom rule IDs must start with 'CUSTOM-'.
    """
    entries: list[dict] = []
    error_count = 0
    for yml in sorted(catalog_dir.glob("*.yaml")):
        try:
            data = load_yaml(yml.read_text())
        except Exception as e:
            print(f"ERROR: cannot parse {yml}: {e}", file=sys.stderr)
            error_count += 1
            continue
        # Schema validation. Skip the entry if any required field is missing
        # — the alternative (loading partial entries) lets bugs hide.
        errs = validate_catalog_entry(data, str(yml))
        if errs:
            for msg in errs:
                print(f"ERROR: {msg}", file=sys.stderr)
            error_count += len(errs)
            continue
        status = data.get("status", "active")
        if status == "deprecated":
            continue
        if status == "stub" and not include_stubs:
            continue
        entries.append(data)
    if strict and error_count:
        print(
            f"FATAL: {error_count} catalogue error(s); aborting (--strict-catalog)",
            file=sys.stderr,
        )
        sys.exit(2)

    # Load custom rules from extra_rules_dir if provided
    if extra_rules_dir is not None and Path(extra_rules_dir).is_dir():
        for yml in sorted(Path(extra_rules_dir).glob("*.yaml")):
            try:
                data = load_yaml(yml.read_text())
            except Exception as e:
                print(f"ERROR: cannot parse custom rule {yml}: {e}", file=sys.stderr)
                continue
            rule_id = data.get("id", "")
            if not str(rule_id).startswith("CUSTOM-"):
                print(
                    f"WARN: custom rule {yml} has id '{rule_id}' which does not "
                    f"start with 'CUSTOM-'; skipping",
                    file=sys.stderr,
                )
                continue
            errs = validate_catalog_entry(data, str(yml))
            if errs:
                for msg in errs:
                    print(f"ERROR: {msg}", file=sys.stderr)
                continue
            status = data.get("status", "active")
            if status == "deprecated":
                continue
            if status == "stub" and not include_stubs:
                continue
            entries.append(data)

    return entries
