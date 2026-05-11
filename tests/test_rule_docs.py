"""Contract tests for the per-rule documentation site at ``docs/rules/``.

Locks the relationship between the catalogue YAML and the generated
Markdown pages — every active rule has a doc, every doc points at a
real rule, and the generator is deterministic (re-running produces
byte-identical output).

Also asserts that the engine's link-target constants (`RULE_DOCS_URL_BASE`,
`SARIF_HELP_URI_BASE`) point at the doc site, so changing one without
the other is a test-fail tripwire.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
CATALOG_DIR = REPO_ROOT / "catalog"
DOCS_RULES_DIR = REPO_ROOT / "docs" / "rules"
GEN_SCRIPT = REPO_ROOT / "scripts" / "gen_rule_docs.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import detect  # noqa: E402
from detect import load_yaml  # noqa: E402


def _active_rule_ids() -> set[str]:
    out: set[str] = set()
    for yml in sorted(CATALOG_DIR.glob("*.yaml")):
        try:
            data = load_yaml(yml.read_text())
        except Exception:
            continue
        if data.get("status") == "deprecated":
            continue
        if data.get("id"):
            out.add(data["id"])
    return out


# ---------------------------------------------------------------------------
# Coverage: catalogue ↔ docs
# ---------------------------------------------------------------------------


class TestRuleDocCoverage:
    def test_every_active_rule_has_a_docs_page(self):
        rule_ids = _active_rule_ids()
        missing = sorted(
            rid for rid in rule_ids
            if not (DOCS_RULES_DIR / f"{rid}.md").exists()
        )
        assert not missing, (
            f"{len(missing)} active rule(s) missing docs/rules/<id>.md. "
            f"Run `python3 scripts/gen_rule_docs.py`. First few: "
            f"{missing[:5]}"
        )

    def test_every_docs_page_corresponds_to_a_rule(self):
        # Stale doc files (rule was renamed/deleted) must be removed.
        rule_ids = _active_rule_ids()
        orphans = []
        for md in DOCS_RULES_DIR.glob("*.md"):
            if md.stem == "index":
                continue
            if md.stem not in rule_ids:
                orphans.append(md.stem)
        assert not orphans, (
            f"{len(orphans)} doc page(s) have no corresponding rule "
            f"(catalogue entry was renamed or deleted): {orphans[:5]}"
        )

    def test_index_page_exists(self):
        assert (DOCS_RULES_DIR / "index.md").exists(), (
            "docs/rules/index.md is missing — it's the public landing "
            "page for the rule reference. Run `gen_rule_docs.py`."
        )


# ---------------------------------------------------------------------------
# Generator determinism: re-running on the current catalogue must
# produce byte-identical output, otherwise the docs are drift-prone.
# ---------------------------------------------------------------------------


class TestSEOAndDeepLinks:
    """Lock the C6 SEO + deep-link enrichments shipped on the per-rule
    docs pages: front matter, Schema.org JSON-LD, the Open-in-VS-Code
    button, and the (config-gated) giscus block. Without these tests
    a future generator regression could silently strip Rich-Results
    eligibility — the kind of bug that's invisible until a search-
    console alert fires weeks later."""

    SAMPLE = "SEC-AWS-IAM-001"

    @pytest.fixture(scope="class")
    def page(self) -> str:
        return (DOCS_RULES_DIR / f"{self.SAMPLE}.md").read_text()

    def test_front_matter_present(self, page: str) -> None:
        # jekyll-seo-tag reads `title:` and `description:` from front matter.
        assert page.startswith("---\n")
        head = page.split("---\n", 2)[1]
        assert "title:" in head
        assert "description:" in head
        assert "keywords:" in head

    def test_front_matter_description_within_seo_length(self, page: str) -> None:
        # Google truncates the snippet around 160 chars. The generator
        # caps at 158 + ellipsis; this guards against accidental drift.
        head = page.split("---\n", 2)[1]
        for line in head.splitlines():
            if line.startswith("description:"):
                desc = line.split(":", 1)[1].strip().strip('"')
                assert len(desc) <= 160, (
                    f"description is {len(desc)} chars (>160): {desc[:80]}…"
                )
                break

    def test_jsonld_techarticle_present(self, page: str) -> None:
        import json as _json
        marker = '<script type="application/ld+json">'
        assert marker in page, "JSON-LD <script> block missing"
        # Extract and parse the JSON payload.
        start = page.index(marker) + len(marker)
        end = page.index("</script>", start)
        payload = _json.loads(page[start:end].strip())
        assert payload["@type"] == "TechArticle"
        assert payload["@context"] == "https://schema.org"
        # Required fields for Google's TechArticle Rich Results.
        for required in ("headline", "description", "url",
                         "mainEntityOfPage", "author", "publisher"):
            assert required in payload, f"JSON-LD missing required field {required!r}"
        assert self.SAMPLE in payload["headline"]
        assert payload["url"].startswith("https://chrisadkin8.github.io/tf-analyze/rules/")

    def test_open_in_vscode_button_present(self, page: str) -> None:
        # The `vscode://` URI is the click target the extension's
        # registerUriHandler routes back to RuleExplainerPanel.
        assert f"vscode://tfanalyze.tf-analyze/rule/{self.SAMPLE}" in page
        assert "Open in VS Code" in page

    def test_giscus_block_is_liquid_gated(self, page: str) -> None:
        # The block must be wrapped in `{% if site.giscus.enabled %}`
        # so the script tag never escapes when comments are off.
        assert "{% if site.giscus.enabled %}" in page
        assert "{% endif %}" in page
        # giscus client URL only present inside the gated block.
        assert "giscus.app/client.js" in page

    def test_jsonld_passes_schema_org_validator(self, page: str) -> None:
        """Validate the JSON-LD payload against the structural rules a
        Schema.org-aware parser (Google Rich Results, schema.org's own
        validator) enforces. We don't pull a heavy parser in (`pyld` /
        `jsonschema`) — instead we encode the constraints inline so a
        regression in the generator is caught without a dependency
        burden.

        Catches: tampered `@type`, malformed URLs, dropped required
        fields, wrong nesting on `mainEntityOfPage`, non-string keywords.
        """
        import json as _json
        from urllib.parse import urlparse

        marker = '<script type="application/ld+json">'
        start = page.index(marker) + len(marker)
        end = page.index("</script>", start)
        payload = _json.loads(page[start:end].strip())

        # @context / @type — controlled values per Schema.org TechArticle.
        assert payload["@context"] == "https://schema.org", (
            f"@context must be 'https://schema.org', got {payload['@context']!r}"
        )
        assert payload["@type"] == "TechArticle", (
            f"@type must be 'TechArticle', got {payload['@type']!r}"
        )

        # Required fields per Google TechArticle Rich Results guide.
        for field in ("headline", "description", "url", "mainEntityOfPage",
                      "author", "publisher"):
            assert field in payload, f"missing required field {field!r}"
            assert payload[field], f"required field {field!r} is empty"

        # URL fields must be absolute https URLs.
        def _is_https_absolute(url: str) -> bool:
            p = urlparse(url)
            return p.scheme == "https" and bool(p.netloc)

        assert _is_https_absolute(payload["url"]), (
            f"url is not an absolute https URL: {payload['url']!r}"
        )

        # mainEntityOfPage must be a {@type: WebPage, @id: <url>} object,
        # not a bare string. Google explicitly demotes the bare-string form.
        moep = payload["mainEntityOfPage"]
        assert isinstance(moep, dict), (
            "mainEntityOfPage must be an object, not a bare URL string"
        )
        assert moep.get("@type") == "WebPage", (
            f"mainEntityOfPage.@type must be 'WebPage', got {moep.get('@type')!r}"
        )
        assert "@id" in moep, "mainEntityOfPage missing @id"
        assert _is_https_absolute(moep["@id"]), (
            f"mainEntityOfPage.@id is not an absolute https URL: {moep['@id']!r}"
        )

        # author / publisher must be Organization or Person objects.
        for actor_key in ("author", "publisher"):
            actor = payload[actor_key]
            assert isinstance(actor, dict), f"{actor_key} must be an object"
            assert actor.get("@type") in ("Organization", "Person"), (
                f"{actor_key}.@type must be Organization or Person, "
                f"got {actor.get('@type')!r}"
            )
            assert actor.get("name"), f"{actor_key}.name missing or empty"

        # publisher.url, when present, must be absolute https.
        if "url" in payload["publisher"]:
            assert _is_https_absolute(payload["publisher"]["url"]), (
                f"publisher.url not absolute https: {payload['publisher']['url']!r}"
            )

        # keywords is a comma-separated string per Schema.org (not a list).
        # Google accepts both, but the generator pins to string for stability.
        assert isinstance(payload["keywords"], str), (
            f"keywords must be a comma-separated string, got "
            f"{type(payload['keywords']).__name__}"
        )

        # proficiencyLevel — Schema.org defines a free-text string here,
        # but the controlled vocab is {Beginner, Expert}. We pin to
        # those values; loosening is a deliberate choice that should
        # update this test.
        if "proficiencyLevel" in payload:
            assert payload["proficiencyLevel"] in ("Beginner", "Expert"), (
                f"proficiencyLevel outside controlled vocab: "
                f"{payload['proficiencyLevel']!r}"
            )

        # isAccessibleForFree must be a boolean (not "true"/"false" strings —
        # Google's parser silently demotes string booleans).
        if "isAccessibleForFree" in payload:
            assert isinstance(payload["isAccessibleForFree"], bool), (
                "isAccessibleForFree must be a JSON boolean, not a string"
            )

        # No keys may slip in starting with a leading whitespace or @-fork
        # other than the recognised JSON-LD keywords.
        recognised_at_keys = {"@context", "@type", "@id", "@graph"}
        for k in payload:
            if k.startswith("@"):
                assert k in recognised_at_keys, (
                    f"unrecognised JSON-LD reserved key: {k!r}"
                )

    def test_jsonld_validates_across_every_rule_page(self) -> None:
        """The structural validator must pass for ALL rule pages, not
        just the SAMPLE. A regression in `_json_ld()` could affect a
        subset (e.g. rules with empty `recommendation` rendering an
        empty description). Walk the whole tree with a tighter check
        focused on the failure modes that historically slip past.
        """
        import json as _json

        for path in sorted(DOCS_RULES_DIR.glob("*.md")):
            if path.name == "index.md":
                continue
            text = path.read_text(encoding="utf-8")
            marker = '<script type="application/ld+json">'
            assert marker in text, f"{path.name}: missing JSON-LD"
            start = text.index(marker) + len(marker)
            end = text.index("</script>", start)
            try:
                payload = _json.loads(text[start:end].strip())
            except _json.JSONDecodeError as e:
                pytest.fail(f"{path.name}: JSON-LD payload invalid JSON: {e}")
            # Spot-check the failure modes most likely to silently break.
            assert payload.get("@type") == "TechArticle", path.name
            assert payload.get("url", "").startswith("https://"), path.name
            assert payload.get("description"), (
                f"{path.name}: description empty (would demote rich-result eligibility)"
            )
            assert isinstance(payload.get("mainEntityOfPage"), dict), path.name

    def test_family_backlinks_present(self, page: str) -> None:
        # The Family section turns each leaf rule page into a hub
        # linking siblings sharing the prefix-up-to-numeric-segment
        # (e.g. `SEC-AWS-IAM-*`). Multiplies internal-link density
        # across the rules subtree → meaningful PageRank lift.
        assert "## Family" in page, "Family backlink section missing"
        assert "SEC-AWS-IAM-*" in page, "family prefix label missing"
        # SEC-AWS-IAM-001's siblings (002, 003) must be linked.
        assert "[`SEC-AWS-IAM-002`](./SEC-AWS-IAM-002.md)" in page
        assert "[`SEC-AWS-IAM-003`](./SEC-AWS-IAM-003.md)" in page
        # The current rule must NOT link to itself.
        assert "[`SEC-AWS-IAM-001`](./SEC-AWS-IAM-001.md)" not in page

    def test_family_section_omitted_for_singleton_rules(self) -> None:
        # A rule whose family has no other members shouldn't render
        # an empty "## Family" section. Pick a known singleton (the
        # generator promises this for any family of size 1).
        from gen_rule_docs import _build_family_index, _family_prefix
        entries = []
        for yml in sorted(CATALOG_DIR.glob("*.yaml")):
            try:
                entry = load_yaml(yml.read_text())
            except Exception:
                continue
            if entry.get("status") == "deprecated":
                continue
            entries.append(entry)
        index = _build_family_index(entries)
        singletons = [
            e["id"] for e in entries
            if len(index.get(_family_prefix(e["id"]), [])) == 1
        ]
        if not singletons:
            pytest.skip("no singleton families in current catalogue")
        sample = singletons[0]
        text = (DOCS_RULES_DIR / f"{sample}.md").read_text()
        assert "## Family" not in text, (
            f"{sample} is a singleton family; the Family section should "
            f"be omitted (generator returned an empty section block)"
        )

    def test_jsonld_block_present_on_every_rule_page(self) -> None:
        """Doc-test the property holds for ALL rules, not just one."""
        sample_count = 0
        for path in sorted(DOCS_RULES_DIR.glob("*.md")):
            if path.name == "index.md":
                continue
            text = path.read_text(encoding="utf-8")
            assert '<script type="application/ld+json">' in text, (
                f"{path.name} is missing JSON-LD"
            )
            assert "vscode://tfanalyze.tf-analyze/rule/" in text, (
                f"{path.name} is missing the Open-in-VS-Code link"
            )
            sample_count += 1
        # Sanity: assert we actually checked something.
        assert sample_count >= 200, f"only checked {sample_count} pages"


class TestGeneratorDeterminism:
    def test_check_mode_passes_on_current_catalogue(self):
        # `--check` exits 1 if any doc is stale relative to the catalogue.
        # If this fails, run `python3 scripts/gen_rule_docs.py` to rebuild.
        res = subprocess.run(
            [sys.executable, str(GEN_SCRIPT), "--check"],
            capture_output=True, text=True, timeout=60,
        )
        assert res.returncode == 0, (
            f"`gen_rule_docs.py --check` failed (exit {res.returncode}). "
            f"Stderr:\n{res.stderr}"
        )
        # Audit follow-up #13/#18 — exit 0 is not enough on its own.
        # A partial generation that prints a Traceback to stderr but
        # still happens to write a coherent docs/rules/ tree would
        # exit 0 and slip through. Assert stderr is clean too.
        assert "Traceback (most recent call last)" not in (res.stderr or ""), (
            f"gen_rule_docs.py emitted a Python traceback even on exit 0:\n{res.stderr}"
        )


# ---------------------------------------------------------------------------
# Engine link contract: detect.py constants point at the docs site.
# ---------------------------------------------------------------------------


class TestEngineLinkContract:
    def test_rule_docs_url_base_points_at_pages_site(self):
        assert "github.io/tf-analyze/rules" in detect.RULE_DOCS_URL_BASE, (
            f"RULE_DOCS_URL_BASE drifted: {detect.RULE_DOCS_URL_BASE!r}"
        )

    def test_sarif_help_uri_uses_the_same_base(self):
        # SARIF consumers (GitHub Code Scanning, Azure DevOps) follow
        # `helpUri`. Decoupling it from the docs site is a regression.
        assert detect.SARIF_HELP_URI_BASE == detect.RULE_DOCS_URL_BASE, (
            "SARIF_HELP_URI_BASE drifted from RULE_DOCS_URL_BASE — "
            "split URL targets confuse downstream consumers."
        )

    def test_url_template_includes_rule_id_placeholder(self):
        # The URL must be formattable with `{id}`.
        sample = detect.RULE_DOCS_URL_BASE.format(id="SEC-AWS-IAM-001")
        assert "SEC-AWS-IAM-001" in sample, (
            f"RULE_DOCS_URL_BASE doesn't substitute {{id}}: {sample!r}"
        )

    def test_url_uses_pretty_form_not_html_extension(self):
        # GitHub Pages serves /rules/<id>/ (with trailing slash), not
        # /rules/<id>.html — the .html form returns 404. Lock the
        # pretty form so future drift is caught locally rather than
        # only at runtime.
        sample = detect.RULE_DOCS_URL_BASE.format(id="SEC-AWS-IAM-001")
        assert sample.endswith("/SEC-AWS-IAM-001/"), (
            f"RULE_DOCS_URL_BASE must produce pretty URL ending in /<id>/, "
            f"got: {sample!r}"
        )
        assert not sample.endswith(".html"), (
            "RULE_DOCS_URL_BASE must not use .html extension — Pages 404s on "
            "those URLs."
        )


# ---------------------------------------------------------------------------
# Compliance text + HTML carry the URL.
# ---------------------------------------------------------------------------


class TestComplianceLinkSurface:
    def test_compliance_text_emits_per_rule_url_for_failed_rules(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        res = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "detect.py"),
             "--target", str(tmp_path), "--format", "compliance",
             "--no-hcl2"],
            capture_output=True, text=True, timeout=60,
        )
        # Header line that explains the URL convention is always present.
        assert "github.io/tf-analyze/rules" in res.stdout, (
            "compliance text output should advertise the per-rule docs URL"
        )

    def test_compliance_html_wraps_rule_ids_as_anchors(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        res = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "detect.py"),
             "--target", str(tmp_path), "--format", "html", "--compliance",
             "--no-hcl2"],
            capture_output=True, text=True, timeout=60,
        )
        # At least one <a> with the docs URL must be present in compliance section.
        assert "github.io/tf-analyze/rules/" in res.stdout
        assert "<a href=" in res.stdout

    def test_findings_panel_rule_header_links_to_docs(self, tmp_path: Path):
        (tmp_path / "main.tf").write_text(
            'resource "aws_db_instance" "x" {\n'
            '  identifier        = "demo"\n'
            '  engine            = "postgres"\n'
            '  storage_encrypted = false\n'
            '}\n'
        )
        res = subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "detect.py"),
             "--target", str(tmp_path), "--format", "html",
             "--no-hcl2"],
            capture_output=True, text=True, timeout=60,
        )
        # Findings tab header must wrap the rule ID in an anchor.
        assert "title='Open rule documentation'" in res.stdout
        assert "github.io/tf-analyze/rules/" in res.stdout
