"""Provider `default_tags` reach a local child module's resources.

Terraform applies the AWS provider's `default_tags` to every resource that
uses that provider configuration, including resources in child modules it
is passed to. The engine recorded them only for the folder declaring the
provider, so every untagged resource in a child module got a missing-tags
finding (OPS-AWS-TAGS-001) the provider was already fixing.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

DETECT = Path(__file__).resolve().parents[1] / "scripts" / "detect.py"

BUCKET = 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'
TAGGED = 'provider "aws" {\n  region = "eu-west-1"\n%s  default_tags {\n    tags = { Owner = "team" }\n  }\n}\n'
PLAIN = 'provider "aws" {\n  region = "eu-west-1"\n%s}\n'


def _tag_findings(root: Path, files: dict[str, str]) -> set[str]:
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    proc = subprocess.run(
        [sys.executable, str(DETECT), "--target", str(root), "--format", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), proc.stderr
    return {
        f["file"].split(str(root) + "/", 1)[-1]
        for f in json.loads(proc.stdout)["findings"]
        if f["id"] == "OPS-AWS-TAGS-001"
    }


def test_a_child_inherits_the_callers_default_tags(tmp_path) -> None:
    files = {
        "main.tf": TAGGED % "" + 'module "store" {\n  source = "./modules/store"\n}\n',
        "modules/store/main.tf": BUCKET,
    }
    assert _tag_findings(tmp_path, files) == set()


def test_inheritance_goes_down_more_than_one_level(tmp_path) -> None:
    files = {
        "main.tf": TAGGED % "" + 'module "a" {\n  source = "./modules/a"\n}\n',
        "modules/a/main.tf": 'module "b" {\n  source = "../b"\n}\n',
        "modules/b/main.tf": BUCKET,
    }
    assert _tag_findings(tmp_path, files) == set()


def test_a_caller_without_default_tags_still_reports(tmp_path) -> None:
    files = {
        "main.tf": PLAIN % "" + 'module "store" {\n  source = "./modules/store"\n}\n',
        "modules/store/main.tf": BUCKET,
    }
    assert _tag_findings(tmp_path, files) == {"modules/store/main.tf"}


def test_an_aliased_provider_passed_in_counts_only_if_it_has_default_tags(
    tmp_path,
) -> None:
    call = 'module "store" {\n  source = "./modules/store"\n  providers = {\n    aws = aws.west\n  }\n}\n'
    tagged_alias = TAGGED % '  alias  = "west"\n'
    plain_alias = PLAIN % '  alias  = "west"\n'
    # The default provider has default_tags, but the child is given aws.west.
    assert _tag_findings(
        tmp_path / "a",
        {"main.tf": TAGGED % "" + plain_alias + call, "modules/store/main.tf": BUCKET},
    ) == {"modules/store/main.tf"}
    assert (
        _tag_findings(
            tmp_path / "b",
            {
                "main.tf": PLAIN % "" + tagged_alias + call,
                "modules/store/main.tf": BUCKET,
            },
        )
        == set()
    )


def test_a_child_called_twice_reports_for_the_untagged_caller(tmp_path) -> None:
    files = {
        "envs/a/main.tf": TAGGED % ""
        + 'module "store" {\n  source = "../../modules/store"\n}\n',
        "envs/b/main.tf": PLAIN % ""
        + 'module "store" {\n  source = "../../modules/store"\n}\n',
        "modules/store/main.tf": BUCKET,
    }
    assert _tag_findings(tmp_path, files) == {"modules/store/main.tf"}
