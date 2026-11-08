#
# Copyright (c) 2026 Semgrep Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# version 2.1 as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the file
# LICENSE for more details.
#
import json

import pytest
from tests.fixtures import RunSemgrep

from semgrep.constants import OutputFormat

_RULE = """\
rules:
- id: my-test-rule
  pattern: foo($X)
  message: found foo
  languages: [python]
  severity: INFO
"""

_PASSING_TARGET = "# ruleid: my-test-rule\nfoo(1)\n"
_FAILING_TARGET = "# ruleid: my-test-rule\nbar(1)\n"


def _write_pair(tmp_path, rule_text=_RULE, target_text=_PASSING_TARGET):
    rule = tmp_path / "myrule.yaml"
    rule.write_text(rule_text)
    target = tmp_path / "myrule.py"
    target.write_text(target_text)
    return rule, target


@pytest.mark.slow
def test_test_mode_passing_rule_json(run_semgrep_in_tmp: RunSemgrep, tmp_path):
    rule, target = _write_pair(tmp_path)
    result = run_semgrep_in_tmp(
        config=str(rule),
        subcommand="scan",
        target_name=str(target),
        assume_targets_dir=False,
        options=["--test"],
        output_format=OutputFormat.JSON,
        assert_exit_code=0,
    )
    data = json.loads(result.stdout)
    # stdout paths are masked to <MASKED> by the runner; assert structurally
    assert len(data["results"]) == 1
    checks = next(iter(data["results"].values()))["checks"]
    assert checks["my-test-rule"]["passed"] is True


@pytest.mark.slow
def test_test_mode_failing_rule_json(run_semgrep_in_tmp: RunSemgrep, tmp_path):
    rule, target = _write_pair(tmp_path, target_text=_FAILING_TARGET)
    result = run_semgrep_in_tmp(
        config=str(rule),
        subcommand="scan",
        target_name=str(target),
        assume_targets_dir=False,
        options=["--test"],
        output_format=OutputFormat.JSON,
        assert_exit_code=1,
    )
    data = json.loads(result.stdout)
    assert len(data["results"]) == 1
    checks = next(iter(data["results"].values()))["checks"]
    assert checks["my-test-rule"]["passed"] is False


@pytest.mark.slow
def test_test_mode_text_output(run_semgrep_in_tmp: RunSemgrep, tmp_path):
    rule, target = _write_pair(tmp_path)
    result = run_semgrep_in_tmp(
        config=str(rule),
        subcommand="scan",
        target_name=str(target),
        assume_targets_dir=False,
        options=["--test"],
        output_format=None,
        assert_exit_code=0,
    )
    assert "1/1: ✓ All tests passed" in result.stdout


@pytest.mark.slow
def test_test_mode_reports_config_missing_tests(
    run_semgrep_in_tmp: RunSemgrep, tmp_path
):
    rules_dir = tmp_path / "myrules"
    rules_dir.mkdir()
    (rules_dir / "with_tests.yaml").write_text(_RULE)
    (rules_dir / "without_tests.yaml").write_text(
        _RULE.replace("my-test-rule", "other-rule")
    )
    targets_dir = tmp_path / "mytargets"
    targets_dir.mkdir()
    (targets_dir / "with_tests.py").write_text(_PASSING_TARGET)
    result = run_semgrep_in_tmp(
        config=str(rules_dir),
        subcommand="scan",
        target_name=str(targets_dir),
        assume_targets_dir=False,
        options=["--test"],
        output_format=OutputFormat.JSON,
        assert_exit_code=0,
    )
    data = json.loads(result.stdout)
    assert len(data["config_missing_tests"]) == 1
    assert len(data["results"]) == 1
    checks = next(iter(data["results"].values()))["checks"]
    assert checks["my-test-rule"]["passed"] is True
