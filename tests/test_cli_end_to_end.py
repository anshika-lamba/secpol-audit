"""End-to-end CLI tests verifying exit codes (0, 1, 2), formats, HTML output, and offline harness."""

from __future__ import annotations

import json
from pathlib import Path
import stat
import subprocess
import sys

import pytest

from secpol_audit.cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests/fixtures/sample_qemu_logs"


def test_cli_check_vulnerable_adas_sarif_exits_1(capsys) -> None:
    rc = main(
        [
            "check",
            str(REPO_ROOT / "examples/adas_12svc.secpol"),
            "--ifs",
            str(REPO_ROOT / "examples/adas_12svc.ifs"),
            "--format",
            "sarif",
        ]
    )
    assert rc == 1
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert doc["version"] == "2.1.0"
    rule_ids = {r["ruleId"] for r in doc["runs"][0]["results"]}
    assert "ESCALATION_CHAIN" in rule_ids
    assert "PRE_SECPOLPUSH_LAUNCH" in rule_ids
    assert "UNTYPED_IFS_SERVICE" in rule_ids
    assert "UNDEFINED_IFS_TYPE" in rule_ids


def test_cli_check_fixed_adas_exits_0(capsys) -> None:
    rc = main(
        [
            "check",
            str(REPO_ROOT / "examples/adas_12svc_fixed.secpol"),
            "--ifs",
            str(REPO_ROOT / "examples/adas_12svc_fixed.ifs"),
            "--format",
            "json",
        ]
    )
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["total_findings"] == 0
    assert payload["summary"]["escalation_chains"] == 0
    # Honest skipped status when secpolcompile is not installed on host
    assert payload["secpolcompile"]["status"] in {"skipped", "pass"}


def test_cli_check_secpolcompile_fail_causes_exit_1(tmp_path: Path, capsys) -> None:
    pol = tmp_path / "clean.secpol"
    pol.write_text("type a_t;\n", encoding="utf-8")

    fake_fail = tmp_path / "fail_compile.sh"
    fake_fail.write_text("#!/bin/sh\necho 'bad binary range' >&2\nexit 1\n", encoding="utf-8")
    fake_fail.chmod(fake_fail.stat().st_mode | stat.S_IXUSR)

    rc = main(["check", str(pol), "--secpolcompile-bin", str(fake_fail), "--format", "json"])
    assert rc == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["secpolcompile"]["status"] == "fail"
    assert "bad binary range" in payload["secpolcompile"]["stderr"]


def test_cli_paths_generates_offline_html_and_exits_1(tmp_path: Path, capsys) -> None:
    html_file = tmp_path / "adas_report.html"
    rc = main(
        [
            "paths",
            str(REPO_ROOT / "examples/adas_12svc.secpol"),
            "--ifs",
            str(REPO_ROOT / "examples/adas_12svc.ifs"),
            "--html",
            str(html_file),
        ]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "ivi_ui_t -> diag_helper_t -> can_hal_t" in out
    assert html_file.is_file()
    content = html_file.read_text(encoding="utf-8")
    assert "ivi_ui_t -> diag_helper_t -> can_hal_t" in content
    assert "http://" not in content
    assert "https://" not in content


def test_cli_paths_fixed_exits_0(capsys) -> None:
    rc = main(["paths", str(REPO_ROOT / "examples/adas_12svc_fixed.secpol")])
    assert rc == 0
    assert "Escalation Chains: 0" in capsys.readouterr().out


def test_cli_diff_adas_fixed_reports_minus_1_and_exits_0(capsys) -> None:
    rc = main(
        [
            "diff",
            str(REPO_ROOT / "examples/adas_12svc.secpol"),
            str(REPO_ROOT / "examples/adas_12svc_fixed.secpol"),
        ]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "-1 escalation chain (0 remaining)" in out


def test_cli_diff_regression_exits_1(capsys) -> None:
    rc = main(
        [
            "diff",
            str(REPO_ROOT / "examples/adas_12svc_fixed.secpol"),
            str(REPO_ROOT / "examples/adas_12svc.secpol"),
        ]
    )
    assert rc == 1
    out = capsys.readouterr().out
    assert "+1 escalation chain (1 remaining)" in out


def test_cli_verify_runtime_clean_and_drift(capsys) -> None:
    rc_clean = main(
        [
            "verify-runtime",
            str(FIXTURES / "pidin_clean.log"),
            "--policy",
            str(REPO_ROOT / "examples/adas_12svc_fixed.secpol"),
            "--ifs",
            str(REPO_ROOT / "examples/adas_12svc_fixed.ifs"),
        ]
    )
    assert rc_clean == 0
    assert "PASS" in capsys.readouterr().out

    rc_drift = main(
        [
            "verify-runtime",
            str(FIXTURES / "pidin_drift.log"),
            "--policy",
            str(REPO_ROOT / "examples/adas_12svc_fixed.secpol"),
            "--ifs",
            str(REPO_ROOT / "examples/adas_12svc_fixed.ifs"),
            "--format",
            "json",
        ]
    )
    assert rc_drift == 1
    payload = json.loads(capsys.readouterr().out)
    rules = {f["rule_id"] for f in payload["findings"]}
    assert {"RUNTIME_UNTYPED_PROCESS", "RUNTIME_TYPE_MISMATCH", "RUNTIME_UNDECLARED_TYPE"}.issubset(rules)


@pytest.mark.parametrize(
    "bad_content,expected_code",
    [
        ("allow_magic a_t b_t;\n", "UNSUPPORTED_CONSTRUCT"),
        ("type a_t;\nallow a_t self:ability { io\n", "PARSE_ERROR"),
        ("type a_t\n", "PARSE_ERROR"),
    ],
)
def test_cli_fail_closed_exits_2_on_parse_errors(
    tmp_path: Path, capsys, bad_content: str, expected_code: str
) -> None:
    bad_file = tmp_path / "broken.secpol"
    bad_file.write_text(bad_content, encoding="utf-8")

    rc = main(["check", str(bad_file)])
    assert rc == 2
    err = capsys.readouterr().err
    assert expected_code in err
    assert str(bad_file) in err


def test_cli_fail_closed_exits_2_on_bad_ifs(tmp_path: Path, capsys) -> None:
    pol = tmp_path / "ok.secpol"
    pol.write_text("type a_t;\n", encoding="utf-8")
    bad_ifs = tmp_path / "bad.ifs"
    bad_ifs.write_text("[+script] startup-script = {\n  on -T\n}\n", encoding="utf-8")

    rc = main(["check", str(pol), "--ifs", str(bad_ifs)])
    assert rc == 2
    assert "PARSE_ERROR" in capsys.readouterr().err


def test_cli_invalid_usage_exits_2(capsys) -> None:
    rc = main(["unknown-subcommand"])
    assert rc == 2
    capsys.readouterr()


def test_python_m_secpol_audit_and_verify_offline_fixtures() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "secpol_audit", "diff",
         str(REPO_ROOT / "qnx_demo/mutants/M3_2hop_escalate.secpol"),
         str(REPO_ROOT / "qnx_demo/mutants/M3_fixed.secpol")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0
    assert "-1 escalation chain (0 remaining)" in proc.stdout

    replay = subprocess.run(
        [sys.executable, str(REPO_ROOT / "harness/verify_offline.py"), "--fixtures"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert replay.returncode == 0
    assert "MATCH (fixture)" in replay.stdout
    assert "MISMATCH" not in replay.stdout
