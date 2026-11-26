"""Tests for `harness/extract_secpolgen.py` and `secpol-audit prune`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from harness.extract_secpolgen import (
    SecpolgenExtractError,
    extract_secpolgen_file,
    extract_secpolgen_text,
    main as extract_main,
)
from secpol_audit.cli import main as cli_main
from secpol_audit.ir import Severity
from secpol_audit.parser_secpol import parse_secpol_text
from secpol_audit.prune import prune_policy

SAMPLE_CLEAN_CAPTURE = (
    "=== SECPOLGEN_CAPTURE_BEGIN ===\r\n"
    "=== PIDIN_BEGIN ===\r\n"
    "   1 - procnto-smp-instr\r\n"
    "=== PIDIN_END ===\r\n"
    "=== SECPOLGEN_POLICY_BEGIN ===\r\n"
    "type slogger2_t;\r\n"
    "type pipe_t;\r\n"
    "allow_attach slogger2_t /dev/slog2;\r\n"
    "allow pipe_t slogger2_t : channel connect;\r\n"
    "=== SECPOLGEN_POLICY_END ===\r\n"
    "=== SECPOLGEN_UNUSED_BEGIN ===\r\n"
    "# No unused rules\r\n"
    "=== SECPOLGEN_UNUSED_END ===\r\n"
    "=== SECPOLGEN_ERRORS_BEGIN ===\r\n"
    "=== SECPOLGEN_ERRORS_END ===\r\n"
    "=== SECPOL_AUDIT_DONE ===\r\n"
)


def test_extract_secpolgen_text_splits_all_three_sections_and_strips_crlf() -> None:
    res = extract_secpolgen_text(SAMPLE_CLEAN_CAPTURE)
    assert "\r" not in res.policy_text
    assert "type slogger2_t;" in res.policy_text
    assert "allow pipe_t slogger2_t : channel connect;" in res.policy_text
    assert "# No unused rules" in res.unused_text
    assert res.errors_text == ""


def test_extract_secpolgen_fails_closed_on_missing_or_unterminated_markers() -> None:
    with pytest.raises(SecpolgenExtractError):
        extract_secpolgen_text("boot log without markers\n")
    with pytest.raises(SecpolgenExtractError):
        extract_secpolgen_text("=== SECPOLGEN_POLICY_BEGIN ===\ntype a_t;\n")


def test_extract_secpolgen_cli_writes_files_and_runs_check(tmp_path: Path) -> None:
    log_path = tmp_path / "capture.log"
    log_path.write_text(SAMPLE_CLEAN_CAPTURE, encoding="utf-8")
    out_dir = tmp_path / "extracted"

    rc = extract_main([str(log_path), "--out-dir", str(out_dir)])
    assert rc == 0
    assert (out_dir / "qnx8_generated.secpol").is_file()
    assert (out_dir / "qnx8_unused.txt").is_file()
    assert (out_dir / "qnx8_errors.txt").is_file()

    # Missing log file -> fail-closed exit 2
    assert extract_main([str(tmp_path / "nope.log"), "--out-dir", str(out_dir)]) == 2


def test_extract_secpolgen_cli_detects_policy_findings_exit_1(tmp_path: Path) -> None:
    vuln_capture = (
        "=== SECPOLGEN_POLICY_BEGIN ===\n"
        "type ui_t;\n"
        "type hal_t;\n"
        "allow hal_t self:ability { nonroot mem_phys:0xfe000000-0xfe010000 };\n"
        "allow ui_t self:ability { nonroot settypeid:hal_t };\n"
        "=== SECPOLGEN_POLICY_END ===\n"
    )
    log_path = tmp_path / "vuln.log"
    log_path.write_text(vuln_capture, encoding="utf-8")
    out_dir = tmp_path / "out_vuln"

    rc = extract_main([str(log_path), "--out-dir", str(out_dir)])
    assert rc == 1
    # --no-check only extracts and returns 0
    assert extract_main([str(log_path), "--out-dir", str(out_dir), "--no-check"]) == 0


def test_prune_flags_unused_privileged_abilities_and_unregistered_sigevents() -> None:
    pol = parse_secpol_text(
        """
        type can_hal_t;
        type diag_helper_t;
        type sec_mgr_t;
        allow can_hal_t self:ability {
            nonroot
            mem_phys:0xfe000000-0xfe010000
            io
            public_channel
        };
        allow diag_helper_t self:ability { nonroot settypeid:can_hal_t };
        allow sec_mgr_t self:ability { nonroot mac_policy };
        """,
        "demo.secpol",
    )
    unused_txt = (
        "allow can_hal_t self:ability {\n"
        "    mem_phys:0xfe000000-0xfe010000\n"
        "    io\n"
        "    public_channel\n"
        "};\n"
        "diag_helper_t: ability settypeid:can_hal_t\n"
        "sec_mgr_t: unused ability mac_policy\n"
    )
    errors_txt = (
        "Unregistered sigevent received from pid 4098 (type=diag_helper_t)\n"
        "Unable to resolve pathspace rule for /dev/unknown\n"
    )

    res = prune_policy(
        pol,
        unused_txt,
        unused_path="unused.txt",
        errors_text=errors_txt,
        errors_path="errors.txt",
    )
    assert len(res.unused_privileged_rules) == 4
    flagged_abilities = {r["ability"].split(":", 1)[0] for r in res.unused_privileged_rules}
    assert flagged_abilities == {"mem_phys", "io", "settypeid", "mac_policy"}
    # Non-privileged `public_channel` must not be flagged
    assert "public_channel" not in flagged_abilities
    assert len(res.unregistered_sigevents) == 1
    assert len(res.other_errors) == 1

    rule_ids = [f.rule_id for f in res.findings]
    assert rule_ids.count("UNUSED_PRIVILEGED_RULE") == 4
    assert rule_ids.count("UNREGISTERED_SIGEVENT") == 1
    assert rule_ids.count("SECPOLGEN_ERROR") == 1
    assert all(
        f.severity == Severity.HIGH
        for f in res.findings
        if f.rule_id in ("UNUSED_PRIVILEGED_RULE", "UNREGISTERED_SIGEVENT")
    )


def test_cli_prune_json_clean_and_error_exit_codes(tmp_path: Path, capsys) -> None:
    pol_path = tmp_path / "p.secpol"
    pol_path.write_text(
        "type svc_t;\nallow svc_t self:ability { nonroot io public_channel };\n",
        encoding="utf-8",
    )
    unused_clean = tmp_path / "unused_clean.txt"
    unused_clean.write_text("allow svc_t self:ability public_channel;\n", encoding="utf-8")
    errors_clean = tmp_path / "errors_clean.txt"
    errors_clean.write_text("# clean\n", encoding="utf-8")

    # Clean -> exit 0
    rc_clean = cli_main(
        [
            "prune",
            str(pol_path),
            "--unused",
            str(unused_clean),
            "--errors",
            str(errors_clean),
            "--format",
            "json",
        ]
    )
    clean_payload = json.loads(capsys.readouterr().out)
    assert rc_clean == 0
    assert clean_payload["summary"]["total_findings"] == 0

    # Unused privileged + unregistered sigevent -> exit 1
    unused_dirty = tmp_path / "unused_dirty.txt"
    unused_dirty.write_text("allow svc_t self:ability io;\n", encoding="utf-8")
    errors_dirty = tmp_path / "errors_dirty.txt"
    errors_dirty.write_text("Unregistered sigevent on svc_t\n", encoding="utf-8")

    rc_dirty = cli_main(
        [
            "prune",
            str(pol_path),
            "--unused",
            str(unused_dirty),
            "--errors",
            str(errors_dirty),
            "--format",
            "json",
        ]
    )
    dirty_payload = json.loads(capsys.readouterr().out)
    assert rc_dirty == 1
    assert dirty_payload["summary"]["unused_privileged_rules"] == 1
    assert dirty_payload["summary"]["unregistered_sigevents"] == 1

    # Missing file -> exit 2
    assert cli_main(["prune", str(pol_path), "--unused", str(tmp_path / "missing.txt")]) == 2
