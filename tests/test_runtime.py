"""Unit tests for QNX 8.0 `pidin -f a_n` parser and runtime drift verification."""

from __future__ import annotations

from pathlib import Path
import pytest

from harness.observe import observe_serial_file
from secpol_audit.ir import ParseDiagnostic, Severity
from secpol_audit.parser_ifs import parse_ifs_file
from secpol_audit.parser_secpol import parse_secpol_file
from secpol_audit.runtime import parse_pidin_file, parse_pidin_text, verify_runtime

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests/fixtures/sample_qemu_logs"


def test_parse_pidin_handles_headers_empty_cols_markers_and_args() -> None:
    sample = """
         pid type                 name
           1                      procnto-smp-instr -v
        4098 slogger2_t           /proc/boot/slogger2
        4099 -                    /proc/boot/untyped_dash
        4100 0                    /proc/boot/untyped_zero --flag
        4101                      /proc/boot/untyped_blank -x
        4102 can_hal_t            can_server
    """
    procs = parse_pidin_text(sample, "sample.log")
    by_pid = {p.pid: p for p in procs}
    assert by_pid[1].name == "procnto-smp-instr"
    assert by_pid[1].secpol_type is None
    assert by_pid[4098].secpol_type == "slogger2_t"
    assert by_pid[4099].secpol_type is None
    assert by_pid[4099].name == "untyped_dash"
    assert by_pid[4100].secpol_type is None
    assert by_pid[4100].name == "untyped_zero"
    assert by_pid[4101].secpol_type is None
    assert by_pid[4101].name == "untyped_blank"
    assert by_pid[4102].secpol_type == "can_hal_t"


def test_parse_pidin_without_header_line() -> None:
    sample = """
    1 procnto-smp-instr
    200 can_hal_t /proc/boot/can_server
    201 /proc/boot/rogue_untyped --arg
    202 - /proc/boot/dash_untyped
    """
    procs = parse_pidin_text(sample, "noheader.log")
    assert [(p.pid, p.secpol_type, p.name) for p in procs] == [
        (1, None, "procnto-smp-instr"),
        (200, "can_hal_t", "can_server"),
        (201, None, "rogue_untyped"),
        (202, None, "dash_untyped"),
    ]


def test_parse_pidin_garbage_fails_closed() -> None:
    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_pidin_text("this is not a pidin output at all\nfoo bar baz\n", "garbage.log")
    assert excinfo.value.code == "PARSE_ERROR"


def test_verify_runtime_clean_fixture() -> None:
    pol = parse_secpol_file(REPO_ROOT / "examples/adas_12svc_fixed.secpol")
    ifs = parse_ifs_file(REPO_ROOT / "examples/adas_12svc_fixed.ifs")
    procs = parse_pidin_file(FIXTURES / "pidin_clean.log")

    diff = verify_runtime(procs, policy=pol, ifs=ifs, source_path="pidin_clean.log")
    assert diff.findings == []
    assert len(diff.matched) == 12


def test_verify_runtime_drift_fixture_catches_all_four_drift_types() -> None:
    pol = parse_secpol_file(REPO_ROOT / "examples/adas_12svc_fixed.secpol")
    ifs = parse_ifs_file(REPO_ROOT / "examples/adas_12svc_fixed.ifs")
    procs = parse_pidin_file(FIXTURES / "pidin_drift.log")

    diff = verify_runtime(procs, policy=pol, ifs=ifs, source_path="pidin_drift.log")
    rules = {(f.rule_id, f.severity) for f in diff.findings}
    assert ("RUNTIME_UNTYPED_PROCESS", Severity.CRITICAL) in rules
    assert ("RUNTIME_TYPE_MISMATCH", Severity.HIGH) in rules
    assert ("RUNTIME_UNDECLARED_TYPE", Severity.HIGH) in rules
    assert ("RUNTIME_MISSING_SERVICE", Severity.INFO) in rules

    untyped_names = {f.metadata["process"] for f in diff.findings if f.rule_id == "RUNTIME_UNTYPED_PROCESS"}
    assert untyped_names == {"ota_agent", "telemetry_svc"}


def test_harness_observe_serial_fixtures() -> None:
    obs_m3 = observe_serial_file(FIXTURES / "M3_2hop_escalate.log")
    assert obs_m3.is_synthetic_fixture is True
    assert obs_m3.mutant == "M3_2hop_escalate"
    assert obs_m3.direct_result == "DENIED"
    assert obs_m3.direct_errno == 1
    assert obs_m3.hop1_spawn == "OK"
    assert obs_m3.hop2_transition == "OK"
    assert obs_m3.hop2_result == "GRANTED"
    assert len(obs_m3.pidin_processes) == 3
    assert obs_m3.completed is True

    obs_m2 = observe_serial_file(FIXTURES / "M2_untyped_server.log")
    assert any(p.name == "can_server" and p.secpol_type is None for p in obs_m2.pidin_processes)
