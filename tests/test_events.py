"""Tests for QNX 8.0 `libsecpolev` kernel-trace correlation (`secpol-audit verify-events`)."""

from __future__ import annotations

import json
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

from secpol_audit.cli import main
from secpol_audit.events import correlate_events, parse_events_file, parse_events_text
from secpol_audit.ir import ParseDiagnostic, Severity
from secpol_audit.parser_ifs import parse_ifs_file
from secpol_audit.parser_secpol import parse_secpol_file

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = REPO_ROOT / "tests/fixtures/sample_qemu_logs"
M0_SENTRY_POLICY = REPO_ROOT / "qnx_demo/mutants/M0_sentry_clean.secpol"
M3_SENTRY_POLICY = REPO_ROOT / "qnx_demo/mutants/M3_sentry_escalate.secpol"
SENTRY_IFS = REPO_ROOT / "qnx_demo/build_sentry.ifs.in"


def test_sentry_policies_parse_and_check_cleanly() -> None:
    rc_m0 = main(["check", str(M0_SENTRY_POLICY), "--ifs", str(SENTRY_IFS), "--no-secpolcompile"])
    assert rc_m0 == 0

    p0 = parse_secpol_file(M0_SENTRY_POLICY)
    assert "sentry" in p0.classes
    assert p0.classes["sentry"].permissions == ("read_events",)
    sentry_abilities = [
        spec.name
        for r in p0.ability_rules
        if "secpol_sentry_t" in r.sources
        for spec in r.abilities
    ]
    assert "trace" in sentry_abilities

    rc_m3 = main(["check", str(M3_SENTRY_POLICY), "--ifs", str(SENTRY_IFS), "--no-secpolcompile"])
    assert rc_m3 == 1


def test_parse_events_jsonl_alerts_stats_and_fixture_detection() -> None:
    parsed = parse_events_file(FIXTURES / "sentry_M3_2hop_fixture.log")
    assert parsed.is_synthetic_fixture is True
    assert len(parsed.events) == 9
    assert len(parsed.alerts) == 2
    assert parsed.stats is not None
    assert (parsed.stats.ok, parsed.stats.denied, parsed.stats.dropped) == (7, 2, 0)
    assert parsed.sentry_read_auth == "OK"
    assert parsed.sentry_read_unauth == "DENIED"

    # Real (untagged) log must report is_synthetic_fixture=False
    raw = (
        'SECPOLEV_JSON:{"ts_ns":100,"verdict":"OK","proc":"p","type":"t","kind":"ability",'
        '"ability":"trace","root":false,"range":null,"path":"","status":"","class":"","perm":"","obj_type":""}\n'
        "SECPOLEV_STATS: ok=1 denied=0 dropped=0\n"
    )
    real_parsed = parse_events_text(raw, "real.log")
    assert real_parsed.is_synthetic_fixture is False
    assert len(real_parsed.events) == 1


@pytest.mark.parametrize(
    "bad_log",
    [
        'SECPOLEV_JSON:{not valid json}\n',
        'SECPOLEV_JSON:{"ts_ns":1,"verdict":"MAYBE","proc":"p","type":"t","kind":"ability"}\n',
        'SECPOLEV_JSON:{"ts_ns":1,"verdict":"OK","proc":"p","type":"t","kind":"bogus"}\n',
        'SECPOLEV_JSON:{"ts_ns":-5,"verdict":"OK","proc":"p","type":"t","kind":"ability"}\n',
        'SECPOLEV_ALERT:{"kind":"multi_hop_chain","chain":"not_a_list","ts_ns":1}\n',
        "SECPOLEV_STATS: ok=abc denied=0 dropped=0\n",
        "Just boot noise without any secpolev lines\n",
    ],
)
def test_parse_events_fail_closed_on_malformed_lines(bad_log: str) -> None:
    with pytest.raises(ParseDiagnostic) as exc:
        parse_events_text(bad_log, "bad.log")
    assert exc.value.code == "PARSE_ERROR"


def test_correlate_m3_sentry_detects_verified_2hop_chain_and_custom_perm() -> None:
    policy = parse_secpol_file(M3_SENTRY_POLICY)
    ifs = parse_ifs_file(SENTRY_IFS)
    log = parse_events_file(FIXTURES / "sentry_M3_2hop_fixture.log")

    res = correlate_events(log, policy, ifs=ifs)
    assert res.verified_edges == [
        ("diag_helper_t", "can_hal_t"),
        ("ivi_ui_t", "diag_helper_t"),
    ]
    assert res.verified_chains == [["ivi_ui_t", "diag_helper_t", "can_hal_t"]]
    assert len(res.custom_perm_grants) == 1
    assert res.custom_perm_grants[0].type == "audit_reader_t"
    assert len(res.custom_perm_denials) == 1
    assert res.custom_perm_denials[0].type == "ivi_ui_t"
    assert len(res.unexpected_denials) == 0
    # Blocked direct attempts include both ivi_ui_t channel_connect DENIED and custom sentry:read_events DENIED
    assert len(res.blocked_direct_attempts) == 2

    crit_rules = [f for f in res.findings if f.rule_id == "KERNEL_TRACE_ESCALATION_OBSERVED"]
    assert len(crit_rules) == 1
    assert crit_rules[0].severity == Severity.CRITICAL
    assert "ivi_ui_t -> diag_helper_t -> can_hal_t" in crit_rules[0].message


def test_correlate_m0_sentry_clean_passes_with_zero_findings() -> None:
    policy = parse_secpol_file(M0_SENTRY_POLICY)
    ifs = parse_ifs_file(SENTRY_IFS)
    log = parse_events_file(FIXTURES / "sentry_M0_clean_fixture.log")

    res = correlate_events(log, policy, ifs=ifs)
    assert res.verified_edges == []
    assert res.verified_chains == []
    assert res.findings == []
    assert len(res.blocked_direct_attempts) == 3
    assert len(res.custom_perm_grants) == 1
    assert len(res.custom_perm_denials) == 1


def test_correlate_dropped_events_and_unexpected_denials() -> None:
    policy = parse_secpol_file(M0_SENTRY_POLICY)
    log_text = (
        "# SYNTHETIC UNIT-TEST FIXTURE\n"
        'SECPOLEV_JSON:{"ts_ns":100,"verdict":"DENIED","proc":"secpol_sentry","type":"secpol_sentry_t",'
        '"kind":"ability","ability":"trace","root":false,"range":null,"path":"","status":"","class":"","perm":"","obj_type":""}\n'
        'SECPOLEV_JSON:{"ts_ns":200,"verdict":"DENIED","proc":"cat","type":"audit_reader_t",'
        '"kind":"custom","ability":"","root":false,"range":null,"path":"","status":"","class":"sentry","perm":"read_events","obj_type":"secpol_sentry_t"}\n'
        "SECPOLEV_STATS: ok=10 denied=2 dropped=3\n"
    )
    log = parse_events_text(log_text, "dropped_and_denied.log")
    res = correlate_events(log, policy)

    rule_ids = {f.rule_id for f in res.findings}
    assert "SECPOLEV_DROPPED_EVENTS" in rule_ids
    assert "UNEXPECTED_RUNTIME_DENIAL" in rule_ids
    assert len(res.unexpected_denials) == 2


def test_cli_verify_events_exit_codes_sarif_html_and_svg(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # 1. Clean sentry fixture -> exit 0
    rc_clean = main(
        [
            "verify-events",
            str(M0_SENTRY_POLICY),
            "--log",
            str(FIXTURES / "sentry_M0_clean_fixture.log"),
            "--ifs",
            str(SENTRY_IFS),
        ]
    )
    out_clean = capsys.readouterr().out
    assert rc_clean == 0
    assert "PASS (0 findings)" in out_clean

    # 2. Vulnerable M3 sentry fixture -> exit 1 + SARIF 2.1.0 + offline HTML & SVG with KERNEL TRACE VERIFIED badge
    sarif_out = tmp_path / "verify_events.sarif.json"
    html_out = tmp_path / "verify_events.html"
    svg_out = tmp_path / "verify_events.svg"

    rc_vuln = main(
        [
            "verify-events",
            str(M3_SENTRY_POLICY),
            "--log",
            str(FIXTURES / "sentry_M3_2hop_fixture.log"),
            "--ifs",
            str(SENTRY_IFS),
            "--format",
            "sarif",
            "--output",
            str(sarif_out),
            "--html",
            str(html_out),
            "--svg",
            str(svg_out),
        ]
    )
    assert rc_vuln == 1

    sarif = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    sarif_rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
    assert "KERNEL_TRACE_ESCALATION_OBSERVED" in sarif_rule_ids

    html_doc = html_out.read_text(encoding="utf-8")
    assert "KERNEL TRACE VERIFIED" in html_doc
    assert "http://" not in html_doc
    assert "https://" not in html_doc

    svg_doc = svg_out.read_text(encoding="utf-8")
    assert "KERNEL TRACE VERIFIED" in svg_doc
    root = ET.fromstring(svg_doc)
    assert root.tag.endswith("svg")

    # 3. Malformed event log -> exit 2 (fail-closed)
    bad_log = tmp_path / "broken.log"
    bad_log.write_text("SECPOLEV_JSON:{broken\n", encoding="utf-8")
    rc_bad = main(["verify-events", str(M0_SENTRY_POLICY), "--log", str(bad_log)])
    err_bad = capsys.readouterr().err
    assert rc_bad == 2
    assert "PARSE_ERROR" in err_bad
