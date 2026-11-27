"""Unit tests for Step 4: evidence-aware `secpol-audit blast`, `blast-diff`, and offline HTML explorer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secpol_audit.blast import (
    STATE_OBSERVED_AND_CORRELATED,
    STATE_STATIC_ONLY,
    STATE_SYSCALL_ONLY_UNOBSERVABLE,
    analyze_blast,
    diff_blast_reports,
    parse_blast_log_text,
)
from secpol_audit.blast_html import render_blast_html
from secpol_audit.cli import main as cli_main
from secpol_audit.ir import ParseDiagnostic
from secpol_audit.parser_ifs import parse_ifs_file
from secpol_audit.parser_secpol import parse_secpol_file

REPO_ROOT = Path(__file__).resolve().parent.parent
M0_SECPOL = REPO_ROOT / "qnx_demo" / "mutants" / "M0_sentry_clean.secpol"
M3_SECPOL = REPO_ROOT / "qnx_demo" / "mutants" / "M3_sentry_escalate.secpol"
BLAST_IFS = REPO_ROOT / "qnx_demo" / "build_blast.ifs.in"
STOCK_QNX8_SECPOL = REPO_ROOT / "evidence" / "secpolgenerate" / "qnx8_generated.secpol"
REAL_M3_SENTRY_LOG = REPO_ROOT / "evidence" / "qemu_logs" / "M3_sentry_escalate.log"

# SYNTHETIC UNIT-TEST FIXTURE — mirrors exact output format of qnx_demo/kprobe.c + secpol_sentry.c
SYNTHETIC_M3_COMPLETE_LOG = """\
# SYNTHETIC UNIT-TEST FIXTURE
SECPOLEV_START: monitoring /dev/secpol_sentry
KPROBE_JSON:{"origin":"ivi_ui_t","op":"settypeid","target":"diag_helper_t","outcome":"ALLOW","errno":0}
SECPOLEV_JSON:{"ts_ns":1001000,"verdict":"OK","proc":"proc/boot/kprobe","type":"ivi_ui_t","kind":"ability","ability":"settypeid","root":false,"range":null,"path":"","status":"","class":"","perm":"","obj_type":""}
KPROBE_JSON:{"origin":"ivi_ui_t","op":"settypeid","target":"can_hal_t","outcome":"DENY","errno":1}
KPROBE_JSON:{"origin":"ivi_ui_t","op":"channel_connect","target":"can_ctrl","outcome":"DENY","errno":13}
KPROBE_JSON:{"origin":"ivi_ui_t","op":"allow_attach","target":"can_ctrl","outcome":"DENY","errno":1}
KPROBE_JSON:{"origin":"diag_helper_t","op":"settypeid","target":"can_hal_t","outcome":"ALLOW","errno":0}
SECPOLEV_JSON:{"ts_ns":1002000,"verdict":"OK","proc":"proc/boot/kprobe","type":"diag_helper_t","kind":"ability","ability":"settypeid","root":false,"range":null,"path":"","status":"","class":"","perm":"","obj_type":""}
KPROBE_JSON:{"origin":"diag_helper_t","op":"channel_connect","target":"can_ctrl","outcome":"DENY","errno":13}
SECPOLEV_STATS: ok=2 denied=0 dropped=0
=== SECPOL_AUDIT_DONE ===
"""

# SYNTHETIC UNIT-TEST FIXTURE — same probes, but dropped=2 in libsecpolev
SYNTHETIC_M3_DROPPED_LOG = SYNTHETIC_M3_COMPLETE_LOG.replace(
    "dropped=0", "dropped=2"
)

# SYNTHETIC UNIT-TEST FIXTURE — model-vs-syscall mismatch (policy says DENY for ivi_ui_t -> can_hal_t, kprobe says ALLOW)
SYNTHETIC_M3_MISMATCH_LOG = """\
# SYNTHETIC UNIT-TEST FIXTURE
KPROBE_JSON:{"origin":"ivi_ui_t","op":"settypeid","target":"can_hal_t","outcome":"ALLOW","errno":0}
SECPOLEV_STATS: ok=0 denied=0 dropped=0
=== SECPOL_AUDIT_DONE ===
"""


def test_three_state_evidence_classification_and_complete_result() -> None:
    policy = parse_secpol_file(M3_SECPOL)
    ifs = parse_ifs_file(BLAST_IFS)
    report = analyze_blast(
        policy,
        policy_source_bytes=M3_SECPOL.read_bytes(),
        ifs=ifs,
        log_text=SYNTHETIC_M3_COMPLETE_LOG,
        log_path="<synthetic-m3>",
    )

    comp = report.completeness
    assert comp.result == "COMPLETE"
    assert comp.probes_total == 6
    assert comp.probes_completed == 6
    assert comp.kernel_events_correlated == 2
    assert comp.unobservable_operations == 4
    assert comp.dropped_events == 0
    assert comp.mismatches == 0
    assert comp.execution == "independent-verification-boot"

    ivi_view = report.origins["ivi_ui_t"]
    by_key = {(r.origin, r.op, r.target): r for r in ivi_view.receipts}

    # 1. OBSERVED_AND_CORRELATED: static ALLOW + kprobe ALLOW + libsecpolev OK
    hop1 = by_key[("ivi_ui_t", "settypeid", "diag_helper_t")]
    assert hop1.static_prediction == "ALLOW"
    assert hop1.syscall_outcome == "ALLOW"
    assert hop1.kernel_witness_verdict == "OK"
    assert hop1.evidence_state == STATE_OBSERVED_AND_CORRELATED
    assert hop1.mismatch is False

    # 2. SYSCALL_ONLY_UNOBSERVABLE: kprobe DENY with no libsecpolev event
    direct_attach = by_key[("ivi_ui_t", "allow_attach", "can_ctrl")]
    assert direct_attach.static_prediction == "DENY"
    assert direct_attach.syscall_outcome == "DENY"
    assert direct_attach.syscall_errno == 1
    assert direct_attach.kernel_witness_verdict is None
    assert direct_attach.evidence_state == STATE_SYSCALL_ONLY_UNOBSERVABLE

    # 3. STATIC_ONLY: edge in policy that kprobe did not probe
    sentry_ipc = by_key[("ivi_ui_t", "channel_connect", "secpol_sentry_t")]
    assert sentry_ipc.static_prediction == "ALLOW"
    assert sentry_ipc.syscall_outcome is None
    assert sentry_ipc.kernel_witness_verdict is None
    assert sentry_ipc.evidence_state == STATE_STATIC_ONLY


def test_concentric_ring_layout_for_two_hop_escalation() -> None:
    policy = parse_secpol_file(M3_SECPOL)
    report = analyze_blast(policy, origin_filter="ivi_ui_t")
    view = report.origins["ivi_ui_t"]
    ring_by_node = {n.name: n.ring for n in view.nodes}

    assert ring_by_node["ivi_ui_t"] == 0
    assert ring_by_node["secpol_sentry_t"] == 1
    assert ring_by_node["diag_helper_t"] == 2
    assert ring_by_node["can_hal_t"] == 3
    assert "can_hal_t" in view.reachable_sinks
    assert "ivi_ui_t -> diag_helper_t -> can_hal_t" in view.escalation_chains


def test_completeness_partial_on_dropped_events_and_incomplete_probes() -> None:
    policy = parse_secpol_file(M3_SECPOL)

    rep_dropped = analyze_blast(
        policy,
        log_text=SYNTHETIC_M3_DROPPED_LOG,
        log_path="<synthetic-dropped>",
    )
    assert rep_dropped.completeness.dropped_events == 2
    assert rep_dropped.completeness.result == "PARTIAL"

    rep_incomplete = analyze_blast(
        policy,
        log_text=SYNTHETIC_M3_COMPLETE_LOG,
        log_path="<synthetic-incomplete>",
        expected_probes=10,
    )
    assert rep_incomplete.completeness.probes_completed == 6
    assert rep_incomplete.completeness.probes_total == 10
    assert rep_incomplete.completeness.result == "PARTIAL"

    rep_static = analyze_blast(policy)
    assert rep_static.completeness.probes_completed == 0
    assert rep_static.completeness.result == "PARTIAL"


def test_completeness_mismatch_when_syscall_contradicts_static_model() -> None:
    policy = parse_secpol_file(M3_SECPOL)
    report = analyze_blast(
        policy,
        log_text=SYNTHETIC_M3_MISMATCH_LOG,
        log_path="<synthetic-mismatch>",
    )
    assert report.completeness.mismatches == 1
    assert report.completeness.result == "MISMATCH"


def test_blast_diff_detects_shrink_and_expansion() -> None:
    m3 = analyze_blast(parse_secpol_file(M3_SECPOL)).to_dict()
    m0 = analyze_blast(parse_secpol_file(M0_SECPOL)).to_dict()

    remediated = diff_blast_reports(m3, m0)
    assert remediated["blast_expanded"] is False
    assert "ivi_ui_t -> diag_helper_t -> can_hal_t" in remediated["removed_escalation_chains"]
    assert "can_hal_t" in remediated["removed_sinks_by_origin"]["ivi_ui_t"]

    regressed = diff_blast_reports(m0, m3)
    assert regressed["blast_expanded"] is True
    assert "ivi_ui_t -> diag_helper_t -> can_hal_t" in regressed["added_escalation_chains"]
    assert "can_hal_t" in regressed["added_sinks_by_origin"]["ivi_ui_t"]


def test_blast_html_offline_zero_external_urls_and_diff_toggle() -> None:
    m3_rep = analyze_blast(
        parse_secpol_file(M3_SECPOL),
        log_text=SYNTHETIC_M3_COMPLETE_LOG,
        log_path="<synthetic-m3>",
    )
    m0_rep = analyze_blast(parse_secpol_file(M0_SECPOL))

    html_doc = render_blast_html(m3_rep, after_report=m0_rep)
    assert "http://" not in html_doc
    assert "https://" not in html_doc
    assert "#090D16" in html_doc
    assert 'id="blast-svg"' in html_doc
    assert 'data-has-diff="true"' in html_doc
    assert "OBSERVED_AND_CORRELATED" in html_doc
    assert "SYSCALL_ONLY_UNOBSERVABLE" in html_doc
    assert "KPROBE_JSON:" in html_doc


def test_real_stock_qnx8_generated_policy_works_in_blast() -> None:
    policy = parse_secpol_file(STOCK_QNX8_SECPOL)
    report = analyze_blast(policy, policy_source_bytes=STOCK_QNX8_SECPOL.read_bytes())
    assert len(report.policy_hash) == 64
    assert "pipe_t" in report.origins
    html_doc = render_blast_html(report)
    assert "http://" not in html_doc
    assert "https://" not in html_doc


def test_real_m3_sentry_log_without_kprobe_is_partial_not_error() -> None:
    policy = parse_secpol_file(M3_SECPOL)
    report = analyze_blast(
        policy,
        log_text=REAL_M3_SENTRY_LOG.read_text(encoding="utf-8", errors="replace"),
        log_path=str(REAL_M3_SENTRY_LOG),
    )
    assert report.completeness.probes_completed == 0
    assert report.completeness.result == "PARTIAL"


def test_malformed_kprobe_json_fails_closed() -> None:
    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_blast_log_text('KPROBE_JSON:{"origin":"ivi_ui_t","op":"bogus","target":"x","outcome":"ALLOW"}\n')
    assert excinfo.value.code == "PARSE_ERROR"


def test_cli_blast_and_blast_diff_end_to_end(tmp_path: Path) -> None:
    log_file = tmp_path / "m3_blast.log"
    log_file.write_text(SYNTHETIC_M3_COMPLETE_LOG, encoding="utf-8")

    m3_json = tmp_path / "m3.json"
    m0_json = tmp_path / "m0.json"
    comp_json = tmp_path / "completeness.json"
    html_out = tmp_path / "explorer.html"

    rc_m3 = cli_main([
        "blast",
        str(M3_SECPOL),
        "--ifs",
        str(BLAST_IFS),
        "--log",
        str(log_file),
        "--format",
        "json",
        "--completeness-out",
        str(comp_json),
        "--html",
        str(html_out),
        "--after-policy",
        str(M0_SECPOL),
        "-o",
        str(m3_json),
    ])
    assert rc_m3 == 1  # escalation sink reachable
    comp_payload = json.loads(comp_json.read_text(encoding="utf-8"))
    assert comp_payload["result"] == "COMPLETE"
    assert comp_payload["dropped_events"] == 0
    html_text = html_out.read_text(encoding="utf-8")
    assert "http://" not in html_text and "https://" not in html_text

    rc_m0 = cli_main([
        "blast",
        str(M0_SECPOL),
        "--format",
        "json",
        "-o",
        str(m0_json),
    ])
    assert rc_m0 == 0  # clean policy has 0 reachable sinks

    diff_out = tmp_path / "diff.json"
    rc_diff_ok = cli_main([
        "blast-diff",
        str(m3_json),
        str(m0_json),
        "--format",
        "json",
        "-o",
        str(diff_out),
    ])
    assert rc_diff_ok == 0
    assert json.loads(diff_out.read_text(encoding="utf-8"))["blast_expanded"] is False

    rc_diff_fail = cli_main([
        "blast-diff",
        str(m0_json),
        str(m3_json),
    ])
    assert rc_diff_fail == 1

    # Unknown origin fails closed with exit code 2
    rc_bad_origin = cli_main([
        "blast",
        str(M3_SECPOL),
        "--origin",
        "nonexistent_type_t",
    ])
    assert rc_bad_origin == 2


def test_allow_attach_five_way_errno_classification_and_completeness_gating() -> None:
    from secpol_audit.blast import classify_allow_attach_errno

    assert classify_allow_attach_errno(0, 0, "ALLOW") == ("ALLOW", None)
    assert classify_allow_attach_errno(-1, 13, "DENY") == ("DENY_POLICY", None)
    assert classify_allow_attach_errno(-1, 1, "DENY") == ("DENY_ABILITY", None)
    assert classify_allow_attach_errno(-1, 17, "DENY") == ("INCONCLUSIVE", "PATH_COLLISION")
    assert classify_allow_attach_errno(-1, 2, "DENY") == ("SETUP_FAILURE", "INCONCLUSIVE")

    policy = parse_secpol_file(M3_SECPOL)

    # EEXIST (17) -> INCONCLUSIVE (PATH_COLLISION) prevents COMPLETE
    log_eexist = (
        'KPROBE_JSON:{"origin":"ivi_ui_t","op":"allow_attach","path":"/dev/secpol_probe_deny_ivi_ui_t",'
        '"target":"/dev/secpol_probe_deny_ivi_ui_t","ret":-1,"outcome":"DENY","errno":17,"errno_name":"EEXIST"}\n'
        'SECPOLEV_STATS: ok=0 denied=0 dropped=0\n'
    )
    rep_eexist = analyze_blast(policy, log_text=log_eexist, log_path="<eexist>")
    assert rep_eexist.kprobes[0].classification == "INCONCLUSIVE"
    assert rep_eexist.kprobes[0].classification_reason == "PATH_COLLISION"
    assert rep_eexist.completeness.result == "PARTIAL"

    # ENOENT (2) -> SETUP_FAILURE prevents COMPLETE
    log_enoent = (
        'KPROBE_JSON:{"origin":"ivi_ui_t","op":"allow_attach","path":"/dev/secpol_probe_deny_ivi_ui_t",'
        '"target":"/dev/secpol_probe_deny_ivi_ui_t","ret":-1,"outcome":"DENY","errno":2,"errno_name":"ENOENT"}\n'
        'SECPOLEV_STATS: ok=0 denied=0 dropped=0\n'
    )
    rep_enoent = analyze_blast(policy, log_text=log_enoent, log_path="<enoent>")
    assert rep_enoent.kprobes[0].classification == "SETUP_FAILURE"
    assert rep_enoent.completeness.result == "PARTIAL"
