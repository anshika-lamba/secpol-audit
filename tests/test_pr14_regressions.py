"""PR #14 regression tests: PID-aware correlation, 8 fail-closed pipeline tests, derive_type sets, manifest."""

from __future__ import annotations

from pathlib import Path
import shutil

import pytest

from harness.generate_manifest import build_manifest
from harness.verify_offline import run_verification
from secpol_audit.blast import analyze_blast, classify_allow_attach_errno, parse_blast_log_text
from secpol_audit.events import correlate_events, parse_events_text
from secpol_audit.ir import ParseDiagnostic
from secpol_audit.parser_secpol import parse_secpol_file, parse_secpol_text

REPO_ROOT = Path(__file__).resolve().parent.parent
M3_SECPOL = REPO_ROOT / "qnx_demo" / "mutants" / "M3_sentry_escalate.secpol"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "sample_qemu_logs"


def test_pid_aware_two_hop_correlation_and_unrelated_pid_rejection() -> None:
    pol = parse_secpol_file(M3_SECPOL)

    # Valid causal chain: hop1 (16388 -> 20485) -> hop2 (20485 -> 20486)
    valid_log = (
        'LINEAGE_HOP1:{"parent_pid":16388,"child_pid":20485,"origin_type":"ivi_ui_t","requested_target_type":"diag_helper_t","outcome":"OK","errno":0}\n'
        'SECPOLEV_JSON:{"ts_ns":1000,"pid":16388,"verdict":"OK","proc":"proc/boot/ivi_exploit","type":"ivi_ui_t","kind":"ability","ability":"settypeid","root":false}\n'
        'SECPOLEV_JSON:{"ts_ns":1100,"pid":20485,"verdict":"OK","proc":"proc/boot/diag_helper","type":"diag_helper_t","kind":"ability","ability":"prot_exec","root":false}\n'
        'LINEAGE_HOP2:{"parent_pid":20485,"child_pid":20486,"origin_type":"diag_helper_t","requested_target_type":"can_hal_t","outcome":"OK","errno":0}\n'
        'SECPOLEV_JSON:{"ts_ns":1200,"pid":20485,"verdict":"OK","proc":"proc/boot/diag_helper","type":"diag_helper_t","kind":"ability","ability":"settypeid","root":false}\n'
        'SECPOLEV_JSON:{"ts_ns":1300,"pid":20486,"verdict":"OK","proc":"proc/boot/diag_helper","type":"can_hal_t","kind":"ability","ability":"channel_connect","root":false}\n'
        'SECPOLEV_STATS: ok=4 denied=0 dropped=0\n'
    )
    parsed = parse_events_text(valid_log, "<pid-valid>")
    res = correlate_events(parsed, pol)
    assert ("ivi_ui_t", "diag_helper_t") in res.verified_edges
    assert ("diag_helper_t", "can_hal_t") in res.verified_edges
    assert ["ivi_ui_t", "diag_helper_t", "can_hal_t"] in res.verified_chains

    # Unrelated PIDs (hop2.parent_pid != hop1.child_pid) must NOT verify the 2-hop chain
    broken_pid_log = valid_log.replace('"parent_pid":20485,"child_pid":20486', '"parent_pid":99999,"child_pid":20486')
    parsed_bad = parse_events_text(broken_pid_log, "<pid-unrelated>")
    res_bad = correlate_events(parsed_bad, pol)
    assert ["ivi_ui_t", "diag_helper_t", "can_hal_t"] not in res_bad.verified_chains


def _copy_fixtures(tmp_path: Path) -> Path:
    d = tmp_path / "logs"
    shutil.copytree(FIXTURES_DIR, d)
    return d


# 1. Timeout / missing completion marker
def test_neg_1_missing_completion_marker_fails_closed(tmp_path: Path) -> None:
    d = _copy_fixtures(tmp_path)
    p = d / "M0_clean.log"
    p.write_text(p.read_text().replace("=== SECPOL_AUDIT_DONE ===", ""), encoding="utf-8")
    assert run_verification(d) == 1


# 2. Missing log file
def test_neg_2_missing_log_file_fails_closed(tmp_path: Path) -> None:
    d = _copy_fixtures(tmp_path)
    (d / "M0_clean.log").unlink()
    assert run_verification(d) == 1


# 3. Wrong mutant name inside a log
def test_neg_3_wrong_mutant_name_fails_closed(tmp_path: Path) -> None:
    d = _copy_fixtures(tmp_path)
    p = d / "M0_clean.log"
    p.write_text(p.read_text().replace("M0_clean", "M99_bogus"), encoding="utf-8")
    assert run_verification(d) == 1


# 4. Missing required probe output
def test_neg_4_missing_required_probe_output_prevents_complete() -> None:
    pol = parse_secpol_file(M3_SECPOL)
    rep = analyze_blast(
        pol,
        log_text='KPROBE_JSON:{"origin":"ivi_ui_t","op":"settypeid","target":"diag_helper_t","outcome":"ALLOW","errno":0}\nSECPOLEV_STATS: ok=1 denied=0 dropped=0\n',
        expected_probes=5,
    )
    assert rep.completeness.result == "PARTIAL"


# 5. EEXIST (errno=17) on allow_attach -> INCONCLUSIVE (never DENY) & prevents COMPLETE
def test_neg_5_eexist_inconclusive_prevents_complete(tmp_path: Path) -> None:
    assert classify_allow_attach_errno(-1, 17, "DENY") == ("INCONCLUSIVE", "PATH_COLLISION")
    d = _copy_fixtures(tmp_path)
    p = d / "M0_clean.log"
    p.write_text(
        p.read_text() + '\nKPROBE_JSON:{"origin":"ivi_ui_t","op":"allow_attach","path":"/dev/x","target":"/dev/x","ret":-1,"outcome":"DENY","errno":17,"errno_name":"EEXIST"}\n',
        encoding="utf-8",
    )
    assert run_verification(d) == 1


# 6. Nonzero dropped event count in libsecpolev stats
def test_neg_6_nonzero_dropped_events_fails_closed(tmp_path: Path) -> None:
    d = _copy_fixtures(tmp_path)
    p = d / "M0_clean.log"
    p.write_text(p.read_text() + "\nSECPOLEV_STATS: ok=1 denied=0 dropped=3\n", encoding="utf-8")
    assert run_verification(d) == 1


# 7. Malformed or incomplete SECPOLEV_JSON / KPROBE_JSON telemetry
def test_neg_7_malformed_telemetry_fails_closed() -> None:
    with pytest.raises(ParseDiagnostic):
        parse_blast_log_text('KPROBE_JSON:{"origin":"ivi_ui_t","op":"allow_attach"\n')
    with pytest.raises(ParseDiagnostic):
        parse_events_text('SECPOLEV_JSON:{"ts_ns":100,"pid":"not_an_int","verdict":"OK","proc":"p","type":"t","kind":"ability"}\n')


# 8. Static prediction vs. runtime outcome mismatch
def test_neg_8_static_vs_runtime_mismatch_fails_closed(tmp_path: Path) -> None:
    d = _copy_fixtures(tmp_path)
    p = d / "M1_no_connect.log"
    p.write_text(p.read_text().replace("HOP2_RESULT=DENIED", "HOP2_RESULT=GRANTED"), encoding="utf-8")
    assert run_verification(d) == 1


def test_derive_type_set_syntax_and_mixed_forms() -> None:
    policy_text = """
    type a_t;
    type b_t;
    type c_t;
    derive_type { a_t b_t } { run1 run2 } c_t;
    derive_type a_t { run3 run4 } c_t;
    derive_type { a_t b_t } run5 c_t;
    """
    ir = parse_secpol_text(policy_text, "<derive-set>")
    pairs = {(r.src_type, r.name, r.dst_type) for r in ir.derive_rules}
    assert pairs == {
        ("a_t", "run1", "c_t"),
        ("a_t", "run2", "c_t"),
        ("b_t", "run1", "c_t"),
        ("b_t", "run2", "c_t"),
        ("a_t", "run3", "c_t"),
        ("a_t", "run4", "c_t"),
        ("a_t", "run5", "c_t"),
        ("b_t", "run5", "c_t"),
    }


def test_generate_manifest_structure() -> None:
    m = build_manifest()
    assert "source_commit" in m
    assert "capture_date" in m
    assert "policies_sha256" in m
    assert "evidence_logs_sha256" in m
    assert "M0_sentry_clean.secpol" in m["policies_sha256"]


def test_blast_one_to_one_pid_witness_rejects_duplicate_reuse() -> None:
    pol = parse_secpol_file(M3_SECPOL)
    # Two kprobes for ivi_ui_t settypeid with different PIDs, but only ONE SECPOLEV_JSON event
    log_text = (
        'KPROBE_JSON:{"origin":"ivi_ui_t","op":"settypeid","target":"diag_helper_t","target_id":4,"pid":101,"ret":0,"outcome":"ALLOW","errno":0,"errno_name":"OK"}\n'
        'KPROBE_JSON:{"origin":"ivi_ui_t","op":"settypeid","target":"can_hal_t","target_id":5,"pid":102,"ret":-1,"outcome":"DENY","errno":1,"errno_name":"EPERM"}\n'
        'SECPOLEV_JSON:{"ts_ns":1000,"pid":101,"verdict":"OK","proc":"proc/boot/kprobe","type":"ivi_ui_t","kind":"ability","ability":"settypeid","root":false,"range":[4,4]}\n'
        'SECPOLEV_STATS: ok=1 denied=0 dropped=0\n'
    )
    rep = analyze_blast(pol, log_text=log_text, log_path="<pid-1to1>")
    assert rep.completeness.kernel_events_correlated == 1
    assert rep.completeness.unobservable_operations == 1

    # Duplicate probe with same PID 101 must NOT reuse the already-consumed SECPOLEV_JSON event
    dup_log = (
        'KPROBE_JSON:{"origin":"ivi_ui_t","op":"settypeid","target":"diag_helper_t","target_id":4,"pid":101,"ret":0,"outcome":"ALLOW","errno":0,"errno_name":"OK"}\n'
        'KPROBE_JSON:{"origin":"ivi_ui_t","op":"settypeid","target":"diag_helper_t","target_id":4,"pid":101,"ret":0,"outcome":"ALLOW","errno":0,"errno_name":"OK"}\n'
        'SECPOLEV_JSON:{"ts_ns":1000,"pid":101,"verdict":"OK","proc":"proc/boot/kprobe","type":"ivi_ui_t","kind":"ability","ability":"settypeid","root":false,"range":[4,4]}\n'
        'SECPOLEV_STATS: ok=1 denied=0 dropped=0\n'
    )
    rep_dup = analyze_blast(pol, log_text=dup_log, log_path="<pid-dup>")
    assert rep_dup.completeness.kernel_events_correlated == 1
    assert rep_dup.completeness.unobservable_operations == 1


def test_docs_index_html_offline_and_evidence_manifest_integrity() -> None:
    import hashlib
    import json

    docs_html = REPO_ROOT / "docs" / "index.html"
    assert docs_html.is_file(), "docs/index.html must exist"
    html_text = docs_html.read_text(encoding="utf-8")
    assert "http://" not in html_text
    assert "https://" not in html_text
    assert 'data-has-diff="true"' in html_text

    manifest_path = REPO_ROOT / "evidence" / "MANIFEST.json"
    assert manifest_path.is_file(), "evidence/MANIFEST.json must exist"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    logs = manifest["evidence_logs_sha256"]
    assert len(logs) > 0
    for rel, expected_sha in logs.items():
        p = REPO_ROOT / "evidence" / rel
        assert p.is_file(), f"Missing evidence log: {p}"
        actual_sha = hashlib.sha256(p.read_bytes()).hexdigest()
        assert actual_sha == expected_sha, f"SHA-256 mismatch for {rel}"
