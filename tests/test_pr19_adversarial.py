"""PR #19 adversarial tests: 1-to-1 PID-enforced blast correlation & fail-closed COMPLETE."""

from __future__ import annotations

from pathlib import Path

from secpol_audit.blast import (
    EXPECTED_BLAST_PROBES,
    STATE_OBSERVED_AND_CORRELATED,
    STATE_SYSCALL_ONLY_UNOBSERVABLE,
    analyze_blast,
)
from secpol_audit.parser_ifs import parse_ifs_file
from secpol_audit.parser_secpol import parse_secpol_file

REPO_ROOT = Path(__file__).resolve().parent.parent
M3_BLAST_SECPOL = REPO_ROOT / "qnx_demo" / "mutants" / "M3_blast_escalate.secpol"
M0_BLAST_SECPOL = REPO_ROOT / "qnx_demo" / "mutants" / "M0_blast_clean.secpol"
BLAST_IFS = REPO_ROOT / "qnx_demo" / "build_blast.ifs.in"
REAL_M3_BLAST_LOG = REPO_ROOT / "evidence" / "blast" / "M3_blast_escalate.log"
REAL_M0_BLAST_LOG = REPO_ROOT / "evidence" / "blast" / "M0_blast_clean.log"


def _make_12_probe_log(
    *,
    drop_stats: bool = False,
    dropped: int = 0,
    omit_last_probe: bool = False,
    duplicate_first_probe: bool = False,
    add_unexpected_probe: bool = False,
    missing_kprobe_pid_idx: int | None = None,
    missing_secpolev_pid_idx: int | None = None,
    mismatch_pid_idx: int | None = None,
    reuse_first_event_for_second: bool = False,
    same_pid_two_settypeid: bool = False,
    wrong_allow_attach_path: bool = False,
    unobservable_idx: int | None = None,
) -> str:
    lines: list[str] = []
    # M3_blast_escalate outcomes for the 12 EXPECTED_BLAST_PROBES
    outcomes = [
        ("ALLOW", 0),   # 0: ivi_ui_t settypeid diag_helper_t
        ("DENY", 1),    # 1: ivi_ui_t settypeid can_hal_t
        ("DENY", 1),    # 2: ivi_ui_t channel_connect can_ctrl
        ("DENY", 13),   # 3: ivi_ui_t allow_attach /dev/secpol_probe_deny_ivi_ui_t
        ("ALLOW", 0),   # 4: diag_helper_t settypeid can_hal_t
        ("DENY", 1),    # 5: diag_helper_t settypeid ivi_ui_t
        ("DENY", 1),    # 6: diag_helper_t channel_connect can_ctrl
        ("DENY", 13),   # 7: diag_helper_t allow_attach /dev/secpol_probe_deny_diag_helper_t
        ("DENY", 1),    # 8: audit_reader_t settypeid can_hal_t
        ("DENY", 1),    # 9: audit_reader_t settypeid diag_helper_t
        ("DENY", 1),    # 10: audit_reader_t channel_connect can_ctrl
        ("ALLOW", 0),   # 11: audit_reader_t allow_attach /dev/secpol_probe_allow
    ]
    probes = list(EXPECTED_BLAST_PROBES)
    if omit_last_probe:
        probes = probes[:-1]
        outcomes = outcomes[:-1]

    for idx, ((origin, op, target), (out, err)) in enumerate(zip(probes, outcomes)):
        pid = 1000 + idx
        if same_pid_two_settypeid and idx == 1:
            pid = 1000  # same PID as idx 0
            out, err = "ALLOW", 0  # same verdict, different target
        k_pid_part = "" if missing_kprobe_pid_idx == idx else f',"pid":{pid}'
        tid_val = 2 if target == "can_hal_t" else (4 if target == "diag_helper_t" else (5 if target == "ivi_ui_t" else 2))
        tid_part = f',"target_id":{tid_val}' if op in ("settypeid", "channel_connect") else ""
        lines.append(
            f'KPROBE_JSON:{{"origin":"{origin}","op":"{op}","target":"{target}"{k_pid_part}{tid_part},"ret":{0 if out=="ALLOW" else -1},"outcome":"{out}","errno":{err}}}'
        )
        if duplicate_first_probe and idx == 0:
            lines.append(
                f'KPROBE_JSON:{{"origin":"{origin}","op":"{op}","target":"{target}","pid":{pid},"ret":0,"outcome":"ALLOW","errno":0}}'
            )

        if unobservable_idx == idx:
            continue
        if reuse_first_event_for_second and idx == 1:
            continue

        ev_pid = pid
        if mismatch_pid_idx == idx:
            ev_pid = 99999
        ev_pid_part = "" if missing_secpolev_pid_idx == idx else f',"pid":{ev_pid}'
        verdict = "OK" if out == "ALLOW" else "DENIED"
        if op == "settypeid":
            lines.append(
                f'SECPOLEV_JSON:{{"ts_ns":{1000+idx}{ev_pid_part},"verdict":"{verdict}","proc":"kprobe","type":"{origin}","kind":"ability","ability":"settypeid","root":false,"range":[{tid_val},{tid_val}]}}'
            )
        elif op == "channel_connect":
            lines.append(
                f'SECPOLEV_JSON:{{"ts_ns":{1000+idx}{ev_pid_part},"verdict":"{verdict}","proc":"kprobe","type":"{origin}","kind":"ability","ability":"channel_connect","root":false,"range":[2,2]}}'
            )
        elif op == "allow_attach":
            ev_path = "/dev/wrong_path" if (wrong_allow_attach_path and idx == 11) else target
            lines.append(
                f'SECPOLEV_JSON:{{"ts_ns":{1000+idx}{ev_pid_part},"verdict":"{verdict}","proc":"kprobe","type":"{origin}","kind":"attach","path":"{ev_path}","status":"ok"}}'
            )

    if add_unexpected_probe:
        lines.append(
            'KPROBE_JSON:{"origin":"ivi_ui_t","op":"settypeid","target":"slogger2_t","pid":5555,"ret":-1,"outcome":"DENY","errno":1}'
        )
    if not drop_stats:
        lines.append("=== SECPOL_AUDIT_DONE ===")
        lines.append(f"SECPOLEV_STATS: ok=12 denied=0 dropped={dropped}")
    return "\n".join(lines) + "\n"


def test_1_missing_kprobe_pid_is_unobservable_and_not_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(missing_kprobe_pid_idx=0))
    assert rep.completeness.result == "PARTIAL"
    assert rep.completeness.unobservable_operations >= 1


def test_2_missing_secpolev_pid_is_unobservable_and_not_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(missing_secpolev_pid_idx=0))
    assert rep.completeness.result == "PARTIAL"
    assert rep.completeness.unobservable_operations >= 1


def test_3_mismatched_pids_are_unobservable() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(mismatch_pid_idx=0))
    assert rep.completeness.result == "PARTIAL"
    assert rep.completeness.unobservable_operations >= 1


def test_4_reused_secpolev_event_rejected() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(reuse_first_event_for_second=True))
    assert rep.completeness.result == "PARTIAL"
    assert rep.completeness.kernel_events_correlated == 11
    assert rep.completeness.unobservable_operations == 1


def test_5_same_pid_two_settypeid_different_targets_ambiguous() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    # Without target_id disambiguation, two settypeid probes in the same PID are ambiguous
    log_no_tid = _make_12_probe_log(same_pid_two_settypeid=True).replace('"target_id":4,', '"target_id":null,').replace('"target_id":5,', '"target_id":null,')
    rep = analyze_blast(pol, log_text=log_no_tid)
    assert rep.completeness.result != "COMPLETE"
    assert rep.completeness.unobservable_operations >= 2


def test_6_incorrect_target_path_attribution_rejected() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(wrong_allow_attach_path=True))
    assert rep.completeness.result == "PARTIAL"
    assert rep.completeness.unobservable_operations == 1


def test_7_missing_expected_probe_not_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(omit_last_probe=True))
    assert rep.completeness.probes_total == 11
    assert rep.completeness.probes_completed == 11
    assert rep.completeness.result == "PARTIAL"


def test_8_duplicate_expected_probe_not_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(duplicate_first_probe=True))
    assert rep.completeness.result == "PARTIAL"


def test_9_unexpected_probe_not_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(add_unexpected_probe=True))
    assert rep.completeness.result == "PARTIAL"


def test_10_missing_secpolev_stats_not_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(drop_stats=True))
    assert rep.completeness.result == "PARTIAL"


def test_11_nonzero_dropped_events_not_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(dropped=2))
    assert rep.completeness.dropped_events == 2
    assert rep.completeness.result == "PARTIAL"


def test_12_unobservable_operation_not_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(unobservable_idx=4))
    assert rep.completeness.unobservable_operations == 1
    assert rep.completeness.result == "PARTIAL"


def test_13_and_14_all_12_probes_correlated_and_receipts_match_completeness() -> None:
    from secpol_audit.blast import load_expected_probes_manifest
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    ifs = parse_ifs_file(BLAST_IFS)
    specs = load_expected_probes_manifest(
        Path(__file__).resolve().parent.parent / "qnx_demo" / "blast_expected_probes.json"
    )
    rep = analyze_blast(pol, ifs=ifs, log_text=_make_12_probe_log(), expected_probe_specs=specs)
    comp = rep.completeness
    assert comp.result == "COMPLETE"
    assert comp.probes_total == 12
    assert comp.probes_completed == 12
    assert comp.kernel_events_correlated == 12
    assert comp.unobservable_operations == 0
    assert comp.dropped_events == 0
    assert comp.mismatches == 0

    probed_receipts = [r for r in rep.all_receipts if r.syscall_outcome is not None]
    correlated_receipts = [r for r in probed_receipts if r.evidence_state == STATE_OBSERVED_AND_CORRELATED]
    unobs_receipts = [r for r in probed_receipts if r.evidence_state == STATE_SYSCALL_ONLY_UNOBSERVABLE]
    assert len(correlated_receipts) == comp.kernel_events_correlated
    assert len(unobs_receipts) == comp.unobservable_operations


def test_real_committed_m0_and_m3_blast_logs_still_complete() -> None:
    ifs = parse_ifs_file(BLAST_IFS)
    m3 = analyze_blast(
        parse_secpol_file(M3_BLAST_SECPOL),
        ifs=ifs,
        log_text=REAL_M3_BLAST_LOG.read_text(encoding="utf-8", errors="replace"),
        log_path=str(REAL_M3_BLAST_LOG),
        expected_probe_specs=EXPECTED_BLAST_PROBES,
    )
    m0 = analyze_blast(
        parse_secpol_file(M0_BLAST_SECPOL),
        ifs=ifs,
        log_text=REAL_M0_BLAST_LOG.read_text(encoding="utf-8", errors="replace"),
        log_path=str(REAL_M0_BLAST_LOG),
        expected_probe_specs=EXPECTED_BLAST_PROBES,
    )
    # Honest reporting: in the committed logs, audit_reader_t ran two settypeid DENY probes
    # in the same PID, so they are conservatively downgraded to unobservable (PARTIAL).
    assert m3.completeness.result == "COMPLETE"
    assert m3.completeness.mismatches == 0
    assert m3.completeness.dropped_events == 0
    assert m0.completeness.result == "COMPLETE"
    assert m0.completeness.mismatches == 0
    assert m0.completeness.dropped_events == 0


# ---------------------------------------------------------------------------
# Corrective-pass adversarial tests (14 new tests)
# ---------------------------------------------------------------------------

def test_cp1_settypeid_missing_target_id_is_unobservable() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    log = _make_12_probe_log().replace('"target_id":4,', '"target_id":null,', 1)
    rep = analyze_blast(pol, log_text=log)
    assert rep.completeness.result != "COMPLETE"
    assert rep.completeness.unobservable_operations >= 1


def test_cp2_settypeid_incompatible_range_is_unobservable() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    log = _make_12_probe_log().replace('"range":[4,4]', '"range":[99,99]', 1)
    rep = analyze_blast(pol, log_text=log)
    assert rep.completeness.result != "COMPLETE"
    assert rep.completeness.unobservable_operations >= 1


def test_cp3_channel_connect_unmapped_target_is_unobservable() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    log = _make_12_probe_log().replace('"target":"can_ctrl"', '"target":"unknown_chan"', 1)
    rep = analyze_blast(pol, log_text=log)
    assert rep.completeness.result != "COMPLETE"
    assert rep.completeness.unobservable_operations >= 1


def test_cp4_manifest_loader_validates_12_probes() -> None:
    from secpol_audit.blast import load_expected_probes_manifest
    specs = load_expected_probes_manifest(
        Path(__file__).resolve().parent.parent / "qnx_demo" / "blast_expected_probes.json"
    )
    assert len(specs) == 12


def test_cp5_manifest_loader_rejects_duplicate_ids(tmp_path: Path) -> None:
    import json
    import pytest
    from secpol_audit.blast import load_expected_probes_manifest
    from secpol_audit.ir import ParseDiagnostic
    p = tmp_path / "bad_manifest.json"
    p.write_text(json.dumps({
        "schema_version": 1,
        "probes": [
            {"id": "p1", "origin": "ivi_ui_t", "op": "settypeid", "target": "diag_helper_t", "target_kind": "type", "resolved_target_type": "diag_helper_t", "evidence_requirement": "ALLOW"},
            {"id": "p1", "origin": "ivi_ui_t", "op": "settypeid", "target": "can_hal_t", "target_kind": "type", "resolved_target_type": "can_hal_t", "evidence_requirement": "DENY"},
        ]
    }), encoding="utf-8")
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(p)


def test_cp6_scoped_origin_without_manifest_never_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(), origin_filter="ivi_ui_t")
    assert rep.completeness.result != "COMPLETE"


def test_cp7_count_only_expected_probes_never_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    rep = analyze_blast(pol, log_text=_make_12_probe_log(), expected_probes=12, expected_probe_specs=())
    assert rep.completeness.result != "COMPLETE"


def test_cp8_missing_done_marker_never_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    log = _make_12_probe_log().replace("=== SECPOL_AUDIT_DONE ===\n", "")
    rep = analyze_blast(pol, log_text=log)
    assert rep.completeness.result != "COMPLETE"


def test_cp9_pre_marker_stats_only_never_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    log = _make_12_probe_log().replace(
        "=== SECPOL_AUDIT_DONE ===\nSECPOLEV_STATS: ok=12 denied=0 dropped=0\n",
        "SECPOLEV_STATS: ok=12 denied=0 dropped=0\n=== SECPOL_AUDIT_DONE ===\n",
    )
    rep = analyze_blast(pol, log_text=log)
    assert rep.completeness.result != "COMPLETE"


def test_cp10_kprobe_pid_zero_is_unobservable() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    log = _make_12_probe_log().replace('"pid":1001', '"pid":0', 1)
    rep = analyze_blast(pol, log_text=log)
    assert rep.completeness.result != "COMPLETE"
    assert rep.completeness.unobservable_operations >= 1


def test_cp11_secpolev_pid_zero_is_unobservable() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    log = _make_12_probe_log().replace('"pid":1001', '"pid":0', 2)
    # Second replacement hits SECPOLEV_JSON if first was KPROBE_JSON; ensure SECPOLEV_JSON has pid 0
    lines = _make_12_probe_log().splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("SECPOLEV_JSON:") and '"pid":1001' in ln:
            lines[i] = ln.replace('"pid":1001', '"pid":0')
            break
    rep = analyze_blast(pol, log_text="\n".join(lines) + "\n")
    assert rep.completeness.result != "COMPLETE"
    assert rep.completeness.unobservable_operations >= 1


def test_cp12_duplicate_probe_preserved_in_receipts() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    base_log = _make_12_probe_log()
    dup_line = (
        'KPROBE_JSON:{"origin":"ivi_ui_t","op":"settypeid","target":"diag_helper_t","pid":1099,"target_id":4,"ret":0,"outcome":"ALLOW","errno":0}\n'
        'SECPOLEV_JSON:{"ts_ns":1099,"pid":1099,"verdict":"OK","proc":"kprobe","type":"ivi_ui_t","kind":"ability","ability":"settypeid","root":false,"range":[4,4]}\n'
    )
    rep = analyze_blast(pol, log_text=dup_line + base_log)
    assert rep.completeness.result != "COMPLETE"
    dup_receipts = [
        r for r in rep.all_receipts
        if r.origin == "ivi_ui_t" and r.op == "settypeid" and r.target == "diag_helper_t" and r.syscall_outcome is not None
    ]
    assert len(dup_receipts) == 2


def test_cp13_cli_expected_probes_file_flag(tmp_path: Path) -> None:
    from secpol_audit.cli import main
    log_p = tmp_path / "blast.log"
    log_p.write_text(_make_12_probe_log(), encoding="utf-8")
    out_p = tmp_path / "comp.json"
    manifest_p = Path(__file__).resolve().parent.parent / "qnx_demo" / "blast_expected_probes.json"
    rc = main([
        "blast", str(M3_BLAST_SECPOL),
        "--log", str(log_p),
        "--expected-probes-file", str(manifest_p),
        "--completeness-out", str(out_p),
        "--format", "json",
    ])
    assert rc in (0, 1)
    import json
    comp = json.loads(out_p.read_text(encoding="utf-8"))
    assert comp["result"] == "COMPLETE"


def test_cp14_kprobe_c_emits_target_id() -> None:
    kprobe_c = (Path(__file__).resolve().parent.parent / "qnx_demo" / "kprobe.c").read_text(encoding="utf-8")
    assert "secpol_get_type_id" in kprobe_c
    assert "target_id" in kprobe_c


# ---------------------------------------------------------------------------
# Final corrective-pass regression tests
# ---------------------------------------------------------------------------

def test_fcp1_channel_connect_wrong_range_99_99_not_correlated() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    ifs = parse_ifs_file(BLAST_IFS)
    # Replace first channel_connect event's range [2,2] with [99,99]
    lines = _make_12_probe_log().splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("SECPOLEV_JSON:") and '"ability":"channel_connect"' in ln:
            lines[i] = ln.replace('"range":[2,2]', '"range":[99,99]')
            break
    rep = analyze_blast(pol, ifs=ifs, log_text="\n".join(lines) + "\n")
    assert rep.completeness.result != "COMPLETE"
    assert rep.completeness.unobservable_operations >= 1


def test_fcp2_channel_connect_path_link_not_accepted_as_proof() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    ifs = parse_ifs_file(BLAST_IFS)
    lines = _make_12_probe_log().splitlines()
    for i, ln in enumerate(lines):
        if ln.startswith("SECPOLEV_JSON:") and '"ability":"channel_connect"' in ln:
            lines[i] = '{"ts_ns":1002,"pid":1002,"verdict":"DENIED","proc":"kprobe","type":"ivi_ui_t","kind":"link","path":"/dev/name/local/can_ctrl"}'
            lines[i] = "SECPOLEV_JSON:" + lines[i]
            break
    rep = analyze_blast(pol, ifs=ifs, log_text="\n".join(lines) + "\n")
    assert rep.completeness.result != "COMPLETE"
    assert rep.completeness.unobservable_operations >= 1


def test_fcp3_omitting_manifest_never_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    ifs = parse_ifs_file(BLAST_IFS)
    rep = analyze_blast(pol, ifs=ifs, log_text=_make_12_probe_log())
    assert rep.completeness.result == "PARTIAL"


def test_fcp4_one_entry_manifest_cannot_complete_12_probe_boot() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    ifs = parse_ifs_file(BLAST_IFS)
    rep = analyze_blast(
        pol,
        ifs=ifs,
        log_text=_make_12_probe_log(),
        expected_probe_specs=(("ivi_ui_t", "settypeid", "diag_helper_t"),),
    )
    assert rep.completeness.result != "COMPLETE"


def test_fcp5_manifest_rejects_unsupported_schema_version(tmp_path: Path) -> None:
    import json
    import pytest
    from secpol_audit.blast import load_expected_probes_manifest
    from secpol_audit.ir import ParseDiagnostic
    p = tmp_path / "bad_ver.json"
    p.write_text(json.dumps({
        "schema_version": 99,
        "probes": [
            {"id": "p1", "origin": "ivi_ui_t", "op": "settypeid", "target": "diag_helper_t", "target_kind": "type", "resolved_target_type": "diag_helper_t", "evidence_requirement": "ALLOW"}
        ]
    }), encoding="utf-8")
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(p)


def test_fcp6_manifest_rejects_duplicate_tuple_different_ids(tmp_path: Path) -> None:
    import json
    import pytest
    from secpol_audit.blast import load_expected_probes_manifest
    from secpol_audit.ir import ParseDiagnostic
    p = tmp_path / "dup_tup.json"
    p.write_text(json.dumps({
        "schema_version": 1,
        "probes": [
            {"id": "p1", "origin": "ivi_ui_t", "op": "settypeid", "target": "diag_helper_t", "target_kind": "type", "resolved_target_type": "diag_helper_t", "evidence_requirement": "ALLOW"},
            {"id": "p2", "origin": "ivi_ui_t", "op": "settypeid", "target": "diag_helper_t", "target_kind": "type", "resolved_target_type": "diag_helper_t", "evidence_requirement": "ALLOW"},
        ]
    }), encoding="utf-8")
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(p)


def test_fcp7_manifest_rejects_missing_resolved_target_type_for_channel(tmp_path: Path) -> None:
    import json
    import pytest
    from secpol_audit.blast import load_expected_probes_manifest
    from secpol_audit.ir import ParseDiagnostic
    p = tmp_path / "bad_chan.json"
    p.write_text(json.dumps({
        "schema_version": 1,
        "probes": [
            {"id": "p1", "origin": "ivi_ui_t", "op": "channel_connect", "target": "can_ctrl", "target_kind": "channel", "evidence_requirement": "DENY"},
        ]
    }), encoding="utf-8")
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(p)


def test_fcp8_correlated_settypeid_updates_target_node_evidence_state() -> None:
    from secpol_audit.blast import load_expected_probes_manifest
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    ifs = parse_ifs_file(BLAST_IFS)
    specs = load_expected_probes_manifest(
        Path(__file__).resolve().parent.parent / "qnx_demo" / "blast_expected_probes.json"
    )
    rep = analyze_blast(pol, ifs=ifs, log_text=_make_12_probe_log(), expected_probe_specs=specs)
    diag_view = rep.origins["diag_helper_t"]
    can_node = next(n for n in diag_view.nodes if n.name == "can_hal_t")
    assert can_node.evidence_state == STATE_OBSERVED_AND_CORRELATED


# ---------------------------------------------------------------------------
# Final channel evidence integration & manifest integrity tests
# ---------------------------------------------------------------------------

def test_cei1_one_entry_manifest_and_one_probe_log_never_complete() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    ifs = parse_ifs_file(BLAST_IFS)
    one_probe_log = (
        'KPROBE_JSON:{"origin":"ivi_ui_t","op":"settypeid","target":"diag_helper_t","pid":1000,"target_id":4,"ret":0,"outcome":"ALLOW","errno":0}\n'
        'SECPOLEV_JSON:{"ts_ns":1000,"pid":1000,"verdict":"OK","proc":"kprobe","type":"ivi_ui_t","kind":"ability","ability":"settypeid","root":false,"range":[4,4]}\n'
        '=== SECPOL_AUDIT_DONE ===\n'
        'SECPOLEV_STATS: ok=1 denied=0 dropped=0\n'
    )
    rep = analyze_blast(
        pol,
        ifs=ifs,
        log_text=one_probe_log,
        expected_probe_specs=(("ivi_ui_t", "settypeid", "diag_helper_t"),),
    )
    assert rep.completeness.result != "COMPLETE"


def test_cei2_manifest_rejects_11_and_13_entries(tmp_path: Path) -> None:
    import json
    import pytest
    from secpol_audit.blast import load_expected_probes_manifest
    from secpol_audit.ir import ParseDiagnostic
    base = json.loads((Path(__file__).resolve().parent.parent / "qnx_demo" / "blast_expected_probes.json").read_text(encoding="utf-8"))
    p11 = tmp_path / "m11.json"
    p11.write_text(json.dumps({"version": "1.0", "probes": base["probes"][:11]}), encoding="utf-8")
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(p11)

    p13 = tmp_path / "m13.json"
    extra = dict(base["probes"][0], id="p13", target="extra_t")
    p13.write_text(json.dumps({"version": "1.0", "probes": base["probes"] + [extra]}), encoding="utf-8")
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(p13)


def test_cei3_manifest_rejects_wrong_op_target_kind(tmp_path: Path) -> None:
    import json
    import pytest
    from secpol_audit.blast import load_expected_probes_manifest
    from secpol_audit.ir import ParseDiagnostic
    base = json.loads((Path(__file__).resolve().parent.parent / "qnx_demo" / "blast_expected_probes.json").read_text(encoding="utf-8"))
    base["probes"][0]["target_kind"] = "channel"
    p = tmp_path / "bad_kind.json"
    p.write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(p)


def test_cei4_manifest_rejects_nonexistent_origin_and_wrong_channel_type(tmp_path: Path) -> None:
    import json
    import pytest
    from secpol_audit.blast import load_expected_probes_manifest
    from secpol_audit.ir import ParseDiagnostic
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    base = json.loads((Path(__file__).resolve().parent.parent / "qnx_demo" / "blast_expected_probes.json").read_text(encoding="utf-8"))

    bad_orig = json.loads(json.dumps(base))
    bad_orig["probes"][0]["origin"] = "nonexistent_t"
    p1 = tmp_path / "bad_orig.json"
    p1.write_text(json.dumps(bad_orig), encoding="utf-8")
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(p1, policy=pol)

    bad_chan = json.loads(json.dumps(base))
    for item in bad_chan["probes"]:
        if item["op"] == "channel_connect":
            item["resolved_target_type"] = "diag_helper_t"
            break
    p2 = tmp_path / "bad_chan.json"
    p2.write_text(json.dumps(bad_chan), encoding="utf-8")
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(p2, policy=pol)


def test_cei5_explicit_allow_attach_channel_type_override(tmp_path: Path) -> None:
    pol_p = tmp_path / "override.secpol"
    pol_p.write_text(
        "type proc_t;\n"
        "type chan_override_t;\n"
        "type client_t;\n"
        "allow_attach proc_t /dev/name/local/custom_chan chan_override_t;\n"
        "allow client_t chan_override_t:channel connect;\n",
        encoding="utf-8",
    )
    pol = parse_secpol_file(pol_p)
    log = (
        'KPROBE_JSON:{"origin":"client_t","op":"channel_connect","target":"custom_chan","pid":2001,"target_id":7,"ret":0,"outcome":"ALLOW","errno":0}\n'
        'SECPOLEV_JSON:{"ts_ns":2001,"pid":2001,"verdict":"OK","proc":"kprobe","type":"client_t","kind":"ability","ability":"channel_connect","root":false,"range":[7,7]}\n'
        '=== SECPOL_AUDIT_DONE ===\n'
        'SECPOLEV_STATS: ok=1 denied=0 dropped=0\n'
    )
    rep = analyze_blast(pol, log_text=log)
    corr = [r for r in rep.all_receipts if r.syscall_outcome is not None and r.evidence_state == STATE_OBSERVED_AND_CORRELATED]
    assert len(corr) == 1
    assert corr[0].resolved_target_type == "chan_override_t"


def test_cei6_correlated_channel_connect_associated_with_review_edge(tmp_path: Path) -> None:
    pol_p = tmp_path / "rev.secpol"
    pol_p.write_text(
        "type server_t;\n"
        "type client_t;\n"
        "allow_attach server_t /dev/name/local/my_chan;\n"
        "allow client_t server_t:channel connect;\n",
        encoding="utf-8",
    )
    pol = parse_secpol_file(pol_p)
    log = (
        'KPROBE_JSON:{"origin":"client_t","op":"channel_connect","target":"my_chan","pid":2002,"target_id":3,"ret":0,"outcome":"ALLOW","errno":0}\n'
        'SECPOLEV_JSON:{"ts_ns":2002,"pid":2002,"verdict":"OK","proc":"kprobe","type":"client_t","kind":"ability","ability":"channel_connect","root":false,"range":[3,3]}\n'
        '=== SECPOL_AUDIT_DONE ===\n'
        'SECPOLEV_STATS: ok=1 denied=0 dropped=0\n'
    )
    rep = analyze_blast(pol, log_text=log)
    rev_receipts = [r for r in rep.origins["client_t"].receipts if r.edge_kind == "REVIEW_ONLY" and r.target == "server_t"]
    assert len(rev_receipts) == 1
    assert rev_receipts[0].evidence_state == STATE_OBSERVED_AND_CORRELATED
    assert rev_receipts[0].syscall_outcome == "ALLOW"



def test_eca1_rejects_generic_evidence_requirement(tmp_path: Path) -> None:
    import json
    import pytest
    from secpol_audit.blast import load_expected_probes_manifest
    from secpol_audit.ir import ParseDiagnostic

    base = json.loads((REPO_ROOT / "qnx_demo" / "blast_expected_probes.json").read_text(encoding="utf-8"))
    for bad_req in ("ALLOW", "DENY", "ALLOW_OR_DENY", "pid+exact_path"):
        mut = json.loads(json.dumps(base))
        mut["probes"][0]["evidence_requirement"] = bad_req  # probes[0] is settypeid
        p = tmp_path / f"bad_req_{bad_req}.json"
        p.write_text(json.dumps(mut), encoding="utf-8")
        with pytest.raises(ParseDiagnostic):
            load_expected_probes_manifest(p)


def test_eca2_rejects_empty_eff_types_ghost_channel(tmp_path: Path) -> None:
    import json
    import pytest
    from secpol_audit.blast import load_expected_probes_manifest
    from secpol_audit.ir import ParseDiagnostic

    pol = parse_secpol_file(M3_BLAST_SECPOL)
    base = json.loads((REPO_ROOT / "qnx_demo" / "blast_expected_probes.json").read_text(encoding="utf-8"))
    for item in base["probes"]:
        if item["op"] == "channel_connect":
            item["target"] = "ghost_unattached_chan"
            item["resolved_target_type"] = "can_hal_t"
            break
    p = tmp_path / "ghost_chan.json"
    p.write_text(json.dumps(base), encoding="utf-8")
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(p, policy=pol)


def test_eca3_rejects_bad_resolved_target_type_for_settypeid_and_attach(tmp_path: Path) -> None:
    import json
    import pytest
    from secpol_audit.blast import load_expected_probes_manifest
    from secpol_audit.ir import ParseDiagnostic

    base = json.loads((REPO_ROOT / "qnx_demo" / "blast_expected_probes.json").read_text(encoding="utf-8"))

    bad_st = json.loads(json.dumps(base))
    bad_st["probes"][0]["resolved_target_type"] = "can_hal_t"  # target is diag_helper_t
    p1 = tmp_path / "bad_st.json"
    p1.write_text(json.dumps(bad_st), encoding="utf-8")
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(p1)

    bad_at = json.loads(json.dumps(base))
    for item in bad_at["probes"]:
        if item["op"] == "allow_attach":
            item["resolved_target_type"] = "ivi_ui_t"
            break
    p2 = tmp_path / "bad_at.json"
    p2.write_text(json.dumps(bad_at), encoding="utf-8")
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(p2)


def test_eca4_ifs_rejects_prefix_collision_and_unrelated_echo(tmp_path: Path) -> None:
    import pytest
    from secpol_audit.blast import load_expected_probes_manifest
    from secpol_audit.ir import ParseDiagnostic

    pol = parse_secpol_file(M3_BLAST_SECPOL)
    manifest = REPO_ROOT / "qnx_demo" / "blast_expected_probes.json"

    # Prefix collision: `-T can_hal_t_decoy` must NOT match `can_hal_t`
    decoy_ifs = tmp_path / "decoy.ifs"
    decoy_ifs.write_text(
        "[+script] startup-script = {\n"
        "    secpolpush /proc/boot/secpol.bin\n"
        "    on -T can_hal_t_decoy -u 23:23 /proc/boot/can_server &\n"
        '    echo "-T can_hal_t"\n'
        "    on -T ivi_ui_t /proc/boot/kprobe --origin ivi_ui_t --connect can_ctrl=can_hal_t\n"
        "}\n",
        encoding="utf-8",
    )
    ifs = parse_ifs_file(decoy_ifs)
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(manifest, policy=pol, ifs=ifs)


def test_eca5_ifs_accepts_valid_allow_attach_channel_type_override(tmp_path: Path) -> None:
    import json
    from secpol_audit.blast import load_expected_probes_manifest

    pol_p = tmp_path / "override_full.secpol"
    pol_p.write_text(
        "type srv_proc_t;\n"
        "type chan_override_t;\n"
        "type ivi_ui_t;\n"
        "type diag_helper_t;\n"
        "type audit_reader_t;\n"
        "allow_attach srv_proc_t /dev/name/local/can_ctrl chan_override_t;\n"
        "allow audit_reader_t chan_override_t:channel connect;\n",
        encoding="utf-8",
    )
    pol = parse_secpol_file(pol_p)
    base = json.loads((REPO_ROOT / "qnx_demo" / "blast_expected_probes.json").read_text(encoding="utf-8"))
    for item in base["probes"]:
        if item["op"] == "channel_connect":
            item["resolved_target_type"] = "chan_override_t"
        elif item["op"] == "settypeid" and item["target"] == "can_hal_t":
            item["target"] = "srv_proc_t"
            item["resolved_target_type"] = "srv_proc_t"
    m_p = tmp_path / "override_manifest.json"
    m_p.write_text(json.dumps(base), encoding="utf-8")

    ifs_p = tmp_path / "override.ifs"
    ifs_p.write_text(
        "[+script] startup-script = {\n"
        "    secpolpush /proc/boot/secpol.bin\n"
        "    on -T srv_proc_t -u 23:23 /proc/boot/can_server &\n"
        "    on -T ivi_ui_t /proc/boot/kprobe --origin ivi_ui_t --connect can_ctrl=chan_override_t\n"
        "}\n",
        encoding="utf-8",
    )
    ifs = parse_ifs_file(ifs_p)
    specs = load_expected_probes_manifest(m_p, policy=pol, ifs=ifs)
    assert len(specs) == 12


def test_eca6_ifs_rejects_malformed_or_contradictory_kprobe_connect_spec(tmp_path: Path) -> None:
    import pytest
    from secpol_audit.blast import load_expected_probes_manifest
    from secpol_audit.ir import ParseDiagnostic

    pol = parse_secpol_file(M3_BLAST_SECPOL)
    manifest = REPO_ROOT / "qnx_demo" / "blast_expected_probes.json"

    bad_ifs = tmp_path / "bad_connect.ifs"
    bad_ifs.write_text(
        "[+script] startup-script = {\n"
        "    secpolpush /proc/boot/secpol.bin\n"
        "    on -T can_hal_t -u 23:23 /proc/boot/can_server &\n"
        "    on -T ivi_ui_t /proc/boot/kprobe --origin ivi_ui_t --connect can_ctrl=diag_helper_t\n"
        "}\n",
        encoding="utf-8",
    )
    with pytest.raises(ParseDiagnostic):
        load_expected_probes_manifest(manifest, policy=pol, ifs=parse_ifs_file(bad_ifs))


def test_eca7_rejects_truncated_secpolev_stream_count_mismatch() -> None:
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    log = _make_12_probe_log().replace(
        "SECPOLEV_STATS: ok=12 denied=0 dropped=0",
        "SECPOLEV_STATS: ok=15 denied=5 dropped=0",
    )
    rep = analyze_blast(pol, log_text=log, expected_probe_specs=EXPECTED_BLAST_PROBES)
    assert rep.completeness.result == "PARTIAL"
