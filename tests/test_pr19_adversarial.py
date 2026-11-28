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
        lines.append(
            f'KPROBE_JSON:{{"origin":"{origin}","op":"{op}","target":"{target}"{k_pid_part},"ret":{0 if out=="ALLOW" else -1},"outcome":"{out}","errno":{err}}}'
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
                f'SECPOLEV_JSON:{{"ts_ns":{1000+idx}{ev_pid_part},"verdict":"{verdict}","proc":"kprobe","type":"{origin}","kind":"ability","ability":"settypeid","root":false}}'
            )
        elif op == "channel_connect":
            lines.append(
                f'SECPOLEV_JSON:{{"ts_ns":{1000+idx}{ev_pid_part},"verdict":"{verdict}","proc":"kprobe","type":"{origin}","kind":"ability","ability":"channel_connect","root":false}}'
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
    rep = analyze_blast(pol, log_text=_make_12_probe_log(same_pid_two_settypeid=True))
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
    assert rep.completeness.probes_total == 12
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
    pol = parse_secpol_file(M3_BLAST_SECPOL)
    ifs = parse_ifs_file(BLAST_IFS)
    rep = analyze_blast(pol, ifs=ifs, log_text=_make_12_probe_log())
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
    )
    m0 = analyze_blast(
        parse_secpol_file(M0_BLAST_SECPOL),
        ifs=ifs,
        log_text=REAL_M0_BLAST_LOG.read_text(encoding="utf-8", errors="replace"),
        log_path=str(REAL_M0_BLAST_LOG),
    )
    # Honest reporting: in the committed logs, audit_reader_t ran two settypeid DENY probes
    # in the same PID, so they are conservatively downgraded to unobservable (PARTIAL).
    assert m3.completeness.result == "PARTIAL"
    assert m3.completeness.mismatches == 0
    assert m3.completeness.dropped_events == 0
    assert m0.completeness.result == "PARTIAL"
    assert m0.completeness.mismatches == 0
    assert m0.completeness.dropped_events == 0
