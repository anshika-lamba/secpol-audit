"""Phase 2 tests: generalized probe generator, kernel policy-ID binding, and 12-service ADAS channel-override matrix."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from secpol_audit.blast import (
    EXPECTED_BLAST_PROBES,
    analyze_blast,
    extract_ifs_scheduled_probes,
    generate_expected_probes_manifest,
    load_expected_probes_manifest,
)
from secpol_audit.cli import main as cli_main
from secpol_audit.ir import ParseDiagnostic
from secpol_audit.parser_ifs import parse_ifs_file
from secpol_audit.parser_secpol import parse_secpol_file
from secpol_audit.paths import analyze_paths

REPO_ROOT = Path(__file__).resolve().parent.parent
ADAS_VULN = REPO_ROOT / "qnx_demo" / "mutants" / "ADAS_12svc_blast.secpol"
ADAS_FIXED = REPO_ROOT / "qnx_demo" / "mutants" / "ADAS_12svc_fixed_blast.secpol"
ADAS_IFS = REPO_ROOT / "qnx_demo" / "build_adas_blast.ifs.in"
ADAS_MANIFEST = REPO_ROOT / "qnx_demo" / "adas_expected_probes.json"
M3_BLAST = REPO_ROOT / "qnx_demo" / "mutants" / "M3_blast_escalate.secpol"
BLAST_IFS = REPO_ROOT / "qnx_demo" / "build_blast.ifs.in"


def test_p2_1_adas_16_probe_manifest_validates_with_channel_type_override() -> None:
    pol = parse_secpol_file(ADAS_VULN)
    ifs = parse_ifs_file(ADAS_IFS)
    specs = load_expected_probes_manifest(ADAS_MANIFEST, policy=pol, ifs=ifs)
    assert len(specs) == 16
    scheduled = extract_ifs_scheduled_probes(ifs)
    assert len(scheduled) == 16
    assert set(scheduled) == set(specs)

    # Vulnerable has 2-hop escalation; fixed has 0 escalation chains
    vuln_paths = analyze_paths(pol, ifs=ifs)
    assert any(ep.chain_str() == "ivi_ui_t -> diag_helper_t -> can_hal_t" for ep in vuln_paths.escalation_paths)
    fixed_pol = parse_secpol_file(ADAS_FIXED)
    fixed_paths = analyze_paths(fixed_pol, ifs=ifs)
    assert fixed_paths.escalation_paths == []


def test_p2_2_generate_probes_roundtrip_cli_passes_strict_validation(tmp_path: Path) -> None:
    out_m = tmp_path / "gen_manifest.json"
    out_ifs = tmp_path / "gen_kprobe.ifs.inc"
    rc = cli_main([
        "generate-probes",
        str(ADAS_VULN),
        "--ifs",
        str(ADAS_IFS),
        "--origins",
        "ivi_ui_t,diag_helper_t,ota_agent_t,planner_t",
        "--out-manifest",
        str(out_m),
        "--out-ifs-snippet",
        str(out_ifs),
    ])
    assert rc == 0
    assert out_m.is_file()
    assert out_ifs.is_file()

    # Build a synthetic IFS containing the server + generated kprobe lines and validate round-trip
    gen_ifs = tmp_path / "full.ifs"
    gen_ifs.write_text(
        "[+script] startup-script = {\n"
        "    secpolpush /proc/boot/secpol.bin\n"
        "    on -T can_hal_t -u 23:23 /proc/boot/can_server &\n"
        + "\n".join("    " + ln for ln in out_ifs.read_text(encoding="utf-8").splitlines() if ln.strip())
        + "\n}\n",
        encoding="utf-8",
    )
    pol = parse_secpol_file(ADAS_VULN)
    ifs = parse_ifs_file(gen_ifs)
    specs = load_expected_probes_manifest(out_m, policy=pol, ifs=ifs)
    assert len(specs) >= 12


def test_p2_3_kernel_policy_id_zero_forbids_complete_and_expected_id_binds_provenance() -> None:
    pol = parse_secpol_file(M3_BLAST)
    ifs = parse_ifs_file(BLAST_IFS)
    from tests.test_pr19_adversarial import _make_12_probe_log

    # Policy ID == 0 (no active QNX security policy) must fail closed to PARTIAL
    log_zero = "SECPOLEV_POLICY_ID: 0\n" + _make_12_probe_log()
    rep_zero = analyze_blast(pol, ifs=ifs, log_text=log_zero, expected_probe_specs=EXPECTED_BLAST_PROBES)
    assert rep_zero.completeness.kernel_policy_id == 0
    assert rep_zero.completeness.result == "PARTIAL"

    # Non-zero policy ID matching expected_policy_id achieves COMPLETE
    log_ok = "SECPOLEV_POLICY_ID: 42\n" + _make_12_probe_log()
    rep_ok = analyze_blast(
        pol, ifs=ifs, log_text=log_ok, expected_probe_specs=EXPECTED_BLAST_PROBES, expected_policy_id=42
    )
    assert rep_ok.completeness.kernel_policy_id == 42
    assert rep_ok.completeness.result == "COMPLETE"

    # Mismatched expected_policy_id fails closed to PARTIAL
    rep_bad = analyze_blast(
        pol, ifs=ifs, log_text=log_ok, expected_probe_specs=EXPECTED_BLAST_PROBES, expected_policy_id=99
    )
    assert rep_bad.completeness.result == "PARTIAL"


def test_p2_4_adas_16_probe_channel_override_boot_reaches_complete() -> None:
    pol = parse_secpol_file(ADAS_VULN)
    ifs = parse_ifs_file(ADAS_IFS)
    specs = load_expected_probes_manifest(ADAS_MANIFEST, policy=pol, ifs=ifs)

    # Synthetic 16-probe QNX 8.0 log for ADAS_12svc_blast with can_chan_t override (type_id=3)
    tid_map = {"can_hal_t": 2, "can_chan_t": 3, "diag_helper_t": 11, "ivi_ui_t": 12}
    outcomes = [
        ("ALLOW", 0), ("DENY", 1), ("DENY", 1), ("DENY", 13),   # ivi_ui_t
        ("ALLOW", 0), ("DENY", 1), ("DENY", 1), ("DENY", 13),   # diag_helper_t
        ("DENY", 1),  ("DENY", 1), ("DENY", 1), ("DENY", 13),   # ota_agent_t
        ("DENY", 1),  ("DENY", 1), ("ALLOW", 0), ("ALLOW", 0),  # planner_t (allowed to connect to can_chan_t!)
    ]
    lines = ["SECPOLEV_POLICY_ID: 7"]
    ok_n = 0
    den_n = 0
    for idx, ((origin, op, target), (out, err)) in enumerate(zip(specs, outcomes)):
        pid = 2000 + idx
        verdict = "OK" if out == "ALLOW" else "DENIED"
        if out == "ALLOW":
            ok_n += 1
        else:
            den_n += 1
        if op == "settypeid":
            tid = tid_map[target]
            lines.append(f'KPROBE_JSON:{{"origin":"{origin}","op":"settypeid","target":"{target}","pid":{pid},"target_id":{tid},"ret":{0 if out=="ALLOW" else -1},"outcome":"{out}","errno":{err}}}')
            lines.append(f'SECPOLEV_JSON:{{"ts_ns":{3000+idx},"pid":{pid},"verdict":"{verdict}","proc":"kprobe","type":"{origin}","kind":"ability","ability":"settypeid","root":false,"range":[{tid},{tid}]}}')
        elif op == "channel_connect":
            tid = tid_map["can_chan_t"]
            lines.append(f'KPROBE_JSON:{{"origin":"{origin}","op":"channel_connect","target":"{target}","pid":{pid},"target_id":{tid},"ret":{0 if out=="ALLOW" else -1},"outcome":"{out}","errno":{err}}}')
            lines.append(f'SECPOLEV_JSON:{{"ts_ns":{3000+idx},"pid":{pid},"verdict":"{verdict}","proc":"kprobe","type":"{origin}","kind":"ability","ability":"channel_connect","root":false,"range":[{tid},{tid}]}}')
        else:
            lines.append(f'KPROBE_JSON:{{"origin":"{origin}","op":"allow_attach","target":"{target}","pid":{pid},"ret":{0 if out=="ALLOW" else -1},"outcome":"{out}","errno":{err}}}')
            lines.append(f'SECPOLEV_JSON:{{"ts_ns":{3000+idx},"pid":{pid},"verdict":"{verdict}","proc":"kprobe","type":"{origin}","kind":"attach","path":"{target}","status":"ok"}}')
    lines.append("=== SECPOL_AUDIT_DONE ===")
    lines.append(f"SECPOLEV_STATS: ok={ok_n} denied={den_n} dropped=0")

    rep = analyze_blast(pol, ifs=ifs, log_text="\n".join(lines) + "\n", expected_probe_specs=specs, expected_policy_id=7)
    assert rep.completeness.result == "COMPLETE"
    assert rep.completeness.probes_total == 16
    assert rep.completeness.probes_completed == 16
    assert rep.completeness.kernel_events_correlated == 16
    assert rep.completeness.kernel_policy_id == 7
