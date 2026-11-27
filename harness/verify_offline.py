#!/usr/bin/env python3
"""Replay QEMU serial logs against `secpol-audit` static predictions (`make verify-offline`).

Honesty guardrail:
- By default, inspects `evidence/qemu_logs/` for real QNX 8.0 QEMU TCG boot logs.
- If no real logs are present yet, reports `NOT RUN (no real QNX 8.0 QEMU logs in evidence/qemu_logs/)`
  rather than fabricating runtime observations.
- Pass `--fixtures` to verify the offline replay pipeline against clearly labeled synthetic
  unit-test fixtures in `tests/fixtures/sample_qemu_logs/`.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys

# Ensure repo root is importable when invoked as a script
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from harness.observe import SerialObservation, observe_serial_file  # noqa: E402
from secpol_audit.checks import run_all_checks  # noqa: E402
from secpol_audit.parser_ifs import parse_ifs_file  # noqa: E402
from secpol_audit.parser_secpol import parse_secpol_file  # noqa: E402
from secpol_audit.runtime import verify_runtime  # noqa: E402


@dataclass(frozen=True)
class MutantSpec:
    name: str
    policy_path: Path
    ifs_path: Path | None
    log_filename: str


MUTANT_SPECS = [
    MutantSpec(
        name="M0_clean",
        policy_path=REPO_ROOT / "qnx_demo/mutants/M0_clean.secpol",
        ifs_path=None,
        log_filename="M0_clean.log",
    ),
    MutantSpec(
        name="M1_no_connect",
        policy_path=REPO_ROOT / "qnx_demo/mutants/M1_no_connect.secpol",
        ifs_path=None,
        log_filename="M1_no_connect.log",
    ),
    MutantSpec(
        name="M2_untyped_server",
        policy_path=REPO_ROOT / "qnx_demo/mutants/M0_clean.secpol",
        ifs_path=REPO_ROOT / "qnx_demo/mutants/M2_untyped_server.ifs",
        log_filename="M2_untyped_server.log",
    ),
    MutantSpec(
        name="M3_2hop_escalate",
        policy_path=REPO_ROOT / "qnx_demo/mutants/M3_2hop_escalate.secpol",
        ifs_path=None,
        log_filename="M3_2hop_escalate.log",
    ),
    MutantSpec(
        name="M3_fixed",
        policy_path=REPO_ROOT / "qnx_demo/mutants/M3_fixed.secpol",
        ifs_path=None,
        log_filename="M3_fixed.log",
    ),
]


def _summarize_prediction(spec: MutantSpec) -> tuple[str, bool, bool]:
    """Return `(prediction_text, expects_escalation, expects_untyped)`."""
    policy = parse_secpol_file(spec.policy_path)
    ifs = parse_ifs_file(spec.ifs_path) if spec.ifs_path else None
    findings, path_res = run_all_checks(policy, ifs=ifs, include_paths=True)

    has_esc = len(path_res.escalation_paths) > 0
    has_untyped = any(f.rule_id == "UNTYPED_IFS_SERVICE" for f in findings)

    if has_esc:
        return f"FAIL: {path_res.escalation_paths[0].chain_str()}", True, has_untyped
    if has_untyped:
        return "FAIL: UNTYPED_IFS_SERVICE (can_server)", False, True
    return "PASS (0 chains, 0 wiring errors)", False, False


def _check_agreement(
    spec: MutantSpec,
    obs: SerialObservation,
    *,
    expects_escalation: bool,
    expects_untyped: bool,
) -> tuple[str, bool]:
    policy = parse_secpol_file(spec.policy_path)
    ifs = parse_ifs_file(spec.ifs_path) if spec.ifs_path else None
    rt = verify_runtime(obs.pidin_processes, policy=policy, ifs=ifs, source_path=obs.log_path)
    observed_untyped = any(f.rule_id == "RUNTIME_UNTYPED_PROCESS" for f in rt.findings)
    observed_escalation = obs.hop2_result == "GRANTED"

    parts = []
    if obs.direct_result:
        parts.append(f"direct={obs.direct_result}")
    if obs.hop1_spawn:
        parts.append(f"hop1={obs.hop1_spawn}")
    if obs.hop2_result:
        parts.append(f"hop2={obs.hop2_result}")
    elif obs.hop2_spawn:
        parts.append(f"hop2_spawn={obs.hop2_spawn}")
    if observed_untyped:
        parts.append("pidin=UNTYPED")
    observed_str = ", ".join(parts) or "no telemetry"

    agrees = (
        (observed_escalation == expects_escalation)
        and (observed_untyped == expects_untyped)
        and bool(obs.completed)
        and (obs.mutant == spec.name)
    )
    return observed_str, agrees


def run_verification(log_dir: Path, *, allow_missing: bool = False) -> int:
    print(f"Log directory: {log_dir}")
    print("-" * 108)
    print(f"{'Mutant':<20} | {'Static Prediction (secpol-audit)':<42} | {'Observed Log':<28} | {'Status'}")
    print("-" * 108)

    all_ok = True
    any_missing = False

    for spec in MUTANT_SPECS:
        pred_text, exp_esc, exp_untyped = _summarize_prediction(spec)
        log_file = log_dir / spec.log_filename
        if not log_file.is_file():
            any_missing = True
            if not allow_missing:
                all_ok = False
            print(f"{spec.name:<20} | {pred_text:<42} | {'(no QEMU log present)':<28} | {'SKIPPED' if allow_missing else 'MISSING'}")
            continue

        raw_text = log_file.read_text(encoding="utf-8", errors="replace")
        obs = observe_serial_file(log_file)
        obs_text, agrees = _check_agreement(
            spec,
            obs,
            expects_escalation=exp_esc,
            expects_untyped=exp_untyped,
        )
        # Fail closed on nonzero dropped events or INCONCLUSIVE/EEXIST probes if present
        if "SECPOLEV_STATS:" in raw_text or "KPROBE_JSON:" in raw_text:
            from secpol_audit.blast import parse_blast_log_text
            try:
                kps, pev = parse_blast_log_text(raw_text, str(log_file))
                if pev and pev.stats and pev.stats.dropped > 0:
                    agrees = False
                    obs_text += f", dropped={pev.stats.dropped}"
                if any(kp.classification in ("INCONCLUSIVE", "SETUP_FAILURE") for kp in kps):
                    agrees = False
                    obs_text += ", INCONCLUSIVE"
            except Exception:
                agrees = False
                obs_text += ", PARSE_ERROR"

        suffix = " (fixture)" if obs.is_synthetic_fixture else ""
        status = f"MATCH{suffix}" if agrees else f"MISMATCH{suffix}"
        if not agrees:
            all_ok = False
        print(f"{spec.name:<20} | {pred_text:<42} | {obs_text:<28} | {status}")

    print("-" * 108)
    if any_missing:
        print(
            "NOTE: Real QNX 8.0 QEMU logs were not found in this directory.\n"
            "      On a host with QNX SDP 8.0 + QEMU x86_64, run `make qemu-mutants` to populate evidence/qemu_logs/.\n"
            "      To test the replay pipeline with synthetic unit-test fixtures, run:\n"
            "        python3 harness/verify_offline.py --fixtures"
        )
        if not allow_missing:
            return 1
    return 0 if all_ok else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Replay QEMU serial logs against secpol-audit static predictions."
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=REPO_ROOT / "evidence/qemu_logs",
        help="Directory containing mutant serial logs (default: evidence/qemu_logs)",
    )
    parser.add_argument(
        "--fixtures",
        action="store_true",
        help="Replay clearly labeled synthetic unit-test fixtures from tests/fixtures/sample_qemu_logs/",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="Allow missing log files without failing closed",
    )
    args = parser.parse_args(argv)
    target_dir = (REPO_ROOT / "tests/fixtures/sample_qemu_logs") if args.fixtures else args.log_dir
    return run_verification(target_dir, allow_missing=args.allow_missing)


if __name__ == "__main__":
    sys.exit(main())
