"""Regression tests for `harness/run_qemu.sh` using a fake `qemu-system-x86_64` in PATH."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN_QEMU = REPO_ROOT / "harness" / "run_qemu.sh"


def _run_fake_qemu(
    tmp_path: Path,
    *,
    qemu_script: str,
    timeout_sec: str = "2",
    extra_args: list[str] | None = None,
    fake_tee_fail: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)

    qemu_bin = bin_dir / "qemu-system-x86_64"
    qemu_bin.write_text(f"#!/usr/bin/env bash\n{qemu_script}\n", encoding="utf-8")
    qemu_bin.chmod(0o755)

    if fake_tee_fail:
        tee_bin = bin_dir / "tee"
        tee_bin.write_text("#!/usr/bin/env bash\nexit 1\n", encoding="utf-8")
        tee_bin.chmod(0o755)

    ifs_img = tmp_path / "test.ifs"
    ifs_img.write_bytes(b"IFS")
    out_log = tmp_path / "serial.log"

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"

    cmd = ["bash", str(RUN_QEMU)]
    if extra_args:
        cmd.extend(extra_args)
    cmd.extend([str(ifs_img), str(out_log), timeout_sec])

    res = subprocess.run(cmd, env=env, capture_output=True, text=True, check=False)
    return res, out_log


# Positive 1: emits marker + required stats, exits 0
def test_pos_1_clean_exit_with_post_marker(tmp_path: Path) -> None:
    res, log = _run_fake_qemu(
        tmp_path,
        qemu_script='printf "BOOT\\r\\n=== SECPOL_AUDIT_DONE ===\\r\\nSECPOLEV_STATS: ok=5 denied=0 dropped=0\\r\\n"\nexit 0',
        extra_args=["--require-post-marker", "SECPOLEV_STATS:"],
    )
    assert res.returncode == 0
    text = log.read_text(encoding="utf-8")
    assert "=== SECPOL_AUDIT_DONE ===" in text
    assert "SECPOLEV_STATS: ok=5 denied=0 dropped=0" in text


# Positive 2: emits marker + stats, idles until timeout (124) -> succeeds
def test_pos_2_idle_timeout_after_post_marker_succeeds(tmp_path: Path) -> None:
    res, log = _run_fake_qemu(
        tmp_path,
        qemu_script='printf "BOOT\\r\\n=== SECPOL_AUDIT_DONE ===\\r\\nSECPOLEV_STATS: ok=2 denied=0 dropped=0\\r\\n"\nsleep 5',
        timeout_sec="1",
        extra_args=["--require-post-marker", "SECPOLEV_STATS:"],
    )
    assert res.returncode == 0
    assert "SECPOLEV_STATS: ok=2 denied=0 dropped=0" in log.read_text(encoding="utf-8")


# Positive 3: complete output after marker is retained
def test_pos_3_post_marker_output_retained(tmp_path: Path) -> None:
    res, log = _run_fake_qemu(
        tmp_path,
        qemu_script='printf "=== SECPOL_AUDIT_DONE ===\\nPOST_LINE_1\\nSECPOLEV_STATS: ok=1 denied=0 dropped=0\\nPOST_LINE_2\\n"\nexit 0',
    )
    assert res.returncode == 0
    text = log.read_text(encoding="utf-8")
    assert "POST_LINE_1" in text
    assert "POST_LINE_2" in text


# Positive 4: existing invocation without --require-post-marker remains compatible
def test_pos_4_compat_without_post_marker(tmp_path: Path) -> None:
    res, log = _run_fake_qemu(
        tmp_path,
        qemu_script='printf "=== SECPOL_AUDIT_DONE ===\\r\\n"\nexit 0',
    )
    assert res.returncode == 0
    assert "=== SECPOL_AUDIT_DONE ===" in log.read_text(encoding="utf-8")


# Negative 5: timeout before completion marker -> fails (124)
def test_neg_5_timeout_before_marker_fails(tmp_path: Path) -> None:
    res, log = _run_fake_qemu(
        tmp_path,
        qemu_script='printf "BOOTING...\\n"\nsleep 5',
        timeout_sec="1",
    )
    assert res.returncode == 124
    assert "=== SECPOL_AUDIT_DONE ===" not in log.read_text(encoding="utf-8")


# Negative 6: prints marker but omits required post-marker record -> fails (1)
def test_neg_6_missing_required_post_marker_fails(tmp_path: Path) -> None:
    res, _ = _run_fake_qemu(
        tmp_path,
        qemu_script='printf "=== SECPOL_AUDIT_DONE ===\\n"\nexit 0',
        extra_args=["--require-post-marker", "SECPOLEV_STATS:"],
    )
    assert res.returncode == 1


# Negative 7: prints marker and stats, then exits nonzero (e.g. crash rc=139) -> fails
def test_neg_7_nonzero_qemu_exit_after_marker_fails(tmp_path: Path) -> None:
    res, _ = _run_fake_qemu(
        tmp_path,
        qemu_script='printf "=== SECPOL_AUDIT_DONE ===\\nSECPOLEV_STATS: ok=1 denied=0 dropped=0\\n"\nexit 139',
        extra_args=["--require-post-marker", "SECPOLEV_STATS:"],
    )
    assert res.returncode == 139


# Negative 8: logging pipeline (tee) fails -> fails
def test_neg_8_logging_pipeline_failure_fails(tmp_path: Path) -> None:
    res, _ = _run_fake_qemu(
        tmp_path,
        qemu_script='printf "=== SECPOL_AUDIT_DONE ===\\n"\nexit 0',
        fake_tee_fail=True,
    )
    assert res.returncode != 0


# Negative 9: truncated/incomplete output (marker missing on clean exit) -> fails
def test_neg_9_truncated_output_fails(tmp_path: Path) -> None:
    res, _ = _run_fake_qemu(
        tmp_path,
        qemu_script='printf "=== SECPOL_AUDIT_"\nexit 0',
    )
    assert res.returncode == 1


# Negative 10: required terminal record appears BEFORE rather than AFTER completion marker -> fails
def test_neg_10_post_marker_before_done_fails(tmp_path: Path) -> None:
    res, _ = _run_fake_qemu(
        tmp_path,
        qemu_script='printf "SECPOLEV_STATS: ok=1 denied=0 dropped=0\\n=== SECPOL_AUDIT_DONE ===\\n"\nexit 0',
        extra_args=["--require-post-marker", "SECPOLEV_STATS:"],
    )
    assert res.returncode == 1


# Negative 11: natural QEMU exit 124 after valid marker & stats -> MUST fail (not a timeout)
def test_neg_11_natural_qemu_exit_124_after_valid_stats_fails(tmp_path: Path) -> None:
    res, _ = _run_fake_qemu(
        tmp_path,
        qemu_script='printf "=== SECPOL_AUDIT_DONE ===\\r\\nSECPOLEV_STATS: ok=5 denied=0 dropped=0\\r\\n"\nexit 124',
        timeout_sec="5",
        extra_args=["--require-post-marker", "SECPOLEV_STATS:"],
    )
    assert res.returncode == 124


# Negative 12: incomplete or malformed SECPOLEV_STATS records -> MUST fail
def test_neg_12_incomplete_or_malformed_secpolev_stats_fails(tmp_path: Path) -> None:
    bad_records = [
        "SECPOLEV_STATS:",
        "SECPOLEV_STATS: ok=327 denied=",
        "SECPOLEV_STATS: ok=1 denied=0",
        "SECPOLEV_STATS: ok=abc denied=0 dropped=0",
    ]
    for idx, rec in enumerate(bad_records):
        sub = tmp_path / f"case_{idx}"
        sub.mkdir()
        res, _ = _run_fake_qemu(
            sub,
            qemu_script=f'printf "=== SECPOL_AUDIT_DONE ===\\r\\n{rec}\\r\\n"\nexit 0',
            extra_args=["--require-post-marker", "SECPOLEV_STATS:"],
        )
        assert res.returncode == 1, f"Expected failure for malformed stats: {rec!r}"


def test_makefile_loops_propagate_run_qemu_failure() -> None:
    makefile_text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    run_lines = [ln for ln in makefile_text.splitlines() if "bash harness/run_qemu.sh" in ln]
    assert len(run_lines) >= 4
    # Every loop invocation (lines with $$m) must propagate failure via || exit $$?
    loop_lines = [ln for ln in run_lines if "$$m" in ln]
    assert len(loop_lines) == 3
    for ln in loop_lines:
        assert "|| exit $$?" in ln, f"Missing failure propagation in Makefile line: {ln}"
