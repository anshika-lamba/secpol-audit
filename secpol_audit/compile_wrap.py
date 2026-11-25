"""Honest QNX 8.0 `secpolcompile` wrapper (`pass` / `fail` / `skipped`)."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any


@dataclass(frozen=True)
class CompileResult:
    """Result of delegating policy compilation to QNX `secpolcompile`."""

    status: str  # "pass" | "fail" | "skipped"
    binary: str | None
    returncode: int | None
    stdout: str
    stderr: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "binary": self.binary,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "message": self.message,
        }


def _resolve_binary(secpolcompile_bin: str | None) -> str | None:
    if secpolcompile_bin:
        p = Path(secpolcompile_bin)
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
        return shutil.which(secpolcompile_bin)
    return shutil.which("secpolcompile")


def run_secpolcompile(
    policy_path: str | Path,
    *,
    secpolcompile_bin: str | None = None,
    output_path: str | Path | None = None,
    timeout: int = 30,
) -> CompileResult:
    """Invoke QNX `secpolcompile` if available; honestly report `skipped` if absent."""
    binary = _resolve_binary(secpolcompile_bin)
    if binary is None:
        detail = (
            f"Requested binary '{secpolcompile_bin}' was not found or is not executable"
            if secpolcompile_bin
            else "secpolcompile not found on PATH (QNX SDP 8.0 not installed on host)"
        )
        return CompileResult(
            status="skipped",
            binary=None,
            returncode=None,
            stdout="",
            stderr="",
            message=f"{detail}; external secpolcompile validation skipped.",
        )

    tmp_file: Path | None = None
    try:
        if output_path is not None:
            out_target = Path(output_path)
        else:
            fd, tmp_name = tempfile.mkstemp(prefix="secpol_audit_", suffix=".bin")
            os.close(fd)
            tmp_file = Path(tmp_name)
            out_target = tmp_file

        proc = subprocess.run(
            [binary, "-o", str(out_target), str(policy_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if proc.returncode == 0:
            return CompileResult(
                status="pass",
                binary=binary,
                returncode=0,
                stdout=proc.stdout,
                stderr=proc.stderr,
                message=f"secpolcompile succeeded via '{binary}'.",
            )
        return CompileResult(
            status="fail",
            binary=binary,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            message=f"secpolcompile failed with exit code {proc.returncode}: {proc.stderr.strip() or proc.stdout.strip()}",
        )
    except subprocess.TimeoutExpired as exc:
        return CompileResult(
            status="fail",
            binary=binary,
            returncode=None,
            stdout=str(exc.stdout or ""),
            stderr=str(exc.stderr or ""),
            message=f"secpolcompile timed out after {timeout}s.",
        )
    except OSError as exc:
        return CompileResult(
            status="fail",
            binary=binary,
            returncode=None,
            stdout="",
            stderr=str(exc),
            message=f"Failed to execute secpolcompile '{binary}': {exc}",
        )
    finally:
        if tmp_file is not None and tmp_file.exists():
            try:
                tmp_file.unlink()
            except OSError:
                pass
