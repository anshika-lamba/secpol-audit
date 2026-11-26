#!/usr/bin/env python3
"""Extract QNX 8.0 `secpolgenerate` policy/unused/errors captures from a QEMU serial log.

Splits a captured serial log containing `=== SECPOLGEN_*_BEGIN ===` / `END` markers into:
  - `<out-dir>/qnx8_generated.secpol`
  - `<out-dir>/qnx8_unused.txt`
  - `<out-dir>/qnx8_errors.txt`

and runs `secpol-audit check` against the extracted `qnx8_generated.secpol`.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from secpol_audit.cli import main as secpol_audit_main

POLICY_BEGIN = "=== SECPOLGEN_POLICY_BEGIN ==="
POLICY_END = "=== SECPOLGEN_POLICY_END ==="
UNUSED_BEGIN = "=== SECPOLGEN_UNUSED_BEGIN ==="
UNUSED_END = "=== SECPOLGEN_UNUSED_END ==="
ERRORS_BEGIN = "=== SECPOLGEN_ERRORS_BEGIN ==="
ERRORS_END = "=== SECPOLGEN_ERRORS_END ==="


class SecpolgenExtractError(ValueError):
    """Raised when required `secpolgenerate` capture markers are missing or malformed."""


@dataclass(frozen=True)
class ExtractedSecpolgen:
    policy_text: str
    unused_text: str
    errors_text: str
    policy_path: Path | None = None
    unused_path: Path | None = None
    errors_path: Path | None = None


def _extract_block(lines: list[str], begin_marker: str, end_marker: str, *, required: bool) -> str:
    start_idx: int | None = None
    end_idx: int | None = None
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if start_idx is None and begin_marker in stripped:
            start_idx = idx + 1
            continue
        if start_idx is not None and end_marker in stripped:
            end_idx = idx
            break

    if start_idx is None:
        if required:
            raise SecpolgenExtractError(f"Missing required capture marker: '{begin_marker}'")
        return ""
    if end_idx is None:
        raise SecpolgenExtractError(
            f"Found '{begin_marker}' without matching closing marker '{end_marker}'"
        )

    body = "\n".join(lines[start_idx:end_idx])
    return (body + "\n") if body else ""


def extract_secpolgen_text(text: str) -> ExtractedSecpolgen:
    """Split raw QEMU serial text into `(policy_text, unused_text, errors_text)`."""
    normalized_lines = [line.rstrip("\r") for line in text.splitlines()]
    policy_text = _extract_block(normalized_lines, POLICY_BEGIN, POLICY_END, required=True)
    unused_text = _extract_block(normalized_lines, UNUSED_BEGIN, UNUSED_END, required=False)
    errors_text = _extract_block(normalized_lines, ERRORS_BEGIN, ERRORS_END, required=False)
    return ExtractedSecpolgen(
        policy_text=policy_text,
        unused_text=unused_text,
        errors_text=errors_text,
    )


def extract_secpolgen_file(log_path: str | Path, out_dir: str | Path) -> ExtractedSecpolgen:
    """Read `log_path`, extract `secpolgenerate` sections, and write files to `out_dir`."""
    src = Path(log_path)
    if not src.is_file():
        raise SecpolgenExtractError(f"Capture log file not found: {src}")

    raw = src.read_text(encoding="utf-8", errors="replace")
    extracted = extract_secpolgen_text(raw)

    dst = Path(out_dir)
    dst.mkdir(parents=True, exist_ok=True)
    policy_path = dst / "qnx8_generated.secpol"
    unused_path = dst / "qnx8_unused.txt"
    errors_path = dst / "qnx8_errors.txt"

    policy_path.write_text(extracted.policy_text, encoding="utf-8")
    unused_path.write_text(extracted.unused_text, encoding="utf-8")
    errors_path.write_text(extracted.errors_text, encoding="utf-8")

    return ExtractedSecpolgen(
        policy_text=extracted.policy_text,
        unused_text=extracted.unused_text,
        errors_text=extracted.errors_text,
        policy_path=policy_path,
        unused_path=unused_path,
        errors_path=errors_path,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract QNX 8.0 secpolgenerate policy/unused/errors and run secpol-audit check."
    )
    parser.add_argument("capture_log", help="Path to QEMU serial log captured from secpolgen_capture.ifs")
    parser.add_argument(
        "--out-dir",
        default="qnx_demo/build/secpolgen",
        help="Directory to write qnx8_generated.secpol, qnx8_unused.txt, and qnx8_errors.txt",
    )
    parser.add_argument(
        "--no-check",
        action="store_true",
        help="Extract files only without invoking `secpol-audit check`",
    )
    parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="Output format for `secpol-audit check`",
    )
    args = parser.parse_args(argv)

    try:
        extracted = extract_secpolgen_file(args.capture_log, args.out_dir)
    except SecpolgenExtractError as exc:
        sys.stderr.write(f"ERROR [SECPOLGEN_EXTRACT]: {exc}\n")
        return 2

    assert extracted.policy_path is not None
    assert extracted.unused_path is not None
    assert extracted.errors_path is not None
    print(f"Extracted policy : {extracted.policy_path} ({len(extracted.policy_text)} bytes)")
    print(f"Extracted unused : {extracted.unused_path} ({len(extracted.unused_text)} bytes)")
    print(f"Extracted errors : {extracted.errors_path} ({len(extracted.errors_text)} bytes)")

    if args.no_check:
        return 0

    return secpol_audit_main(
        [
            "check",
            str(extracted.policy_path),
            "--format",
            args.format,
        ]
    )


if __name__ == "__main__":
    sys.exit(main())
