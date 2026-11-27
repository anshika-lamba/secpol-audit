#!/usr/bin/env python3
"""Generate `evidence/MANIFEST.json` provenance manifest for captured QNX 8.0 artifacts."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _cmd_output(cmd: list[str]) -> str:
    try:
        res = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        out = (res.stdout or res.stderr or "").strip().splitlines()
        return out[0] if out else "unknown"
    except Exception:
        return "unknown"


def build_manifest(
    *,
    evidence_dir: Path | None = None,
    policies_dir: Path | None = None,
    images_dir: Path | None = None,
    build_command: str = "make -C qnx_demo sentry-images blast-images secpolgen-image",
) -> dict[str, Any]:
    ev_dir = evidence_dir or (REPO_ROOT / "evidence")
    pol_dir = policies_dir or (REPO_ROOT / "qnx_demo" / "mutants")
    img_dir = images_dir or (REPO_ROOT / "qnx_demo" / "build")

    raw_logs: dict[str, str] = {}
    if ev_dir.is_dir():
        for p in sorted(ev_dir.rglob("*.log")):
            rel = p.relative_to(ev_dir).as_posix()
            raw_logs[rel] = _sha256_file(p)

    policies: dict[str, str] = {}
    if pol_dir.is_dir():
        for p in sorted(pol_dir.glob("*.secpol")):
            policies[p.name] = _sha256_file(p)

    images: dict[str, str] = {}
    if img_dir.is_dir():
        for p in sorted(img_dir.glob("*.ifs")):
            images[p.name] = _sha256_file(p)

    return {
        "source_commit": _cmd_output(["git", "rev-parse", "HEAD"]),
        "capture_date": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "qnx_sdp_version": _cmd_output(["sh", "-c", "echo ${QNX_TARGET:-unknown}"]),
        "qcc_version": _cmd_output(["qcc", "-V"]),
        "qemu_version": _cmd_output(["qemu-system-x86_64", "--version"]),
        "build_command": build_command,
        "policies_sha256": policies,
        "images_sha256": images,
        "evidence_logs_sha256": raw_logs,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate provenance MANIFEST.json for evidence/.")
    parser.add_argument(
        "-o",
        "--out",
        type=Path,
        default=REPO_ROOT / "evidence" / "MANIFEST.json",
        help="Output manifest path (default: evidence/MANIFEST.json)",
    )
    args = parser.parse_args(argv)
    manifest = build_manifest()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
