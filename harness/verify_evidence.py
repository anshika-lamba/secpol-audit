#!/usr/bin/env python3
"""Verify integrity of committed QNX 8.0 evidence logs, MANIFEST.json hashes, and completeness JSONs."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    manifest_path = REPO_ROOT / "evidence" / "MANIFEST.json"
    if not manifest_path.is_file():
        print(f"ERROR: missing {manifest_path}", file=sys.stderr)
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    errors: list[str] = []

    if not manifest.get("source_commit") or manifest["source_commit"] == "unknown":
        errors.append("MANIFEST.json missing valid source_commit")

    for rel, expected_hash in sorted(manifest.get("evidence_logs_sha256", {}).items()):
        p = REPO_ROOT / "evidence" / rel
        if not p.is_file():
            errors.append(f"Missing evidence log listed in MANIFEST.json: {rel}")
            continue
        actual = _sha256(p)
        if actual != expected_hash:
            errors.append(f"SHA-256 mismatch for evidence/{rel}: expected {expected_hash}, got {actual}")

    for pname, expected_hash in sorted(manifest.get("policies_sha256", {}).items()):
        p = REPO_ROOT / "qnx_demo" / "mutants" / pname
        if not p.is_file():
            errors.append(f"Missing policy listed in MANIFEST.json: {pname}")
            continue
        actual = _sha256(p)
        if actual != expected_hash:
            errors.append(f"SHA-256 mismatch for qnx_demo/mutants/{pname}: expected {expected_hash}, got {actual}")

    comp_files = sorted((REPO_ROOT / "evidence").rglob("*_completeness.json"))
    if len(comp_files) < 4:
        errors.append(f"Expected >= 4 completeness JSONs (M0/M3 + ADAS vuln/fixed), found {len(comp_files)}")
    for cf in comp_files:
        d = json.loads(cf.read_text(encoding="utf-8"))
        if d.get("result") != "COMPLETE":
            errors.append(f"{cf.relative_to(REPO_ROOT)}: result={d.get('result')} (expected COMPLETE)")
        if d.get("mismatches", 1) != 0 or d.get("dropped_events", 1) != 0:
            errors.append(f"{cf.relative_to(REPO_ROOT)}: nonzero mismatches or dropped_events")

    if errors:
        for e in errors:
            print(f"FAIL: {e}", file=sys.stderr)
        return 1

    print(
        f"verify_evidence: OK ({len(manifest.get('evidence_logs_sha256', {}))} logs, "
        f"{len(manifest.get('policies_sha256', {}))} policies, {len(comp_files)} COMPLETE reports verified)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
