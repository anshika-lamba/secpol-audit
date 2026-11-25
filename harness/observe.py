#!/usr/bin/env python3
"""Parse QNX 8.0 QEMU serial logs (`pidin -f a_n`, `errno`, `DIRECT_RESULT`, `HOP1_SPAWN`, `HOP2_SPAWN`, `HOP2_RESULT`)."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import sys
from typing import Any

from secpol_audit.ir import RuntimeProcess
from secpol_audit.runtime import parse_pidin_text

MUTANT_RE = re.compile(r"SECPOL_AUDIT_MUTANT=([A-Za-z0-9_.-]+)")
DIRECT_RE = re.compile(r"DIRECT_RESULT=(GRANTED|DENIED)(?:\s+errno=(\d+))?")
HOP1_RE = re.compile(r"HOP1_SPAWN=(OK|DENIED)(?:\s+(?:child_pid=(\d+)|errno=(\d+)))?")
HOP2_SPAWN_RE = re.compile(r"HOP2_SPAWN=(OK|DENIED)(?:\s+(?:child_pid=(\d+)|errno=(\d+)))?")
HOP2_PROBE_RE = re.compile(r"HOP2_PROBE_START\s+pid=(\d+)")
HOP2_TRANS_RE = re.compile(r"HOP2_TRANSITION=(OK|DENIED)(?:\s+(?:target=([A-Za-z0-9_]+)|errno=(\d+)))?")
HOP2_RES_RE = re.compile(
    r"HOP2_RESULT=(GRANTED|DENIED)(?:\s+(?:coid=(\d+)|reply=([A-Za-z0-9_]+)|errno=(\d+)))?"
)


@dataclass
class SerialObservation:
    """Structured telemetry extracted from a QNX 8.0 QEMU serial log."""

    log_path: str
    mutant: str | None = None
    is_synthetic_fixture: bool = False
    direct_result: str | None = None
    direct_errno: int | None = None
    hop1_spawn: str | None = None
    hop1_child_pid: int | None = None
    hop1_errno: int | None = None
    hop2_spawn: str | None = None
    hop2_child_pid: int | None = None
    hop2_spawn_errno: int | None = None
    hop2_probe_pid: int | None = None
    hop2_transition: str | None = None
    hop2_transition_errno: int | None = None
    hop2_result: str | None = None
    hop2_coid: int | None = None
    hop2_reply: str | None = None
    hop2_errno: int | None = None
    pidin_processes: list[RuntimeProcess] = field(default_factory=list)
    completed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "log_path": self.log_path,
            "mutant": self.mutant,
            "is_synthetic_fixture": self.is_synthetic_fixture,
            "direct_result": self.direct_result,
            "direct_errno": self.direct_errno,
            "hop1_spawn": self.hop1_spawn,
            "hop1_child_pid": self.hop1_child_pid,
            "hop1_errno": self.hop1_errno,
            "hop2_spawn": self.hop2_spawn,
            "hop2_child_pid": self.hop2_child_pid,
            "hop2_spawn_errno": self.hop2_spawn_errno,
            "hop2_probe_pid": self.hop2_probe_pid,
            "hop2_transition": self.hop2_transition,
            "hop2_transition_errno": self.hop2_transition_errno,
            "hop2_result": self.hop2_result,
            "hop2_coid": self.hop2_coid,
            "hop2_reply": self.hop2_reply,
            "hop2_errno": self.hop2_errno,
            "pidin_count": len(self.pidin_processes),
            "pidin_processes": [p.to_dict() for p in self.pidin_processes],
            "completed": self.completed,
        }


def observe_serial_text(text: str, log_path: str = "<memory>") -> SerialObservation:
    """Extract structured runtime outcomes and `pidin -f a_n` snapshot from serial text."""
    obs = SerialObservation(log_path=log_path)
    if "SYNTHETIC UNIT-TEST FIXTURE" in text:
        obs.is_synthetic_fixture = True

    in_pidin = False
    pidin_lines: list[str] = []

    for line in text.splitlines():
        if "=== PIDIN_BEGIN ===" in line:
            in_pidin = True
            continue
        if "=== PIDIN_END ===" in line:
            in_pidin = False
            continue
        if in_pidin:
            pidin_lines.append(line)
            continue

        if "=== SECPOL_AUDIT_DONE ===" in line:
            obs.completed = True

        if m := MUTANT_RE.search(line):
            obs.mutant = m.group(1)
        if m := DIRECT_RE.search(line):
            obs.direct_result = m.group(1)
            obs.direct_errno = int(m.group(2)) if m.group(2) else None
        if m := HOP1_RE.search(line):
            obs.hop1_spawn = m.group(1)
            obs.hop1_child_pid = int(m.group(2)) if m.group(2) else None
            obs.hop1_errno = int(m.group(3)) if m.group(3) else None
        if m := HOP2_SPAWN_RE.search(line):
            obs.hop2_spawn = m.group(1)
            obs.hop2_child_pid = int(m.group(2)) if m.group(2) else None
            obs.hop2_spawn_errno = int(m.group(3)) if m.group(3) else None
        if m := HOP2_PROBE_RE.search(line):
            obs.hop2_probe_pid = int(m.group(1))
        if m := HOP2_TRANS_RE.search(line):
            obs.hop2_transition = m.group(1)
            obs.hop2_transition_errno = int(m.group(3)) if m.group(3) else None
        if m := HOP2_RES_RE.search(line):
            obs.hop2_result = m.group(1)
            obs.hop2_coid = int(m.group(2)) if m.group(2) else None
            obs.hop2_reply = m.group(3) if m.group(3) else None
            obs.hop2_errno = int(m.group(4)) if m.group(4) else None

    if pidin_lines:
        obs.pidin_processes = parse_pidin_text("\n".join(pidin_lines), source_path=log_path)

    return obs


def observe_serial_file(path: str | Path) -> SerialObservation:
    p = Path(path)
    return observe_serial_text(p.read_text(encoding="utf-8"), str(p))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Parse QNX 8.0 QEMU serial logs.")
    parser.add_argument("log_file", help="Path to QEMU serial capture file")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Emit JSON output")
    args = parser.parse_args(argv)

    obs = observe_serial_file(args.log_file)
    if args.as_json:
        print(json.dumps(obs.to_dict(), indent=2))
    else:
        tag = " [SYNTHETIC FIXTURE]" if obs.is_synthetic_fixture else ""
        print(f"Log: {obs.log_path}{tag}")
        print(f"  Mutant:           {obs.mutant or '-'}")
        print(f"  Direct connect:   {obs.direct_result or '-'} (errno={obs.direct_errno})")
        print(f"  Hop 1 spawn:      {obs.hop1_spawn or '-'} (child_pid={obs.hop1_child_pid}, errno={obs.hop1_errno})")
        if obs.hop2_spawn is not None:
            print(
                f"  Hop 2 spawn:      {obs.hop2_spawn} "
                f"(child_pid={obs.hop2_child_pid}, errno={obs.hop2_spawn_errno})"
            )
        if obs.hop2_probe_pid is not None:
            print(f"  Hop 2 probe pid:  {obs.hop2_probe_pid}")
        if obs.hop2_transition is not None:
            print(f"  Hop 2 transition: {obs.hop2_transition} (errno={obs.hop2_transition_errno})")
        print(
            f"  Hop 2 result:     {obs.hop2_result or '-'} "
            f"(coid={obs.hop2_coid}, reply={obs.hop2_reply}, errno={obs.hop2_errno})"
        )
        print(f"  pidin rows:       {len(obs.pidin_processes)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
