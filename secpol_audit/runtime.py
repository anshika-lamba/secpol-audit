"""QNX 8.0 `pidin -f a_n` parser and static-vs-runtime drift detector (`verify-runtime`)."""

from __future__ import annotations

import os
from pathlib import Path
import re

from secpol_audit.ir import (
    Finding,
    IfsIR,
    ParseDiagnostic,
    PolicyIR,
    RuntimeDiff,
    RuntimeProcess,
    Severity,
    SourceSpan,
)

UNTYPED_MARKERS = frozenset({"", "-", "0", "<none>", "(none)", "none", "untyped"})
KERNEL_PROCESS_PREFIXES = ("procnto",)
IGNORED_TRANSIENT_TOOLS = frozenset({"pidin", "secpolpush"})

HEADER_RE = re.compile(r"^\s*pid\b.*\bname\b", re.IGNORECASE)
PID_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*)$")


def _is_kernel_process(proc_name: str) -> bool:
    lower = proc_name.lower()
    if lower in ("kernel", "idle"):
        return True
    return any(lower.startswith(prefix) for prefix in KERNEL_PROCESS_PREFIXES)


def _extract_proc_name(raw_name_field: str) -> tuple[str, str]:
    """Return `(basename, full_name)` from a process command/name column."""
    stripped = raw_name_field.strip()
    if not stripped:
        return "", ""
    first_tok = stripped.split()[0]
    return os.path.basename(first_tok), stripped


def parse_pidin_text(text: str, source_path: str = "<memory>") -> list[RuntimeProcess]:
    """Parse QNX 8.0 `pidin -f a_n` output into `RuntimeProcess` entries.

    Tolerates:
    - Header lines (`pid type name`, `pid _ name`, etc.)
    - Surrounding serial log banners / comments (`# ...`)
    - Varying column spacing and fixed-width empty type columns
    - Kernel processes (`procnto-smp-instr`)
    - Trailing command arguments
    - Empty type columns or `0` / `-` / `<none>` markers for untyped processes
    """
    processes: list[RuntimeProcess] = []
    name_col_idx: int | None = None
    lines = text.splitlines()
    saw_pidin_section = False

    for idx, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if HEADER_RE.match(raw_line):
            saw_pidin_section = True
            # Capture exact column start of `name` header to reliably parse blank type columns
            m_name = re.search(r"\bname\b", raw_line, re.IGNORECASE)
            if m_name:
                name_col_idx = m_name.start()
            continue

        m = PID_LINE_RE.match(raw_line)
        if not m:
            continue

        saw_pidin_section = True
        pid = int(m.group(1))
        rest_after_pid = m.group(2)

        raw_type = ""
        raw_name = ""

        # If we have header column alignment and the line aligns cleanly with empty type column
        if name_col_idx is not None and len(raw_line) > name_col_idx:
            pid_end = m.start(2)
            # Check slice between pid end and name_col_idx
            between = raw_line[pid_end:name_col_idx].strip()
            at_name = raw_line[name_col_idx:].strip()
            if at_name and (not between or len(between.split()) == 1):
                raw_type = between
                raw_name = at_name

        # Fallback whitespace parsing when no header or shifted alignment
        if not raw_name:
            parts = rest_after_pid.split()
            if len(parts) == 1:
                raw_type = ""
                raw_name = parts[0]
            else:
                first = parts[0]
                if first.lower() in UNTYPED_MARKERS:
                    raw_type = first
                    raw_name = " ".join(parts[1:])
                elif first.startswith("/") or first.startswith("./") or first.startswith("proc/"):
                    # Path directly after PID with arguments means empty type column
                    raw_type = ""
                    raw_name = " ".join(parts)
                elif first.lower().startswith("procnto"):
                    raw_type = ""
                    raw_name = " ".join(parts)
                else:
                    raw_type = first
                    raw_name = " ".join(parts[1:])

        basename, full_name = _extract_proc_name(raw_name)
        if not basename:
            continue

        secpol_type = None if raw_type.strip().lower() in UNTYPED_MARKERS else raw_type.strip()
        processes.append(
            RuntimeProcess(
                pid=pid,
                secpol_type=secpol_type,
                raw_type=raw_type.strip(),
                name=basename,
                full_name=full_name,
                line=idx,
            )
        )

    if not processes and text.strip() and not saw_pidin_section:
        # Check if all non-empty lines were comments
        non_comment = [ln for ln in lines if ln.strip() and not ln.strip().startswith("#")]
        if non_comment:
            raise ParseDiagnostic(
                "PARSE_ERROR",
                "No valid QNX `pidin -f a_n` process entries found in input",
                SourceSpan(file=source_path, line=1, col=1, snippet=non_comment[0]),
            )

    return processes


def parse_pidin_file(path: str | Path) -> list[RuntimeProcess]:
    """Read and parse a `pidin -f a_n` capture file."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ParseDiagnostic(
            "PARSE_ERROR",
            f"Unable to read runtime pidin file: {exc}",
            SourceSpan(file=str(p), line=1, col=1),
        ) from exc
    return parse_pidin_text(text, str(p))


def verify_runtime(
    processes: list[RuntimeProcess],
    *,
    policy: PolicyIR,
    ifs: IfsIR | None = None,
    source_path: str = "<pidin>",
) -> RuntimeDiff:
    """Compare observed QNX `pidin -f a_n` processes against expected `.secpol` + `build.ifs`."""
    findings: list[Finding] = []
    matched: list[dict[str, Any]] = []

    # Build expected executable -> set of expected types from build.ifs
    expected_by_exe: dict[str, list[tuple[str | None, SourceSpan]]] = {}
    if ifs is not None:
        for cmd in ifs.commands:
            if cmd.is_secpolpush or cmd.is_builtin or not cmd.executable:
                continue
            expected_by_exe.setdefault(cmd.executable, []).append((cmd.on_type, cmd.span))

    observed_names: set[str] = set()

    for proc in processes:
        observed_names.add(proc.name)
        span = SourceSpan(
            file=source_path,
            line=proc.line,
            col=1,
            snippet=f"{proc.pid} {proc.raw_type or '-'} {proc.full_name}",
        )

        # Kernel and transient inspector commands are not userland IFS daemons
        if _is_kernel_process(proc.name):
            continue
        if proc.name in IGNORED_TRANSIENT_TOOLS and proc.name not in expected_by_exe:
            continue

        # 1. RUNTIME_UNTYPED_PROCESS
        if proc.secpol_type is None:
            findings.append(
                Finding(
                    rule_id="RUNTIME_UNTYPED_PROCESS",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Process '{proc.name}' (PID {proc.pid}) is running UNTYPED "
                        f"(raw type='{proc.raw_type or '<empty>'}') in runtime snapshot"
                    ),
                    span=span,
                    remediation=(
                        f"Ensure '{proc.name}' is launched after 'secpolpush' with 'on -T <declared_type>'."
                    ),
                    metadata={"pid": proc.pid, "process": proc.name, "raw_type": proc.raw_type},
                )
            )
            continue

        has_issue = False

        # 2. RUNTIME_UNDECLARED_TYPE
        if proc.secpol_type not in policy.types:
            has_issue = True
            findings.append(
                Finding(
                    rule_id="RUNTIME_UNDECLARED_TYPE",
                    severity=Severity.HIGH,
                    message=(
                        f"Process '{proc.name}' (PID {proc.pid}) is running under undeclared security type "
                        f"'{proc.secpol_type}' (not defined in '{policy.source_path}')"
                    ),
                    span=span,
                    remediation=(
                        f"Verify the loaded policy binary matches '{policy.source_path}' or declare type '{proc.secpol_type}'."
                    ),
                    metadata={"pid": proc.pid, "process": proc.name, "observed_type": proc.secpol_type},
                )
            )

        # 3. RUNTIME_TYPE_MISMATCH
        if proc.name in expected_by_exe:
            expected_types = [t for t, _ in expected_by_exe[proc.name] if t is not None]
            if expected_types and proc.secpol_type not in expected_types:
                has_issue = True
                findings.append(
                    Finding(
                        rule_id="RUNTIME_TYPE_MISMATCH",
                        severity=Severity.HIGH,
                        message=(
                            f"Process '{proc.name}' (PID {proc.pid}) is running as '{proc.secpol_type}', "
                            f"but build.ifs binds it to '{', '.join(sorted(set(expected_types)))}'"
                        ),
                        span=span,
                        remediation=(
                            f"Investigate unauthorized settypeid transition or IFS launch drift for '{proc.name}'."
                        ),
                        metadata={
                            "pid": proc.pid,
                            "process": proc.name,
                            "observed_type": proc.secpol_type,
                            "expected_types": sorted(set(expected_types)),
                        },
                    )
                )

        if not has_issue:
            matched.append(
                {
                    "pid": proc.pid,
                    "process": proc.name,
                    "type": proc.secpol_type,
                }
            )

    # 4. RUNTIME_MISSING_SERVICE
    for exe, bindings in sorted(expected_by_exe.items()):
        if exe not in observed_names:
            expected_types = [t for t, _ in bindings if t is not None]
            first_span = bindings[0][1]
            findings.append(
                Finding(
                    rule_id="RUNTIME_MISSING_SERVICE",
                    severity=Severity.INFO,
                    message=(
                        f"Service '{exe}' declared in build.ifs "
                        f"(expected type: {', '.join(expected_types) if expected_types else 'untyped'}) "
                        "was not observed in the runtime pidin snapshot"
                    ),
                    span=first_span,
                    remediation=f"Confirm whether '{exe}' exited normally, crashed, or failed to start.",
                    metadata={"executable": exe, "expected_types": expected_types},
                )
            )

    findings.sort(key=lambda f: (f.severity.rank, f.span.line if f.span else 0, f.rule_id))
    return RuntimeDiff(
        source_path=source_path,
        processes=processes,
        findings=findings,
        matched=matched,
    )
