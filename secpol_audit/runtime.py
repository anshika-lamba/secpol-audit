"""QNX 8.0 `pidin` parser and static-vs-runtime drift detector (`verify-runtime`)."""

from __future__ import annotations

from dataclasses import dataclass
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

HEADER_PID_RE = re.compile(r"\bpid\b", re.IGNORECASE)
HEADER_NAME_RE = re.compile(r"\bname\b", re.IGNORECASE)
# Recognizes `security type`, `secpol type`, `secpol_type`, `sec_type`, `secpol`, `stype`, `type`, or `_`
HEADER_TYPE_RE = re.compile(
    r"(?:\bsecurity\s+type\b|\bsecpol\s+type\b|\bsecpol_type\b|\bsec_type\b|\bsecpol\b|\bstype\b|\btype\b|(?<!\S)_(?!\S))",
    re.IGNORECASE,
)
PID_LINE_RE = re.compile(r"^\s*(\d+)\s+(.*)$")


@dataclass(frozen=True)
class _PidinHeader:
    """Auto-detected column metadata from a QNX `pidin` header line."""

    order: str  # "type_first" (pid ... type ... name) or "name_first" (pid ... name ... type)
    type_start: int | None
    name_start: int | None
    extra_leading_cols: int  # e.g. tid/uid columns between pid and type/name


def _detect_header(raw_line: str) -> _PidinHeader | None:
    """Detect QNX `pidin` header columns regardless of column label or ordering."""
    m_pid = HEADER_PID_RE.search(raw_line)
    m_name = HEADER_NAME_RE.search(raw_line)
    if not m_pid or not m_name:
        return None

    m_type = HEADER_TYPE_RE.search(raw_line)
    type_start = m_type.start() if m_type else None
    name_start = m_name.start()

    if type_start is not None and type_start > name_start:
        order = "name_first"
    else:
        order = "type_first"

    # Count any extra columns (like `tid` or `uid`) between `pid` and the next known column
    first_col_start = min(c for c in (type_start, name_start) if c is not None)
    between_pid = raw_line[m_pid.end() : first_col_start].strip()
    extra_leading = len(between_pid.split()) if between_pid else 0

    return _PidinHeader(
        order=order,
        type_start=type_start,
        name_start=name_start,
        extra_leading_cols=extra_leading,
    )


def _is_kernel_process(proc_name: str) -> bool:
    lower = proc_name.lower()
    if lower in ("kernel", "idle"):
        return True
    return any(lower.startswith(prefix) for prefix in KERNEL_PROCESS_PREFIXES)


def _looks_like_path_or_kernel(token: str) -> bool:
    low = token.lower()
    if low.startswith("procnto"):
        return True
    return (
        token.startswith("/")
        or token.startswith("./")
        or token.startswith("proc/")
        or token.startswith("bin/")
        or token.startswith("sbin/")
        or token.startswith("usr/")
        or "/" in token
    )


def _extract_proc_name(raw_name_field: str) -> tuple[str, str]:
    """Return `(basename, full_name)` from a process command/name column."""
    stripped = raw_name_field.strip()
    if not stripped:
        return "", ""
    first_tok = stripped.split()[0]
    return os.path.basename(first_tok), stripped


def _is_clean_column_boundary(raw_line: str, col_idx: int) -> bool:
    """Return True if slicing at `col_idx` does not split an identifier mid-word."""
    if col_idx <= 0 or col_idx >= len(raw_line):
        return False
    return raw_line[col_idx - 1].isspace()


def _parse_type_first_row(
    raw_line: str,
    rest_after_pid: str,
    pid_rest_start: int,
    header: _PidinHeader | None,
) -> tuple[str, str]:
    """Parse a row in `pid [extra...] [type] name [args...]` layout."""
    # If header specifies extra leading columns (e.g., tid), skip them from the token stream
    extra = header.extra_leading_cols if header else 0

    # Strategy 1: Header column boundary alignment (handles blank type columns even when
    # the process name has no leading '/' and includes trailing flags, e.g. `telemetry_svc --daemon`)
    if header is not None and header.name_start is not None and extra == 0:
        ns = header.name_start
        if len(raw_line) > ns and _is_clean_column_boundary(raw_line, ns):
            between = raw_line[pid_rest_start:ns].strip()
            at_name = raw_line[ns:].strip()
            if at_name and (not between or len(between.split()) == 1):
                if not _looks_like_path_or_kernel(between):
                    return between, at_name

    # Strategy 2: Resilient token-based parsing (handles shifted/overflowed columns & no-header captures)
    parts = rest_after_pid.split()
    if extra > 0 and len(parts) > extra:
        parts = parts[extra:]

    if not parts:
        return "", ""
    if len(parts) == 1:
        return "", parts[0]

    first = parts[0]
    if first.lower() in UNTYPED_MARKERS:
        return first, " ".join(parts[1:])
    if _looks_like_path_or_kernel(first):
        return "", " ".join(parts)

    # Check if second token looks like a CLI flag (e.g. `telemetry_svc --daemon` with blank type & shifted col)
    if parts[1].startswith("-") and parts[1].lower() not in UNTYPED_MARKERS:
        return "", " ".join(parts)

    return first, " ".join(parts[1:])


def _parse_name_first_row(
    raw_line: str,
    rest_after_pid: str,
    pid_rest_start: int,
    header: _PidinHeader,
) -> tuple[str, str]:
    """Parse a row in `pid [extra...] name [type]` layout (e.g., `pidin -f an_`)."""
    extra = header.extra_leading_cols

    # Strategy 1: Clean header boundary at `type_start`
    if header.type_start is not None and extra == 0:
        ts = header.type_start
        if len(raw_line) >= ts and _is_clean_column_boundary(raw_line, ts):
            name_part = raw_line[pid_rest_start:ts].strip()
            type_part = raw_line[ts:].strip()
            if name_part:
                # If type_part is empty, the process is untyped
                if not type_part or len(type_part.split()) == 1:
                    return type_part, name_part

    # Strategy 2: Token-based fallback for overflowed name columns
    parts = rest_after_pid.split()
    if extra > 0 and len(parts) > extra:
        parts = parts[extra:]

    if not parts:
        return "", ""
    if len(parts) == 1:
        return "", parts[0]

    last = parts[-1]
    if last.lower() in UNTYPED_MARKERS:
        return last, " ".join(parts[:-1])
    # If the last token is a CLI flag (`-v`, `--daemon`) rather than a type, treat as untyped
    if last.startswith("-") and last != "-":
        return "", " ".join(parts)
    return last, " ".join(parts[:-1])


def parse_pidin_text(text: str, source_path: str = "<memory>") -> list[RuntimeProcess]:
    """Parse QNX 8.0 `pidin` output into `RuntimeProcess` entries.

    Auto-detects header columns (`pid`, `name`, `type` / `secpol` / `security type` / `_`)
    in either `pid type name` or `pid name type` order, tolerates varying whitespace,
    column overflow, leading paths (`/proc/boot/can_server` vs `can_server`), kernel
    `procnto-*` rows, trailing args, and blank / `-` / `0` / `(none)` / `<none>` untyped entries.
    """
    processes: list[RuntimeProcess] = []
    header: _PidinHeader | None = None
    lines = text.splitlines()
    saw_pidin_section = False

    for idx, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        detected = _detect_header(raw_line)
        if detected is not None:
            header = detected
            saw_pidin_section = True
            continue

        m = PID_LINE_RE.match(raw_line)
        if not m:
            continue

        saw_pidin_section = True
        pid = int(m.group(1))
        rest_after_pid = m.group(2)
        pid_rest_start = m.start(2)

        if header is not None and header.order == "name_first":
            raw_type, raw_name = _parse_name_first_row(raw_line, rest_after_pid, pid_rest_start, header)
        else:
            raw_type, raw_name = _parse_type_first_row(raw_line, rest_after_pid, pid_rest_start, header)

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
        non_comment = [ln for ln in lines if ln.strip() and not ln.strip().startswith("#")]
        if non_comment:
            raise ParseDiagnostic(
                "PARSE_ERROR",
                "No valid QNX `pidin` process entries found in input",
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
    """Compare observed QNX `pidin` processes against expected `.secpol` + `build.ifs`."""
    findings: list[Finding] = []
    matched: list[dict[str, Any]] = []

    expected_by_exe: dict[str, list[tuple[str | None, SourceSpan]]] = {}
    if ifs is not None:
        for cmd in ifs.commands:
            if cmd.is_secpolpush or cmd.is_builtin or not cmd.executable:
                continue
            exe_key = os.path.basename(cmd.executable)
            expected_by_exe.setdefault(exe_key, []).append((cmd.on_type, cmd.span))

    observed_names: set[str] = set()

    for proc in processes:
        proc_base = os.path.basename(proc.name)
        observed_names.add(proc_base)
        span = SourceSpan(
            file=source_path,
            line=proc.line,
            col=1,
            snippet=f"{proc.pid} {proc.raw_type or '-'} {proc.full_name}",
        )

        if _is_kernel_process(proc_base):
            continue
        if proc_base in IGNORED_TRANSIENT_TOOLS and proc_base not in expected_by_exe:
            continue

        if proc.secpol_type is None:
            findings.append(
                Finding(
                    rule_id="RUNTIME_UNTYPED_PROCESS",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Process '{proc_base}' (PID {proc.pid}) is running UNTYPED "
                        f"(raw type='{proc.raw_type or '<empty>'}') in runtime snapshot"
                    ),
                    span=span,
                    remediation=(
                        f"Ensure '{proc_base}' is launched after 'secpolpush' with 'on -T <declared_type>'."
                    ),
                    metadata={"pid": proc.pid, "process": proc_base, "raw_type": proc.raw_type},
                )
            )
            continue

        has_issue = False

        if proc.secpol_type not in policy.types:
            has_issue = True
            findings.append(
                Finding(
                    rule_id="RUNTIME_UNDECLARED_TYPE",
                    severity=Severity.HIGH,
                    message=(
                        f"Process '{proc_base}' (PID {proc.pid}) is running under undeclared security type "
                        f"'{proc.secpol_type}' (not defined in '{policy.source_path}')"
                    ),
                    span=span,
                    remediation=(
                        f"Verify the loaded policy binary matches '{policy.source_path}' or declare type '{proc.secpol_type}'."
                    ),
                    metadata={"pid": proc.pid, "process": proc_base, "observed_type": proc.secpol_type},
                )
            )

        if proc_base in expected_by_exe:
            expected_types = [t for t, _ in expected_by_exe[proc_base] if t is not None]
            if expected_types and proc.secpol_type not in expected_types:
                has_issue = True
                findings.append(
                    Finding(
                        rule_id="RUNTIME_TYPE_MISMATCH",
                        severity=Severity.HIGH,
                        message=(
                            f"Process '{proc_base}' (PID {proc.pid}) is running as '{proc.secpol_type}', "
                            f"but build.ifs binds it to '{', '.join(sorted(set(expected_types)))}'"
                        ),
                        span=span,
                        remediation=(
                            f"Investigate unauthorized settypeid transition or IFS launch drift for '{proc_base}'."
                        ),
                        metadata={
                            "pid": proc.pid,
                            "process": proc_base,
                            "observed_type": proc.secpol_type,
                            "expected_types": sorted(set(expected_types)),
                        },
                    )
                )

        if not has_issue:
            matched.append(
                {
                    "pid": proc.pid,
                    "process": proc_base,
                    "type": proc.secpol_type,
                }
            )

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
