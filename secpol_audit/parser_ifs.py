"""Scoped, deterministic, fail-closed QNX Neutrino 8.0 `build.ifs` startup-script parser."""

from __future__ import annotations

import os
from pathlib import Path
import re

from secpol_audit.ir import IfsCommand, IfsIR, ParseDiagnostic, SourceSpan

IFS_BUILTINS = frozenset(
    {
        "display_msg",
        "waitfor",
        "procmgr_symlink",
        "reopen",
        "sleep",
        "echo",
        "pidin",
        "secpolpush",
        "export",
        "umask",
        "cd",
        "true",
        "false",
        "setconf",
    }
)

# QNX `on` flags that consume a following argument
ON_ARG_FLAGS = frozenset(
    {"-T", "-u", "-U", "-g", "-p", "-C", "-R", "-W", "-w", "-n", "-r", "-t", "-f", "-e", "-l", "-m", "-P"}
)

# QNX `on` boolean flags
ON_BOOL_FLAGS = frozenset({"-d", "-k", "-s", "-h", "-i", "-c", "-S", "-X", "-v"})

ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=.*$")
SCRIPT_ATTR_RE = re.compile(r"\[[^\]]*\+script[^\]]*\]")
SCRIPT_HEADER_RE = re.compile(r"^(?:(?:\[[^\]]*\]\s*)*)(startup-script|\.script|[A-Za-z0-9_.-]+)\s*=\s*(.*)$")


def _strip_comment_and_split_commands(line: str, source_path: str, line_no: int) -> list[tuple[str, int]]:
    """Strip unquoted `#` comments and split `;`-separated commands while validating quotes."""
    commands: list[tuple[str, int]] = []
    buf: list[str] = []
    quote: str | None = None
    quote_col = 1
    cmd_start_col: int | None = None
    i = 0
    n = len(line)

    while i < n:
        ch = line[i]
        col = i + 1

        if quote is not None:
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(ch)
                buf.append(line[i + 1])
                i += 2
                continue
            buf.append(ch)
            if ch == quote:
                quote = None
            i += 1
            continue

        if ch == "#":
            break

        if ch in ('"', "'"):
            if cmd_start_col is None:
                cmd_start_col = col
            quote = ch
            quote_col = col
            buf.append(ch)
            i += 1
            continue

        if ch == ";":
            segment = "".join(buf).strip()
            if segment:
                commands.append((segment, cmd_start_col or 1))
            buf = []
            cmd_start_col = None
            i += 1
            continue

        if ch not in (" ", "\t", "\r") and cmd_start_col is None:
            cmd_start_col = col
        buf.append(ch)
        i += 1

    if quote is not None:
        raise ParseDiagnostic(
            "PARSE_ERROR",
            f"Unterminated {quote} quote in startup-script line",
            SourceSpan(file=source_path, line=line_no, col=quote_col, snippet=line.rstrip("\r\n")),
        )

    segment = "".join(buf).strip()
    if segment:
        commands.append((segment, cmd_start_col or 1))
    return commands


def _tokenize_shell_cmd(cmd: str, source_path: str, line_no: int, base_col: int, raw_line: str) -> list[str]:
    """Quote-aware shell command tokenizer for QNX startup-script lines."""
    tokens: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    in_token = False
    i = 0
    n = len(cmd)

    while i < n:
        ch = cmd[i]
        if quote is not None:
            if ch == "\\" and quote == '"' and i + 1 < n:
                buf.append(cmd[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            else:
                buf.append(ch)
            i += 1
            continue

        if ch in (" ", "\t"):
            if in_token:
                tokens.append("".join(buf))
                buf = []
                in_token = False
            i += 1
            continue

        if ch in ('"', "'"):
            quote = ch
            in_token = True
            i += 1
            continue

        if ch == "&" and not in_token:
            tokens.append("&")
            i += 1
            continue

        if ch == "&" and i == n - 1:
            if in_token:
                tokens.append("".join(buf))
                buf = []
                in_token = False
            tokens.append("&")
            i += 1
            continue

        buf.append(ch)
        in_token = True
        i += 1

    if quote is not None:
        raise ParseDiagnostic(
            "PARSE_ERROR",
            f"Unterminated {quote} quote in startup-script command",
            SourceSpan(file=source_path, line=line_no, col=base_col, snippet=raw_line.rstrip("\r\n")),
        )

    if in_token:
        tokens.append("".join(buf))
    return tokens


def _parse_on_command(
    tokens: list[str],
    raw: str,
    span: SourceSpan,
    background: bool,
) -> IfsCommand:
    """Parse a QNX `on` invocation supporting arbitrary flag order."""
    on_type: str | None = None
    on_user: str | None = None
    idx = 1
    n = len(tokens)

    while idx < n:
        tok = tokens[idx]
        if tok == "--":
            idx += 1
            break
        if not tok.startswith("-") or tok == "-":
            break

        # Attached -T<type> or -u<uid:gid>
        if tok.startswith("-T") and len(tok) > 2:
            on_type = tok[2:]
            idx += 1
            continue
        if tok.startswith("-u") and len(tok) > 2:
            on_user = tok[2:]
            idx += 1
            continue

        if tok == "-T":
            if idx + 1 >= n or tokens[idx + 1].startswith("-"):
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    "Flag '-T' in 'on' command requires a security type argument",
                    span,
                )
            on_type = tokens[idx + 1]
            idx += 2
            continue

        if tok in ON_ARG_FLAGS:
            if idx + 1 >= n:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Flag '{tok}' in 'on' command requires an argument",
                    span,
                )
            if tok == "-u":
                on_user = tokens[idx + 1]
            idx += 2
            continue

        if tok in ON_BOOL_FLAGS:
            idx += 1
            continue

        # Allow combined short flags like `-ds` if all chars are known boolean flags
        if len(tok) > 2 and all(f"-{c}" in ON_BOOL_FLAGS for c in tok[1:]):
            idx += 1
            continue

        raise ParseDiagnostic(
            "UNSUPPORTED_CONSTRUCT",
            f"Unsupported flag '{tok}' in QNX 'on' command",
            span,
        )

    if idx >= n:
        raise ParseDiagnostic(
            "PARSE_ERROR",
            "'on' command is missing a target executable",
            span,
        )

    # Skip any VAR=VAL right before executable
    while idx < n and ENV_ASSIGN_RE.match(tokens[idx]):
        idx += 1
    if idx >= n:
        raise ParseDiagnostic(
            "PARSE_ERROR",
            "'on' command is missing a target executable after environment assignments",
            span,
        )

    exe_path = tokens[idx]
    exe_name = os.path.basename(exe_path)
    is_secpolpush = exe_name == "secpolpush"
    is_builtin = exe_name in IFS_BUILTINS and not is_secpolpush

    return IfsCommand(
        raw=raw,
        tokens=tuple(tokens),
        span=span,
        is_secpolpush=is_secpolpush,
        secpolpush_args=tuple(tokens[idx + 1 :]) if is_secpolpush else (),
        is_on=True,
        on_type=on_type,
        on_user=on_user,
        executable=exe_name,
        executable_path=exe_path,
        is_builtin=is_builtin,
        background=background,
    )


def _parse_script_command(
    cmd: str,
    source_path: str,
    line_no: int,
    col: int,
    raw_line: str,
) -> IfsCommand | None:
    tokens = _tokenize_shell_cmd(cmd, source_path, line_no, col, raw_line)
    if not tokens:
        return None

    background = False
    if tokens[-1] == "&":
        background = True
        tokens = tokens[:-1]
    if not tokens:
        return None

    span = SourceSpan(
        file=source_path,
        line=line_no,
        col=col,
        end_line=line_no,
        end_col=col + len(cmd),
        snippet=raw_line.rstrip("\r\n"),
    )

    # Pure environment assignment(s) like `PATH=/proc/boot:/bin`
    idx = 0
    while idx < len(tokens) and ENV_ASSIGN_RE.match(tokens[idx]):
        idx += 1
    if idx == len(tokens):
        return IfsCommand(
            raw=cmd,
            tokens=tuple(tokens),
            span=span,
            is_secpolpush=False,
            secpolpush_args=(),
            is_on=False,
            on_type=None,
            on_user=None,
            executable=None,
            executable_path=None,
            is_builtin=True,
            background=background,
        )

    effective_tokens = tokens[idx:]
    head = effective_tokens[0]
    head_base = os.path.basename(head)

    if head_base == "secpolpush":
        return IfsCommand(
            raw=cmd,
            tokens=tuple(tokens),
            span=span,
            is_secpolpush=True,
            secpolpush_args=tuple(effective_tokens[1:]),
            is_on=False,
            on_type=None,
            on_user=None,
            executable="secpolpush",
            executable_path=head,
            is_builtin=True,
            background=background,
        )

    if head_base == "on":
        return _parse_on_command(effective_tokens, cmd, span, background)

    is_builtin = head_base in IFS_BUILTINS
    return IfsCommand(
        raw=cmd,
        tokens=tuple(tokens),
        span=span,
        is_secpolpush=False,
        secpolpush_args=(),
        is_on=False,
        on_type=None,
        on_user=None,
        executable=head_base,
        executable_path=head,
        is_builtin=is_builtin,
        background=background,
    )


def parse_ifs_text(text: str, source_path: str = "<memory>") -> IfsIR:
    """Parse QNX 8.0 `build.ifs` text, extracting and validating startup-script blocks."""
    lines = text.splitlines()
    ir = IfsIR(source_path=source_path)

    in_script = False
    script_open_line = 0
    script_open_col = 1
    pending_script_attr = False
    in_other_block = False

    i = 0
    total = len(lines)
    while i < total:
        raw_line = lines[i]
        line_no = i + 1
        stripped = raw_line.strip()

        if not in_script:
            if not stripped or stripped.startswith("#"):
                i += 1
                continue

            if in_other_block:
                if "}" in stripped:
                    in_other_block = False
                i += 1
                continue

            # Check if line has [+script] attribute (either standalone or on the header line)
            has_script_attr = bool(SCRIPT_ATTR_RE.search(stripped))

            # Standalone `[+script]` line followed by `startup-script = {` on next line
            if has_script_attr and "=" not in stripped:
                pending_script_attr = True
                i += 1
                continue

            m = SCRIPT_HEADER_RE.match(stripped)
            if m:
                block_name = m.group(1)
                rhs = m.group(2).strip()
                is_startup_script = has_script_attr or pending_script_attr or block_name in ("startup-script", ".script")
                pending_script_attr = False

                if is_startup_script:
                    ir.has_startup_script = True
                    # Must open `{` on this line or the immediately following non-blank line
                    if rhs.startswith("{"):
                        in_script = True
                        script_open_line = line_no
                        script_open_col = raw_line.find("{") + 1
                        after_brace = rhs[1:].strip()
                        if after_brace:
                            # Handle single-line `startup-script = { cmd; }`
                            if "}" in after_brace:
                                inner, _ = after_brace.split("}", 1)
                                for seg, seg_col in _strip_comment_and_split_commands(inner, source_path, line_no):
                                    cmd_obj = _parse_script_command(seg, source_path, line_no, seg_col, raw_line)
                                    if cmd_obj is not None:
                                        ir.commands.append(cmd_obj)
                                        if cmd_obj.is_secpolpush:
                                            ir.secpolpush_lines.append(line_no)
                                in_script = False
                            else:
                                for seg, seg_col in _strip_comment_and_split_commands(after_brace, source_path, line_no):
                                    cmd_obj = _parse_script_command(seg, source_path, line_no, seg_col, raw_line)
                                    if cmd_obj is not None:
                                        ir.commands.append(cmd_obj)
                                        if cmd_obj.is_secpolpush:
                                            ir.secpolpush_lines.append(line_no)
                        i += 1
                        continue

                    if rhs == "":
                        # Check if next non-empty line is `{`
                        j = i + 1
                        while j < total and not lines[j].strip():
                            j += 1
                        if j < total and lines[j].strip().startswith("{"):
                            in_script = True
                            script_open_line = j + 1
                            script_open_col = lines[j].find("{") + 1
                            i = j + 1
                            continue

                    raise ParseDiagnostic(
                        "PARSE_ERROR",
                        f"Malformed startup-script block '{block_name}': expected '{{' after '='",
                        SourceSpan(file=source_path, line=line_no, col=1, snippet=raw_line),
                    )
                else:
                    # Other inline block like `boot = { ... }` or `/etc/foo = { ... }`
                    if rhs.startswith("{") and "}" not in rhs[1:]:
                        in_other_block = True
                    i += 1
                    continue

            # Reset pending `[+script]` if an unexpected line appeared
            if pending_script_attr:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    "Expected '<name> = {' following '[+script]' attribute",
                    SourceSpan(file=source_path, line=line_no, col=1, snippet=raw_line),
                )

            i += 1
            continue

        # Inside startup-script = { ... }
        # Handle backslash line continuation
        combined_line = raw_line
        start_line_no = line_no
        while combined_line.rstrip().endswith("\\") and i + 1 < total:
            combined_line = combined_line.rstrip()[:-1] + " " + lines[i + 1].lstrip()
            i += 1

        # Check for closing `}` (outside quotes/comments)
        stripped_in = combined_line.strip()
        if stripped_in == "}":
            in_script = False
            i += 1
            continue

        # Handle closing `}` at end of line after a command (rare, e.g. `slogger2 }`)
        if stripped_in.startswith("}"):
            in_script = False
            i += 1
            continue

        # Detect stray nested `{` outside quotes/comments
        cmd_segments = _strip_comment_and_split_commands(combined_line, source_path, start_line_no)
        for seg, seg_col in cmd_segments:
            if seg == "}":
                in_script = False
                break
            if seg.endswith("}"):
                inner = seg[:-1].strip()
                if inner:
                    cmd_obj = _parse_script_command(inner, source_path, start_line_no, seg_col, raw_line)
                    if cmd_obj is not None:
                        ir.commands.append(cmd_obj)
                        if cmd_obj.is_secpolpush:
                            ir.secpolpush_lines.append(start_line_no)
                in_script = False
                break
            cmd_obj = _parse_script_command(seg, source_path, start_line_no, seg_col, raw_line)
            if cmd_obj is not None:
                ir.commands.append(cmd_obj)
                if cmd_obj.is_secpolpush:
                    ir.secpolpush_lines.append(start_line_no)

        i += 1

    if in_script:
        raise ParseDiagnostic(
            "PARSE_ERROR",
            "Unterminated startup-script '{' block (missing closing '}')",
            SourceSpan(
                file=source_path,
                line=script_open_line,
                col=script_open_col,
                snippet=lines[script_open_line - 1] if 1 <= script_open_line <= len(lines) else "",
            ),
        )

    return ir


def parse_ifs_file(path: str | Path) -> IfsIR:
    """Read and parse a QNX 8.0 `build.ifs` file into `IfsIR`."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as exc:
        raise ParseDiagnostic(
            "PARSE_ERROR",
            f"Unable to read IFS file: {exc}",
            SourceSpan(file=str(p), line=1, col=1),
        ) from exc
    return parse_ifs_text(text, str(p))
