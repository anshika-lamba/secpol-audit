"""Unit tests for the fail-closed QNX 8.0 `build.ifs` startup-script parser."""

from __future__ import annotations

import pytest

from secpol_audit.ir import ParseDiagnostic
from secpol_audit.parser_ifs import parse_ifs_file, parse_ifs_text


def test_parse_valid_ifs_with_arbitrary_on_flag_order() -> None:
    src = """
    [virtual=x86_64,bios +compress] boot = {
        startup-x86
        procnto-smp-instr -v
    }

    [+script] startup-script = {
        display_msg "Starting QNX 8.0..."
        PATH=/proc/boot:/bin:/usr/bin
        LD_LIBRARY_PATH=/proc/boot:/lib:/usr/lib
        procmgr_symlink /dev/console /dev/tty
        reopen /dev/ser1

        secpolpush -r /etc/ranges /etc/secpol.bin
        on -T slogger2_t -u 20:20 slogger2
        waitfor /dev/slog2 5
        on -u 21:21 -T io_sock_t io-sock
        on -T can_hal_t /proc/boot/can_hal &
        echo "boot done"
        pidin -f a_n
    }

    /proc/boot/slogger2=slogger2
    """
    ir = parse_ifs_text(src, "build.ifs")
    assert ir.has_startup_script is True
    assert len(ir.secpolpush_lines) == 1
    push_cmd = [c for c in ir.commands if c.is_secpolpush][0]
    assert push_cmd.secpolpush_args == ("-r", "/etc/ranges", "/etc/secpol.bin")

    daemons = [c for c in ir.commands if not c.is_builtin and not c.is_secpolpush]
    assert [(d.executable, d.on_type, d.on_user, d.background) for d in daemons] == [
        ("slogger2", "slogger2_t", "20:20", False),
        ("io-sock", "io_sock_t", "21:21", False),
        ("can_hal", "can_hal_t", None, True),
    ]


def test_parse_builtins_vs_services() -> None:
    src = """
    [+script] startup-script = {
        display_msg "hi"
        waitfor /dev/null
        PATH=/proc/boot
        LD_LIBRARY_PATH=/lib
        procmgr_symlink /a /b
        reopen /dev/ser1
        sleep 1
        echo "ok"
        pidin -f a_n
        secpolpush /etc/secpol.bin
        ./can_server &
        ota_agent &
    }
    """
    ir = parse_ifs_text(src, "builtins.ifs")
    services = [c.executable for c in ir.commands if not c.is_builtin and not c.is_secpolpush]
    assert services == ["can_server", "ota_agent"]


def test_fail_closed_on_missing_T_argument() -> None:
    src_end = """
    [+script] startup-script = {
        secpolpush /etc/secpol.bin
        on -u 20:20 -T
    }
    """
    with pytest.raises(ParseDiagnostic) as exc1:
        parse_ifs_text(src_end, "bad_T_end.ifs")
    assert exc1.value.code == "PARSE_ERROR"

    src_flag = """
    [+script] startup-script = {
        secpolpush /etc/secpol.bin
        on -T -u 20:20 slogger2
    }
    """
    with pytest.raises(ParseDiagnostic) as exc2:
        parse_ifs_text(src_flag, "bad_T_flag.ifs")
    assert exc2.value.code == "PARSE_ERROR"


def test_fail_closed_on_unterminated_startup_script() -> None:
    src = """
    [+script] startup-script = {
        secpolpush /etc/secpol.bin
        on -T slogger2_t slogger2
    """
    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_ifs_text(src, "unterm.ifs")
    assert excinfo.value.code == "PARSE_ERROR"
    assert "Unterminated" in excinfo.value.message


def test_fail_closed_on_malformed_script_header_and_unclosed_quote() -> None:
    bad_header = "[+script] startup-script = nope\n"
    with pytest.raises(ParseDiagnostic) as exc1:
        parse_ifs_text(bad_header, "bad_hdr.ifs")
    assert exc1.value.code == "PARSE_ERROR"

    bad_quote = '[+script] startup-script = {\n    display_msg "unclosed\n}\n'
    with pytest.raises(ParseDiagnostic) as exc2:
        parse_ifs_text(bad_quote, "bad_quote.ifs")
    assert exc2.value.code == "PARSE_ERROR"


def test_fail_closed_on_missing_executable_after_on() -> None:
    src = """
    [+script] startup-script = {
        secpolpush /etc/secpol.bin
        on -T slogger2_t
    }
    """
    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_ifs_text(src, "no_exe.ifs")
    assert excinfo.value.code == "PARSE_ERROR"


def test_fail_closed_missing_ifs_file() -> None:
    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_ifs_file("/nonexistent/build.ifs")
    assert excinfo.value.code == "PARSE_ERROR"


def test_on_attached_flags_and_env_prefix_and_unsupported_flag() -> None:
    ir = parse_ifs_text(
        """
        [+script] startup-script = {
            secpolpush /etc/secpol.bin
            LD_LIBRARY_PATH=/lib on -Tcan_hal_t -u23:23 /proc/boot/can_hal &
        }
        """,
        "attached.ifs",
    )
    daemons = [c for c in ir.commands if not c.is_builtin and not c.is_secpolpush]
    assert len(daemons) == 1
    assert daemons[0].on_type == "can_hal_t"
    assert daemons[0].on_user == "23:23"
    assert daemons[0].executable == "can_hal"

    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_ifs_text(
            """
            [+script] startup-script = {
                secpolpush /etc/secpol.bin
                on -Z bogus_svc
            }
            """,
            "badflag.ifs",
        )
    assert excinfo.value.code == "UNSUPPORTED_CONSTRUCT"

