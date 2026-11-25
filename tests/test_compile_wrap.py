"""Unit tests for the honest QNX `secpolcompile` wrapper (`pass` / `fail` / `skipped`)."""

from __future__ import annotations

from pathlib import Path
import stat

from secpol_audit.compile_wrap import run_secpolcompile


def test_secpolcompile_skipped_when_binary_absent(tmp_path: Path, monkeypatch) -> None:
    pol = tmp_path / "p.secpol"
    pol.write_text("type a_t;\n", encoding="utf-8")

    monkeypatch.setattr("shutil.which", lambda _name: None)
    res = run_secpolcompile(pol)
    assert res.status == "skipped"
    assert res.status != "pass"
    assert res.binary is None
    assert res.returncode is None


def test_secpolcompile_skipped_when_explicit_bin_missing(tmp_path: Path) -> None:
    pol = tmp_path / "p.secpol"
    pol.write_text("type a_t;\n", encoding="utf-8")

    res = run_secpolcompile(pol, secpolcompile_bin="/no/such/secpolcompile")
    assert res.status == "skipped"
    assert res.binary is None


def test_secpolcompile_pass_with_mock_binary(tmp_path: Path) -> None:
    pol = tmp_path / "p.secpol"
    pol.write_text("type a_t;\n", encoding="utf-8")

    fake_bin = tmp_path / "fake_secpolcompile.sh"
    fake_bin.write_text("#!/bin/sh\necho 'compiled ok'\nexit 0\n", encoding="utf-8")
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IXUSR)

    res = run_secpolcompile(pol, secpolcompile_bin=str(fake_bin))
    assert res.status == "pass"
    assert res.returncode == 0
    assert "compiled ok" in res.stdout


def test_secpolcompile_fail_with_mock_binary_captures_stderr(tmp_path: Path) -> None:
    pol = tmp_path / "p.secpol"
    pol.write_text("type a_t;\n", encoding="utf-8")

    fake_bin = tmp_path / "fake_secpolcompile_fail.sh"
    fake_bin.write_text("#!/bin/sh\necho 'syntax error at line 4' >&2\nexit 1\n", encoding="utf-8")
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IXUSR)

    res = run_secpolcompile(pol, secpolcompile_bin=str(fake_bin))
    assert res.status == "fail"
    assert res.returncode == 1
    assert "syntax error at line 4" in res.stderr
