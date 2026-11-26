"""Tests for pure-Python QNX ELF64 & compiled policy cross-layer auditor (`secpol_audit.firmware`)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import struct

import pytest

from secpol_audit.cli import main
from secpol_audit.firmware import (
    DT_BIND_NOW,
    DT_NEEDED,
    DT_NULL,
    ELFCLASS64,
    ELFDATA2LSB,
    ELFDATA2MSB,
    EM_AARCH64,
    EM_X86_64,
    ET_DYN,
    ET_EXEC,
    PF_X,
    PT_GNU_RELRO,
    PT_GNU_STACK,
    SHT_DYNAMIC,
    SHT_DYNSYM,
    SHT_STRTAB,
    ElfParseError,
    audit_firmware,
    parse_elf64_bytes,
)
from secpol_audit.ir import Severity
from secpol_audit.parser_ifs import parse_ifs_text
from secpol_audit.parser_secpol import parse_secpol_text


def _build_minimal_elf64(
    *,
    e_type: int = ET_DYN,
    e_machine: int = EM_X86_64,
    endian: str = "<",
    gnu_stack_flags: int | None = 0x6,  # RW (NX enabled); 0x7 = RWX (exec stack); None = absent
    has_relro: bool = True,
    bind_now: bool = True,
    dt_needed: tuple[str, ...] = (),
    dynsym_names: tuple[str, ...] = (),
) -> bytes:
    """Construct a valid minimal ELF64 binary strictly in memory for unit tests."""
    ei_data = ELFDATA2LSB if endian == "<" else ELFDATA2MSB

    # Build .dynstr string table
    dynstr = bytearray(b"\x00")
    str_offsets: dict[str, int] = {}
    for s in (*dt_needed, *dynsym_names):
        if s not in str_offsets:
            str_offsets[s] = len(dynstr)
            dynstr.extend(s.encode("utf-8") + b"\x00")

    # Build .dynamic entries (16 bytes each: qQ)
    dynamic_bytes = bytearray()
    for lib in dt_needed:
        dynamic_bytes.extend(struct.pack(f"{endian}qQ", DT_NEEDED, str_offsets[lib]))
    if bind_now:
        dynamic_bytes.extend(struct.pack(f"{endian}qQ", DT_BIND_NOW, 0))
    dynamic_bytes.extend(struct.pack(f"{endian}qQ", DT_NULL, 0))

    # Build .dynsym entries (24 bytes each: IBBHQQ); index 0 is STN_UNDEF
    dynsym_bytes = bytearray(struct.pack(f"{endian}IBBHQQ", 0, 0, 0, 0, 0, 0))
    for sym in dynsym_names:
        dynsym_bytes.extend(struct.pack(f"{endian}IBBHQQ", str_offsets[sym], 0x12, 0, 0, 0, 0))

    # Build program headers (56 bytes each: IIQQQQQQ)
    phdrs: list[bytes] = []
    if gnu_stack_flags is not None:
        phdrs.append(struct.pack(f"{endian}IIQQQQQQ", PT_GNU_STACK, gnu_stack_flags, 0, 0, 0, 0, 0, 16))
    if has_relro:
        phdrs.append(struct.pack(f"{endian}IIQQQQQQ", PT_GNU_RELRO, 0x4, 0, 0, 0, 0, 0, 1))

    ehdr_size = 64
    phentsize = 56
    shentsize = 64
    phoff = ehdr_size if phdrs else 0
    ph_total = len(phdrs) * phentsize

    dynstr_off = ehdr_size + ph_total
    dynamic_off = dynstr_off + len(dynstr)
    dynsym_off = dynamic_off + len(dynamic_bytes)
    shoff = dynsym_off + len(dynsym_bytes)

    # 4 sections: [0]=NULL, [1]=.dynstr, [2]=.dynamic (link=1), [3]=.dynsym (link=1)
    shdrs = [
        struct.pack(f"{endian}IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        struct.pack(f"{endian}IIQQQQIIQQ", 0, SHT_STRTAB, 0, 0, dynstr_off, len(dynstr), 0, 0, 1, 0),
        struct.pack(f"{endian}IIQQQQIIQQ", 0, SHT_DYNAMIC, 0, 0, dynamic_off, len(dynamic_bytes), 1, 0, 8, 16),
        struct.pack(f"{endian}IIQQQQIIQQ", 0, SHT_DYNSYM, 0, 0, dynsym_off, len(dynsym_bytes), 1, 1, 8, 24),
    ]

    e_ident = b"\x7fELF" + bytes([ELFCLASS64, ei_data, 1, 0]) + b"\x00" * 8
    ehdr = e_ident + struct.pack(
        f"{endian}HHIQQQIHHHHHH",
        e_type,
        e_machine,
        1,  # EV_CURRENT
        0,  # e_entry
        phoff,
        shoff,
        0,  # e_flags
        ehdr_size,
        phentsize,
        len(phdrs),
        shentsize,
        len(shdrs),
        0,  # e_shstrndx
    )

    return bytes(ehdr + b"".join(phdrs) + dynstr + dynamic_bytes + dynsym_bytes + b"".join(shdrs))


def test_parse_elf64_x86_64_hardened_and_secpol_symbols() -> None:
    raw = _build_minimal_elf64(
        e_type=ET_DYN,
        e_machine=EM_X86_64,
        gnu_stack_flags=0x6,
        has_relro=True,
        bind_now=True,
        dt_needed=("libc.so.6", "libsecpol.so.1", "libsecpolev.so.1"),
        dynsym_names=(
            "secpol_transition_type",
            "secpol_resmgr_attach",
            "secpol_check_permission",
            "secpolev_init",
        ),
    )
    info = parse_elf64_bytes(raw, "sentry_bin")
    assert info.machine_name == "EM_X86_64"
    assert info.endian == "little"
    assert info.is_pie is True
    assert info.has_nx_stack is True
    assert info.has_relro is True
    assert info.has_full_relro is True
    assert info.missing_mitigations() == []
    assert info.links_libsecpol is True
    assert info.links_libsecpolev is True
    assert set(info.tracked_secpol_symbols) == {
        "secpol_transition_type",
        "secpol_resmgr_attach",
        "secpol_check_permission",
        "secpolev_init",
    }


def test_parse_elf64_aarch64_unhardened_and_big_endian() -> None:
    raw = _build_minimal_elf64(
        e_type=ET_EXEC,
        e_machine=EM_AARCH64,
        endian=">",
        gnu_stack_flags=0x6 | PF_X,  # executable stack!
        has_relro=False,
        bind_now=False,
        dt_needed=("libc.so.6",),
        dynsym_names=("secpol_posix_spawnattr_settypeid",),
    )
    info = parse_elf64_bytes(raw, "can_hal_arm64")
    assert info.machine_name == "EM_AARCH64"
    assert info.endian == "big"
    assert info.is_pie is False
    assert info.has_nx_stack is False
    assert info.has_relro is False
    assert info.has_full_relro is False
    assert len(info.missing_mitigations()) == 3
    assert info.links_libsecpol is False
    assert info.tracked_secpol_symbols == ("secpol_posix_spawnattr_settypeid",)


def test_parse_elf64_rejects_invalid_and_non_elf64() -> None:
    with pytest.raises(ElfParseError):
        parse_elf64_bytes(b"short", "tiny")
    with pytest.raises(ElfParseError):
        parse_elf64_bytes(b"NOTELF" + b"\x00" * 100, "not_elf")
    # ELF32 (EI_CLASS = 1)
    elf32 = b"\x7fELF" + bytes([1, 1, 1, 0]) + b"\x00" * 80
    with pytest.raises(ElfParseError):
        parse_elf64_bytes(elf32, "elf32_bin")


def test_firmware_audit_detects_high_priv_unhardened_elf_critical_and_high(tmp_path: Path) -> None:
    pol = parse_secpol_text(
        """
        type can_hal_t;
        type lidar_t;
        type ui_t;
        allow can_hal_t self:ability { nonroot mem_phys:0xfe000000-0xfe010000 io };
        allow lidar_t self:ability { nonroot mem_phys:0xfd000000-0xfd010000 };
        allow ui_t self:ability { nonroot public_channel };
        """,
        "fw.secpol",
    )
    ifs = parse_ifs_text(
        """
        [+script] startup-script = {
            secpolpush /etc/secpol.bin
            on -T can_hal_t -u 23:23 can_hal &
            on -T lidar_t -u 24:24 lidar_drv &
            on -T ui_t -u 31:31 ivi_ui &
        }
        """,
        "fw.ifs",
    )
    # can_hal: missing PIE + NX + RELRO -> CRITICAL
    (tmp_path / "can_hal").write_bytes(
        _build_minimal_elf64(e_type=ET_EXEC, gnu_stack_flags=0x7, has_relro=False)
    )
    # lidar_drv: missing only RELRO -> HIGH
    (tmp_path / "lidar_drv").write_bytes(
        _build_minimal_elf64(e_type=ET_DYN, gnu_stack_flags=0x6, has_relro=False)
    )
    # ivi_ui: unprivileged, unhardened -> must NOT trigger HIGH_PRIV_UNHARDENED_ELF
    (tmp_path / "ivi_ui").write_bytes(
        _build_minimal_elf64(e_type=ET_EXEC, gnu_stack_flags=0x7, has_relro=False)
    )

    res = audit_firmware(pol, ifs, tmp_path)
    by_type = {f.metadata["type"]: f for f in res.findings if f.rule_id == "HIGH_PRIV_UNHARDENED_ELF"}
    assert set(by_type.keys()) == {"can_hal_t", "lidar_t"}
    assert by_type["can_hal_t"].severity == Severity.CRITICAL
    assert by_type["lidar_t"].severity == Severity.HIGH
    assert "ui_t" not in by_type


def test_firmware_audit_unreachable_transition_api_and_unused_settypeid_surface(tmp_path: Path) -> None:
    pol = parse_secpol_text(
        """
        type no_grant_t;
        type dead_grant_t;
        type valid_spawner_t;
        type worker_t;
        allow dead_grant_t self:ability { nonroot settypeid:worker_t };
        allow valid_spawner_t self:ability { nonroot settypeid:worker_t };
        """,
        "trans.secpol",
    )
    ifs = parse_ifs_text(
        """
        [+script] startup-script = {
            secpolpush /etc/secpol.bin
            on -T no_grant_t -u 21:21 no_grant_svc &
            on -T dead_grant_t -u 22:22 dead_grant_svc &
            on -T valid_spawner_t -u 23:23 valid_spawner &
        }
        """,
        "trans.ifs",
    )
    # Imports secpol_transition_type but policy grants NO settypeid -> UNREACHABLE_TRANSITION_API
    (tmp_path / "no_grant_svc").write_bytes(
        _build_minimal_elf64(
            dt_needed=("libsecpol.so.1",),
            dynsym_names=("secpol_transition_type",),
        )
    )
    # Policy grants settypeid:worker_t, but binary does not link libsecpol -> UNUSED_SETTYPEID_SURFACE
    (tmp_path / "dead_grant_svc").write_bytes(
        _build_minimal_elf64(dt_needed=("libc.so.6",), dynsym_names=())
    )
    # Policy grants settypeid:worker_t AND binary links libsecpol + imports spawnattr API -> CLEAN
    (tmp_path / "valid_spawner").write_bytes(
        _build_minimal_elf64(
            dt_needed=("libsecpol.so.1",),
            dynsym_names=("secpol_posix_spawnattr_settypeid",),
        )
    )

    res = audit_firmware(pol, ifs, tmp_path)
    rules = {(f.rule_id, f.metadata["type"]): f for f in res.findings}
    assert ("UNREACHABLE_TRANSITION_API", "no_grant_t") in rules
    assert rules[("UNREACHABLE_TRANSITION_API", "no_grant_t")].severity == Severity.HIGH
    assert ("UNUSED_SETTYPEID_SURFACE", "dead_grant_t") in rules
    assert rules[("UNUSED_SETTYPEID_SURFACE", "dead_grant_t")].severity == Severity.MEDIUM
    assert not any(f.metadata.get("type") == "valid_spawner_t" for f in res.findings)


def test_firmware_audit_compiled_policy_mutable_zero_id_and_drift(tmp_path: Path) -> None:
    pol_path = tmp_path / "app.secpol"
    pol_text = "type svc_a_t;\ntype svc_b_t;\nallow svc_a_t self:ability { nonroot public_channel };\n"
    pol_path.write_text(pol_text, encoding="utf-8")
    pol = parse_secpol_text(pol_text, str(pol_path))
    ifs = parse_ifs_text(
        "[+script] startup-script = {\n    secpolpush /etc/secpol.bin\n    on -T svc_a_t -u 21:21 svc_a &\n}\n",
        "app.ifs",
    )
    (tmp_path / "svc_a").write_bytes(_build_minimal_elf64())

    info_path = tmp_path / "secpolinfo.txt"
    info_path.write_text(
        "Policy ID: 0\n"
        "Mutable: yes\n"
        "source_sha256: 0000000000000000000000000000000000000000000000000000000000000000\n"
        "types: svc_a_t rogue_extra_t\n",
        encoding="utf-8",
    )

    res = audit_firmware(
        pol,
        ifs,
        tmp_path,
        policy_source_path=pol_path,
        secpol_info_path=info_path,
    )
    rule_ids = {f.rule_id for f in res.findings}
    assert "MUTABLE_COMPILED_POLICY" in rule_ids
    assert "ZERO_POLICY_ID" in rule_ids
    assert "POLICY_SOURCE_DRIFT" in rule_ids
    assert res.compiled_policy is not None
    assert res.compiled_policy.mutable is True
    assert res.compiled_policy.policy_id == 0


def test_firmware_audit_compiled_policy_clean_immutable_matching_sha(tmp_path: Path) -> None:
    pol_path = tmp_path / "clean.secpol"
    pol_text = "type svc_a_t;\nallow svc_a_t self:ability { nonroot public_channel };\n"
    pol_path.write_text(pol_text, encoding="utf-8")
    src_sha = hashlib.sha256(pol_path.read_bytes()).hexdigest()

    ifs_path = tmp_path / "clean.ifs"
    ifs_path.write_text(
        "[+script] startup-script = {\n    secpolpush /etc/secpol.bin\n    on -T svc_a_t -u 21:21 svc_a &\n}\n",
        encoding="utf-8",
    )
    bin_dir = tmp_path / "bins"
    bin_dir.mkdir()
    (bin_dir / "svc_a").write_bytes(_build_minimal_elf64())

    info_path = tmp_path / "secpolinfo_clean.txt"
    info_path.write_text(
        f"Policy ID: 42\nMutable: no\nsource_sha256: {src_sha}\ntypes: svc_a_t\n",
        encoding="utf-8",
    )

    rc = main(
        [
            "audit-firmware",
            str(pol_path),
            "--ifs",
            str(ifs_path),
            "--bin-dir",
            str(bin_dir),
            "--secpol-info",
            str(info_path),
        ]
    )
    assert rc == 0


def test_firmware_audit_offline_secpol_bin_string_table_drift(tmp_path: Path) -> None:
    pol_path = tmp_path / "pol.secpol"
    pol_text = "type svc_a_t;\ntype new_uncompiled_t;\n"
    pol_path.write_text(pol_text, encoding="utf-8")
    pol = parse_secpol_text(pol_text, str(pol_path))
    ifs = parse_ifs_text(
        "[+script] startup-script = {\n    secpolpush /etc/secpol.bin\n    on -T svc_a_t -u 21:21 svc_a &\n}\n",
        "pol.ifs",
    )
    bin_dir = tmp_path / "bins"
    bin_dir.mkdir()
    (bin_dir / "svc_a").write_bytes(_build_minimal_elf64())

    # Synthetic compiled policy binary containing svc_a_t but missing new_uncompiled_t
    fake_secpol_bin = tmp_path / "secpol.bin"
    fake_secpol_bin.write_bytes(b"\x00SECPOL\x00svc_a_t\x00")

    res = audit_firmware(
        pol,
        ifs,
        bin_dir,
        policy_source_path=pol_path,
        secpol_bin=fake_secpol_bin,
    )
    assert any(f.rule_id == "POLICY_SOURCE_DRIFT" for f in res.findings)


def test_cli_audit_firmware_sarif_json_and_error_exit_codes(tmp_path: Path, capsys) -> None:
    pol_path = tmp_path / "fw.secpol"
    pol_path.write_text(
        "type can_hal_t;\nallow can_hal_t self:ability { nonroot mem_phys:0xfe000000-0xfe010000 };\n",
        encoding="utf-8",
    )
    ifs_path = tmp_path / "fw.ifs"
    ifs_path.write_text(
        "[+script] startup-script = {\n    secpolpush /etc/secpol.bin\n    on -T can_hal_t -u 23:23 can_hal &\n}\n",
        encoding="utf-8",
    )
    bin_dir = tmp_path / "bins"
    bin_dir.mkdir()
    (bin_dir / "can_hal").write_bytes(
        _build_minimal_elf64(e_type=ET_EXEC, e_machine=EM_AARCH64, gnu_stack_flags=0x7, has_relro=False)
    )

    # SARIF output -> exit 1
    sarif_out = tmp_path / "fw.sarif"
    rc = main(
        [
            "audit-firmware",
            str(pol_path),
            "--ifs",
            str(ifs_path),
            "--bin-dir",
            str(bin_dir),
            "--format",
            "sarif",
            "--output",
            str(sarif_out),
        ]
    )
    assert rc == 1
    sarif_doc = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_doc["version"] == "2.1.0"
    assert [r["ruleId"] for r in sarif_doc["runs"][0]["results"]] == ["HIGH_PRIV_UNHARDENED_ELF"]

    # JSON output -> exit 1
    rc_json = main(
        [
            "audit-firmware",
            str(pol_path),
            "--ifs",
            str(ifs_path),
            "--bin-dir",
            str(bin_dir),
            "--format",
            "json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert rc_json == 1
    assert payload["summary"]["binaries_scanned"] == 1
    assert payload["binaries"][0]["machine"] == "EM_AARCH64"

    # Corrupt ELF binary -> fail-closed exit 2
    (bin_dir / "can_hal").write_bytes(b"NOT_AN_ELF_FILE")
    rc_bad = main(
        [
            "audit-firmware",
            str(pol_path),
            "--ifs",
            str(ifs_path),
            "--bin-dir",
            str(bin_dir),
        ]
    )
    err_out = capsys.readouterr().err
    assert rc_bad == 2
    assert "ELF_PARSE_ERROR" in err_out

    # Missing bin-dir -> exit 2
    rc_missing = main(
        [
            "audit-firmware",
            str(pol_path),
            "--ifs",
            str(ifs_path),
            "--bin-dir",
            str(tmp_path / "nonexistent"),
        ]
    )
    assert rc_missing == 2


@pytest.mark.parametrize(
    "e_type,stack_flags,relro,expected_missing",
    [
        (ET_DYN, 0x6, True, []),
        (ET_EXEC, 0x6, True, ["PIE (ET_DYN)"]),
        (ET_DYN, None, True, ["NX (PT_GNU_STACK without PF_X)"]),
        (ET_DYN, 0x7, True, ["NX (PT_GNU_STACK without PF_X)"]),
        (ET_DYN, 0x6, False, ["RELRO (PT_GNU_RELRO)"]),
    ],
)
def test_elf64_mitigation_matrix(
    e_type: int,
    stack_flags: int | None,
    relro: bool,
    expected_missing: list[str],
) -> None:
    raw = _build_minimal_elf64(
        e_type=e_type,
        gnu_stack_flags=stack_flags,
        has_relro=relro,
        bind_now=relro,
    )
    info = parse_elf64_bytes(raw, "matrix_bin")
    assert info.missing_mitigations() == expected_missing


def test_unused_settypeid_surface_when_libsecpol_linked_without_transition_syms(tmp_path: Path) -> None:
    pol = parse_secpol_text(
        """
        type mgr_t;
        type worker_t;
        allow mgr_t self:ability { nonroot settypeid:worker_t };
        """,
        "p.secpol",
    )
    ifs = parse_ifs_text(
        "[+script] startup-script = {\n    secpolpush /etc/secpol.bin\n    on -T mgr_t -u 22:22 mgr &\n}\n",
        "b.ifs",
    )
    # Links libsecpol.so.1 for secpol_resmgr_attach ONLY, never imports transition APIs
    (tmp_path / "mgr").write_bytes(
        _build_minimal_elf64(
            dt_needed=("libsecpol.so.1",),
            dynsym_names=("secpol_resmgr_attach",),
        )
    )
    res = audit_firmware(pol, ifs, tmp_path)
    assert [f.rule_id for f in res.findings] == ["UNUSED_SETTYPEID_SURFACE"]
    assert "never imports secpol_transition_type" in res.findings[0].message


def test_firmware_audit_nested_subdir_and_missing_binary_graceful(tmp_path: Path) -> None:
    pol = parse_secpol_text(
        """
        type a_t;
        type b_t;
        allow a_t self:ability { nonroot public_channel };
        allow b_t self:ability { nonroot public_channel };
        """,
        "sub.secpol",
    )
    ifs = parse_ifs_text(
        """
        [+script] startup-script = {
            secpolpush /etc/secpol.bin
            on -T a_t -u 21:21 /sbin/svc_a &
            on -T b_t -u 22:22 missing_svc &
        }
        """,
        "sub.ifs",
    )
    subdir = tmp_path / "sbin"
    subdir.mkdir()
    (subdir / "svc_a").write_bytes(_build_minimal_elf64())

    res = audit_firmware(pol, ifs, tmp_path)
    assert res.findings == []
    assert len(res.binaries_scanned) == 1
    assert len(res.missing_binaries) == 1
    assert res.missing_binaries[0]["executable"] == "missing_svc"


def test_secpolinfo_alternate_text_formats(tmp_path: Path) -> None:
    pol_path = tmp_path / "alt.secpol"
    pol_text = "type alpha_t;\n"
    pol_path.write_text(pol_text, encoding="utf-8")
    pol = parse_secpol_text(pol_text, str(pol_path))
    ifs = parse_ifs_text(
        "[+script] startup-script = {\n    secpolpush /etc/secpol.bin\n    on -T alpha_t -u 21:21 alpha &\n}\n",
        "alt.ifs",
    )
    (tmp_path / "alpha").write_bytes(_build_minimal_elf64())

    info_path = tmp_path / "info.txt"
    info_path.write_text("Policy is mutable\npolicy_id=0x0\ntype 1: alpha_t\n", encoding="utf-8")
    res = audit_firmware(pol, ifs, tmp_path, policy_source_path=pol_path, secpol_info_path=info_path)
    assert {f.rule_id for f in res.findings} == {"MUTABLE_COMPILED_POLICY", "ZERO_POLICY_ID"}

