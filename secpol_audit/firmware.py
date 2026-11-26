"""Pure-Python QNX ELF64 binary hardening & compiled policy cross-layer auditor.

Parses ELF64 binaries (`EM_X86_64`, `EM_AARCH64`) strictly using Python stdlib
`struct.unpack_from`, inspects PIE (`ET_DYN`), NX (`PT_GNU_STACK`), RELRO
(`PT_GNU_RELRO` + `DT_BIND_NOW`), `DT_NEEDED` (`libsecpol.so*`, `libsecpolev.so*`),
and `.dynsym` symbols (`secpol_transition_type`, `secpol_posix_spawnattr_settypeid`,
`secpol_resmgr_attach`, `secpol_check_permission`, `secpolev_init`), then
cross-references each binary against `build.ifs` and `.secpol`.

Also supports optional compiled-policy checks via `--secpol-bin` and/or
`--secpol-info` (`MUTABLE_COMPILED_POLICY`, `ZERO_POLICY_ID`, `POLICY_SOURCE_DRIFT`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import shutil
import struct
import subprocess
from typing import Any

from secpol_audit.checks import INHERITABLE_PRIV_ABILITIES
from secpol_audit.ir import Finding, IfsIR, PolicyIR, Severity, SourceSpan
from secpol_audit.paths import analyze_paths, collect_type_abilities

# ELF64 constants
ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2

ET_EXEC = 2
ET_DYN = 3

EM_X86_64 = 62
EM_AARCH64 = 183

MACHINE_NAMES: dict[int, str] = {
    EM_X86_64: "EM_X86_64",
    EM_AARCH64: "EM_AARCH64",
    3: "EM_386",
    40: "EM_ARM",
    243: "EM_RISCV",
}

PT_LOAD = 1
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552

PF_X = 0x1

SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_DYNSYM = 11

DT_NULL = 0
DT_NEEDED = 1
DT_BIND_NOW = 24
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DF_BIND_NOW = 0x8
DF_1_NOW = 0x1

TRANSITION_API_SYMBOLS = frozenset(
    {
        "secpol_transition_type",
        "secpol_posix_spawnattr_settypeid",
    }
)

TRACKED_SECPOL_SYMBOLS = frozenset(
    {
        "secpol_transition_type",
        "secpol_posix_spawnattr_settypeid",
        "secpol_resmgr_attach",
        "secpol_check_permission",
        "secpolev_init",
    }
)


class ElfParseError(ValueError):
    """Raised when a file cannot be parsed as a valid ELF64 binary."""


@dataclass(frozen=True)
class Elf64Info:
    """Extracted security hardening & dynamic symbol metadata for an ELF64 binary."""

    path: str
    sha256: str
    endian: str  # "little" or "big"
    e_type: int
    e_machine: int
    machine_name: str
    is_pie: bool
    has_gnu_stack: bool
    has_nx_stack: bool
    has_relro: bool
    has_full_relro: bool
    dt_needed: tuple[str, ...]
    dynsym_names: tuple[str, ...]
    tracked_secpol_symbols: tuple[str, ...]
    links_libsecpol: bool
    links_libsecpolev: bool

    def missing_mitigations(self) -> list[str]:
        missing: list[str] = []
        if not self.is_pie:
            missing.append("PIE (ET_DYN)")
        if not self.has_nx_stack:
            missing.append("NX (PT_GNU_STACK without PF_X)")
        if not self.has_relro:
            missing.append("RELRO (PT_GNU_RELRO)")
        return missing

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sha256": self.sha256,
            "machine": self.machine_name,
            "is_pie": self.is_pie,
            "has_nx_stack": self.has_nx_stack,
            "has_relro": self.has_relro,
            "has_full_relro": self.has_full_relro,
            "missing_mitigations": self.missing_mitigations(),
            "dt_needed": list(self.dt_needed),
            "tracked_secpol_symbols": list(self.tracked_secpol_symbols),
            "links_libsecpol": self.links_libsecpol,
            "links_libsecpolev": self.links_libsecpolev,
        }


@dataclass
class CompiledPolicyStatus:
    """Result of optional `--secpol-bin` / `--secpol-info` inspection."""

    secpol_bin: str | None = None
    secpol_bin_sha256: str | None = None
    source_sha256: str | None = None
    secpol_info_source: str | None = None  # file path, "secpolinfo", or "skipped"
    mutable: bool | None = None
    policy_id: int | None = None
    compiled_types: list[str] = field(default_factory=list)
    reported_source_sha256: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "secpol_bin": self.secpol_bin,
            "secpol_bin_sha256": self.secpol_bin_sha256,
            "source_sha256": self.source_sha256,
            "secpol_info_source": self.secpol_info_source,
            "mutable": self.mutable,
            "policy_id": self.policy_id,
            "compiled_types": self.compiled_types,
            "reported_source_sha256": self.reported_source_sha256,
        }


@dataclass
class FirmwareAuditResult:
    """Combined cross-layer ELF64 + IFS + `.secpol` + compiled-policy audit result."""

    policy_path: str
    ifs_path: str
    bin_dir: str
    binaries_scanned: list[dict[str, Any]] = field(default_factory=list)
    missing_binaries: list[dict[str, str]] = field(default_factory=list)
    compiled_policy: CompiledPolicyStatus | None = None
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy_path,
            "ifs": self.ifs_path,
            "bin_dir": self.bin_dir,
            "summary": {
                "binaries_scanned": len(self.binaries_scanned),
                "missing_binaries": len(self.missing_binaries),
                "total_findings": len(self.findings),
            },
            "binaries": self.binaries_scanned,
            "missing_binaries": self.missing_binaries,
            "compiled_policy": self.compiled_policy.to_dict() if self.compiled_policy else None,
            "findings": [f.to_dict() for f in self.findings],
        }


def _read_cstr(buf: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(buf):
        return ""
    end = buf.find(b"\x00", offset)
    if end == -1:
        end = len(buf)
    return buf[offset:end].decode("utf-8", errors="replace")


def parse_elf64_bytes(data: bytes, path_label: str = "<memory>") -> Elf64Info:
    """Parse an ELF64 binary strictly via Python stdlib `struct.unpack_from`."""
    if len(data) < 64:
        raise ElfParseError(f"'{path_label}' is too small ({len(data)} bytes) to be an ELF64 binary")
    if data[:4] != ELF_MAGIC:
        raise ElfParseError(f"'{path_label}' does not start with ELF magic bytes")
    ei_class = data[4]
    if ei_class != ELFCLASS64:
        raise ElfParseError(
            f"'{path_label}' is not ELF64 (EI_CLASS={ei_class}; expected {ELFCLASS64})"
        )
    ei_data = data[5]
    if ei_data == ELFDATA2LSB:
        endian_prefix = "<"
        endian_name = "little"
    elif ei_data == ELFDATA2MSB:
        endian_prefix = ">"
        endian_name = "big"
    else:
        raise ElfParseError(f"'{path_label}' has unknown ELF endianness EI_DATA={ei_data}")

    # ELF64 header fields starting at byte 16 (48 bytes total -> offset 64)
    (
        e_type,
        e_machine,
        _e_version,
        _e_entry,
        e_phoff,
        e_shoff,
        _e_flags,
        _e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        _e_shstrndx,
    ) = struct.unpack_from(f"{endian_prefix}HHIQQQIHHHHHH", data, 16)

    is_pie = e_type == ET_DYN
    has_gnu_stack = False
    has_nx_stack = False
    has_relro = False

    # Parse program headers (Elf64_Phdr: IIQQQQQQ = 56 bytes)
    if e_phoff and e_phnum and e_phentsize >= 56:
        for idx in range(e_phnum):
            off = e_phoff + idx * e_phentsize
            if off + 56 > len(data):
                break
            p_type, p_flags, _p_off, _p_va, _p_pa, _p_fsz, _p_msz, _p_align = struct.unpack_from(
                f"{endian_prefix}IIQQQQQQ", data, off
            )
            if p_type == PT_GNU_STACK:
                has_gnu_stack = True
                has_nx_stack = (p_flags & PF_X) == 0
            elif p_type == PT_GNU_RELRO:
                has_relro = True

    # Parse section headers (Elf64_Shdr: IIQQQQIIQQ = 64 bytes)
    sections: list[tuple[int, int, int, int, int, int, int, int, int, int]] = []
    if e_shoff and e_shnum and e_shentsize >= 64:
        for idx in range(e_shnum):
            off = e_shoff + idx * e_shentsize
            if off + 64 > len(data):
                break
            sh = struct.unpack_from(f"{endian_prefix}IIQQQQIIQQ", data, off)
            sections.append(sh)

    dt_needed: list[str] = []
    bind_now = False
    dynsym_names: list[str] = []

    def _section_slice(sh_idx: int) -> bytes:
        if 0 <= sh_idx < len(sections):
            _, _, _, _, s_off, s_size, _, _, _, _ = sections[sh_idx]
            if s_off + s_size <= len(data):
                return data[s_off : s_off + s_size]
        return b""

    for sh in sections:
        _sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, sh_link, _sh_info, _sh_align, sh_entsize = sh
        if sh_offset + sh_size > len(data):
            continue

        if sh_type == SHT_DYNAMIC:
            strtab = _section_slice(sh_link)
            entsize = sh_entsize if sh_entsize >= 16 else 16
            count = sh_size // entsize
            for i in range(count):
                d_tag, d_val = struct.unpack_from(
                    f"{endian_prefix}qQ", data, sh_offset + i * entsize
                )
                if d_tag == DT_NULL:
                    break
                if d_tag == DT_NEEDED:
                    lib = _read_cstr(strtab, d_val)
                    if lib:
                        dt_needed.append(lib)
                elif d_tag == DT_BIND_NOW:
                    bind_now = True
                elif d_tag == DT_FLAGS and (d_val & DF_BIND_NOW):
                    bind_now = True
                elif d_tag == DT_FLAGS_1 and (d_val & DF_1_NOW):
                    bind_now = True

        elif sh_type == SHT_DYNSYM:
            strtab = _section_slice(sh_link)
            entsize = sh_entsize if sh_entsize >= 24 else 24
            count = sh_size // entsize
            for i in range(count):
                st_name, _st_info, _st_other, _st_shndx, _st_val, _st_size = struct.unpack_from(
                    f"{endian_prefix}IBBHQQ", data, sh_offset + i * entsize
                )
                if st_name:
                    sym = _read_cstr(strtab, st_name)
                    if sym:
                        dynsym_names.append(sym)

    unique_needed = tuple(dict.fromkeys(dt_needed))
    unique_syms = tuple(dict.fromkeys(dynsym_names))
    tracked_syms = tuple(sorted(s for s in unique_syms if s in TRACKED_SECPOL_SYMBOLS))
    links_libsecpol = any(
        lib == "libsecpol.so" or lib.startswith("libsecpol.so.") for lib in unique_needed
    )
    links_libsecpolev = any(
        lib == "libsecpolev.so" or lib.startswith("libsecpolev.so.") for lib in unique_needed
    )

    return Elf64Info(
        path=path_label,
        sha256=hashlib.sha256(data).hexdigest(),
        endian=endian_name,
        e_type=e_type,
        e_machine=e_machine,
        machine_name=MACHINE_NAMES.get(e_machine, f"EM_{e_machine}"),
        is_pie=is_pie,
        has_gnu_stack=has_gnu_stack,
        has_nx_stack=has_nx_stack,
        has_relro=has_relro,
        has_full_relro=has_relro and bind_now,
        dt_needed=unique_needed,
        dynsym_names=unique_syms,
        tracked_secpol_symbols=tracked_syms,
        links_libsecpol=links_libsecpol,
        links_libsecpolev=links_libsecpolev,
    )


def parse_elf64_file(path: str | Path) -> Elf64Info:
    p = Path(path)
    return parse_elf64_bytes(p.read_bytes(), str(p))


def _resolve_binary_path(bin_dir: Path, executable: str, executable_path: str | None) -> Path | None:
    """Locate an IFS service binary inside `bin_dir` deterministically."""
    candidates: list[Path] = []
    if executable_path:
        rel = executable_path.lstrip("/")
        candidates.append(bin_dir / rel)
        candidates.append(bin_dir / Path(rel).name)
    if executable:
        candidates.append(bin_dir / executable)
        candidates.append(bin_dir / Path(executable).name)

    for cand in candidates:
        if cand.is_file():
            return cand

    # Fallback recursive search by basename (sorted for determinism)
    target_name = Path(executable).name
    for found in sorted(bin_dir.rglob(target_name)):
        if found.is_file():
            return found
    return None


def _parse_secpolinfo_text(text: str) -> tuple[bool | None, int | None, list[str], str | None]:
    """Parse `secpolinfo` text output for mutability, policy ID, types, and optional source SHA-256."""
    mutable: bool | None = None
    policy_id: int | None = None
    compiled_types: list[str] = []
    reported_sha: str | None = None

    in_types_section = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            in_types_section = False
            continue
        lower = line.lower()

        # Mutability detection
        m_mut = re.search(r"\bmutable\s*[:=]\s*(yes|true|1|enabled|no|false|0|disabled)\b", lower)
        if m_mut:
            mutable = m_mut.group(1) in ("yes", "true", "1", "enabled")
        elif "policy is mutable" in lower or re.search(r"\bflags\b.*\bmutable\b", lower):
            if "immutable" not in lower:
                mutable = True
        elif "policy is immutable" in lower or "not mutable" in lower:
            mutable = False

        # Policy ID detection
        m_id = re.search(r"\b(?:policy[_\s-]*id|id)\s*[:=]\s*(0x[0-9a-f]+|\d+)\b", lower)
        if m_id:
            val_s = m_id.group(1)
            policy_id = int(val_s, 16) if val_s.startswith("0x") else int(val_s, 10)

        # Optional source SHA-256 line
        m_sha = re.search(r"\b(?:source[_\s-]*sha256|policy[_\s-]*sha256|sha256)\s*[:=]\s*([0-9a-f]{64})\b", lower)
        if m_sha:
            reported_sha = m_sha.group(1)

        # Compiled types list (e.g. `types: foo_t bar_t` or `type foo_t` or bullet list under `types:`)
        m_types_inline = re.match(r"^types\s*[:=]\s*(.+)$", line, flags=re.IGNORECASE)
        if m_types_inline:
            rest = m_types_inline.group(1).strip()
            for tok in re.split(r"[\s,;]+", rest):
                if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tok):
                    compiled_types.append(tok)
            in_types_section = not bool(rest)
            continue
        if re.fullmatch(r"types\s*:", line, flags=re.IGNORECASE):
            in_types_section = True
            continue
        m_type_line = re.match(r"^type\s+(?:\d+\s*[:=]\s*)?([A-Za-z_][A-Za-z0-9_]*)\b", line)
        if m_type_line:
            compiled_types.append(m_type_line.group(1))
            continue
        if in_types_section:
            m_item = re.match(r"^(?:[-*]|\d+\s*[:.])?\s*([A-Za-z_][A-Za-z0-9_]*)\b", line)
            if m_item and ":" not in line:
                compiled_types.append(m_item.group(1))

    return mutable, policy_id, sorted(set(compiled_types)), reported_sha


def _audit_compiled_policy(
    policy: PolicyIR,
    *,
    source_path: Path | None,
    secpol_bin: Path | None,
    secpol_info_path: Path | None,
) -> tuple[CompiledPolicyStatus, list[Finding]]:
    findings: list[Finding] = []
    source_sha = (
        hashlib.sha256(source_path.read_bytes()).hexdigest()
        if source_path is not None and source_path.is_file()
        else None
    )
    bin_sha = (
        hashlib.sha256(secpol_bin.read_bytes()).hexdigest()
        if secpol_bin is not None and secpol_bin.is_file()
        else None
    )

    info_text: str | None = None
    info_source: str = "skipped"
    info_file_label = str(secpol_info_path or secpol_bin or policy.source_path)

    if secpol_info_path is not None:
        info_text = secpol_info_path.read_text(encoding="utf-8", errors="replace")
        info_source = str(secpol_info_path)
    elif secpol_bin is not None:
        secpolinfo_exe = shutil.which("secpolinfo")
        if secpolinfo_exe:
            proc = subprocess.run(
                [secpolinfo_exe, str(secpol_bin)],
                capture_output=True,
                text=True,
                check=False,
                timeout=30,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                info_text = proc.stdout
                info_source = secpolinfo_exe

    status = CompiledPolicyStatus(
        secpol_bin=str(secpol_bin) if secpol_bin else None,
        secpol_bin_sha256=bin_sha,
        source_sha256=source_sha,
        secpol_info_source=info_source,
    )

    span = SourceSpan(
        file=info_file_label,
        line=1,
        col=1,
        end_line=1,
        end_col=1,
        snippet=info_file_label,
    )

    if info_text is not None:
        mutable, policy_id, compiled_types, reported_sha = _parse_secpolinfo_text(info_text)
        status.mutable = mutable
        status.policy_id = policy_id
        status.compiled_types = compiled_types
        status.reported_source_sha256 = reported_sha

        if mutable is True:
            findings.append(
                Finding(
                    rule_id="MUTABLE_COMPILED_POLICY",
                    severity=Severity.HIGH,
                    message=(
                        f"Compiled security policy metadata ({info_file_label}) reports a MUTABLE policy "
                        "(compiled with `secpolcompile -m`); production QNX images must enforce immutable policies"
                    ),
                    span=span,
                    remediation="Recompile the policy without `-m` so runtime policy mutation is disabled.",
                    metadata={"info_source": info_source},
                )
            )

        if policy_id is not None and policy_id == 0:
            findings.append(
                Finding(
                    rule_id="ZERO_POLICY_ID",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Compiled security policy metadata ({info_file_label}) reports policy ID 0; "
                        "unversioned policies hinder firmware traceability and rollback detection"
                    ),
                    span=span,
                    remediation="Pass an explicit non-zero policy identifier when compiling with `secpolcompile -i <id>`.",
                    metadata={"policy_id": policy_id, "info_source": info_source},
                )
            )

        # Source-to-binary SHA-256 drift check
        if reported_sha and source_sha and reported_sha != source_sha:
            findings.append(
                Finding(
                    rule_id="POLICY_SOURCE_DRIFT",
                    severity=Severity.HIGH,
                    message=(
                        f"Compiled policy metadata SHA-256 ({reported_sha[:12]}...) does not match "
                        f"audited source '{policy.source_path}' ({source_sha[:12]}...)"
                    ),
                    span=span,
                    remediation="Rebuild secpol.bin from the audited .secpol source and verify checksums.",
                    metadata={
                        "expected_source_sha256": source_sha,
                        "reported_source_sha256": reported_sha,
                    },
                )
            )

        # Compiled type-set drift check
        if compiled_types:
            src_types = set(policy.types.keys())
            comp_set = set(compiled_types)
            missing_in_compiled = sorted(src_types - comp_set)
            extra_in_compiled = sorted(comp_set - src_types)
            if missing_in_compiled or extra_in_compiled:
                parts: list[str] = []
                if missing_in_compiled:
                    parts.append(f"missing in compiled policy: {', '.join(missing_in_compiled)}")
                if extra_in_compiled:
                    parts.append(f"undeclared in .secpol source: {', '.join(extra_in_compiled)}")
                findings.append(
                    Finding(
                        rule_id="POLICY_SOURCE_DRIFT",
                        severity=Severity.HIGH,
                        message=(
                            f"Compiled policy type table diverges from '{policy.source_path}' "
                            f"({'; '.join(parts)})"
                        ),
                        span=span,
                        remediation="Recompile secpol.bin from the current .secpol source so binary and source stay in sync.",
                        metadata={
                            "missing_in_compiled": missing_in_compiled,
                            "extra_in_compiled": extra_in_compiled,
                        },
                    )
                )

    elif secpol_bin is not None and secpol_bin.is_file():
        # Offline fallback when `secpolinfo` binary is absent: scan printable NUL-delimited ASCII strings
        raw_bytes = secpol_bin.read_bytes()
        ascii_tokens = {
            m.group(0).decode("ascii")
            for m in re.finditer(rb"[A-Za-z_][A-Za-z0-9_]{2,63}", raw_bytes)
        }
        # Only run string-table drift check if the binary actually looks like it carries type names
        matched = set(policy.types.keys()) & ascii_tokens
        missing = sorted(set(policy.types.keys()) - ascii_tokens)
        if matched and missing:
            findings.append(
                Finding(
                    rule_id="POLICY_SOURCE_DRIFT",
                    severity=Severity.HIGH,
                    message=(
                        f"Compiled policy binary '{secpol_bin}' appears out of sync with '{policy.source_path}': "
                        f"type(s) not present in binary string table: {', '.join(missing)}"
                    ),
                    span=span,
                    remediation="Recompile secpol.bin from the audited .secpol source (or supply `--secpol-info` for full verification).",
                    metadata={
                        "missing_types": missing,
                        "secpol_bin_sha256": bin_sha,
                        "source_sha256": source_sha,
                    },
                )
            )

    return status, findings


def audit_firmware(
    policy: PolicyIR,
    ifs: IfsIR,
    bin_dir: str | Path,
    *,
    policy_source_path: str | Path | None = None,
    secpol_bin: str | Path | None = None,
    secpol_info_path: str | Path | None = None,
) -> FirmwareAuditResult:
    """Cross-reference ELF64 service binaries in `bin_dir` against `ifs` and `policy`."""
    bin_root = Path(bin_dir)
    path_res = analyze_paths(policy, ifs=ifs)
    abilities_by_type = collect_type_abilities(policy)

    # Determine which concrete types have settypeid permissions in policy
    types_with_settypeid: dict[str, list[str]] = {}
    for tname, spec_list in abilities_by_type.items():
        targets: list[str] = []
        for spec, _ in spec_list:
            if spec.name == "settypeid":
                targets.extend(spec.args or ("*",))
        if targets:
            types_with_settypeid[tname] = sorted(set(targets))

    result = FirmwareAuditResult(
        policy_path=policy.source_path,
        ifs_path=ifs.source_path,
        bin_dir=str(bin_root),
    )

    seen_pair: set[tuple[str, str]] = set()
    for cmd in ifs.commands:
        if cmd.is_builtin or cmd.is_secpolpush or not cmd.executable or not cmd.on_type:
            continue
        tname = cmd.on_type
        if tname not in policy.types:
            continue

        resolved = _resolve_binary_path(bin_root, cmd.executable, cmd.executable_path)
        if resolved is None:
            result.missing_binaries.append(
                {
                    "executable": cmd.executable,
                    "type": tname,
                    "ifs_location": cmd.span.format_loc(),
                }
            )
            continue

        pair_key = (tname, str(resolved))
        if pair_key in seen_pair:
            continue
        seen_pair.add(pair_key)

        elf = parse_elf64_file(resolved)
        node_info = path_res.nodes.get(tname, {})
        type_ability_names = {spec.name for spec, _ in abilities_by_type.get(tname, [])}
        is_privileged = bool(node_info.get("is_sink")) or bool(
            type_ability_names & INHERITABLE_PRIV_ABILITIES
        )

        entry = elf.to_dict()
        entry["type"] = tname
        entry["executable"] = cmd.executable
        entry["is_privileged"] = is_privileged
        entry["ifs_location"] = cmd.span.format_loc()
        result.binaries_scanned.append(entry)

        # 1. HIGH_PRIV_UNHARDENED_ELF
        missing_mits = elf.missing_mitigations()
        if is_privileged and missing_mits:
            sev = (
                Severity.CRITICAL
                if (len(missing_mits) >= 2 or (not elf.has_nx_stack and node_info.get("is_sink")))
                else Severity.HIGH
            )
            result.findings.append(
                Finding(
                    rule_id="HIGH_PRIV_UNHARDENED_ELF",
                    severity=sev,
                    message=(
                        f"Privileged service binary '{resolved.name}' ({elf.machine_name}, type '{tname}') "
                        f"is missing ELF64 hardening mitigation(s): {', '.join(missing_mits)}"
                    ),
                    span=cmd.span,
                    remediation=(
                        f"Rebuild '{resolved.name}' with QNX hardening flags: "
                        "'-fPIE -pie -Wl,-z,noexecstack -Wl,-z,relro,-z,now'."
                    ),
                    metadata={
                        "binary": str(resolved),
                        "sha256": elf.sha256,
                        "machine": elf.machine_name,
                        "type": tname,
                        "missing_mitigations": missing_mits,
                    },
                )
            )

        # 2. UNREACHABLE_TRANSITION_API: binary imports transition API, policy grants NO settypeid
        imported_transitions = sorted(s for s in elf.dynsym_names if s in TRANSITION_API_SYMBOLS)
        has_policy_settypeid = tname in types_with_settypeid
        if imported_transitions and not has_policy_settypeid:
            result.findings.append(
                Finding(
                    rule_id="UNREACHABLE_TRANSITION_API",
                    severity=Severity.HIGH,
                    message=(
                        f"Service binary '{resolved.name}' (type '{tname}') dynamically imports QNX transition "
                        f"API(s) {', '.join(imported_transitions)}, but policy '{policy.source_path}' grants no "
                        f"`settypeid` ability to '{tname}'"
                    ),
                    span=cmd.span,
                    remediation=(
                        f"Either remove dead transition calls from '{resolved.name}' or explicitly grant "
                        f"a tightly-scoped `settypeid:<target_t>` ability to '{tname}' if required."
                    ),
                    metadata={
                        "binary": str(resolved),
                        "type": tname,
                        "imported_transition_apis": imported_transitions,
                    },
                )
            )

        # 3. UNUSED_SETTYPEID_SURFACE: policy grants settypeid, binary never links/imports transition APIs
        if has_policy_settypeid and (not elf.links_libsecpol or not imported_transitions):
            reason = (
                "does not link libsecpol.so"
                if not elf.links_libsecpol
                else "never imports secpol_transition_type or secpol_posix_spawnattr_settypeid"
            )
            result.findings.append(
                Finding(
                    rule_id="UNUSED_SETTYPEID_SURFACE",
                    severity=Severity.MEDIUM,
                    message=(
                        f"Policy grants `settypeid:{','.join(types_with_settypeid[tname])}` to type '{tname}', "
                        f"but its binary '{resolved.name}' {reason} (unnecessary transition attack surface)"
                    ),
                    span=cmd.span,
                    remediation=(
                        f"Remove unused `settypeid:{','.join(types_with_settypeid[tname])}` from '{tname}' "
                        "to reduce transition attack surface."
                    ),
                    metadata={
                        "binary": str(resolved),
                        "type": tname,
                        "granted_settypeid_targets": types_with_settypeid[tname],
                        "links_libsecpol": elf.links_libsecpol,
                    },
                )
            )

    # Optional compiled-policy inspection (`--secpol-bin` / `--secpol-info`)
    if secpol_bin is not None or secpol_info_path is not None:
        cp_status, cp_findings = _audit_compiled_policy(
            policy,
            source_path=Path(policy_source_path) if policy_source_path else Path(policy.source_path),
            secpol_bin=Path(secpol_bin) if secpol_bin else None,
            secpol_info_path=Path(secpol_info_path) if secpol_info_path else None,
        )
        result.compiled_policy = cp_status
        result.findings.extend(cp_findings)

    return result
