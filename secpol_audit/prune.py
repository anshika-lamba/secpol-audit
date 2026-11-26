"""QNX 8.0 `secpolgenerate` unused-rule pruner and `/dev/secpolgenerate/errors` auditor."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any

from secpol_audit.ir import Finding, PolicyIR, Severity, SourceSpan
from secpol_audit.paths import collect_type_abilities

PRUNE_PRIVILEGED_ABILITIES = frozenset({"mem_phys", "io", "settypeid", "mac_policy"})

_ALLOW_ABILITY_BLOCK_RE = re.compile(
    r"allow\s+(?P<subject>\{[^}]+\}|[A-Za-z_][A-Za-z0-9_]*)\s+self\s*:\s*ability\s*"
    r"(?:\{(?P<block>[^}]*)\}|(?P<single>[^;]+))\s*;",
    re.MULTILINE | re.DOTALL,
)
_ABILITY_TOKEN_RE = re.compile(
    r"\b(mem_phys|io|settypeid|mac_policy)(?::([A-Za-z0-9_,.*:/-]+))?\b"
)
_LINE_TYPE_RE = re.compile(r"\b(?:type\s*[:=]\s*)?([A-Za-z_][A-Za-z0-9_]*_t)\b")
_COLON_PREFIX_TYPE_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*:")


@dataclass
class PruneResult:
    """Result of auditing a policy against `/dev/secpolgenerate/unused` and `errors`."""

    policy_path: str
    unused_path: str
    errors_path: str | None = None
    unused_privileged_rules: list[dict[str, Any]] = field(default_factory=list)
    unregistered_sigevents: list[dict[str, Any]] = field(default_factory=list)
    other_errors: list[dict[str, Any]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy_path,
            "unused_file": self.unused_path,
            "errors_file": self.errors_path,
            "summary": {
                "unused_privileged_rules": len(self.unused_privileged_rules),
                "unregistered_sigevents": len(self.unregistered_sigevents),
                "other_errors": len(self.other_errors),
                "total_findings": len(self.findings),
            },
            "unused_privileged_rules": self.unused_privileged_rules,
            "unregistered_sigevents": self.unregistered_sigevents,
            "other_errors": self.other_errors,
            "findings": [f.to_dict() for f in self.findings],
        }


def _extract_unused_entries(
    unused_text: str,
    policy: PolicyIR,
    unused_path: str,
) -> list[tuple[str, str, str | None, SourceSpan]]:
    """Extract `(type_name, ability_name, ability_arg, span)` from `/dev/secpolgenerate/unused`.

    Supports both full QNX `.secpol` rule syntax (`allow foo_t self:ability { mem_phys };`)
    and line-oriented `secpolgenerate/unused` formats (`foo_t: ability settypeid:bar_t`).
    """
    entries: list[tuple[str, str, str | None, SourceSpan]] = []
    seen: set[tuple[str, str, str | None]] = set()
    lines = unused_text.splitlines()

    def _offset_to_line(offset: int) -> int:
        return unused_text.count("\n", 0, offset) + 1

    # Pass 1: full `.secpol` `allow <subj> self:ability ...;` rules
    matched_ranges: list[tuple[int, int]] = []
    for m in _ALLOW_ABILITY_BLOCK_RE.finditer(unused_text):
        matched_ranges.append((m.start(), m.end()))
        subj_raw = m.group("subject").strip()
        if subj_raw.startswith("{") and subj_raw.endswith("}"):
            subjects = [tok for tok in subj_raw[1:-1].split() if tok]
        else:
            subjects = [subj_raw]
        body = m.group("block") if m.group("block") is not None else (m.group("single") or "")
        line_no = _offset_to_line(m.start())
        snippet = lines[line_no - 1].strip() if 0 <= line_no - 1 < len(lines) else m.group(0).strip()
        span = SourceSpan(
            file=unused_path,
            line=line_no,
            col=1,
            end_line=line_no,
            end_col=max(1, len(snippet)),
            snippet=snippet,
        )
        for subj in subjects:
            concrete = [c for c, _ in policy.expand_subject(subj)] if policy.is_declared_identifier(subj) else [subj]
            for ab_m in _ABILITY_TOKEN_RE.finditer(body):
                ab_name = ab_m.group(1)
                ab_arg = ab_m.group(2)
                for ct in concrete:
                    key = (ct, ab_name, ab_arg)
                    if key not in seen:
                        seen.add(key)
                        entries.append((ct, ab_name, ab_arg, span))

    # Pass 2: line-oriented entries outside matched `allow ...;` blocks
    offset = 0
    for line_no, raw_line in enumerate(lines, start=1):
        line_start = offset
        line_end = offset + len(raw_line)
        offset = line_end + 1
        if any(s <= line_start and line_end <= e for s, e in matched_ranges):
            continue
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        ab_matches = list(_ABILITY_TOKEN_RE.finditer(stripped))
        if not ab_matches:
            continue

        # Resolve subject type from declared policy types, `<name>:` prefix, or `*_t` token
        type_name: str | None = None
        m_prefix = _COLON_PREFIX_TYPE_RE.match(stripped)
        if m_prefix and m_prefix.group(1) in policy.types:
            type_name = m_prefix.group(1)
        if type_name is None:
            for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", stripped):
                if tok in policy.types:
                    type_name = tok
                    break
        if type_name is None:
            m_t = _LINE_TYPE_RE.search(stripped)
            if m_t:
                type_name = m_t.group(1)
        if type_name is None:
            type_name = "<unknown>"

        span = SourceSpan(
            file=unused_path,
            line=line_no,
            col=1,
            end_line=line_no,
            end_col=max(1, len(stripped)),
            snippet=stripped,
        )
        for ab_m in ab_matches:
            ab_name = ab_m.group(1)
            ab_arg = ab_m.group(2)
            key = (type_name, ab_name, ab_arg)
            if key not in seen:
                seen.add(key)
                entries.append((type_name, ab_name, ab_arg, span))

    return entries


def prune_policy(
    policy: PolicyIR,
    unused_text: str,
    *,
    unused_path: str = "<unused>",
    errors_text: str | None = None,
    errors_path: str | None = None,
) -> PruneResult:
    """Flag unused privileged rules and `/dev/secpolgenerate/errors` unregistered sigevents."""
    result = PruneResult(
        policy_path=policy.source_path,
        unused_path=unused_path,
        errors_path=errors_path,
    )

    abilities_by_type = collect_type_abilities(policy)
    unused_entries = _extract_unused_entries(unused_text, policy, unused_path)

    for tname, ab_name, ab_arg, unused_span in unused_entries:
        if ab_name not in PRUNE_PRIVILEGED_ABILITIES:
            continue
        # Match against the source policy span if declared on `tname`
        policy_span: SourceSpan | None = None
        in_policy = False
        for spec, _ in abilities_by_type.get(tname, []):
            if spec.name == ab_name:
                if ab_arg is None or ab_arg in spec.args or (spec.raw_arg and ab_arg == spec.raw_arg):
                    policy_span = spec.span
                    in_policy = True
                    break
        canonical_ab = f"{ab_name}:{ab_arg}" if ab_arg else ab_name
        record = {
            "type": tname,
            "ability": canonical_ab,
            "present_in_policy": in_policy,
            "unused_location": unused_span.format_loc(),
            "policy_location": policy_span.format_loc() if policy_span else None,
        }
        result.unused_privileged_rules.append(record)
        result.findings.append(
            Finding(
                rule_id="UNUSED_PRIVILEGED_RULE",
                severity=Severity.HIGH,
                message=(
                    f"Privileged ability '{canonical_ab}' on type '{tname}' was never exercised "
                    f"under QNX secpolgenerate ({unused_span.format_loc()})"
                ),
                span=policy_span or unused_span,
                remediation=(
                    f"Prune unused privileged ability '{canonical_ab}' from '{tname}' in '{policy.source_path}' "
                    "to enforce least privilege."
                ),
                metadata=record,
            )
        )

    if errors_text is not None:
        err_label = errors_path or "<errors>"
        for line_no, raw_line in enumerate(errors_text.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            span = SourceSpan(
                file=err_label,
                line=line_no,
                col=1,
                end_line=line_no,
                end_col=max(1, len(stripped)),
                snippet=stripped,
            )
            if "sigevent" in stripped.lower():
                rec = {"line": line_no, "text": stripped}
                result.unregistered_sigevents.append(rec)
                result.findings.append(
                    Finding(
                        rule_id="UNREGISTERED_SIGEVENT",
                        severity=Severity.HIGH,
                        message=(
                            f"QNX secpolgenerate reported an unregistered sigevent at {err_label}:{line_no}: "
                            f"{stripped}"
                        ),
                        span=span,
                        remediation=(
                            "Register the sigevent with the kernel via MsgRegisterEvent() before passing it "
                            "to a resource manager, or add the required QNX sigevent permission."
                        ),
                        metadata=rec,
                    )
                )
            else:
                rec = {"line": line_no, "text": stripped}
                result.other_errors.append(rec)
                result.findings.append(
                    Finding(
                        rule_id="SECPOLGEN_ERROR",
                        severity=Severity.MEDIUM,
                        message=f"QNX secpolgenerate error at {err_label}:{line_no}: {stripped}",
                        span=span,
                        remediation="Inspect the failing service under QNX secpolgenerate and resolve the runtime policy error.",
                        metadata=rec,
                    )
                )

    return result


def prune_policy_files(
    policy: PolicyIR,
    unused_file: str | Path,
    *,
    errors_file: str | Path | None = None,
) -> PruneResult:
    u_path = Path(unused_file)
    unused_text = u_path.read_text(encoding="utf-8", errors="replace")
    errors_text: str | None = None
    e_str: str | None = None
    if errors_file is not None:
        e_path = Path(errors_file)
        errors_text = e_path.read_text(encoding="utf-8", errors="replace")
        e_str = str(e_path)
    return prune_policy(
        policy,
        unused_text,
        unused_path=str(u_path),
        errors_text=errors_text,
        errors_path=e_str,
    )
