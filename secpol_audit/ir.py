"""Core Intermediate Representation (IR) dataclasses for secpol-audit."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

RESERVED_TYPES = frozenset({"self", "default_rules"})


class Severity(str, Enum):
    """Finding severity levels ordered from highest to lowest."""

    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    WARNING = "WARNING"
    INFO = "INFO"

    @property
    def is_failing(self) -> bool:
        """Return True if this severity causes non-zero exit code 1."""
        return self in {Severity.CRITICAL, Severity.ERROR, Severity.HIGH, Severity.MEDIUM}

    @property
    def sarif_level(self) -> str:
        """Map severity to SARIF 2.1.0 level."""
        if self in {Severity.CRITICAL, Severity.ERROR, Severity.HIGH}:
            return "error"
        if self in {Severity.MEDIUM, Severity.WARNING}:
            return "warning"
        return "note"

    @property
    def rank(self) -> int:
        """Numeric sort rank (lower is more severe)."""
        order = {
            Severity.CRITICAL: 0,
            Severity.ERROR: 1,
            Severity.HIGH: 2,
            Severity.MEDIUM: 3,
            Severity.WARNING: 4,
            Severity.INFO: 5,
        }
        return order[self]


@dataclass(frozen=True)
class SourceSpan:
    """Exact 1-indexed source location."""

    file: str
    line: int
    col: int
    end_line: int | None = None
    end_col: int | None = None
    snippet: str = ""

    def format_loc(self) -> str:
        return f"{self.file}:{self.line}:{self.col}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "col": self.col,
            "end_line": self.end_line if self.end_line is not None else self.line,
            "end_col": self.end_col if self.end_col is not None else self.col,
            "snippet": self.snippet,
        }

    def __str__(self) -> str:
        return self.format_loc()


class ParseDiagnostic(Exception):
    """Fail-closed parser error or unsupported QNX construct (always exits with code 2)."""

    def __init__(self, code: str, message: str, span: SourceSpan) -> None:
        self.code = code
        self.message = message
        self.span = span
        super().__init__(f"{code} at {span.format_loc()}: {message}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "location": self.span.to_dict(),
        }


@dataclass(frozen=True)
class AttributeDecl:
    name: str
    span: SourceSpan


@dataclass(frozen=True)
class TypeDecl:
    name: str
    attributes: tuple[str, ...]
    span: SourceSpan


@dataclass(frozen=True)
class AbilitySpec:
    name: str
    args: tuple[str, ...]
    raw_arg: str | None
    modifiers: tuple[str, ...]
    span: SourceSpan
    raw: str

    @property
    def has_unlock(self) -> bool:
        return "unlock" in self.modifiers or "unlocked" in self.modifiers

    def canonical(self) -> str:
        mod_prefix = " ".join(self.modifiers)
        base = f"{self.name}:{','.join(self.args)}" if self.args else self.name
        return f"{mod_prefix} {base}".strip()


@dataclass(frozen=True)
class AbilityRule:
    sources: tuple[str, ...]
    targets: tuple[str, ...]
    abilities: tuple[AbilitySpec, ...]
    span: SourceSpan
    raw: str


@dataclass(frozen=True)
class ChannelConnectRule:
    sources: tuple[str, ...]
    targets: tuple[str, ...]
    span: SourceSpan
    raw: str


@dataclass(frozen=True)
class AttachPath:
    raw: str
    ftype: str | None
    path: str


@dataclass(frozen=True)
class AttachRule:
    types: tuple[str, ...]
    paths: tuple[AttachPath, ...]
    channel_type: str | None
    span: SourceSpan
    raw: str


@dataclass(frozen=True)
class LinkRule:
    types: tuple[str, ...]
    paths: tuple[str, ...]
    span: SourceSpan
    raw: str


@dataclass(frozen=True)
class DeriveTypeRule:
    src_type: str
    name: str
    dst_type: str
    span: SourceSpan
    raw: str


@dataclass(frozen=True)
class DefaultSpawnTypeRule:
    src_type: str
    dst_type: str
    span: SourceSpan
    raw: str


@dataclass(frozen=True)
class MountPointRule:
    owner: str
    perms: str
    paths: tuple[str, ...]
    span: SourceSpan
    raw: str


@dataclass
class PolicyIR:
    """Parsed QNX 8.0 security policy intermediate representation."""

    source_path: str
    attributes: dict[str, AttributeDecl] = field(default_factory=dict)
    types: dict[str, TypeDecl] = field(default_factory=dict)
    ability_rules: list[AbilityRule] = field(default_factory=list)
    connect_rules: list[ChannelConnectRule] = field(default_factory=list)
    attach_rules: list[AttachRule] = field(default_factory=list)
    link_rules: list[LinkRule] = field(default_factory=list)
    derive_rules: list[DeriveTypeRule] = field(default_factory=list)
    default_spawn_rules: list[DefaultSpawnTypeRule] = field(default_factory=list)
    mount_point_rules: list[MountPointRule] = field(default_factory=list)

    def is_declared_identifier(self, name: str) -> bool:
        return name in self.types or name in self.attributes or name in RESERVED_TYPES

    def types_for_attribute(self, attr_name: str) -> list[str]:
        return sorted(
            tname for tname, tdecl in self.types.items() if attr_name in tdecl.attributes
        )

    def types_with_allow_rules(self) -> set[str]:
        """Types that have at least one explicit `allow` rule (directly or via attribute)."""
        active: set[str] = set()
        for rule in self.ability_rules:
            for src in rule.sources:
                if src == "default_rules":
                    continue
                if src in self.types:
                    active.add(src)
                elif src in self.attributes:
                    active.update(self.types_for_attribute(src))
        for rule in self.connect_rules:
            for src in rule.sources:
                if src == "default_rules":
                    continue
                if src in self.types:
                    active.add(src)
                elif src in self.attributes:
                    active.update(self.types_for_attribute(src))
        return active

    def expand_subject(self, name: str, *, allow_default_rules: bool = True) -> list[tuple[str, str | None]]:
        """Expand a type, attribute, or `default_rules` into `(concrete_type, via_attr)` pairs."""
        if name == "default_rules" and allow_default_rules:
            return [(t, "default_rules") for t in sorted(self.types_with_allow_rules())]
        if name in self.types:
            return [(name, None)]
        if name in self.attributes:
            return [(t, name) for t in self.types_for_attribute(name)]
        return []


@dataclass(frozen=True)
class IfsCommand:
    """Single command inside a QNX `build.ifs` startup-script block."""

    raw: str
    tokens: tuple[str, ...]
    span: SourceSpan
    is_secpolpush: bool
    secpolpush_args: tuple[str, ...]
    is_on: bool
    on_type: str | None
    on_user: str | None
    executable: str | None
    executable_path: str | None
    is_builtin: bool
    background: bool


@dataclass
class IfsIR:
    """Parsed QNX 8.0 `build.ifs` startup-script representation."""

    source_path: str
    has_startup_script: bool = False
    commands: list[IfsCommand] = field(default_factory=list)
    secpolpush_lines: list[int] = field(default_factory=list)

    @property
    def first_secpolpush_line(self) -> int | None:
        return self.secpolpush_lines[0] if self.secpolpush_lines else None


@dataclass(frozen=True)
class Finding:
    """Structured audit finding emitted by static, path, or runtime checks."""

    rule_id: str
    severity: Severity
    message: str
    span: SourceSpan | None = None
    remediation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "location": self.span.to_dict() if self.span else None,
            "remediation": self.remediation,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class GraphEdge:
    """Directed edge in the QNX security-policy graph."""

    src: str
    dst: str
    kind: str  # "ESCALATION" or "REVIEW_ONLY"
    mechanism: str  # "settypeid", "derive_type", "default_spawn_type", "channel_connect", "allow_link"
    span: SourceSpan
    raw: str
    via_attribute: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "kind": self.kind,
            "mechanism": self.mechanism,
            "location": self.span.to_dict(),
            "raw": self.raw,
            "via_attribute": self.via_attribute,
        }


@dataclass(frozen=True)
class EscalationPath:
    """Transitive privilege-escalation path across ESCALATION edges only."""

    source: str
    sink: str
    nodes: tuple[str, ...]
    edges: tuple[GraphEdge, ...]
    sink_reasons: tuple[str, ...]
    hops: int

    def chain_str(self) -> str:
        return " -> ".join(self.nodes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "sink": self.sink,
            "chain": self.chain_str(),
            "nodes": list(self.nodes),
            "hops": self.hops,
            "sink_reasons": list(self.sink_reasons),
            "edges": [e.to_dict() for e in self.edges],
        }


@dataclass
class PathAnalysisResult:
    """Full graph and escalation-path analysis output."""

    nodes: dict[str, dict[str, Any]]
    escalation_edges: list[GraphEdge]
    review_edges: list[GraphEdge]
    escalation_paths: list[EscalationPath]
    findings: list[Finding] = field(default_factory=list)


@dataclass(frozen=True)
class RuntimeProcess:
    """Single process entry parsed from QNX `pidin -f a_n`."""

    pid: int
    secpol_type: str | None
    raw_type: str
    name: str
    full_name: str
    line: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "pid": self.pid,
            "secpol_type": self.secpol_type,
            "raw_type": self.raw_type,
            "name": self.name,
            "full_name": self.full_name,
            "line": self.line,
        }


@dataclass
class RuntimeDiff:
    """Result of comparing runtime `pidin -f a_n` snapshot against static policy/IFS."""

    source_path: str
    processes: list[RuntimeProcess] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    matched: list[dict[str, Any]] = field(default_factory=list)
