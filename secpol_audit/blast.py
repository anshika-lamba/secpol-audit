"""Evidence-aware blast-radius analyzer joining Static Policy + KPROBE_JSON + SECPOLEV_JSON.

Explicitly classifies every reachable edge and probed operation into three
honest evidence states (never treating an absent `libsecpolev` event as proof
of denial):
  1. `OBSERVED_AND_CORRELATED`   — syscall outcome + matching `SECPOLEV_JSON:` witness
  2. `SYSCALL_ONLY_UNOBSERVABLE` — syscall outcome via `KPROBE_JSON:`, no `libsecpolev` event
  3. `STATIC_ONLY`               — predicted statically from `.secpol`, not probed on target
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
import fnmatch
import hashlib
import json
from pathlib import Path
from typing import Any

from secpol_audit.events import (
    SECPOLEV_ALERT_PREFIX,
    SECPOLEV_JSON_PREFIX,
    SecpolEvent,
    ParsedEventLog,
    parse_events_text,
)
from secpol_audit.ir import (
    GraphEdge,
    IfsIR,
    ParseDiagnostic,
    PathAnalysisResult,
    PolicyIR,
    SourceSpan,
)
from secpol_audit.paths import analyze_paths, collect_type_abilities, collect_type_attaches

KPROBE_JSON_PREFIX = "KPROBE_JSON:"
VALID_KPROBE_OPS = frozenset({"settypeid", "channel_connect", "allow_attach"})
VALID_KPROBE_OUTCOMES = frozenset({"ALLOW", "DENY"})

STATE_OBSERVED_AND_CORRELATED = "OBSERVED_AND_CORRELATED"
STATE_SYSCALL_ONLY_UNOBSERVABLE = "SYSCALL_ONLY_UNOBSERVABLE"
STATE_STATIC_ONLY = "STATIC_ONLY"

EXPECTED_BLAST_PROBES: tuple[tuple[str, str, str], ...] = (
    ("ivi_ui_t", "settypeid", "diag_helper_t"),
    ("ivi_ui_t", "settypeid", "can_hal_t"),
    ("ivi_ui_t", "channel_connect", "can_ctrl"),
    ("ivi_ui_t", "allow_attach", "/dev/secpol_probe_deny_ivi_ui_t"),
    ("diag_helper_t", "settypeid", "can_hal_t"),
    ("diag_helper_t", "settypeid", "ivi_ui_t"),
    ("diag_helper_t", "channel_connect", "can_ctrl"),
    ("diag_helper_t", "allow_attach", "/dev/secpol_probe_deny_diag_helper_t"),
    ("audit_reader_t", "settypeid", "can_hal_t"),
    ("audit_reader_t", "settypeid", "diag_helper_t"),
    ("audit_reader_t", "channel_connect", "can_ctrl"),
    ("audit_reader_t", "allow_attach", "/dev/secpol_probe_allow"),
)


def classify_allow_attach_errno(
    ret: int | None,
    err_num: int,
    outcome: str = "DENY",
) -> tuple[str, str | None]:
    """Strict 5-way classification for `allow_attach` kprobe results.

    Returns `(classification, reason)`:
      - `ret >= 0` (`errno == 0`) -> `("ALLOW", None)`
      - `errno == 13` (`EACCES`) -> `("DENY_POLICY", None)`
      - `errno == 1` (`EPERM`)   -> `("DENY_ABILITY", None)`
      - `errno == 17` (`EEXIST`) -> `("INCONCLUSIVE", "PATH_COLLISION")`
      - any other non-zero errno -> `("SETUP_FAILURE", "INCONCLUSIVE")`
    """
    if (ret is not None and ret >= 0 and err_num == 0) or (
        ret is None and outcome == "ALLOW" and err_num == 0
    ):
        return "ALLOW", None
    if err_num == 13:
        return "DENY_POLICY", None
    if err_num == 1:
        return "DENY_ABILITY", None
    if err_num == 17:
        return "INCONCLUSIVE", "PATH_COLLISION"
    return "SETUP_FAILURE", "INCONCLUSIVE"


@dataclass(frozen=True)
class KprobeRecord:
    """Single parsed `KPROBE_JSON:` on-target syscall probe result."""

    origin: str
    op: str  # "settypeid" | "channel_connect" | "allow_attach"
    target: str
    outcome: str  # "ALLOW" | "DENY"
    errno: int
    line: int
    raw: str
    path: str | None = None
    pid: int | None = None
    target_id: int | None = None
    ret: int | None = None
    errno_name: str | None = None
    classification: str | None = None
    classification_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "origin": self.origin,
            "op": self.op,
            "target": self.target,
            "outcome": self.outcome,
            "errno": self.errno,
            "line": self.line,
            "raw": self.raw,
        }
        if self.path is not None:
            d["path"] = self.path
        if self.pid is not None:
            d["pid"] = self.pid
        if self.target_id is not None:
            d["target_id"] = self.target_id
        if self.ret is not None:
            d["ret"] = self.ret
        if self.errno_name is not None:
            d["errno_name"] = self.errno_name
        if self.classification is not None:
            d["classification"] = self.classification
        if self.classification_reason is not None:
            d["classification_reason"] = self.classification_reason
        return d


@dataclass(frozen=True)
class EvidenceReceipt:
    """3-way evidence receipt for one edge or probed operation."""

    receipt_id: str
    origin: str
    op: str  # "settypeid" | "derive_type" | "default_spawn_type" | "channel_connect" | "allow_attach" | "allow_link"
    edge_kind: str  # "ESCALATION" | "REVIEW_ONLY" | "PROBE"
    target: str
    resolved_target_type: str | None
    hop: int
    ring: int
    static_prediction: str  # "ALLOW" | "DENY"
    syscall_outcome: str | None  # "ALLOW" | "DENY" | None
    syscall_errno: int | None
    syscall_line: int | None
    syscall_raw: str | None
    kernel_witness_verdict: str | None  # "OK" | "DENIED" | None
    kernel_witness_line: int | None
    kernel_witness_raw: str | None
    evidence_state: str  # OBSERVED_AND_CORRELATED | SYSCALL_ONLY_UNOBSERVABLE | STATIC_ONLY
    mismatch: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "origin": self.origin,
            "op": self.op,
            "edge_kind": self.edge_kind,
            "target": self.target,
            "resolved_target_type": self.resolved_target_type,
            "hop": self.hop,
            "ring": self.ring,
            "static_prediction": self.static_prediction,
            "syscall_outcome": self.syscall_outcome,
            "syscall_errno": self.syscall_errno,
            "syscall_line": self.syscall_line,
            "syscall_raw": self.syscall_raw,
            "kernel_witness_verdict": self.kernel_witness_verdict,
            "kernel_witness_line": self.kernel_witness_line,
            "kernel_witness_raw": self.kernel_witness_raw,
            "evidence_state": self.evidence_state,
            "mismatch": self.mismatch,
        }


@dataclass(frozen=True)
class BlastNode:
    """Node positioned on a concentric blast-radius ring for a specific origin."""

    name: str
    ring: int  # 0=Origin, 1=Direct IPC/Paths, 2=Hop-1 settypeid, 3=Hop-2+ / Privileged Sink
    hop: int
    is_sink: bool
    sink_reasons: tuple[str, ...]
    abilities: tuple[str, ...]
    attaches: tuple[str, ...]
    reach_mechanism: str  # "origin" | "channel_connect" | "settypeid" | "derive_type" | "default_spawn_type"
    evidence_state: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ring": self.ring,
            "hop": self.hop,
            "is_sink": self.is_sink,
            "sink_reasons": list(self.sink_reasons),
            "abilities": list(self.abilities),
            "attaches": list(self.attaches),
            "reach_mechanism": self.reach_mechanism,
            "evidence_state": self.evidence_state,
        }


@dataclass
class OriginBlastView:
    """Complete concentric blast radius starting from one compromised origin type."""

    origin: str
    nodes: list[BlastNode] = field(default_factory=list)
    receipts: list[EvidenceReceipt] = field(default_factory=list)
    reachable_sinks: list[str] = field(default_factory=list)
    escalation_chains: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "reachable_types_count": len([n for n in self.nodes if n.ring > 0]),
            "reachable_sinks": self.reachable_sinks,
            "escalation_chains": self.escalation_chains,
            "nodes": [n.to_dict() for n in self.nodes],
            "receipts": [r.to_dict() for r in self.receipts],
        }


@dataclass
class EvidenceCompleteness:
    """Machine-readable verification completeness report."""

    target: str
    execution: str
    policy_path: str
    policy_hash: str
    log_path: str | None
    probes_total: int
    probes_completed: int
    kernel_events_correlated: int
    unobservable_operations: int
    dropped_events: int
    mismatches: int
    result: str  # "COMPLETE" | "PARTIAL" | "MISMATCH"
    kernel_policy_id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "target": self.target,
            "execution": self.execution,
            "policy_path": self.policy_path,
            "policy_hash": self.policy_hash,
            "log_path": self.log_path,
            "probes_total": self.probes_total,
            "probes_completed": self.probes_completed,
            "kernel_events_correlated": self.kernel_events_correlated,
            "unobservable_operations": self.unobservable_operations,
            "dropped_events": self.dropped_events,
            "mismatches": self.mismatches,
            "result": self.result,
        }
        if self.kernel_policy_id is not None:
            d["kernel_policy_id"] = self.kernel_policy_id
        return d


@dataclass
class BlastReport:
    """Full evidence-aware blast-radius analysis result."""

    policy_path: str
    policy_hash: str
    ifs_path: str | None
    log_path: str | None
    selected_origin: str
    completeness: EvidenceCompleteness
    origins: dict[str, OriginBlastView] = field(default_factory=dict)
    all_receipts: list[EvidenceReceipt] = field(default_factory=list)
    kprobes: list[KprobeRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy_path,
            "policy_hash": self.policy_hash,
            "ifs": self.ifs_path,
            "log": self.log_path,
            "selected_origin": self.selected_origin,
            "completeness": self.completeness.to_dict(),
            "origins": {k: v.to_dict() for k, v in sorted(self.origins.items())},
            "receipts": [r.to_dict() for r in self.all_receipts],
            "kprobes": [k.to_dict() for k in self.kprobes],
        }


def parse_blast_log_text(
    text: str,
    source_path: str = "<memory>",
) -> tuple[list[KprobeRecord], ParsedEventLog | None]:
    """Parse `KPROBE_JSON:` lines and optional `SECPOLEV_*` telemetry fail-closed."""
    kprobes: list[KprobeRecord] = []
    has_secpolev = False

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip("\r\n")
        if (
            SECPOLEV_JSON_PREFIX in line
            or SECPOLEV_ALERT_PREFIX in line
            or "SECPOLEV_STATS:" in line
        ):
            has_secpolev = True

        if line.startswith(KPROBE_JSON_PREFIX):
            payload_str = line[len(KPROBE_JSON_PREFIX) :].strip()
            span = SourceSpan(file=source_path, line=line_no, col=1, snippet=line)
            try:
                obj = json.loads(payload_str)
            except json.JSONDecodeError as exc:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Malformed KPROBE_JSON payload: {exc.msg}",
                    span,
                ) from exc
            if not isinstance(obj, dict):
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    "KPROBE_JSON payload must be a JSON object",
                    span,
                )
            origin = obj.get("origin")
            op = obj.get("op")
            path_val = obj.get("path")
            target = obj.get("target")
            if (not isinstance(target, str) or not target) and isinstance(path_val, str) and path_val:
                target = path_val
            ret_val = obj.get("ret")
            pid_val = obj.get("pid")
            target_id_val = obj.get("target_id")
            err_num = obj.get("errno", 0)
            err_name = obj.get("errno_name")
            outcome = obj.get("outcome")
            if outcome is None and ret_val is not None:
                outcome = "ALLOW" if (isinstance(ret_val, int) and not isinstance(ret_val, bool) and ret_val >= 0 and err_num == 0) else "DENY"
            if not isinstance(origin, str) or not origin:
                raise ParseDiagnostic("PARSE_ERROR", "KPROBE_JSON requires non-empty string 'origin'", span)
            if op not in VALID_KPROBE_OPS:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Invalid KPROBE_JSON op '{op}' (expected settypeid|channel_connect|allow_attach)",
                    span,
                )
            if not isinstance(target, str) or not target:
                raise ParseDiagnostic("PARSE_ERROR", "KPROBE_JSON requires non-empty string 'target'", span)
            if outcome not in VALID_KPROBE_OUTCOMES:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Invalid KPROBE_JSON outcome '{outcome}' (expected 'ALLOW' or 'DENY')",
                    span,
                )
            if not isinstance(err_num, int) or isinstance(err_num, bool) or err_num < 0:
                raise ParseDiagnostic("PARSE_ERROR", f"Invalid KPROBE_JSON errno '{err_num}'", span)
            if outcome == "ALLOW" and (
                err_num != 0
                or (isinstance(ret_val, int) and not isinstance(ret_val, bool) and ret_val < 0)
            ):
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Inconsistent KPROBE_JSON ALLOW with ret={ret_val} errno={err_num}",
                    span,
                )
            classification: str | None = None
            classification_reason: str | None = None
            if op == "allow_attach":
                classification, classification_reason = classify_allow_attach_errno(
                    ret_val if isinstance(ret_val, int) and not isinstance(ret_val, bool) else None,
                    err_num,
                    outcome,
                )
            elif op == "channel_connect" and outcome == "DENY" and err_num == 2:
                # ENOENT means the target server/channel was absent, not a policy denial
                classification = "UNAVAILABLE"
                classification_reason = "SERVER_NOT_FOUND"
            kprobes.append(
                KprobeRecord(
                    origin=origin,
                    op=op,
                    target=target,
                    outcome=outcome,
                    errno=err_num,
                    line=line_no,
                    raw=line,
                    path=path_val if isinstance(path_val, str) and path_val else None,
                    pid=pid_val if isinstance(pid_val, int) and not isinstance(pid_val, bool) else None,
                    target_id=target_id_val if isinstance(target_id_val, int) and not isinstance(target_id_val, bool) else None,
                    ret=ret_val if isinstance(ret_val, int) and not isinstance(ret_val, bool) else None,
                    errno_name=err_name if isinstance(err_name, str) and err_name else None,
                    classification=classification,
                    classification_reason=classification_reason,
                )
            )

    parsed_events: ParsedEventLog | None = None
    if has_secpolev:
        parsed_events = parse_events_text(text, source_path)

    if not kprobes and parsed_events is None:
        raise ParseDiagnostic(
            "PARSE_ERROR",
            f"No KPROBE_JSON or SECPOLEV telemetry lines found in '{source_path}'",
            SourceSpan(file=source_path, line=1, col=1),
        )

    return kprobes, parsed_events


def _name_matches_path(name_or_path: str, attach_path: str) -> bool:
    """Match a QNX `name_attach`/`name_open` name (e.g. `can_ctrl`) against an attach path."""
    p = attach_path.split(":", 1)[1] if ":" in attach_path else attach_path
    q = name_or_path.strip()
    if q == p:
        return True
    if not q.startswith("/"):
        candidates = (
            f"/dev/name/local/{q}",
            f"/dev/name/global/{q}",
            f"/dev/{q}",
        )
        if p in candidates or p.endswith("/" + q):
            return True
    if "*" in p:
        return fnmatch.fnmatch(q, p) or (not q.startswith("/") and fnmatch.fnmatch(f"/dev/name/local/{q}", p))
    if p.endswith("..."):
        prefix = p[:-3].rstrip("/")
        return q == prefix or q.startswith(prefix + "/") or (
            not q.startswith("/") and f"/dev/name/local/{q}".startswith(prefix + "/")
        )
    return False


VALID_TARGET_KINDS = frozenset({"type", "channel", "path"})


def load_expected_probes_manifest(
    path: Path | str,
    *,
    policy: PolicyIR | None = None,
    ifs: IfsIR | None = None,
) -> tuple[tuple[str, str, str], ...]:
    """Load and strictly validate a JSON expected-probe manifest."""
    path = Path(path)
    span = SourceSpan(file=str(path), line=1, col=1)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ParseDiagnostic("PARSE_ERROR", f"Invalid expected-probes manifest '{path}': {exc}", span) from exc
    if not isinstance(data, dict) or (data.get("schema_version") != 1 and data.get("version") != "1.0"):
        raise ParseDiagnostic("PARSE_ERROR", f"Manifest '{path}' must have version '1.0' or schema_version == 1", span)
    if not isinstance(data.get("probes"), list) or len(data["probes"]) < 1:
        raise ParseDiagnostic("PARSE_ERROR", f"Manifest '{path}' must contain at least 1 probe", span)

    attaches_by_type = collect_type_attaches(policy) if policy is not None else {}

    op_to_kind = {
        "settypeid": "type",
        "derive_type": "type",
        "default_spawn_type": "type",
        "channel_connect": "channel",
        "allow_attach": "path",
    }
    op_to_req = {
        "settypeid": "pid+ability_range",
        "derive_type": "pid+ability_range",
        "default_spawn_type": "pid+ability_range",
        "channel_connect": "pid+server_type_range",
        "allow_attach": "pid+exact_path",
    }

    # Pre-extract structured IFS server launch types and kprobe --connect specs
    # using parser_ifs.py's parsed IfsCommand AST (never raw substring search).
    ifs_non_kprobe_launch_types: set[str] = set()
    ifs_kprobe_connect_specs: list[tuple[str, str, int]] = []
    if ifs is not None:
        for cmd in ifs.commands:
            if cmd.is_on and cmd.on_type and cmd.executable != "kprobe":
                ifs_non_kprobe_launch_types.add(cmd.on_type)
            if cmd.executable == "kprobe":
                toks = cmd.tokens
                i = 0
                while i < len(toks):
                    if toks[i] == "--connect" and i + 1 < len(toks):
                        csv_val = toks[i + 1]
                        for spec in csv_val.split(","):
                            if "=" not in spec:
                                raise ParseDiagnostic(
                                    "PARSE_ERROR",
                                    f"IFS kprobe --connect spec '{spec}' missing '=server_type' annotation",
                                    cmd.span,
                                )
                            ch_name, srv_t = spec.split("=", 1)
                            if not ch_name.strip() or not srv_t.strip():
                                raise ParseDiagnostic(
                                    "PARSE_ERROR",
                                    f"IFS kprobe --connect spec '{spec}' has empty channel name or server type",
                                    cmd.span,
                                )
                            ifs_kprobe_connect_specs.append((ch_name.strip(), srv_t.strip(), cmd.span.line))
                        i += 2
                    else:
                        i += 1

    seen_ids: set[str] = set()
    seen_tuples: set[tuple[str, str, str]] = set()
    specs: list[tuple[str, str, str]] = []
    for idx, item in enumerate(data["probes"]):
        if not isinstance(item, dict):
            raise ParseDiagnostic("PARSE_ERROR", f"Manifest probe[{idx}] must be an object", span)
        pid_str = item.get("id")
        origin = item.get("origin")
        op = item.get("op")
        target = item.get("target")
        tkind = item.get("target_kind")
        req = item.get("evidence_requirement")
        resolved_t = item.get("resolved_target_type")
        for fname, fval in (("id", pid_str), ("origin", origin), ("target", target), ("evidence_requirement", req)):
            if not isinstance(fval, str) or not fval.strip():
                raise ParseDiagnostic("PARSE_ERROR", f"Manifest probe[{idx}] missing non-empty '{fname}'", span)
        if pid_str in seen_ids:
            raise ParseDiagnostic("PARSE_ERROR", f"Duplicate manifest probe id '{pid_str}'", span)
        seen_ids.add(pid_str)
        if op not in VALID_KPROBE_OPS:
            raise ParseDiagnostic("PARSE_ERROR", f"Manifest probe[{idx}] unsupported op '{op}'", span)
        if tkind not in VALID_TARGET_KINDS or tkind != op_to_kind[op]:
            raise ParseDiagnostic("PARSE_ERROR", f"Manifest probe[{idx}] invalid target_kind '{tkind}' for op '{op}'", span)
        if req != op_to_req[op]:
            raise ParseDiagnostic(
                "PARSE_ERROR",
                f"Manifest probe[{idx}] invalid evidence_requirement '{req}' for op '{op}' (expected '{op_to_req[op]}')",
                span,
            )
        if op in ("settypeid", "derive_type", "default_spawn_type"):
            if resolved_t != target:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Manifest probe[{idx}] resolved_target_type '{resolved_t}' must equal target '{target}' for op '{op}'",
                    span,
                )
        elif op == "allow_attach":
            if resolved_t is not None:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Manifest probe[{idx}] resolved_target_type must be null for op 'allow_attach'",
                    span,
                )
        elif op == "channel_connect":
            if not isinstance(resolved_t, str) or not resolved_t.strip():
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Manifest probe[{idx}] missing 'resolved_target_type' for channel_connect",
                    span,
                )

        attaching_proc_types: set[str] = set()
        if policy is not None:
            if origin not in policy.types:
                raise ParseDiagnostic("PARSE_ERROR", f"Manifest probe[{idx}] unknown origin type '{origin}'", span)
            if op in ("settypeid", "derive_type", "default_spawn_type") and target not in policy.types:
                raise ParseDiagnostic("PARSE_ERROR", f"Manifest probe[{idx}] unknown target type '{target}'", span)
            if op == "channel_connect":
                if resolved_t not in policy.types:
                    raise ParseDiagnostic("PARSE_ERROR", f"Manifest probe[{idx}] unknown resolved_target_type '{resolved_t}'", span)
                eff_types: set[str] = set()
                for tname, alist in attaches_by_type.items():
                    for _ft, ap_path, _raw, ct in alist:
                        if _name_matches_path(target, ap_path):
                            eff_types.add(ct if ct else tname)
                            attaching_proc_types.add(tname)
                if len(eff_types) != 1 or eff_types != {resolved_t}:
                    raise ParseDiagnostic(
                        "PARSE_ERROR",
                        f"Manifest probe[{idx}] resolved_target_type '{resolved_t}' disagrees with policy channel types {sorted(eff_types)}",
                        span,
                    )

        if ifs is not None and op == "channel_connect":
            # Support both standard server launches (process type == channel type) and
            # QNX 8.0 `allow_attach <proc_type> <path> <channel_type>;` overrides where
            # the server process launches with `-T <proc_type>` while the channel's
            # effective security type is `<channel_type>`.
            expected_launch_types = attaching_proc_types if attaching_proc_types else {resolved_t}
            if not (ifs_non_kprobe_launch_types & expected_launch_types):
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Manifest probe[{idx}] channel '{target}' (effective type '{resolved_t}') has no non-kprobe IFS launch with -T in {sorted(expected_launch_types)}",
                    span,
                )
            for ch_name, srv_t, _line in ifs_kprobe_connect_specs:
                if ch_name == target and srv_t != resolved_t:
                    raise ParseDiagnostic(
                        "PARSE_ERROR",
                        f"Manifest probe[{idx}] resolved_target_type '{resolved_t}' disagrees with IFS kprobe --connect '{ch_name}={srv_t}'",
                        span,
                    )

        tup = (origin, op, target)
        if tup in seen_tuples:
            raise ParseDiagnostic("PARSE_ERROR", f"Duplicate manifest probe tuple {tup}", span)
        seen_tuples.add(tup)
        specs.append(tup)

    if ifs is not None:
        scheduled = extract_ifs_scheduled_probes(ifs)
        if scheduled:
            missing_from_manifest = [t for t in scheduled if t not in seen_tuples]
            if missing_from_manifest:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Manifest '{path}' omits {len(missing_from_manifest)} IFS-scheduled kprobe(s): {missing_from_manifest[:3]}",
                    span,
                )
    return tuple(specs)


def extract_ifs_scheduled_probes(ifs: IfsIR) -> tuple[tuple[str, str, str], ...]:
    """Extract all `(origin, op, target)` probes scheduled by `kprobe` invocations in an IFS."""
    scheduled: list[tuple[str, str, str]] = []
    for cmd in ifs.commands:
        if cmd.executable != "kprobe":
            continue
        toks = cmd.tokens
        origin: str | None = cmd.on_type
        settypeid_csv: str | None = None
        connect_csv: str | None = None
        attach_csv: str | None = None
        i = 0
        while i < len(toks):
            if toks[i] == "--origin" and i + 1 < len(toks):
                origin = toks[i + 1]
                i += 2
            elif toks[i] == "--settypeid" and i + 1 < len(toks):
                settypeid_csv = toks[i + 1]
                i += 2
            elif toks[i] == "--connect" and i + 1 < len(toks):
                connect_csv = toks[i + 1]
                i += 2
            elif toks[i] == "--attach" and i + 1 < len(toks):
                attach_csv = toks[i + 1]
                i += 2
            else:
                i += 1
        if not origin:
            continue
        if settypeid_csv:
            for t in settypeid_csv.split(","):
                if t.strip():
                    scheduled.append((origin, "settypeid", t.strip()))
        if connect_csv:
            for spec in connect_csv.split(","):
                ch = spec.split("=", 1)[0].strip()
                if ch:
                    scheduled.append((origin, "channel_connect", ch))
        if attach_csv:
            for ap in attach_csv.split(","):
                if ap.strip():
                    scheduled.append((origin, "allow_attach", ap.strip()))
    return tuple(scheduled)


def _extract_kernel_policy_id(log_text: str) -> int | None:
    """Extract QNX 8.0 `SECPOLEV_POLICY_ID: <uint32>`; return 0 (fail-closed) on conflicting IDs."""
    import re
    pid_re = re.compile(r"^SECPOLEV_POLICY_ID:\s*(\d+)\b")
    found: set[int] = set()
    for raw_line in log_text.splitlines():
        m = pid_re.match(raw_line.rstrip("\r\n"))
        if m:
            found.add(int(m.group(1)))
    if not found:
        return None
    if len(found) > 1:
        return 0
    return next(iter(found))


def generate_expected_probes_manifest(
    policy: PolicyIR,
    *,
    ifs: IfsIR | None = None,
    origins: list[str] | tuple[str, ...] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    """Generate a validated expected-probe manifest AND matching QNX IFS `kprobe` lines for any policy."""
    path_res = analyze_paths(policy, ifs=ifs)
    attaches_by_type = collect_type_attaches(policy)

    # Identify channel servers (prefer channels with a unique effective type and, if IFS given, a live launch)
    ifs_launch_types: set[str] = set()
    if ifs is not None:
        for cmd in ifs.commands:
            if cmd.is_on and cmd.on_type and cmd.executable != "kprobe":
                ifs_launch_types.add(cmd.on_type)

    channel_candidates: list[tuple[str, str]] = []
    seen_ch: set[str] = set()
    for tname, alist in sorted(attaches_by_type.items()):
        for _ft, ap_path, _raw, ct in alist:
            if not ap_path.startswith("/dev/name/local/"):
                continue
            ch_name = ap_path.rsplit("/", 1)[-1]
            if ch_name == "_tracelog" or ch_name in seen_ch:
                continue
            eff_t = ct if ct else tname
            if ifs is not None and tname not in ifs_launch_types:
                continue
            seen_ch.add(ch_name)
            channel_candidates.append((ch_name, eff_t))

    # Pick origins: explicit list, else non-infrastructure types (preferring escalation sources/sinks)
    infra = {"secpol_sentry_t", "slogger2_t"}
    if origins:
        selected_origins = [o for o in origins if o in policy.types]
    else:
        esc_sources = sorted({e.src for e in path_res.escalation_edges if e.src not in infra})
        other_types = sorted(
            t for t in policy.types
            if t not in infra and t not in esc_sources
            and t not in {eff for _, eff in channel_candidates}
        )
        selected_origins = (esc_sources + other_types)[:4]
        if not selected_origins:
            selected_origins = sorted(policy.types.keys())[:3]

    # Pick a high-value sink target for negative settypeid probes
    sinks = sorted(t for t, info in path_res.nodes.items() if info.get("is_sink") and t not in infra)
    default_sink = sinks[0] if sinks else (sorted(policy.types.keys())[0] if policy.types else "")

    probes: list[dict[str, Any]] = []
    ifs_lines: list[str] = []
    pid_counter = 0
    uid_base = 31

    for idx_o, origin in enumerate(selected_origins):
        settypeid_targets: list[str] = []
        # Include any allowed escalation transitions from this origin
        for e in sorted(path_res.escalation_edges, key=lambda x: x.dst):
            if e.src == origin and e.dst != origin and e.dst not in settypeid_targets:
                settypeid_targets.append(e.dst)
        # Always include at least one denied settypeid target for negative verification
        for cand in [default_sink] + sorted(policy.types.keys()):
            if cand and cand != origin and cand not in infra and cand not in settypeid_targets:
                settypeid_targets.append(cand)
                if len(settypeid_targets) >= 2:
                    break

        connect_specs: list[tuple[str, str]] = channel_candidates[:1]

        # Pick an allow_attach path: an explicitly allowed isolated probe path if declared, else negative deny path
        origin_attaches = [ap for _ft, ap, _r, _ct in attaches_by_type.get(origin, []) if "probe_allow" in ap]
        attach_path = origin_attaches[0] if origin_attaches else f"/dev/secpol_probe_deny_{origin}"

        for st in settypeid_targets:
            pid_counter += 1
            probes.append({
                "id": f"P{pid_counter:02d}",
                "origin": origin,
                "op": "settypeid",
                "target": st,
                "target_kind": "type",
                "resolved_target_type": st,
                "evidence_requirement": "pid+ability_range",
            })
        for ch_name, eff_t in connect_specs:
            pid_counter += 1
            probes.append({
                "id": f"P{pid_counter:02d}",
                "origin": origin,
                "op": "channel_connect",
                "target": ch_name,
                "target_kind": "channel",
                "resolved_target_type": eff_t,
                "evidence_requirement": "pid+server_type_range",
            })
        pid_counter += 1
        probes.append({
            "id": f"P{pid_counter:02d}",
            "origin": origin,
            "op": "allow_attach",
            "target": attach_path,
            "target_kind": "path",
            "resolved_target_type": None,
            "evidence_requirement": "pid+exact_path",
        })

        parts = [
            f"on -T {origin} -u {uid_base + idx_o}:{uid_base + idx_o} /proc/boot/kprobe --origin {origin}"
        ]
        if settypeid_targets:
            parts.append(f"--settypeid {','.join(settypeid_targets)}")
        if connect_specs:
            parts.append("--connect " + ",".join(f"{c}={t}" for c, t in connect_specs))
        parts.append(f"--attach {attach_path}")
        ifs_lines.append(" ".join(parts))

    manifest = {
        "schema_version": 1,
        "version": "1.0",
        "description": f"Auto-generated {len(probes)}-probe verification matrix for {policy.source_path}",
        "probes": probes,
    }
    return manifest, ifs_lines


def _has_valid_post_marker_stats(log_text: str) -> bool:
    """Return True iff exactly one DONE marker is followed by exactly one strict SECPOLEV_STATS and no trailing events."""
    import re
    stats_re = re.compile(r"^SECPOLEV_STATS:\s*ok=\d+\s+denied=\d+\s+dropped=\d+\s*$")
    done_count = 0
    stats_before_done = 0
    stats_after_done = 0
    events_after_stats = 0
    for raw_line in log_text.splitlines():
        line = raw_line.rstrip("\r\n")
        if "=== SECPOL_AUDIT_DONE ===" in line:
            done_count += 1
            continue
        if stats_re.match(line):
            if done_count == 0:
                stats_before_done += 1
            else:
                stats_after_done += 1
            continue
        if stats_after_done > 0 and (
            line.startswith(KPROBE_JSON_PREFIX) or line.startswith(SECPOLEV_JSON_PREFIX)
        ):
            events_after_stats += 1
    return (
        done_count == 1
        and stats_before_done == 0
        and stats_after_done == 1
        and events_after_stats == 0
    )


def _find_kernel_witness(
    events: list[SecpolEvent],
    origin: str,
    op: str,
    target: str,
    expected_outcome: str | None,
    *,
    probe_pid: int | None = None,
    target_id: int | None = None,
    server_types_for_target: tuple[str, ...] = (),
    used_event_lines: set[int] | None = None,
) -> SecpolEvent | None:
    """Correlate a matching `SECPOLEV_JSON:` event for `(origin, op, target)`."""
    if probe_pid is None or probe_pid <= 0:
        return None

    want_verdict = (
        ("OK" if expected_outcome == "ALLOW" else "DENIED")
        if expected_outcome in ("ALLOW", "DENY")
        else None
    )

    matches: list[SecpolEvent] = []
    for ev in events:
        if used_event_lines is not None and ev.line in used_event_lines:
            continue
        if ev.pid is None or ev.pid <= 0 or ev.pid != probe_pid:
            continue
        if ev.type != origin:
            continue
        if want_verdict is not None and ev.verdict != want_verdict:
            continue
        if op in ("settypeid", "derive_type", "default_spawn_type"):
            if ev.kind == "ability" and ev.ability == "settypeid":
                if target_id is None or target_id < 0 or ev.range is None:
                    continue
                if ev.range[0] <= target_id <= ev.range[1]:
                    matches.append(ev)
        elif op == "channel_connect":
            if len(server_types_for_target) != 1:
                continue
            if ev.kind == "ability" and ev.ability == "channel_connect":
                if target_id is None or target_id < 0 or ev.range is None:
                    continue
                if ev.range[0] <= target_id <= ev.range[1]:
                    matches.append(ev)
        elif op == "allow_attach":
            if ev.kind == "attach" and ev.path and _name_matches_path(target, ev.path):
                matches.append(ev)
    if len(matches) == 1:
        return matches[0]
    return None


def _static_prediction_for_op(
    policy: PolicyIR,
    path_res: PathAnalysisResult,
    attaches_by_type: dict[str, list[tuple[str | None, str, str, str | None]]],
    origin: str,
    op: str,
    target: str,
) -> tuple[str, str | None]:
    """Return `(prediction: "ALLOW"|"DENY", resolved_target_type)` from static policy."""
    if op in ("settypeid", "derive_type", "default_spawn_type"):
        allowed = any(e.src == origin and e.dst == target for e in path_res.escalation_edges)
        return ("ALLOW" if allowed else "DENY"), (target if target in policy.types else None)

    if op == "channel_connect":
        # Target may be a concrete type name OR a QNX name_open name (`can_ctrl`)
        server_types: list[str] = []
        if target in policy.types:
            server_types.append(target)
        else:
            for tname, alist in sorted(attaches_by_type.items()):
                for _ft, ap_path, _raw, ct in alist:
                    if _name_matches_path(target, ap_path):
                        eff = ct if ct else tname
                        if eff not in server_types:
                            server_types.append(eff)
        allowed = any(
            e.src == origin and e.mechanism == "channel_connect" and e.dst in server_types
            for e in path_res.review_edges
        )
        return ("ALLOW" if allowed else "DENY"), (server_types[0] if server_types else None)

    if op == "allow_attach":
        allowed = any(
            _name_matches_path(target, ap_path)
            for _ft, ap_path, _raw, _ct in attaches_by_type.get(origin, [])
        )
        return ("ALLOW" if allowed else "DENY"), None

    return "DENY", None


def analyze_blast(
    policy: PolicyIR,
    *,
    policy_source_bytes: bytes | None = None,
    ifs: IfsIR | None = None,
    log_text: str | None = None,
    log_path: str | None = None,
    origin_filter: str | None = None,
    execution_mode: str | None = None,
    expected_probes: int | None = None,
    expected_probe_specs: tuple[tuple[str, str, str], ...] | None = None,
    expected_policy_id: int | None = None,
) -> BlastReport:
    """Build an evidence-aware concentric blast-radius report across all 3 oracles."""
    if origin_filter and origin_filter not in policy.types:
        raise ParseDiagnostic(
            "PARSE_ERROR",
            f"Requested --origin '{origin_filter}' is not declared in '{policy.source_path}'",
            SourceSpan(file=policy.source_path, line=1, col=1),
        )

    if policy_source_bytes is not None:
        policy_hash = hashlib.sha256(policy_source_bytes).hexdigest()
    elif Path(policy.source_path).is_file():
        policy_hash = hashlib.sha256(Path(policy.source_path).read_bytes()).hexdigest()
    else:
        policy_hash = hashlib.sha256(policy.source_path.encode("utf-8")).hexdigest()

    path_res = analyze_paths(policy, ifs=ifs)
    abilities_by_type = collect_type_abilities(policy)
    attaches_by_type = collect_type_attaches(policy)

    kprobes: list[KprobeRecord] = []
    parsed_events: ParsedEventLog | None = None
    if log_text is not None:
        kprobes, parsed_events = parse_blast_log_text(log_text, log_path or "<log>")

    secpolev_events = parsed_events.events if parsed_events is not None else []
    dropped_events = (
        parsed_events.stats.dropped
        if (parsed_events is not None and parsed_events.stats is not None)
        else 0
    )

    # Index kprobes by (origin, op, target) as a list so duplicates are NEVER overwritten
    kprobes_by_tuple: dict[tuple[str, str, str], list[KprobeRecord]] = defaultdict(list)
    for kp in kprobes:
        kprobes_by_tuple[(kp.origin, kp.op, kp.target)].append(kp)

    def _server_types_for_channel(target_name: str) -> tuple[str, ...]:
        if target_name in policy.types:
            return (target_name,)
        found: set[str] = set()
        for tname, alist in sorted(attaches_by_type.items()):
            for _ft, ap_path, _raw, ct in alist:
                if _name_matches_path(target_name, ap_path):
                    found.add(ct if ct else tname)
        return tuple(sorted(found))

    # Build one authoritative 1-to-1 PID-enforced correlation mapping for BOTH receipts and completeness.
    witness_by_kprobe_line: dict[int, SecpolEvent] = {}
    used_witness_lines: set[int] = set()
    for kp in kprobes:
        if kp.pid is None or kp.pid <= 0:
            continue
        srv_types = _server_types_for_channel(kp.target) if kp.op == "channel_connect" else ()
        w = _find_kernel_witness(
            secpolev_events,
            kp.origin,
            kp.op,
            kp.target,
            kp.outcome,
            probe_pid=kp.pid,
            target_id=kp.target_id,
            server_types_for_target=srv_types,
            used_event_lines=used_witness_lines,
        )
        if w is not None:
            used_witness_lines.add(w.line)
            witness_by_kprobe_line[kp.line] = w

    # Build adjacency maps for static BFS
    esc_adj: dict[str, list[GraphEdge]] = defaultdict(list)
    rev_adj: dict[str, list[GraphEdge]] = defaultdict(list)
    for e in path_res.escalation_edges:
        if e.src != e.dst:
            esc_adj[e.src].append(e)
    for e in path_res.review_edges:
        if e.src != e.dst:
            rev_adj[e.src].append(e)

    target_origins = [origin_filter] if origin_filter else sorted(policy.types.keys())
    origins_map: dict[str, OriginBlastView] = {}
    all_receipts: list[EvidenceReceipt] = []
    seen_receipt_keys: set[tuple[str, str, str]] = set()
    receipt_counter = 0

    def _next_id() -> str:
        nonlocal receipt_counter
        receipt_counter += 1
        return f"R-{receipt_counter:03d}"

    def _make_receipt(
        origin: str,
        op: str,
        edge_kind: str,
        target: str,
        hop: int,
        ring: int,
        kp: KprobeRecord | None,
    ) -> EvidenceReceipt:
        static_pred, resolved_t = _static_prediction_for_op(
            policy, path_res, attaches_by_type, origin, op, target
        )
        syscall_out = kp.outcome if kp is not None else None
        witness = witness_by_kprobe_line.get(kp.line) if kp is not None else None

        if kp is not None and witness is not None:
            ev_state = STATE_OBSERVED_AND_CORRELATED
        elif kp is not None:
            ev_state = STATE_SYSCALL_ONLY_UNOBSERVABLE
        else:
            ev_state = STATE_STATIC_ONLY

        mismatch = kp is not None and (static_pred != kp.outcome)
        return EvidenceReceipt(
            receipt_id=_next_id(),
            origin=origin,
            op=op,
            edge_kind=edge_kind,
            target=target,
            resolved_target_type=resolved_t,
            hop=hop,
            ring=ring,
            static_prediction=static_pred,
            syscall_outcome=syscall_out,
            syscall_errno=kp.errno if kp is not None else None,
            syscall_line=kp.line if kp is not None else None,
            syscall_raw=kp.raw if kp is not None else None,
            kernel_witness_verdict=witness.verdict if witness is not None else None,
            kernel_witness_line=witness.line if witness is not None else None,
            kernel_witness_raw=witness.raw if witness is not None else None,
            evidence_state=ev_state,
            mismatch=mismatch,
        )

    for origin in target_origins:
        # BFS over ESCALATION edges to determine escalation hop distance
        esc_hop: dict[str, int] = {origin: 0}
        esc_mech: dict[str, str] = {origin: "origin"}
        esc_parent_edge: dict[str, GraphEdge] = {}
        q: deque[str] = deque([origin])
        while q:
            cur = q.popleft()
            for edge in sorted(esc_adj.get(cur, []), key=lambda e: (e.dst, e.mechanism)):
                if edge.dst not in esc_hop:
                    esc_hop[edge.dst] = esc_hop[cur] + 1
                    esc_mech[edge.dst] = edge.mechanism
                    esc_parent_edge[edge.dst] = edge
                    q.append(edge.dst)

        # Direct Ring 1 REVIEW_ONLY neighbors
        rev_neighbors: dict[str, GraphEdge] = {}
        for edge in sorted(rev_adj.get(origin, []), key=lambda e: (e.dst, e.mechanism)):
            if edge.dst not in rev_neighbors:
                rev_neighbors[edge.dst] = edge

        # Build concentric BlastNodes for this origin
        view_nodes: list[BlastNode] = []
        view_receipts: list[EvidenceReceipt] = []
        origin_receipt_keys: set[tuple[str, str, str]] = set()

        def _node_meta(tname: str) -> tuple[bool, tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
            ninfo = path_res.nodes.get(tname, {})
            is_sink = bool(ninfo.get("is_sink"))
            reasons = tuple(ninfo.get("sink_reasons", ()))
            ab_list = tuple(sorted({s.canonical() for s, _ in abilities_by_type.get(tname, [])}))
            at_list = tuple(sorted({ap for _ft, ap, _r, _ct in attaches_by_type.get(tname, [])}))
            return is_sink, reasons, ab_list, at_list

        # 1. Build edge receipts along escalation subgraph reachable from origin
        edge_state_for_dst: dict[str, str] = {origin: STATE_STATIC_ONLY}
        consumed_kprobe_lines: set[int] = set()
        for dst, hop in sorted(esc_hop.items(), key=lambda kv: (kv[1], kv[0])):
            if dst == origin:
                continue
            edge = esc_parent_edge[dst]
            ring = 3 if hop >= 2 else 2
            matching_kps = kprobes_by_tuple.get((edge.src, "settypeid", edge.dst), [])
            if not matching_kps:
                rec = _make_receipt(edge.src, edge.mechanism, "ESCALATION", edge.dst, hop, ring, None)
                view_receipts.append(rec)
                edge_state_for_dst[dst] = rec.evidence_state
                if (rec.origin, rec.op, rec.target) not in seen_receipt_keys:
                    seen_receipt_keys.add((rec.origin, rec.op, rec.target))
                    all_receipts.append(rec)
            else:
                is_new_global = (edge.src, edge.mechanism, edge.dst) not in seen_receipt_keys
                for kp in matching_kps:
                    consumed_kprobe_lines.add(kp.line)
                    rec = _make_receipt(edge.src, edge.mechanism, "ESCALATION", edge.dst, hop, ring, kp)
                    view_receipts.append(rec)
                    edge_state_for_dst[dst] = rec.evidence_state
                    if is_new_global:
                        all_receipts.append(rec)
                seen_receipt_keys.add((edge.src, edge.mechanism, edge.dst))
            origin_receipt_keys.add((edge.src, edge.mechanism, edge.dst))

        # 2. Build direct REVIEW_ONLY IPC edge receipts
        for dst, edge in sorted(rev_neighbors.items()):
            # Match kprobe by type name OR any attach path name of `dst`
            matching_kps = kprobes_by_tuple.get((origin, "channel_connect", dst), [])
            if not matching_kps:
                for _ft, ap_path, _r, _ct in attaches_by_type.get(dst, []):
                    base = ap_path.rsplit("/", 1)[-1]
                    if (origin, "channel_connect", base) in kprobes_by_tuple:
                        matching_kps = kprobes_by_tuple[(origin, "channel_connect", base)]
                        break
            if not matching_kps:
                rec = _make_receipt(origin, edge.mechanism, "REVIEW_ONLY", dst, 1, 1, None)
                view_receipts.append(rec)
                if dst not in edge_state_for_dst:
                    edge_state_for_dst[dst] = rec.evidence_state
                if (rec.origin, rec.op, rec.target) not in seen_receipt_keys:
                    seen_receipt_keys.add((rec.origin, rec.op, rec.target))
                    all_receipts.append(rec)
            else:
                is_new_global = (origin, edge.mechanism, dst) not in seen_receipt_keys
                for kp in matching_kps:
                    consumed_kprobe_lines.add(kp.line)
                    rec = _make_receipt(origin, edge.mechanism, "REVIEW_ONLY", dst, 1, 1, kp)
                    view_receipts.append(rec)
                    if dst not in edge_state_for_dst:
                        edge_state_for_dst[dst] = rec.evidence_state
                    if is_new_global:
                        all_receipts.append(rec)
                seen_receipt_keys.add((origin, edge.mechanism, dst))
            origin_receipt_keys.add((origin, edge.mechanism, dst))

        # 3. Attach every remaining kprobe executed from `origin` (including duplicates & denied negative probes!)
        for kp in kprobes:
                if kp.origin != origin:
                    continue
                if kp.line in consumed_kprobe_lines:
                    continue
                ring = 2 if kp.op == "settypeid" else 1
                rec = _make_receipt(kp.origin, kp.op, "PROBE", kp.target, 1, ring, kp)
                view_receipts.append(rec)
                all_receipts.append(rec)

        # Assemble concentric nodes (Ring 0, Ring 1, Ring 2, Ring 3)
        included_types = set(esc_hop.keys()) | set(rev_neighbors.keys())
        reachable_sinks: list[str] = []
        for tname in sorted(included_types):
                is_sink, reasons, ab_list, at_list = _node_meta(tname)
                if tname == origin:
                    ring, hop, mech = 0, 0, "origin"
                elif tname in esc_hop:
                    hop = esc_hop[tname]
                    mech = esc_mech[tname]
                    ring = 3 if hop >= 2 else 2
                    if is_sink:
                        reachable_sinks.append(tname)
                else:
                    hop = 1
                    ring = 1
                    mech = rev_neighbors[tname].mechanism
                view_nodes.append(
                BlastNode(
                    name=tname,
                    ring=ring,
                    hop=hop,
                    is_sink=is_sink,
                    sink_reasons=reasons,
                    abilities=ab_list,
                    attaches=at_list,
                    reach_mechanism=mech,
                    evidence_state=edge_state_for_dst.get(tname, STATE_STATIC_ONLY),
                )
            )
        view_nodes.sort(key=lambda n: (n.ring, n.hop, n.name))

        origin_chains = [
            p.chain_str()
            for p in path_res.escalation_paths
            if p.source == origin
        ]
        origins_map[origin] = OriginBlastView(
            origin=origin,
            nodes=view_nodes,
            receipts=view_receipts,
            reachable_sinks=sorted(reachable_sinks),
            escalation_chains=origin_chains,
        )

    # Also include any kprobes whose origin wasn't in target_origins (e.g. when --origin filters view)
    # Wait: completeness reflects ALL kprobes in the log when --origin is omitted, or filtered origin's kprobes when --origin is set
    scoped_kprobes = [kp for kp in kprobes if not origin_filter or kp.origin == origin_filter]
    probes_completed = len(scoped_kprobes)

    active_expected_specs = expected_probe_specs if expected_probe_specs else None

    missing_probes: list[tuple[str, str, str]] = []
    duplicate_probes: list[tuple[str, str, str]] = []
    unexpected_probes: list[tuple[str, str, str]] = []
    if active_expected_specs is not None:
        observed_counts: dict[tuple[str, str, str], int] = defaultdict(int)
        for kp in scoped_kprobes:
            observed_counts[(kp.origin, kp.op, kp.target)] += 1
        expected_set = set(active_expected_specs)
        missing_probes = [t for t in active_expected_specs if observed_counts[t] == 0]
        duplicate_probes = [t for t in active_expected_specs if observed_counts[t] > 1]
        unexpected_probes = [t for t in observed_counts if t not in expected_set]
        probes_total = len(active_expected_specs)
    else:
        probes_total = (
            expected_probes
            if expected_probes is not None
            else (probes_completed if log_text is not None else len(all_receipts))
        )

    # Evaluate each scoped kprobe for completeness counts using the authoritative 1-to-1 mapping
    correlated_count = 0
    unobservable_count = 0
    mismatch_count = 0
    inconclusive_count = 0
    for kp in scoped_kprobes:
        if kp.classification in ("INCONCLUSIVE", "SETUP_FAILURE", "UNAVAILABLE"):
            inconclusive_count += 1
        else:
            static_pred, _ = _static_prediction_for_op(
                policy, path_res, attaches_by_type, kp.origin, kp.op, kp.target
            )
            if static_pred != kp.outcome:
                mismatch_count += 1
        if kp.line in witness_by_kprobe_line:
            correlated_count += 1
        else:
            unobservable_count += 1

    has_valid_stats = (
        log_text is not None
        and parsed_events is not None
        and parsed_events.stats is not None
        and _has_valid_post_marker_stats(log_text)
        and len(secpolev_events) == (parsed_events.stats.ok + parsed_events.stats.denied)
    )
    ifs_scheduled = extract_ifs_scheduled_probes(ifs) if ifs is not None else ()
    manifest_covers_ifs = (
        active_expected_specs is not None
        and (not ifs_scheduled or set(ifs_scheduled) == set(active_expected_specs))
    )
    has_explicit_manifest = (
        active_expected_specs is not None
        and len(active_expected_specs) >= 1
        and manifest_covers_ifs
    )
    kernel_policy_id = _extract_kernel_policy_id(log_text) if log_text is not None else None
    if expected_policy_id is not None:
        policy_id_valid = (
            kernel_policy_id is not None
            and kernel_policy_id > 0
            and kernel_policy_id == expected_policy_id
        )
    else:
        # If the kernel explicitly reported policy_id == 0 (no active policy), fail closed.
        policy_id_valid = kernel_policy_id is None or kernel_policy_id > 0

    all_pids_present = all(kp.pid is not None and kp.pid > 0 for kp in scoped_kprobes)
    probe_matrix_exact = (
        not missing_probes and not duplicate_probes and not unexpected_probes
    )

    if mismatch_count > 0:
        comp_result = "MISMATCH"
    elif (
        log_text is not None
        and not (parsed_events is not None and parsed_events.is_synthetic_fixture)
        and has_explicit_manifest
        and has_valid_stats
        and policy_id_valid
        and dropped_events == 0
        and inconclusive_count == 0
        and probes_total > 0
        and probes_completed == probes_total
        and probe_matrix_exact
        and all_pids_present
        and correlated_count == probes_total
        and unobservable_count == 0
    ):
        comp_result = "COMPLETE"
    else:
        comp_result = "PARTIAL"

    exec_label = execution_mode or (
        "independent-verification-boot"
        if (log_text is not None and parsed_events is not None)
        else ("syscall-probe-only" if log_text is not None else "static-analysis-only")
    )

    completeness = EvidenceCompleteness(
        target="QNX Neutrino 8.0 · QEMU x86_64 TCG",
        execution=exec_label,
        policy_path=policy.source_path,
        policy_hash=policy_hash,
        log_path=log_path,
        probes_total=probes_total,
        probes_completed=probes_completed,
        kernel_events_correlated=correlated_count,
        unobservable_operations=unobservable_count,
        dropped_events=dropped_events,
        mismatches=mismatch_count,
        result=comp_result,
        kernel_policy_id=kernel_policy_id,
    )

    # Pick default selected origin: explicit --origin, else highest-impact escalation source, else first type
    if origin_filter:
        selected_origin = origin_filter
    else:
        ranked = sorted(
            origins_map.values(),
            key=lambda v: (
                -len(v.escalation_chains),
                -len(v.reachable_sinks),
                -len([n for n in v.nodes if n.ring > 0]),
                v.origin,
            ),
        )
        selected_origin = ranked[0].origin if ranked else ""

    return BlastReport(
        policy_path=policy.source_path,
        policy_hash=policy_hash,
        ifs_path=ifs.source_path if ifs else None,
        log_path=log_path,
        selected_origin=selected_origin,
        completeness=completeness,
        origins=origins_map,
        all_receipts=all_receipts,
        kprobes=scoped_kprobes,
    )


def diff_blast_reports(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    """Compare two `secpol-audit blast --format json` payloads and detect blast expansion."""
    before_origins = before.get("origins", {})
    after_origins = after.get("origins", {})
    all_origin_names = sorted(set(before_origins.keys()) | set(after_origins.keys()))

    added_chains: list[str] = []
    removed_chains: list[str] = []
    added_sinks_by_origin: dict[str, list[str]] = {}
    removed_sinks_by_origin: dict[str, list[str]] = {}
    origin_deltas: dict[str, dict[str, Any]] = {}

    for o in all_origin_names:
        b_view = before_origins.get(o, {})
        a_view = after_origins.get(o, {})
        b_chains = set(b_view.get("escalation_chains", []))
        a_chains = set(a_view.get("escalation_chains", []))
        b_sinks = set(b_view.get("reachable_sinks", []))
        a_sinks = set(a_view.get("reachable_sinks", []))
        b_reach = {n["name"] for n in b_view.get("nodes", []) if n.get("ring", 0) > 0}
        a_reach = {n["name"] for n in a_view.get("nodes", []) if n.get("ring", 0) > 0}

        inc_chains = sorted(a_chains - b_chains)
        dec_chains = sorted(b_chains - a_chains)
        inc_sinks = sorted(a_sinks - b_sinks)
        dec_sinks = sorted(b_sinks - a_sinks)

        added_chains.extend(inc_chains)
        removed_chains.extend(dec_chains)
        if inc_sinks:
            added_sinks_by_origin[o] = inc_sinks
        if dec_sinks:
            removed_sinks_by_origin[o] = dec_sinks

        if inc_chains or dec_chains or inc_sinks or dec_sinks or b_reach != a_reach:
            origin_deltas[o] = {
                "reachable_before": len(b_reach),
                "reachable_after": len(a_reach),
                "added_reachable": sorted(a_reach - b_reach),
                "removed_reachable": sorted(b_reach - a_reach),
                "added_sinks": inc_sinks,
                "removed_sinks": dec_sinks,
                "added_chains": inc_chains,
                "removed_chains": dec_chains,
            }

    b_comp = before.get("completeness", {})
    a_comp = after.get("completeness", {})
    expanded = bool(added_chains or added_sinks_by_origin or a_comp.get("result") == "MISMATCH")

    return {
        "before_policy": before.get("policy"),
        "after_policy": after.get("policy"),
        "before_completeness": b_comp.get("result"),
        "after_completeness": a_comp.get("result"),
        "blast_expanded": expanded,
        "added_escalation_chains": sorted(set(added_chains)),
        "removed_escalation_chains": sorted(set(removed_chains)),
        "added_sinks_by_origin": added_sinks_by_origin,
        "removed_sinks_by_origin": removed_sinks_by_origin,
        "origin_deltas": origin_deltas,
    }
