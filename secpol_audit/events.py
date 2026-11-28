"""Host-side QNX Neutrino 8.0 `libsecpolev` kernel-trace parser and policy correlator."""

from __future__ import annotations

from dataclasses import dataclass, field
import fnmatch
import json
from pathlib import Path
import re
from typing import Any

from secpol_audit.checks import run_ifs_checks
from secpol_audit.ir import (
    Finding,
    IfsIR,
    ParseDiagnostic,
    PathAnalysisResult,
    PolicyIR,
    Severity,
    SourceSpan,
)
from secpol_audit.paths import analyze_paths, collect_type_abilities, collect_type_attaches

SYNTHETIC_MARKER_RE = re.compile(r"SYNTHETIC[\s_]+(?:UNIT[-_]TEST[\s_]+)?FIXTURE", re.IGNORECASE)
SECPOLEV_JSON_PREFIX = "SECPOLEV_JSON:"
SECPOLEV_ALERT_PREFIX = "SECPOLEV_ALERT:"
SECPOLEV_STATS_RE = re.compile(
    r"SECPOLEV_STATS:\s*ok=(\d+)\s+denied=(\d+)\s+dropped=(\d+)\b"
)
LINEAGE_HOP_RE = re.compile(r"\bLINEAGE_HOP([12]):(\{.*\})")
SENTRY_READ_AUTH_RE = re.compile(r"\b(SENTRY_(?:READ|CLIENT\d+)_AUTH)=(OK|DENIED)\b")
SENTRY_READ_UNAUTH_RE = re.compile(r"\bSENTRY_READ_UNAUTH=(OK|DENIED)\b")

VALID_VERDICTS = frozenset({"OK", "DENIED"})
VALID_KINDS = frozenset({"ability", "attach", "link", "custom"})


@dataclass(frozen=True)
class SecpolEvent:
    """Single parsed `SECPOLEV_JSON:` microkernel security trace event."""

    ts_ns: int
    verdict: str  # "OK" | "DENIED"
    proc: str
    type: str
    kind: str  # "ability" | "attach" | "link" | "custom"
    pid: int | None = None
    ability: str = ""
    root: bool = False
    range: tuple[int, int] | None = None
    path: str = ""
    status: str = ""
    class_name: str = ""
    perm: str = ""
    obj_type: str = ""
    line: int = 1
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ts_ns": self.ts_ns,
            "pid": self.pid,
            "verdict": self.verdict,
            "proc": self.proc,
            "type": self.type,
            "kind": self.kind,
            "ability": self.ability,
            "root": self.root,
            "range": list(self.range) if self.range is not None else None,
            "path": self.path,
            "status": self.status,
            "class": self.class_name,
            "perm": self.perm,
            "obj_type": self.obj_type,
            "line": self.line,
        }


@dataclass(frozen=True)
class SecpolAlert:
    """Single parsed `SECPOLEV_ALERT:` stateful multi-hop alert."""

    kind: str
    chain: tuple[str, ...]
    ts_ns: int
    line: int = 1
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "chain": list(self.chain),
            "ts_ns": self.ts_ns,
            "line": self.line,
        }


@dataclass(frozen=True)
class SecpolStats:
    """Parsed `SECPOLEV_STATS:` shutdown summary."""

    ok: int
    denied: int
    dropped: int
    line: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "denied": self.denied,
            "dropped": self.dropped,
            "line": self.line,
        }


@dataclass(frozen=True)
class LineageHop:
    """Parsed `LINEAGE_HOP1:` / `LINEAGE_HOP2:` exploit lineage marker."""

    hop: int
    parent_pid: int
    child_pid: int
    origin_type: str
    requested_target_type: str
    outcome: str  # "OK" | "DENIED"
    errno: int
    line: int = 1
    raw: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "hop": self.hop,
            "parent_pid": self.parent_pid,
            "child_pid": self.child_pid,
            "origin_type": self.origin_type,
            "requested_target_type": self.requested_target_type,
            "outcome": self.outcome,
            "errno": self.errno,
            "line": self.line,
        }


@dataclass
class ParsedEventLog:
    """Complete parsed `libsecpolev` telemetry log."""

    source_path: str
    is_synthetic_fixture: bool = False
    events: list[SecpolEvent] = field(default_factory=list)
    alerts: list[SecpolAlert] = field(default_factory=list)
    lineage_hops: list[LineageHop] = field(default_factory=list)
    stats: SecpolStats | None = None
    sentry_read_auth: str | None = None
    sentry_read_unauth: str | None = None
    sentry_client_reads: dict[str, str] = field(default_factory=dict)


@dataclass
class EventCorrelationResult:
    """Result of correlating `libsecpolev` kernel telemetry against static policy & paths."""

    log: ParsedEventLog
    path_result: PathAnalysisResult
    verified_edges: list[tuple[str, str]] = field(default_factory=list)
    verified_chains: list[list[str]] = field(default_factory=list)
    blocked_direct_attempts: list[SecpolEvent] = field(default_factory=list)
    custom_perm_grants: list[SecpolEvent] = field(default_factory=list)
    custom_perm_denials: list[SecpolEvent] = field(default_factory=list)
    unexpected_denials: list[SecpolEvent] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "log": self.log.source_path,
            "is_synthetic_fixture": self.log.is_synthetic_fixture,
            "summary": {
                "total_events": len(self.log.events),
                "total_alerts": len(self.log.alerts),
                "stats": self.log.stats.to_dict() if self.log.stats else None,
                "verified_escalation_edges": len(self.verified_edges),
                "verified_escalation_chains": len(self.verified_chains),
                "blocked_direct_attempts": len(self.blocked_direct_attempts),
                "custom_perm_grants": len(self.custom_perm_grants),
                "custom_perm_denials": len(self.custom_perm_denials),
                "unexpected_denials": len(self.unexpected_denials),
                "total_findings": len(self.findings),
                "sentry_read_auth": self.log.sentry_read_auth,
                "sentry_read_unauth": self.log.sentry_read_unauth,
            },
            "verified_edges": [{"src": s, "dst": d} for s, d in self.verified_edges],
            "verified_chains": self.verified_chains,
            "blocked_direct_attempts": [e.to_dict() for e in self.blocked_direct_attempts],
            "custom_perm_grants": [e.to_dict() for e in self.custom_perm_grants],
            "custom_perm_denials": [e.to_dict() for e in self.custom_perm_denials],
            "unexpected_denials": [e.to_dict() for e in self.unexpected_denials],
            "alerts": [a.to_dict() for a in self.log.alerts],
            "findings": [f.to_dict() for f in self.findings],
        }


def parse_events_text(text: str, source_path: str = "<memory>") -> ParsedEventLog:
    """Parse `SECPOLEV_JSON:`, `SECPOLEV_ALERT:`, and `SECPOLEV_STATS:` lines fail-closed."""
    parsed = ParsedEventLog(source_path=source_path)

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip("\r\n")
        if SYNTHETIC_MARKER_RE.search(line):
            parsed.is_synthetic_fixture = True

        m_auth = SENTRY_READ_AUTH_RE.search(line)
        if m_auth:
            parsed.sentry_client_reads[m_auth.group(1)] = m_auth.group(2)
            parsed.sentry_read_auth = m_auth.group(2)

        m_unauth = SENTRY_READ_UNAUTH_RE.search(line)
        if m_unauth:
            parsed.sentry_read_unauth = m_unauth.group(1)

        m_lin = LINEAGE_HOP_RE.search(line)
        if m_lin:
            hop_num = int(m_lin.group(1))
            span = SourceSpan(file=source_path, line=line_no, col=m_lin.start() + 1, snippet=line)
            try:
                lobj = json.loads(m_lin.group(2))
            except json.JSONDecodeError as exc:
                raise ParseDiagnostic("PARSE_ERROR", f"Malformed LINEAGE_HOP{hop_num} JSON: {exc.msg}", span) from exc
            if isinstance(lobj, dict):
                parsed.lineage_hops.append(
                    LineageHop(
                        hop=hop_num,
                        parent_pid=int(lobj.get("parent_pid", -1)),
                        child_pid=int(lobj.get("child_pid", -1)),
                        origin_type=str(lobj.get("origin_type") or ""),
                        requested_target_type=str(lobj.get("requested_target_type") or ""),
                        outcome=str(lobj.get("outcome") or ""),
                        errno=int(lobj.get("errno", 0)),
                        line=line_no,
                        raw=line,
                    )
                )

        if SECPOLEV_JSON_PREFIX in line:
            idx = line.find(SECPOLEV_JSON_PREFIX)
            json_str = line[idx + len(SECPOLEV_JSON_PREFIX) :].strip()
            span = SourceSpan(file=source_path, line=line_no, col=idx + 1, snippet=line)
            try:
                obj = json.loads(json_str)
            except json.JSONDecodeError as exc:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Malformed SECPOLEV_JSON payload: {exc.msg}",
                    span,
                ) from exc
            if not isinstance(obj, dict):
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    "SECPOLEV_JSON payload must be a JSON object",
                    span,
                )

            verdict = obj.get("verdict")
            kind = obj.get("kind")
            ts_ns = obj.get("ts_ns", 0)
            if verdict not in VALID_VERDICTS:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Invalid SECPOLEV_JSON verdict '{verdict}' (expected 'OK' or 'DENIED')",
                    span,
                )
            if kind not in VALID_KINDS:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Invalid SECPOLEV_JSON kind '{kind}' (expected ability|attach|link|custom)",
                    span,
                )
            if not isinstance(ts_ns, int) or isinstance(ts_ns, bool) or ts_ns < 0:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Invalid SECPOLEV_JSON ts_ns '{ts_ns}' (expected non-negative integer)",
                    span,
                )

            rng_raw = obj.get("range")
            rng_val: tuple[int, int] | None = None
            if rng_raw is not None:
                if (
                    not isinstance(rng_raw, list)
                    or len(rng_raw) != 2
                    or not all(isinstance(v, int) and not isinstance(v, bool) for v in rng_raw)
                ):
                    raise ParseDiagnostic(
                        "PARSE_ERROR",
                        f"Invalid SECPOLEV_JSON range '{rng_raw}' (expected [start, end] or null)",
                        span,
                    )
                rng_val = (rng_raw[0], rng_raw[1])

            raw_pid = obj.get("pid")
            if raw_pid is not None and (not isinstance(raw_pid, int) or isinstance(raw_pid, bool)):
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Invalid SECPOLEV_JSON pid '{raw_pid}' (expected integer)",
                    span,
                )

            parsed.events.append(
                SecpolEvent(
                    ts_ns=ts_ns,
                    verdict=verdict,
                    proc=str(obj.get("proc") or ""),
                    type=str(obj.get("type") or ""),
                    kind=kind,
                    pid=raw_pid,
                    ability=str(obj.get("ability") or ""),
                    root=bool(obj.get("root", False)),
                    range=rng_val,
                    path=str(obj.get("path") or ""),
                    status=str(obj.get("status") or ""),
                    class_name=str(obj.get("class") or ""),
                    perm=str(obj.get("perm") or ""),
                    obj_type=str(obj.get("obj_type") or ""),
                    line=line_no,
                    raw=line,
                )
            )
            continue

        if SECPOLEV_ALERT_PREFIX in line:
            idx = line.find(SECPOLEV_ALERT_PREFIX)
            json_str = line[idx + len(SECPOLEV_ALERT_PREFIX) :].strip()
            span = SourceSpan(file=source_path, line=line_no, col=idx + 1, snippet=line)
            try:
                obj = json.loads(json_str)
            except json.JSONDecodeError as exc:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Malformed SECPOLEV_ALERT payload: {exc.msg}",
                    span,
                ) from exc
            if not isinstance(obj, dict):
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    "SECPOLEV_ALERT payload must be a JSON object",
                    span,
                )
            chain_raw = obj.get("chain")
            if not isinstance(chain_raw, list) or not all(isinstance(t, str) and t for t in chain_raw):
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    "SECPOLEV_ALERT 'chain' must be a list of non-empty type strings",
                    span,
                )
            ts_ns = obj.get("ts_ns", 0)
            if not isinstance(ts_ns, int) or isinstance(ts_ns, bool) or ts_ns < 0:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    f"Invalid SECPOLEV_ALERT ts_ns '{ts_ns}'",
                    span,
                )
            parsed.alerts.append(
                SecpolAlert(
                    kind=str(obj.get("kind") or "multi_hop_chain"),
                    chain=tuple(chain_raw),
                    ts_ns=ts_ns,
                    line=line_no,
                    raw=line,
                )
            )
            continue

        if "SECPOLEV_STATS:" in line:
            idx = line.find("SECPOLEV_STATS:")
            span = SourceSpan(file=source_path, line=line_no, col=idx + 1, snippet=line)
            m = SECPOLEV_STATS_RE.search(line)
            if not m:
                raise ParseDiagnostic(
                    "PARSE_ERROR",
                    "Malformed SECPOLEV_STATS line (expected 'SECPOLEV_STATS: ok=<n> denied=<n> dropped=<n>')",
                    span,
                )
            parsed.stats = SecpolStats(
                ok=int(m.group(1)),
                denied=int(m.group(2)),
                dropped=int(m.group(3)),
                line=line_no,
            )

    if not parsed.events and not parsed.alerts and parsed.stats is None:
        raise ParseDiagnostic(
            "PARSE_ERROR",
            f"No libsecpolev telemetry lines (SECPOLEV_JSON / SECPOLEV_ALERT / SECPOLEV_STATS) found in '{source_path}'",
            SourceSpan(file=source_path, line=1, col=1),
        )

    return parsed


def parse_events_file(path: str | Path) -> ParsedEventLog:
    """Read and parse a QNX 8.0 serial log containing `secpol_sentry` telemetry."""
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise ParseDiagnostic(
            "PARSE_ERROR",
            f"Unable to read event log file: {exc}",
            SourceSpan(file=str(p), line=1, col=1),
        ) from exc
    return parse_events_text(text, str(p))


def _policy_allows_custom_perm(
    policy: PolicyIR,
    src_type: str,
    obj_type: str,
    class_name: str,
    perm: str,
) -> bool:
    for rule in policy.class_rules:
        if rule.class_name != class_name or perm not in rule.permissions:
            continue
        expanded_srcs = {
            ct for s in rule.sources for ct, _ in policy.expand_subject(s)
        }
        expanded_dsts = {
            ct for d in rule.targets for ct, _ in policy.expand_subject(d, allow_default_rules=False)
        }
        if src_type in expanded_srcs and (not obj_type or obj_type in expanded_dsts):
            return True
    return False


def _policy_allows_attach(
    attaches_by_type: dict[str, list[tuple[str | None, str, str, str | None]]],
    src_type: str,
    path: str,
) -> bool:
    for _ftype, ap_path, _raw, _ct in attaches_by_type.get(src_type, []):
        if ap_path == path:
            return True
        if ap_path.endswith("..."):
            prefix = ap_path[:-3].rstrip("/")
            if path == prefix or path.startswith(prefix + "/"):
                return True
        if fnmatch.fnmatch(path, ap_path):
            return True
    return False


def correlate_events(
    log: ParsedEventLog,
    policy: PolicyIR,
    *,
    ifs: IfsIR | None = None,
) -> EventCorrelationResult:
    """Correlate `libsecpolev` kernel telemetry against static `.secpol` & `build.ifs`."""
    path_result = analyze_paths(policy, ifs=ifs)
    abilities_by_type = collect_type_abilities(policy)
    attaches_by_type = collect_type_attaches(policy)

    ability_names_by_type: dict[str, set[str]] = {
        t: {spec.name for spec, _ in specs} for t, specs in abilities_by_type.items()
    }

    findings: list[Finding] = []
    if ifs is not None:
        findings.extend(run_ifs_checks(ifs, policy))

    # 1. Check dropped trace events
    if log.stats is not None and log.stats.dropped > 0:
        findings.append(
            Finding(
                rule_id="SECPOLEV_DROPPED_EVENTS",
                severity=Severity.MEDIUM,
                message=(
                    f"libsecpolev reported {log.stats.dropped} dropped kernel security event(s) "
                    f"(ok={log.stats.ok}, denied={log.stats.denied}); trace coverage is incomplete"
                ),
                span=SourceSpan(file=log.source_path, line=log.stats.line, col=1),
                remediation=(
                    "Increase secpolev_init() buffer count or reduce flush delay so microkernel trace "
                    "buffers do not overflow under load."
                ),
                metadata=log.stats.to_dict(),
            )
        )

    # 2. Index observed settypeid OK events (excluding untyped boot launcher `-`),
    #    type appearances, and validated multi-hop alerts.
    settypeid_ok_by_type: dict[str, list[SecpolEvent]] = {}
    type_latest_ts: dict[str, int] = {}
    for ev in log.events:
        if ev.type and ev.type != "-":
            prev = type_latest_ts.get(ev.type, -1)
            if ev.ts_ns >= prev:
                type_latest_ts[ev.type] = ev.ts_ns
        if (
            ev.verdict == "OK"
            and ev.kind == "ability"
            and ev.ability == "settypeid"
            and ev.type
            and ev.type != "-"
        ):
            settypeid_ok_by_type.setdefault(ev.type, []).append(ev)

    static_esc_pairs: set[tuple[str, str]] = {
        (e.src, e.dst) for e in path_result.escalation_edges if e.src != e.dst
    }

    # Filter alerts to valid typed chains (strip boot launcher `-` emitted by `proc/boot/on`)
    alert_edge_pairs: set[tuple[str, str]] = set()
    valid_alerts: list[tuple[SecpolAlert, tuple[str, ...]]] = []
    for alert in log.alerts:
        typed_chain = tuple(t for t in alert.chain if t and t != "-" and t in policy.types)
        if len(typed_chain) < 2:
            continue
        # Only trust an alert edge (a, b) if `a` actually executed a typed `settypeid` OK
        # or (a, b) is a static escalation edge whose source executed `settypeid` OK.
        valid_hops = [
            (typed_chain[i], typed_chain[i + 1])
            for i in range(len(typed_chain) - 1)
            if typed_chain[i] in settypeid_ok_by_type
            and (
                (typed_chain[i], typed_chain[i + 1]) in static_esc_pairs
                or not static_esc_pairs
            )
        ]
        if valid_hops:
            for pair in valid_hops:
                alert_edge_pairs.add(pair)
            if len(valid_hops) == len(typed_chain) - 1:
                valid_alerts.append((alert, typed_chain))

    # Out-degree of static escalation edges per source
    esc_out_counts: dict[str, int] = {}
    for e in path_result.escalation_edges:
        if e.src != e.dst:
            esc_out_counts[e.src] = esc_out_counts.get(e.src, 0) + 1

    # Identify static escalation edges verified by kernel trace:
    # 1. Strict PID-aware correlation from LINEAGE_HOP1/2 markers + SECPOLEV_JSON
    verified_edges_set: set[tuple[str, str]] = set()
    verified_edge_evidence: dict[tuple[str, str], SecpolEvent] = {}
    pid_verified_hops: dict[tuple[str, str], tuple[LineageHop, SecpolEvent, SecpolEvent]] = {}

    for hop in log.lineage_hops:
        ev1_matches = [
            ev
            for ev in log.events
            if ev.pid == hop.parent_pid
            and ev.type == hop.origin_type
            and ev.kind == "ability"
            and ev.ability == "settypeid"
            and ev.verdict == hop.outcome
        ]
        if not ev1_matches:
            continue
        ev1 = min(ev1_matches, key=lambda x: (x.ts_ns, x.line))
        if hop.outcome == "OK":
            ev2_matches = [
                ev
                for ev in log.events
                if ev.ts_ns >= ev1.ts_ns
                and ev.pid == hop.child_pid
                and ev.type == hop.requested_target_type
            ]
            if not ev2_matches:
                continue
            ev2 = min(ev2_matches, key=lambda x: (x.ts_ns, x.line))
            pair = (hop.origin_type, hop.requested_target_type)
            if pair in static_esc_pairs:
                verified_edges_set.add(pair)
                verified_edge_evidence[pair] = ev1
                pid_verified_hops[pair] = (hop, ev1, ev2)

    # 2. Legacy alert-based edges (when no lineage_hops are present)
    for e in path_result.escalation_edges:
        if e.src == e.dst:
            continue
        pair = (e.src, e.dst)
        if pair in verified_edges_set:
            continue
        src_events = settypeid_ok_by_type.get(e.src, [])
        if not src_events:
            continue
        earliest_ev = min(src_events, key=lambda x: (x.ts_ns, x.line))
        if pair in alert_edge_pairs:
            verified_edges_set.add(pair)
            verified_edge_evidence[pair] = earliest_ev

    verified_edges = sorted(verified_edges_set)

    # Identify exercised static escalation chains
    verified_chains: list[list[str]] = []
    covered_alert_chains: set[tuple[str, ...]] = set()
    for ep in path_result.escalation_paths:
        ep_pairs = [(ep.nodes[i], ep.nodes[i + 1]) for i in range(len(ep.nodes) - 1)]
        all_hops_verified = bool(ep_pairs) and all(p in verified_edges_set for p in ep_pairs)
        # If PID-verified hops are present for this chain, enforce causal PID linkage
        if all_hops_verified and len(ep_pairs) >= 2 and all(p in pid_verified_hops for p in ep_pairs):
            causal_ok = True
            for i in range(len(ep_pairs) - 1):
                h_prev, ev1_prev, _ = pid_verified_hops[ep_pairs[i]]
                h_next, ev1_next, _ = pid_verified_hops[ep_pairs[i + 1]]
                if h_next.parent_pid != h_prev.child_pid or ev1_next.ts_ns < ev1_prev.ts_ns:
                    causal_ok = False
                    break
            all_hops_verified = causal_ok
        matching_alert = next(
            (a for a, tc in valid_alerts if tc == ep.nodes),
            None,
        )
        if all_hops_verified or matching_alert is not None:
            verified_chains.append(list(ep.nodes))
            covered_alert_chains.add(ep.nodes)
            # Ensure all edges in an alert-confirmed chain are marked verified
            for p in ep_pairs:
                if p not in verified_edges_set:
                    verified_edges_set.add(p)
            verified_edges = sorted(verified_edges_set)

            first_pair = ep_pairs[0]
            ev_ref = verified_edge_evidence.get(first_pair)
            log_line = ev_ref.line if ev_ref else (matching_alert.line if matching_alert else 1)
            ts_list = [
                verified_edge_evidence[p].ts_ns
                for p in ep_pairs
                if p in verified_edge_evidence
            ]
            range_ids = [
                list(verified_edge_evidence[p].range)
                for p in ep_pairs
                if p in verified_edge_evidence and verified_edge_evidence[p].range is not None
            ]
            findings.append(
                Finding(
                    rule_id="KERNEL_TRACE_ESCALATION_OBSERVED",
                    severity=Severity.CRITICAL,
                    message=(
                        f"Kernel trace confirmed {ep.hops}-hop privilege escalation chain: {ep.chain_str()} "
                        f"({len(ep_pairs)}/{len(ep_pairs)} hops fired OK in libsecpolev; gains {', '.join(ep.sink_reasons)})"
                    ),
                    span=SourceSpan(file=log.source_path, line=log_line, col=1),
                    remediation=(
                        f"Remove the exercised settypeid transition edge(s) along {ep.chain_str()} "
                        "and re-verify under libsecpolev."
                    ),
                    metadata={
                        "chain": list(ep.nodes),
                        "hops": ep.hops,
                        "verified_edges": [[s, d] for s, d in ep_pairs],
                        "timestamps_ns": ts_list,
                        "range_ids": range_ids,
                        "sink_reasons": list(ep.sink_reasons),
                        "is_synthetic_fixture": log.is_synthetic_fixture,
                    },
                )
            )

    # Also report any validated typed multi-hop alert not covered by a static escalation path
    for alert, typed_chain in valid_alerts:
        if len(typed_chain) >= 2 and typed_chain not in covered_alert_chains:
            # Skip strict prefix/subpath of an already-reported verified chain
            if any(
                len(vc) >= len(typed_chain)
                and any(
                    tuple(vc[i : i + len(typed_chain)]) == typed_chain
                    for i in range(len(vc) - len(typed_chain) + 1)
                )
                for vc in verified_chains
            ):
                continue
            verified_chains.append(list(typed_chain))
            findings.append(
                Finding(
                    rule_id="KERNEL_TRACE_ESCALATION_OBSERVED",
                    severity=Severity.CRITICAL,
                    message=(
                        f"libsecpolev stateful detector alerted on multi-hop chain: "
                        f"{' -> '.join(typed_chain)} (ts_ns={alert.ts_ns})"
                    ),
                    span=SourceSpan(file=log.source_path, line=alert.line, col=1),
                    remediation=(
                        f"Audit transition permissions along {' -> '.join(typed_chain)} and remove "
                        "unintended settypeid chains."
                    ),
                    metadata={
                        "chain": list(typed_chain),
                        "alert_kind": alert.kind,
                        "ts_ns": alert.ts_ns,
                        "is_synthetic_fixture": log.is_synthetic_fixture,
                    },
                )
            )

    # 3. Classify DENIED events & custom-permission checks
    blocked_direct_attempts: list[SecpolEvent] = []
    custom_perm_grants: list[SecpolEvent] = []
    custom_perm_denials: list[SecpolEvent] = []
    unexpected_denials: list[SecpolEvent] = []

    for ev in log.events:
        if ev.kind == "custom":
            if ev.verdict == "OK":
                custom_perm_grants.append(ev)
                continue
            # verdict == "DENIED"
            custom_perm_denials.append(ev)
            if ev.type in policy.types and _policy_allows_custom_perm(
                policy, ev.type, ev.obj_type, ev.class_name, ev.perm
            ):
                unexpected_denials.append(ev)
                findings.append(
                    Finding(
                        rule_id="UNEXPECTED_RUNTIME_DENIAL",
                        severity=Severity.HIGH,
                        message=(
                            f"Declared service type '{ev.type}' (proc '{ev.proc}') was unexpectedly DENIED "
                            f"custom permission '{ev.class_name}:{ev.perm}' on '{ev.obj_type}' despite policy grant"
                        ),
                        span=SourceSpan(file=log.source_path, line=ev.line, col=1, snippet=ev.raw),
                        remediation=(
                            f"Verify compiled secpol.bin matches '{policy.source_path}' and check "
                            f"resource manager permission binding for '{ev.class_name}:{ev.perm}'."
                        ),
                        metadata=ev.to_dict(),
                    )
                )
            else:
                blocked_direct_attempts.append(ev)
            continue

        if ev.verdict != "DENIED":
            continue

        if ev.kind == "ability":
            # `channel_connect` and `settypeid` are target-scoped: a DENIED event on a type that holds
            # limited targets (e.g., ivi_ui_t allowed diag_helper_t but denied can_hal_t) is expected defense.
            if ev.ability in ("channel_connect", "settypeid"):
                blocked_direct_attempts.append(ev)
            elif ev.type in policy.types and ev.ability in ability_names_by_type.get(ev.type, set()):
                unexpected_denials.append(ev)
                findings.append(
                    Finding(
                        rule_id="UNEXPECTED_RUNTIME_DENIAL",
                        severity=Severity.HIGH,
                        message=(
                            f"Declared service type '{ev.type}' (proc '{ev.proc}') was unexpectedly DENIED "
                            f"ability '{ev.ability}' despite being granted in '{policy.source_path}'"
                        ),
                        span=SourceSpan(file=log.source_path, line=ev.line, col=1, snippet=ev.raw),
                        remediation=(
                            f"Verify ability range/root modifiers for '{ev.ability}' on '{ev.type}' "
                            "and confirm the target booted with the expected compiled secpol.bin."
                        ),
                        metadata=ev.to_dict(),
                    )
                )
            else:
                blocked_direct_attempts.append(ev)
        elif ev.kind == "attach":
            if ev.type in policy.types and ev.path and _policy_allows_attach(attaches_by_type, ev.type, ev.path):
                unexpected_denials.append(ev)
                findings.append(
                    Finding(
                        rule_id="UNEXPECTED_RUNTIME_DENIAL",
                        severity=Severity.HIGH,
                        message=(
                            f"Declared service type '{ev.type}' (proc '{ev.proc}') was unexpectedly DENIED "
                            f"path attach '{ev.path}' despite allow_attach rule in '{policy.source_path}'"
                        ),
                        span=SourceSpan(file=log.source_path, line=ev.line, col=1, snippet=ev.raw),
                        remediation=(
                            f"Verify '{ev.type}' has 'pathspace'/'public_channel' abilities and matching "
                            f"mount_point permissions for '{ev.path}'."
                        ),
                        metadata=ev.to_dict(),
                    )
                )
            else:
                blocked_direct_attempts.append(ev)
        else:
            blocked_direct_attempts.append(ev)

    findings.sort(
        key=lambda f: (
            f.severity.rank,
            f.span.file if f.span else "",
            f.span.line if f.span else 0,
            f.rule_id,
            f.message,
        )
    )

    return EventCorrelationResult(
        log=log,
        path_result=path_result,
        verified_edges=verified_edges,
        verified_chains=verified_chains,
        blocked_direct_attempts=blocked_direct_attempts,
        custom_perm_grants=custom_perm_grants,
        custom_perm_denials=custom_perm_denials,
        unexpected_denials=unexpected_denials,
        findings=findings,
    )
