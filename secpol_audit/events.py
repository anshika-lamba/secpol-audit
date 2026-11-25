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

SYNTHETIC_MARKER_RE = re.compile(r"SYNTHETIC\s+(?:UNIT-TEST\s+)?FIXTURE", re.IGNORECASE)
SECPOLEV_JSON_PREFIX = "SECPOLEV_JSON:"
SECPOLEV_ALERT_PREFIX = "SECPOLEV_ALERT:"
SECPOLEV_STATS_RE = re.compile(
    r"SECPOLEV_STATS:\s*ok=(\d+)\s+denied=(\d+)\s+dropped=(\d+)\b"
)
SENTRY_READ_AUTH_RE = re.compile(r"\bSENTRY_READ_AUTH=(OK|DENIED)\b")
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


@dataclass
class ParsedEventLog:
    """Complete parsed `libsecpolev` telemetry log."""

    source_path: str
    is_synthetic_fixture: bool = False
    events: list[SecpolEvent] = field(default_factory=list)
    alerts: list[SecpolAlert] = field(default_factory=list)
    stats: SecpolStats | None = None
    sentry_read_auth: str | None = None
    sentry_read_unauth: str | None = None


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
            parsed.sentry_read_auth = m_auth.group(1)

        m_unauth = SENTRY_READ_UNAUTH_RE.search(line)
        if m_unauth:
            parsed.sentry_read_unauth = m_unauth.group(1)

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

            parsed.events.append(
                SecpolEvent(
                    ts_ns=ts_ns,
                    verdict=verdict,
                    proc=str(obj.get("proc") or ""),
                    type=str(obj.get("type") or ""),
                    kind=kind,
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

    # 2. Index observed settypeid OK events, type appearances, and multi-hop alerts
    settypeid_ok_by_type: dict[str, list[SecpolEvent]] = {}
    type_latest_ts: dict[str, int] = {}
    for ev in log.events:
        if ev.type:
            prev = type_latest_ts.get(ev.type, -1)
            if ev.ts_ns >= prev:
                type_latest_ts[ev.type] = ev.ts_ns
        if ev.verdict == "OK" and ev.kind == "ability" and ev.ability == "settypeid" and ev.type:
            settypeid_ok_by_type.setdefault(ev.type, []).append(ev)

    alert_edge_pairs: set[tuple[str, str]] = set()
    for alert in log.alerts:
        for i in range(len(alert.chain) - 1):
            alert_edge_pairs.add((alert.chain[i], alert.chain[i + 1]))

    # Out-degree of static escalation edges per source
    esc_out_counts: dict[str, int] = {}
    for e in path_result.escalation_edges:
        if e.src != e.dst:
            esc_out_counts[e.src] = esc_out_counts.get(e.src, 0) + 1

    # Identify static escalation edges verified by kernel trace
    verified_edges_set: set[tuple[str, str]] = set()
    verified_edge_evidence: dict[tuple[str, str], SecpolEvent] = {}
    for e in path_result.escalation_edges:
        if e.src == e.dst:
            continue
        pair = (e.src, e.dst)
        src_events = settypeid_ok_by_type.get(e.src, [])
        if not src_events:
            continue
        earliest_ev = min(src_events, key=lambda x: (x.ts_ns, x.line))
        dst_appeared_after = (
            e.dst in type_latest_ts and type_latest_ts[e.dst] >= earliest_ev.ts_ns
        )
        if pair in alert_edge_pairs or dst_appeared_after or esc_out_counts.get(e.src, 0) == 1:
            verified_edges_set.add(pair)
            verified_edge_evidence[pair] = earliest_ev

    verified_edges = sorted(verified_edges_set)

    # Identify exercised static escalation chains
    verified_chains: list[list[str]] = []
    covered_alert_chains: set[tuple[str, ...]] = set()
    for ep in path_result.escalation_paths:
        ep_pairs = [(ep.nodes[i], ep.nodes[i + 1]) for i in range(len(ep.nodes) - 1)]
        all_hops_verified = bool(ep_pairs) and all(p in verified_edges_set for p in ep_pairs)
        matching_alert = next(
            (a for a in log.alerts if tuple(a.chain) == ep.nodes),
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
                        "sink_reasons": list(ep.sink_reasons),
                        "is_synthetic_fixture": log.is_synthetic_fixture,
                    },
                )
            )

    # Also report any multi-hop alert not covered by a static escalation path
    for alert in log.alerts:
        if len(alert.chain) >= 2 and alert.chain not in covered_alert_chains:
            # Skip strict prefix of an already-reported verified chain
            if any(
                len(vc) > len(alert.chain) and tuple(vc[: len(alert.chain)]) == alert.chain
                for vc in verified_chains
            ):
                continue
            verified_chains.append(list(alert.chain))
            findings.append(
                Finding(
                    rule_id="KERNEL_TRACE_ESCALATION_OBSERVED",
                    severity=Severity.CRITICAL,
                    message=(
                        f"libsecpolev stateful detector alerted on multi-hop chain: "
                        f"{' -> '.join(alert.chain)} (ts_ns={alert.ts_ns})"
                    ),
                    span=SourceSpan(file=log.source_path, line=alert.line, col=1),
                    remediation=(
                        f"Audit transition permissions along {' -> '.join(alert.chain)} and remove "
                        "unintended settypeid chains."
                    ),
                    metadata={
                        "chain": list(alert.chain),
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
