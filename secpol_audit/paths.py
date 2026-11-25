"""Transitive privilege-escalation graph & path analyzer for QNX 8.0 policies."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
import fnmatch
from typing import Any

from secpol_audit.ir import (
    AbilitySpec,
    EscalationPath,
    Finding,
    GraphEdge,
    IfsIR,
    PathAnalysisResult,
    PolicyIR,
    Severity,
)

DEFAULT_PRIVILEGED_ABILITIES = frozenset(
    {
        "mem_phys",
        "prot_exec",
        "mac_policy",
        "pathspace",
        "io",
    }
)

SENSITIVE_UNLOCK_ABILITIES = frozenset(
    {
        "mem_phys",
        "prot_exec",
        "mac_policy",
        "pathspace",
        "io",
        "setuid",
        "setgid",
        "gain_priv",
        "able_create",
        "procmgr_ability",
    }
)

DEFAULT_PRIVILEGED_ATTACH_PATTERNS = (
    "/dev/can_ctrl",
    "/dev/mem",
    "/dev/io*",
    "/system",
    "/system/*",
)


@dataclass(frozen=True)
class SinkConfig:
    """Configuration defining what constitutes a high-privilege sink."""

    privileged_abilities: frozenset[str] = DEFAULT_PRIVILEGED_ABILITIES
    sensitive_unlock_abilities: frozenset[str] = SENSITIVE_UNLOCK_ABILITIES
    privileged_attach_patterns: tuple[str, ...] = DEFAULT_PRIVILEGED_ATTACH_PATTERNS


def is_privileged_ability(spec: AbilitySpec, config: SinkConfig | None = None) -> tuple[bool, str | None]:
    """Return `(is_priv, reason)` if an ability grants high-privilege capability."""
    cfg = config or SinkConfig()
    if spec.name in cfg.privileged_abilities:
        return True, f"ability:{spec.canonical()}"
    if spec.name == "setuid":
        if not spec.args:
            return True, "ability:setuid(unrestricted)"
        for arg in spec.args:
            if arg == "0" or arg.startswith("0-"):
                return True, f"ability:{spec.canonical()}"
    if spec.name == "gain_priv":
        for arg in spec.args:
            if arg in cfg.privileged_abilities or arg == "setuid":
                return True, f"ability:{spec.canonical()}"
    if spec.has_unlock and spec.name in cfg.sensitive_unlock_abilities:
        return True, f"unlocked:{spec.canonical()}"
    return False, None


def _is_privileged_attach(ftype: str | None, path: str, config: SinkConfig) -> tuple[bool, str | None]:
    if ftype == "*":
        return True, f"attach:*:{path}"
    for pattern in config.privileged_attach_patterns:
        if fnmatch.fnmatch(path, pattern):
            return True, f"attach:{path}"
    return False, None


def _normalize_reason_key(reason: str) -> str:
    """Normalize sink capability keys so privilege gain comparison is semantic."""
    if reason.startswith("ability:"):
        body = reason[len("ability:") :]
        # Strip modifiers like nonroot/noinherit
        tokens = body.split()
        core = tokens[-1] if tokens else body
        name = core.split(":", 1)[0]
        if name == "setuid":
            return "ability:setuid:0"
        return f"ability:{name}"
    return reason


def _classify_trust_zone(
    type_name: str,
    *,
    is_sink: bool,
    is_escalation_source: bool,
) -> str:
    """Assign a layered UI trust zone for BloodHound-style visualization."""
    lower = type_name.lower()
    if any(k in lower for k in ("slogger", "secpol", "procnto", "sysmgr", "core", "init", "boot")):
        return "Core"
    if is_sink or any(k in lower for k in ("hal", "drv", "driver", "can", "lidar", "cam", "safety", "kernel")):
        return "Safety-Critical HAL"
    if is_escalation_source or any(k in lower for k in ("ivi", "ui", "hmi", "untrust", "guest", "web", "app", "ext")):
        return "Untrusted"
    return "Middleware"


def _attach_matches_link(attach_path: str, link_path: str) -> bool:
    """Check if an `allow_link` path targets a namespace attached by `allow_attach`."""
    # Strip optional ftype prefix like `mount+:`
    a = attach_path.split(":", 1)[1] if ":" in attach_path else attach_path
    l = link_path.split(":", 1)[1] if ":" in link_path else link_path
    if a == l:
        return True
    if a.endswith("..."):
        prefix = a[:-3].rstrip("/")
        if l == prefix or l.startswith(prefix + "/"):
            return True
    if l.endswith("..."):
        prefix = l[:-3].rstrip("/")
        if a == prefix or a.startswith(prefix + "/"):
            return True
    return fnmatch.fnmatch(l, a) or fnmatch.fnmatch(a, l)


def collect_type_abilities(policy: PolicyIR) -> dict[str, list[tuple[AbilitySpec, str | None]]]:
    """Expand all ability rules across types, attributes, and `default_rules`."""
    per_type: dict[str, list[tuple[AbilitySpec, str | None]]] = {t: [] for t in policy.types}
    for rule in policy.ability_rules:
        for src in rule.sources:
            for concrete_src, via_attr in policy.expand_subject(src):
                if concrete_src not in per_type:
                    continue
                for spec in rule.abilities:
                    per_type[concrete_src].append((spec, via_attr))
    return per_type


def collect_type_attaches(policy: PolicyIR) -> dict[str, list[tuple[str | None, str, str, str | None]]]:
    """Expand all `allow_attach` rules per concrete type: `(ftype, path, raw, channel_type)`."""
    per_type: dict[str, list[tuple[str | None, str, str, str | None]]] = {t: [] for t in policy.types}
    for rule in policy.attach_rules:
        for t in rule.types:
            for concrete_t, _ in policy.expand_subject(t, allow_default_rules=False):
                if concrete_t not in per_type:
                    continue
                for ap in rule.paths:
                    per_type[concrete_t].append((ap.ftype, ap.path, ap.raw, rule.channel_type))
    return per_type


def analyze_paths(
    policy: PolicyIR,
    *,
    ifs: IfsIR | None = None,
    sink_config: SinkConfig | None = None,
    from_type: str | None = None,
    to_type: str | None = None,
    max_depth: int = 6,
    max_paths_per_pair: int = 5,
) -> PathAnalysisResult:
    """Build the QNX security-policy graph and find all transitive privilege-escalation paths."""
    cfg = sink_config or SinkConfig()
    abilities_by_type = collect_type_abilities(policy)
    attaches_by_type = collect_type_attaches(policy)

    # Map IFS bindings per type (for inspector metadata)
    ifs_bindings: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if ifs is not None:
        for cmd in ifs.commands:
            if cmd.on_type:
                ifs_bindings[cmd.on_type].append(
                    {
                        "executable": cmd.executable,
                        "raw": cmd.raw,
                        "location": cmd.span.format_loc(),
                        "line": cmd.span.line,
                    }
                )

    # Classify sinks and collect reasons
    sink_reasons_by_type: dict[str, list[str]] = {}
    sink_keys_by_type: dict[str, set[str]] = {}
    for tname in sorted(policy.types):
        reasons: list[str] = []
        seen_r: set[str] = set()
        for spec, _ in abilities_by_type[tname]:
            is_priv, reason = is_privileged_ability(spec, cfg)
            if is_priv and reason and reason not in seen_r:
                seen_r.add(reason)
                reasons.append(reason)
        for ftype, path, _raw, _ct in attaches_by_type[tname]:
            is_priv, reason = _is_privileged_attach(ftype, path, cfg)
            if is_priv and reason and reason not in seen_r:
                seen_r.add(reason)
                reasons.append(reason)
        sink_reasons_by_type[tname] = reasons
        sink_keys_by_type[tname] = {_normalize_reason_key(r) for r in reasons}

    escalation_edges: list[GraphEdge] = []
    review_edges: list[GraphEdge] = []
    findings: list[Finding] = []

    # Track direct settypeid pairs `(src, dst)` to validate `derive_type`
    settypeid_pairs: set[tuple[str, str]] = set()
    seen_esc_keys: set[tuple[str, str, str, int]] = set()
    seen_rev_keys: set[tuple[str, str, str, int]] = set()

    # 1. Ability-based edges (`settypeid` = ESCALATION, `channel_connect` = REVIEW_ONLY)
    for rule in policy.ability_rules:
        for src in rule.sources:
            for concrete_src, via_attr in policy.expand_subject(src):
                if concrete_src not in policy.types:
                    continue
                for spec in rule.abilities:
                    if spec.name == "settypeid":
                        for target in spec.args:
                            for concrete_dst, _ in policy.expand_subject(target, allow_default_rules=False):
                                if concrete_dst not in policy.types:
                                    continue
                                settypeid_pairs.add((concrete_src, concrete_dst))
                                key = (concrete_src, concrete_dst, "settypeid", spec.span.line)
                                if key not in seen_esc_keys:
                                    seen_esc_keys.add(key)
                                    escalation_edges.append(
                                        GraphEdge(
                                            src=concrete_src,
                                            dst=concrete_dst,
                                            kind="ESCALATION",
                                            mechanism="settypeid",
                                            span=spec.span,
                                            raw=rule.raw,
                                            via_attribute=via_attr,
                                        )
                                    )
                    elif spec.name == "channel_connect":
                        for target in spec.args:
                            expanded_targets = (
                                [(concrete_src, None)]
                                if target == "self"
                                else policy.expand_subject(target, allow_default_rules=False)
                            )
                            for concrete_dst, _ in expanded_targets:
                                if concrete_dst not in policy.types:
                                    continue
                                key = (concrete_src, concrete_dst, "channel_connect", spec.span.line)
                                if key not in seen_rev_keys:
                                    seen_rev_keys.add(key)
                                    review_edges.append(
                                        GraphEdge(
                                            src=concrete_src,
                                            dst=concrete_dst,
                                            kind="REVIEW_ONLY",
                                            mechanism="channel_connect",
                                            span=spec.span,
                                            raw=rule.raw,
                                            via_attribute=via_attr,
                                        )
                                    )

    # 2. `derive_type` rules: ESCALATION edge if matching `settypeid`, else DANGLING_DERIVE_TYPE warning
    for drule in policy.derive_rules:
        src_list = policy.expand_subject(drule.src_type, allow_default_rules=False)
        dst_list = policy.expand_subject(drule.dst_type, allow_default_rules=False)
        for concrete_src, via_attr in src_list:
            for concrete_dst, _ in dst_list:
                if concrete_src not in policy.types or concrete_dst not in policy.types:
                    continue
                if (concrete_src, concrete_dst) in settypeid_pairs:
                    key = (concrete_src, concrete_dst, "derive_type", drule.span.line)
                    if key not in seen_esc_keys:
                        seen_esc_keys.add(key)
                        escalation_edges.append(
                            GraphEdge(
                                src=concrete_src,
                                dst=concrete_dst,
                                kind="ESCALATION",
                                mechanism="derive_type",
                                span=drule.span,
                                raw=drule.raw,
                                via_attribute=via_attr,
                            )
                        )
                else:
                    findings.append(
                        Finding(
                            rule_id="DANGLING_DERIVE_TYPE",
                            severity=Severity.WARNING,
                            message=(
                                f"derive_type '{concrete_src} {drule.name} {concrete_dst}' has no matching "
                                f"'settypeid:{concrete_dst}' ability on '{concrete_src}'"
                            ),
                            span=drule.span,
                            remediation=(
                                f"Either remove the unused derive_type rule or explicitly grant "
                                f"settypeid:{concrete_dst} if the transition is intentional."
                            ),
                            metadata={"src": concrete_src, "dst": concrete_dst, "name": drule.name},
                        )
                    )

    # 3. `default_spawn_type` rules: ESCALATION edge
    for srule in policy.default_spawn_rules:
        src_list = policy.expand_subject(srule.src_type, allow_default_rules=False)
        dst_list = policy.expand_subject(srule.dst_type, allow_default_rules=False)
        for concrete_src, via_attr in src_list:
            for concrete_dst, _ in dst_list:
                if concrete_src not in policy.types or concrete_dst not in policy.types:
                    continue
                key = (concrete_src, concrete_dst, "default_spawn_type", srule.span.line)
                if key not in seen_esc_keys:
                    seen_esc_keys.add(key)
                    escalation_edges.append(
                        GraphEdge(
                            src=concrete_src,
                            dst=concrete_dst,
                            kind="ESCALATION",
                            mechanism="default_spawn_type",
                            span=srule.span,
                            raw=srule.raw,
                            via_attribute=via_attr,
                        )
                    )

    # 4. `allow A B : channel connect;` -> REVIEW_ONLY edges (NEVER escalation)
    for crule in policy.connect_rules:
        for src in crule.sources:
            for concrete_src, via_attr in policy.expand_subject(src):
                if concrete_src not in policy.types:
                    continue
                for dst in crule.targets:
                    expanded_dsts = (
                        [(concrete_src, None)]
                        if dst == "self"
                        else policy.expand_subject(dst, allow_default_rules=False)
                    )
                    for concrete_dst, _ in expanded_dsts:
                        if concrete_dst not in policy.types:
                            continue
                        key = (concrete_src, concrete_dst, "channel_connect", crule.span.line)
                        if key not in seen_rev_keys:
                            seen_rev_keys.add(key)
                            review_edges.append(
                                GraphEdge(
                                    src=concrete_src,
                                    dst=concrete_dst,
                                    kind="REVIEW_ONLY",
                                    mechanism="channel_connect",
                                    span=crule.span,
                                    raw=crule.raw,
                                    via_attribute=via_attr,
                                )
                            )

    # 5. `allow_link` -> REVIEW_ONLY edges to types attaching matching paths
    for lrule in policy.link_rules:
        for t in lrule.types:
            for concrete_src, via_attr in policy.expand_subject(t, allow_default_rules=False):
                if concrete_src not in policy.types:
                    continue
                for lpath in lrule.paths:
                    for target_t, target_attaches in attaches_by_type.items():
                        if target_t == concrete_src:
                            continue
                        if any(_attach_matches_link(ap_raw, lpath) for _, _, ap_raw, _ in target_attaches):
                            key = (concrete_src, target_t, "allow_link", lrule.span.line)
                            if key not in seen_rev_keys:
                                seen_rev_keys.add(key)
                                review_edges.append(
                                    GraphEdge(
                                        src=concrete_src,
                                        dst=target_t,
                                        kind="REVIEW_ONLY",
                                        mechanism="allow_link",
                                        span=lrule.span,
                                        raw=lrule.raw,
                                        via_attribute=via_attr,
                                    )
                                )

    # Build adjacency list strictly from ESCALATION edges (ignoring self-loops!)
    # Deduplicate parallel edges between same (u, v) for path search while preserving determinism
    mech_priority = {"settypeid": 0, "default_spawn_type": 1, "derive_type": 2}
    best_edge: dict[tuple[str, str], GraphEdge] = {}
    for edge in escalation_edges:
        if edge.src == edge.dst:
            continue
        pair = (edge.src, edge.dst)
        if pair not in best_edge or mech_priority.get(edge.mechanism, 9) < mech_priority.get(
            best_edge[pair].mechanism, 9
        ):
            best_edge[pair] = edge

    adj: dict[str, list[GraphEdge]] = defaultdict(list)
    for (u, v), edge in sorted(best_edge.items()):
        adj[u].append(edge)

    # Discover shortest simple escalation paths via bounded BFS
    raw_paths: list[EscalationPath] = []
    sources_to_search = [from_type] if from_type is not None else sorted(policy.types)
    for src in sources_to_search:
        if src not in policy.types:
            continue
        src_keys = sink_keys_by_type.get(src, set())
        pair_counts: dict[tuple[str, str], int] = defaultdict(int)

        # Queue entries: (current_node, node_tuple, edge_tuple)
        queue: deque[tuple[str, tuple[str, ...], tuple[GraphEdge, ...]]] = deque()
        queue.append((src, (src,), ()))

        while queue:
            curr, nodes_so_far, edges_so_far = queue.popleft()
            depth = len(edges_so_far)
            if depth >= max_depth:
                continue

            for edge in adj.get(curr, []):
                nxt = edge.dst
                # Strict cycle & self-loop guard: never revisit any node already in current path
                if nxt in nodes_so_far:
                    continue

                new_nodes = nodes_so_far + (nxt,)
                new_edges = edges_so_far + (edge,)

                # Check if `nxt` is a genuine higher-privilege sink for `src`
                if to_type is None or nxt == to_type:
                    dst_reasons = sink_reasons_by_type.get(nxt, [])
                    dst_keys = sink_keys_by_type.get(nxt, set())
                    gained_keys = dst_keys - src_keys
                    if dst_reasons and gained_keys:
                        pair = (src, nxt)
                        if pair_counts[pair] < max_paths_per_pair:
                            pair_counts[pair] += 1
                            gained_reasons = tuple(
                                r for r in dst_reasons if _normalize_reason_key(r) in gained_keys
                            )
                            raw_paths.append(
                                EscalationPath(
                                    source=src,
                                    sink=nxt,
                                    nodes=new_nodes,
                                    edges=new_edges,
                                    sink_reasons=gained_reasons,
                                    hops=len(new_edges),
                                )
                            )

                # Continue exploring for longer chains through intermediate nodes
                if depth + 1 < max_depth:
                    queue.append((nxt, new_nodes, new_edges))

    # Suppress strict-suffix subpaths when doing global analysis (so `ivi_ui_t -> diag_helper_t -> can_hal_t`
    # is reported as 1 maximal escalation chain rather than double-counting `diag_helper_t -> can_hal_t`).
    if from_type is None:
        all_node_tuples = [p.nodes for p in raw_paths]
        escalation_paths: list[EscalationPath] = []
        for path in raw_paths:
            is_strict_suffix = False
            plen = len(path.nodes)
            for other in all_node_tuples:
                if len(other) > plen and other[-plen:] == path.nodes:
                    is_strict_suffix = True
                    break
            if not is_strict_suffix:
                escalation_paths.append(path)
    else:
        escalation_paths = raw_paths

    # Deterministic ordering: shortest chains first, then lexicographically by node sequence
    escalation_paths.sort(key=lambda p: (p.hops, p.nodes))

    # Emit ESCALATION_CHAIN findings
    escalation_sources = {p.source for p in escalation_paths}
    for ep in escalation_paths:
        first_edge = ep.edges[0]
        findings.append(
            Finding(
                rule_id="ESCALATION_CHAIN",
                severity=Severity.CRITICAL,
                message=(
                    f"{ep.hops}-hop privilege escalation chain: {ep.chain_str()} "
                    f"(gains {', '.join(ep.sink_reasons)})"
                ),
                span=first_edge.span,
                remediation=(
                    f"Break the transition chain by removing unneeded settypeid/default_spawn_type "
                    f"edges along {ep.chain_str()}."
                ),
                metadata={
                    "source": ep.source,
                    "sink": ep.sink,
                    "nodes": list(ep.nodes),
                    "hops": ep.hops,
                    "sink_reasons": list(ep.sink_reasons),
                },
            )
        )

    # Assemble rich node metadata for CLI / JSON / interactive HTML workbench
    nodes: dict[str, dict[str, Any]] = {}
    for tname, tdecl in sorted(policy.types.items()):
        s_reasons = sink_reasons_by_type.get(tname, [])
        is_sink = len(s_reasons) > 0
        zone = _classify_trust_zone(
            tname,
            is_sink=is_sink,
            is_escalation_source=tname in escalation_sources,
        )
        chains_involving = [p.chain_str() for p in escalation_paths if tname in p.nodes]
        nodes[tname] = {
            "name": tname,
            "trust_zone": zone,
            "attributes": list(tdecl.attributes),
            "location": tdecl.span.to_dict(),
            "abilities": [
                {
                    "canonical": spec.canonical(),
                    "name": spec.name,
                    "args": list(spec.args),
                    "modifiers": list(spec.modifiers),
                    "privileged": is_privileged_ability(spec, cfg)[0],
                    "unlocked": spec.has_unlock,
                    "via_attribute": via_attr,
                    "location": spec.span.format_loc(),
                }
                for spec, via_attr in abilities_by_type[tname]
            ],
            "attaches": [
                {"ftype": ftype, "path": path, "raw": raw, "channel_type": ct}
                for ftype, path, raw, ct in attaches_by_type[tname]
            ],
            "is_sink": is_sink,
            "sink_reasons": s_reasons,
            "ifs_bindings": ifs_bindings.get(tname, []),
            "escalation_chains": chains_involving,
        }

    return PathAnalysisResult(
        nodes=nodes,
        escalation_edges=escalation_edges,
        review_edges=review_edges,
        escalation_paths=escalation_paths,
        findings=findings,
    )
