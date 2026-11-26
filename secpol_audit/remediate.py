"""Weighted Minimum-Cut auto-remediation for QNX 8.0 security policies.

Computes a minimum-weight edge cut over the `ESCALATION` subgraph (`settypeid`,
`derive_type`, `default_spawn_type`) using pure-Python Edmonds-Karp max-flow /
min-cut so that every strictly lower-privilege ancestor is disconnected from
every privileged sink while preserving all `REVIEW_ONLY` (`channel connect`)
edges. Rewrites the `.secpol` text deterministically, prunes orphaned
`gain_priv` entries, and re-verifies that 0 escalation chains remain.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
import difflib
from typing import Any

from secpol_audit.ir import (
    AbilityRule,
    AbilitySpec,
    GraphEdge,
    IfsIR,
    PathAnalysisResult,
    PolicyIR,
    SourceSpan,
)
from secpol_audit.parser_secpol import parse_secpol_text
from secpol_audit.paths import (
    SinkConfig,
    analyze_paths,
    collect_type_abilities,
    is_privileged_ability,
)

# Edge capacity weights per QNX transition primitive (finite; REVIEW_ONLY edges
# are excluded from the flow network so they can never be cut).
EDGE_KIND_WEIGHTS: dict[str, int] = {
    "settypeid": 10,
    "default_spawn_type": 12,
    "derive_type": 15,
}
_INF_CAPACITY = 10**9


@dataclass(frozen=True)
class CutEdge:
    """One escalation edge selected by Edmonds-Karp minimum cut."""

    source: str
    target: str
    weight: int
    kinds: tuple[str, ...]
    via_attributes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "weight": self.weight,
            "kinds": list(self.kinds),
            "via_attributes": list(self.via_attributes),
        }


@dataclass(frozen=True)
class PrunedGainPriv:
    """An orphaned `gain_priv` ability entry pruned after cutting transitions."""

    subject: str
    removed_args: tuple[str, ...]
    kept_args: tuple[str, ...]
    location: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "removed_args": list(self.removed_args),
            "kept_args": list(self.kept_args),
            "location": self.location,
        }


@dataclass
class RemediationResult:
    """Structured output of `remediate_policy()`."""

    policy_path: str
    already_clean: bool
    before_chains: int
    after_chains: int
    before_chain_strs: list[str]
    after_chain_strs: list[str]
    total_cut_weight: int
    cut_edges: list[CutEdge] = field(default_factory=list)
    pruned_gain_priv: list[PrunedGainPriv] = field(default_factory=list)
    preserved_review_edges: int = 0
    original_text: str = ""
    fixed_text: str = ""
    unified_diff: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy": self.policy_path,
            "already_clean": self.already_clean,
            "verified_zero_escalation": self.after_chains == 0,
            "before_escalation_chains": self.before_chains,
            "after_escalation_chains": self.after_chains,
            "before_chains": self.before_chain_strs,
            "after_chains": self.after_chain_strs,
            "total_cut_weight": self.total_cut_weight,
            "cut_edges": [c.to_dict() for c in self.cut_edges],
            "pruned_gain_priv": [p.to_dict() for p in self.pruned_gain_priv],
            "preserved_review_edges": self.preserved_review_edges,
            "unified_diff": self.unified_diff,
        }


def _edmonds_karp_min_cut(
    capacities: dict[tuple[str, str], int],
    super_src: str,
    super_snk: str,
) -> tuple[int, list[tuple[str, str]]]:
    """Run Edmonds-Karp max-flow / min-cut and return `(max_flow, cut_edges)`.

    Deterministic BFS traversal (sorted neighbor order) guarantees reproducible
    minimum cuts across runs and Python versions.
    """
    residual: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    nodes: set[str] = {super_src, super_snk}
    for (u, v), cap in sorted(capacities.items()):
        if cap <= 0:
            continue
        residual[u][v] += cap
        # Ensure reverse residual entry exists
        _ = residual[v][u]
        nodes.add(u)
        nodes.add(v)

    total_flow = 0
    while True:
        # Shortest augmenting path via deterministic BFS
        parent: dict[str, str | None] = {super_src: None}
        queue: deque[str] = deque([super_src])
        found = False
        while queue and not found:
            cur = queue.popleft()
            for nxt in sorted(residual[cur].keys()):
                if nxt not in parent and residual[cur][nxt] > 0:
                    parent[nxt] = cur
                    if nxt == super_snk:
                        found = True
                        break
                    queue.append(nxt)
        if not found:
            break

        # Find bottleneck capacity along augmenting path
        bottleneck = _INF_CAPACITY
        v = super_snk
        while v != super_src:
            u = parent[v]
            assert u is not None
            bottleneck = min(bottleneck, residual[u][v])
            v = u

        # Update residual graph
        v = super_snk
        while v != super_src:
            u = parent[v]
            assert u is not None
            residual[u][v] -= bottleneck
            residual[v][u] += bottleneck
            v = u
        total_flow += bottleneck

    # Reachable set S from super_src in final residual graph
    reachable: set[str] = {super_src}
    queue = deque([super_src])
    while queue:
        cur = queue.popleft()
        for nxt in sorted(residual[cur].keys()):
            if nxt not in reachable and residual[cur][nxt] > 0:
                reachable.add(nxt)
                queue.append(nxt)

    # S-T cut edges: original finite-capacity edges crossing from S to V \ S
    cut_edges: list[tuple[str, str]] = []
    for (u, v), cap in sorted(capacities.items()):
        if cap <= 0 or cap >= _INF_CAPACITY:
            continue
        if u in reachable and v not in reachable:
            cut_edges.append((u, v))

    return total_flow, cut_edges


def _compute_privilege_sets(
    path_res: PathAnalysisResult,
) -> dict[str, set[str]]:
    """Map each concrete type to its semantic privilege capability set."""
    priv_sets: dict[str, set[str]] = {}
    for tname, node in path_res.nodes.items():
        caps: set[str] = set()
        for reason in node.get("sink_reasons", ()):
            if reason.startswith("ability:"):
                body = reason[len("ability:") :]
                toks = body.split()
                core = toks[-1] if toks else body
                name = core.split(":", 1)[0]
                caps.add("ability:setuid:0" if name == "setuid" else f"ability:{name}")
            else:
                caps.add(reason)
        priv_sets[tname] = caps
    return priv_sets


def _reachable_nodes(adj: dict[str, set[str]], start: str) -> set[str]:
    visited: set[str] = {start}
    q: deque[str] = deque([start])
    while q:
        cur = q.popleft()
        for nxt in adj.get(cur, ()):
            if nxt not in visited:
                visited.add(nxt)
                q.append(nxt)
    return visited


def compute_min_cut_edges(
    policy: PolicyIR,
    path_res: PathAnalysisResult,
) -> list[CutEdge]:
    """Compute minimum-weight escalation edges to disconnect all escalation chains.

    Only `ESCALATION` edges (`settypeid`, `derive_type`, `default_spawn_type`)
    enter the flow network. `REVIEW_ONLY` (`channel connect`) edges are never
    touched.

    To guarantee zero residual sub-chains (e.g., cutting `diag_helper_t -> can_hal_t`
    rather than only `ivi_ui_t -> diag_helper_t`), every non-sink node `x` that can
    reach a strictly higher-privilege sink `s` in the active sink tier is wired from
    `SUPER_SRC` with infinite capacity. Multi-tier sink chains (e.g. `low -> mid_priv -> high_priv`)
    are resolved iteratively without ever wiring the same node to both `SUPER_SRC` and `SUPER_SNK`.
    """
    if not path_res.escalation_paths:
        return []

    priv_sets = _compute_privilege_sets(path_res)

    # Group concrete escalation edges by (src, dst)
    edges_by_pair: dict[tuple[str, str], list[GraphEdge]] = defaultdict(list)
    for edge in path_res.escalation_edges:
        if edge.src != edge.dst:
            edges_by_pair[(edge.src, edge.dst)].append(edge)

    active_pairs: set[tuple[str, str]] = set(edges_by_pair.keys())
    chosen_pairs: list[tuple[str, str]] = []

    def _edge_weight(pair: tuple[str, str]) -> int:
        edge_list = edges_by_pair[pair]
        seen_mechs = sorted({e.mechanism for e in edge_list})
        base = sum(EDGE_KIND_WEIGHTS.get(m, 10) for m in seen_mechs)
        # Slightly prefer cutting direct concrete-type rules over shared attribute rules when tied
        if all(e.via_attribute is not None for e in edge_list):
            base += 1
        return base

    super_src = "__SUPER_SRC__"
    super_snk = "__SUPER_SNK__"

    # Iteratively disconnect maximal reachable sinks until 0 escalating pairs remain
    max_iters = len(active_pairs) + 1
    for _ in range(max_iters):
        adj: dict[str, set[str]] = defaultdict(set)
        for u, v in active_pairs:
            adj[u].add(v)

        # Find all escalating (ancestor, sink) pairs: ancestor reaches sink & gains strictly new privilege
        escalating_pairs: list[tuple[str, str]] = []
        sinks_with_ancestors: set[str] = set()
        for u in sorted(path_res.nodes.keys()):
            if u not in adj:
                continue
            reach = _reachable_nodes(adj, u)
            u_priv = priv_sets.get(u, set())
            for s in sorted(reach):
                if s == u:
                    continue
                s_priv = priv_sets.get(s, set())
                if s_priv and bool(s_priv - u_priv):
                    escalating_pairs.append((u, s))
                    sinks_with_ancestors.add(s)

        if not escalating_pairs:
            break

        # Maximal sink tier: sinks in `sinks_with_ancestors` that do NOT themselves
        # escalate to another higher-priv sink in `sinks_with_ancestors`.
        tier_sinks: set[str] = set()
        for s in sinks_with_ancestors:
            s_reach = _reachable_nodes(adj, s)
            s_priv = priv_sets.get(s, set())
            escalates_further = any(
                other != s and other in s_reach and bool(priv_sets.get(other, set()) - s_priv)
                for other in sinks_with_ancestors
            )
            if not escalates_further:
                tier_sinks.add(s)
        if not tier_sinks:
            # Cycle among equal-privilege sinks: break deterministically by highest privilege count
            best_len = max(len(priv_sets.get(s, set())) for s in sinks_with_ancestors)
            tier_sinks = {
                s for s in sinks_with_ancestors if len(priv_sets.get(s, set())) == best_len
            }

        # Every ancestor that can escalate to ANY sink in tier_sinks (strictly disjoint from tier_sinks)
        tier_sources: set[str] = {
            u for (u, s) in escalating_pairs if s in tier_sinks and u not in tier_sinks
        }
        if not tier_sources:
            # All remaining escalating pairs are within tier_sinks (mutual cycle) — pick lexicographically last as sink
            ordered_sinks = sorted(tier_sinks)
            tier_sinks = {ordered_sinks[-1]}
            tier_sources = {
                u for (u, s) in escalating_pairs if s in tier_sinks and u not in tier_sinks
            }
            if not tier_sources:
                break

        # Build Edmonds-Karp capacity map
        capacities: dict[tuple[str, str], int] = {}
        for u in sorted(tier_sources):
            capacities[(super_src, u)] = _INF_CAPACITY
        for s in sorted(tier_sinks):
            capacities[(s, super_snk)] = _INF_CAPACITY
        for u, v in sorted(active_pairs):
            capacities[(u, v)] = _edge_weight((u, v))

        _flow, cut = _edmonds_karp_min_cut(capacities, super_src, super_snk)
        if not cut:
            break
        for pair in cut:
            if pair in active_pairs:
                active_pairs.remove(pair)
                chosen_pairs.append(pair)

    # Deduplicate and wrap into CutEdge objects
    result: list[CutEdge] = []
    seen: set[tuple[str, str]] = set()
    for u, v in chosen_pairs:
        if (u, v) in seen:
            continue
        seen.add((u, v))
        edge_list = edges_by_pair[(u, v)]
        result.append(
            CutEdge(
                source=u,
                target=v,
                weight=_edge_weight((u, v)),
                kinds=tuple(sorted({e.mechanism for e in edge_list})),
                via_attributes=tuple(
                    sorted({e.via_attribute for e in edge_list if e.via_attribute is not None})
                ),
            )
        )
    result.sort(key=lambda c: (c.source, c.target))
    return result


# ---------------------------------------------------------------------------
# Surgical `.secpol` text rewriter
# ---------------------------------------------------------------------------


def _line_col_to_offset(text: str, line: int, col: int) -> int:
    """Convert 1-based `(line, col)` into a 0-based character offset in `text`."""
    lines = text.splitlines(keepends=True)
    if line <= 1:
        return max(0, col - 1)
    offset = sum(len(lines[i]) for i in range(min(line - 1, len(lines))))
    return min(len(text), offset + max(0, col - 1))


def _span_offsets(text: str, span: SourceSpan) -> tuple[int, int]:
    """Return `(start_offset, end_offset)` inclusive of trailing `;` and newline if full-line."""
    start = _line_col_to_offset(text, span.line, span.col)
    end = _line_col_to_offset(text, span.end_line, span.end_col)
    # Extend end to include the terminating semicolon if span stopped just before/on it
    while end < len(text) and text[end] in " \t":
        end += 1
    if end < len(text) and text[end] == ";":
        end += 1
    return start, end


def _format_ability_spec(spec: AbilitySpec, *, include_nonroot: bool = False) -> str:
    mods = [m for m in spec.modifiers if include_nonroot or m != "nonroot"]
    core = spec.name
    if spec.args:
        core = f"{core}:{','.join(spec.args)}"
    if mods:
        return f"{' '.join(mods)} {core}"
    return core


def _render_ability_rule(
    sources: list[str],
    specs: list[AbilitySpec],
    *,
    indent: str = "",
) -> str:
    """Render a valid QNX 8.0 `allow <src> self:ability ...;` rule."""
    if not specs:
        return ""
    src_str = sources[0] if len(sources) == 1 else "{ " + " ".join(sources) + " }"
    all_nonroot = all("nonroot" in s.modifiers for s in specs)
    if len(specs) == 1 and not all_nonroot:
        return f"{indent}allow {src_str} self:ability {_format_ability_spec(specs[0], include_nonroot=True)};"
    lines = [f"{indent}allow {src_str} self:ability {{"]
    if all_nonroot:
        lines.append(f"{indent}    nonroot")
    for spec in specs:
        lines.append(f"{indent}    {_format_ability_spec(spec, include_nonroot=not all_nonroot)}")
    lines.append(f"{indent}}};")
    return "\n".join(lines)


def _rewrite_ability_rule_for_cuts(
    policy: PolicyIR,
    rule: AbilityRule,
    cut_set: set[tuple[str, str]],
) -> tuple[bool, str]:
    """Return `(modified, replacement_text)` for `rule` after removing cut `settypeid` targets."""
    # Expand each subject in rule.sources to concrete types
    affected_any = False
    per_subject_replacements: list[str] = []

    for src in rule.sources:
        concrete_types = [c for c, _ in policy.expand_subject(src)]
        # Determine which concrete types under `src` have at least one cut target in this rule
        type_cut_targets: dict[str, set[str]] = {}
        for ct in concrete_types:
            cuts_for_ct: set[str] = set()
            for spec in rule.abilities:
                if spec.name == "settypeid":
                    for arg in spec.args:
                        for tgt, _ in policy.expand_subject(arg, allow_default_rules=False):
                            if (ct, tgt) in cut_set:
                                cuts_for_ct.add(tgt)
            if cuts_for_ct:
                type_cut_targets[ct] = cuts_for_ct

        if not type_cut_targets:
            # This subject was completely unaffected
            per_subject_replacements.append(_render_ability_rule([src], list(rule.abilities)))
            continue

        affected_any = True

        # Check if ALL concrete types under `src` share the exact same cut targets (common case: single type or whole attr)
        all_same = len(type_cut_targets) == len(concrete_types) and len(
            {frozenset(v) for v in type_cut_targets.values()}
        ) == 1

        if all_same:
            shared_cuts = next(iter(type_cut_targets.values()))
            new_specs = _strip_settypeid_targets(policy, rule.abilities, shared_cuts)
            if new_specs:
                per_subject_replacements.append(_render_ability_rule([src], new_specs))
        else:
            # Split attribute/multi-type rule so unaffected concrete types keep their original abilities
            for ct in concrete_types:
                ct_cuts = type_cut_targets.get(ct, set())
                new_specs = (
                    _strip_settypeid_targets(policy, rule.abilities, ct_cuts)
                    if ct_cuts
                    else list(rule.abilities)
                )
                if new_specs:
                    per_subject_replacements.append(_render_ability_rule([ct], new_specs))

    if not affected_any:
        return False, ""
    return True, "\n".join(r for r in per_subject_replacements if r)


def _strip_settypeid_targets(
    policy: PolicyIR,
    abilities: tuple[AbilitySpec, ...],
    targets_to_remove: set[str],
) -> list[AbilitySpec]:
    new_specs: list[AbilitySpec] = []
    for spec in abilities:
        if spec.name != "settypeid":
            new_specs.append(spec)
            continue
        remaining_args: list[str] = []
        for arg in spec.args:
            expanded = [t for t, _ in policy.expand_subject(arg, allow_default_rules=False)]
            kept = [t for t in expanded if t not in targets_to_remove]
            if len(kept) == len(expanded):
                remaining_args.append(arg)
            else:
                remaining_args.extend(kept)
        if remaining_args:
            raw_arg = ",".join(remaining_args)
            new_specs.append(
                AbilitySpec(
                    name=spec.name,
                    modifiers=spec.modifiers,
                    args=tuple(remaining_args),
                    raw_arg=raw_arg,
                    span=spec.span,
                    raw=f"{spec.name}:{raw_arg}",
                )
            )
    return new_specs


def _apply_span_replacements(
    text: str,
    replacements: list[tuple[int, int, str]],
) -> str:
    """Apply non-overlapping `(start, end, replacement)` edits from back to front."""
    updated = text
    for start, end, repl in sorted(replacements, key=lambda r: r[0], reverse=True):
        if repl == "":
            # If removing the entire statement leaves a blank line with only whitespace, consume its trailing newline
            line_start = updated.rfind("\n", 0, start) + 1
            prefix_only_ws = updated[line_start:start].strip() == ""
            if prefix_only_ws and end < len(updated) and updated[end] == "\n":
                updated = updated[:line_start] + updated[end + 1 :]
            else:
                updated = updated[:start] + updated[end:]
        else:
            updated = updated[:start] + repl + updated[end:]
    return updated


def _prune_orphaned_gain_priv(
    text: str,
    policy_path: str,
) -> tuple[str, list[PrunedGainPriv]]:
    """Prune `gain_priv` abilities that no longer correspond to any active transition target."""
    policy = parse_secpol_text(text, policy_path)
    path_res = analyze_paths(policy)
    abilities_by_type = collect_type_abilities(policy)

    # Build reachability over remaining ESCALATION edges
    adj: dict[str, set[str]] = defaultdict(set)
    for edge in path_res.escalation_edges:
        if edge.src != edge.dst:
            adj[edge.src].add(edge.dst)

    # Determine which ability names each type holds (excluding gain_priv itself)
    held_ability_names: dict[str, set[str]] = {}
    for tname, spec_list in abilities_by_type.items():
        held_ability_names[tname] = {s.name for s, _ in spec_list if s.name != "gain_priv"}
        # If target has channel connect rules, allow `channel_connect` in gain_priv
        for crule in policy.connect_rules:
            for src in crule.sources:
                if any(c == tname for c, _ in policy.expand_subject(src)):
                    held_ability_names[tname].add("channel_connect")

    replacements: list[tuple[int, int, str]] = []
    pruned_records: list[PrunedGainPriv] = []

    for rule in policy.ability_rules:
        if not any(spec.name == "gain_priv" for spec in rule.abilities):
            continue

        # Collect union of abilities held by any reachable transition target of any concrete subject in this rule
        reachable_target_abilities: set[str] = set()
        has_any_outgoing = False
        for src in rule.sources:
            for ct, _ in policy.expand_subject(src):
                reach = _reachable_nodes(adj, ct) - {ct}
                if reach:
                    has_any_outgoing = True
                    for tgt in reach:
                        reachable_target_abilities.update(held_ability_names.get(tgt, set()))

        new_specs: list[AbilitySpec] = []
        rule_changed = False
        for spec in rule.abilities:
            if spec.name != "gain_priv":
                new_specs.append(spec)
                continue
            if not has_any_outgoing:
                # No outgoing transitions remain -> entire gain_priv is orphaned
                rule_changed = True
                pruned_records.append(
                    PrunedGainPriv(
                        subject=",".join(rule.sources),
                        removed_args=spec.args or ("*",),
                        kept_args=(),
                        location=spec.span.format_loc(),
                    )
                )
                continue
            if not spec.args:
                new_specs.append(spec)
                continue
            kept = tuple(a for a in spec.args if a in reachable_target_abilities)
            removed = tuple(a for a in spec.args if a not in reachable_target_abilities)
            if removed:
                rule_changed = True
                pruned_records.append(
                    PrunedGainPriv(
                        subject=",".join(rule.sources),
                        removed_args=removed,
                        kept_args=kept,
                        location=spec.span.format_loc(),
                    )
                )
                if kept:
                    raw_arg = ",".join(kept)
                    new_specs.append(
                        AbilitySpec(
                            name=spec.name,
                            modifiers=spec.modifiers,
                            args=kept,
                            raw_arg=raw_arg,
                            span=spec.span,
                            raw=f"{spec.name}:{raw_arg}",
                        )
                    )
            else:
                new_specs.append(spec)

        if rule_changed:
            start, end = _span_offsets(text, rule.span)
            repl = _render_ability_rule(list(rule.sources), new_specs) if new_specs else ""
            replacements.append((start, end, repl))

    if not replacements:
        return text, []
    return _apply_span_replacements(text, replacements), pruned_records


def remediate_policy_text(
    text: str,
    policy_path: str = "<memory>",
    *,
    ifs: IfsIR | None = None,
    config: SinkConfig | None = None,
) -> RemediationResult:
    """Compute a minimum-cut remediation of `.secpol` text and verify 0 escalation chains."""
    policy = parse_secpol_text(text, policy_path)
    before_paths = analyze_paths(policy, ifs=ifs, sink_config=config)
    before_chains = [p.chain_str() for p in before_paths.escalation_paths]

    if not before_paths.escalation_paths:
        return RemediationResult(
            policy_path=policy_path,
            already_clean=True,
            before_chains=0,
            after_chains=0,
            before_chain_strs=[],
            after_chain_strs=[],
            total_cut_weight=0,
            cut_edges=[],
            pruned_gain_priv=[],
            preserved_review_edges=len(before_paths.review_edges),
            original_text=text,
            fixed_text=text,
            unified_diff="",
        )

    cut_edges = compute_min_cut_edges(policy, before_paths)
    cut_set = {(c.source, c.target) for c in cut_edges}

    replacements: list[tuple[int, int, str]] = []

    # 1. Rewrite `settypeid` ability rules
    for arule in policy.ability_rules:
        modified, repl = _rewrite_ability_rule_for_cuts(policy, arule, cut_set)
        if modified:
            start, end = _span_offsets(text, arule.span)
            replacements.append((start, end, repl))

    # 2. Remove `derive_type` rules matching cut edges
    for drule in policy.derive_rules:
        srcs = [c for c, _ in policy.expand_subject(drule.src_type, allow_default_rules=False)]
        tgts = [c for c, _ in policy.expand_subject(drule.dst_type, allow_default_rules=False)]
        if any((s, t) in cut_set for s in srcs for t in tgts):
            start, end = _span_offsets(text, drule.span)
            replacements.append((start, end, ""))

    # 3. Remove `default_spawn_type` rules matching cut edges
    for srule in policy.default_spawn_rules:
        srcs = [c for c, _ in policy.expand_subject(srule.src_type, allow_default_rules=False)]
        tgts = [c for c, _ in policy.expand_subject(srule.dst_type, allow_default_rules=False)]
        if any((s, t) in cut_set for s in srcs for t in tgts):
            start, end = _span_offsets(text, srule.span)
            replacements.append((start, end, ""))

    rewritten = _apply_span_replacements(text, replacements)

    # 4. Prune orphaned `gain_priv` entries that now have no active transition target
    rewritten, pruned = _prune_orphaned_gain_priv(rewritten, policy_path)

    # 5. Re-parse and verify 0 escalation chains remain (if an edge case left a residual chain,
    # iterate once more on the rewritten policy to guarantee soundness)
    after_policy = parse_secpol_text(rewritten, policy_path)
    after_paths = analyze_paths(after_policy, ifs=ifs, sink_config=config)

    guard = 0
    while after_paths.escalation_paths and guard < 8:
        guard += 1
        extra_cuts = compute_min_cut_edges(after_policy, after_paths)
        if not extra_cuts:
            break
        cut_edges.extend(extra_cuts)
        extra_set = {(c.source, c.target) for c in extra_cuts}
        extra_repls: list[tuple[int, int, str]] = []
        for arule in after_policy.ability_rules:
            modified, repl = _rewrite_ability_rule_for_cuts(after_policy, arule, extra_set)
            if modified:
                start, end = _span_offsets(rewritten, arule.span)
                extra_repls.append((start, end, repl))
        for drule in after_policy.derive_rules:
            srcs = [c for c, _ in after_policy.expand_subject(drule.src_type, allow_default_rules=False)]
            tgts = [c for c, _ in after_policy.expand_subject(drule.dst_type, allow_default_rules=False)]
            if any((s, t) in extra_set for s in srcs for t in tgts):
                start, end = _span_offsets(rewritten, drule.span)
                extra_repls.append((start, end, ""))
        for srule in after_policy.default_spawn_rules:
            srcs = [c for c, _ in after_policy.expand_subject(srule.src_type, allow_default_rules=False)]
            tgts = [c for c, _ in after_policy.expand_subject(srule.dst_type, allow_default_rules=False)]
            if any((s, t) in extra_set for s in srcs for t in tgts):
                start, end = _span_offsets(rewritten, srule.span)
                extra_repls.append((start, end, ""))
        if not extra_repls:
            break
        rewritten = _apply_span_replacements(rewritten, extra_repls)
        rewritten, extra_pruned = _prune_orphaned_gain_priv(rewritten, policy_path)
        pruned.extend(extra_pruned)
        after_policy = parse_secpol_text(rewritten, policy_path)
        after_paths = analyze_paths(after_policy, ifs=ifs, sink_config=config)

    # Deduplicate cut_edges cleanly
    dedup_cuts: dict[tuple[str, str], CutEdge] = {}
    for c in cut_edges:
        dedup_cuts[(c.source, c.target)] = c
    final_cuts = sorted(dedup_cuts.values(), key=lambda c: (c.source, c.target))

    diff_lines = list(
        difflib.unified_diff(
            text.splitlines(keepends=True),
            rewritten.splitlines(keepends=True),
            fromfile=f"a/{policy_path}",
            tofile=f"b/{policy_path}",
        )
    )
    unified_diff = "".join(diff_lines)

    return RemediationResult(
        policy_path=policy_path,
        already_clean=False,
        before_chains=len(before_paths.escalation_paths),
        after_chains=len(after_paths.escalation_paths),
        before_chain_strs=before_chains,
        after_chain_strs=[p.chain_str() for p in after_paths.escalation_paths],
        total_cut_weight=sum(c.weight for c in final_cuts),
        cut_edges=final_cuts,
        pruned_gain_priv=pruned,
        preserved_review_edges=len(after_paths.review_edges),
        original_text=text,
        fixed_text=rewritten,
        unified_diff=unified_diff,
    )
