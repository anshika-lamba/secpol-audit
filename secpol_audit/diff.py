"""Policy-to-policy privilege & escalation-chain diff gate (`secpol-audit diff`)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from secpol_audit.ir import PolicyIR
from secpol_audit.paths import analyze_paths, collect_type_abilities, is_privileged_ability


@dataclass
class PolicyDiffResult:
    """Structured diff between an old and new QNX 8.0 `.secpol` policy."""

    old_path: str
    new_path: str
    added_types: list[str] = field(default_factory=list)
    removed_types: list[str] = field(default_factory=list)
    added_abilities: list[dict[str, Any]] = field(default_factory=list)
    removed_abilities: list[dict[str, Any]] = field(default_factory=list)
    added_privileged_abilities: list[dict[str, Any]] = field(default_factory=list)
    added_escalation_edges: list[dict[str, Any]] = field(default_factory=list)
    removed_escalation_edges: list[dict[str, Any]] = field(default_factory=list)
    added_escalation_chains: list[dict[str, Any]] = field(default_factory=list)
    removed_escalation_chains: list[dict[str, Any]] = field(default_factory=list)
    old_chain_count: int = 0
    new_chain_count: int = 0

    @property
    def chain_delta(self) -> int:
        return self.new_chain_count - self.old_chain_count

    @property
    def has_privilege_expansion(self) -> bool:
        return bool(
            self.added_escalation_chains
            or self.added_privileged_abilities
            or self.added_escalation_edges
        )

    def chain_summary_line(self) -> str:
        delta = self.chain_delta
        noun = "escalation chain" if abs(delta) == 1 else "escalation chains"
        if delta > 0:
            sign = f"+{delta}"
        elif delta < 0:
            sign = f"{delta}"
        else:
            sign = "0"
        return f"{sign} {noun} ({self.new_chain_count} remaining)"

    def to_dict(self) -> dict[str, Any]:
        return {
            "old_policy": self.old_path,
            "new_policy": self.new_path,
            "has_privilege_expansion": self.has_privilege_expansion,
            "chain_summary": self.chain_summary_line(),
            "old_chain_count": self.old_chain_count,
            "new_chain_count": self.new_chain_count,
            "chain_delta": self.chain_delta,
            "added_types": self.added_types,
            "removed_types": self.removed_types,
            "added_abilities": self.added_abilities,
            "removed_abilities": self.removed_abilities,
            "added_privileged_abilities": self.added_privileged_abilities,
            "added_escalation_edges": self.added_escalation_edges,
            "removed_escalation_edges": self.removed_escalation_edges,
            "added_escalation_chains": self.added_escalation_chains,
            "removed_escalation_chains": self.removed_escalation_chains,
        }


def _collect_ability_set(policy: PolicyIR) -> dict[tuple[str, str], dict[str, Any]]:
    abilities_by_type = collect_type_abilities(policy)
    result: dict[tuple[str, str], dict[str, Any]] = {}
    for tname, specs in abilities_by_type.items():
        for spec, _via in specs:
            key = (tname, spec.canonical())
            if key not in result:
                is_priv, reason = is_privileged_ability(spec)
                result[key] = {
                    "type": tname,
                    "ability": spec.canonical(),
                    "privileged": is_priv,
                    "reason": reason,
                }
    return result


def diff_policies(old_policy: PolicyIR, new_policy: PolicyIR) -> PolicyDiffResult:
    """Compare two parsed QNX 8.0 policies and detect any privilege/escalation expansion."""
    old_types = set(old_policy.types.keys())
    new_types = set(new_policy.types.keys())

    old_ab = _collect_ability_set(old_policy)
    new_ab = _collect_ability_set(new_policy)

    added_ab = [new_ab[k] for k in sorted(set(new_ab) - set(old_ab))]
    removed_ab = [old_ab[k] for k in sorted(set(old_ab) - set(new_ab))]
    added_priv_ab = [item for item in added_ab if item["privileged"]]

    old_paths = analyze_paths(old_policy)
    new_paths = analyze_paths(new_policy)

    old_edge_map = {
        (e.src, e.dst, e.mechanism): {"src": e.src, "dst": e.dst, "mechanism": e.mechanism}
        for e in old_paths.escalation_edges
    }
    new_edge_map = {
        (e.src, e.dst, e.mechanism): {"src": e.src, "dst": e.dst, "mechanism": e.mechanism}
        for e in new_paths.escalation_edges
    }
    added_edges = [new_edge_map[k] for k in sorted(set(new_edge_map) - set(old_edge_map))]
    removed_edges = [old_edge_map[k] for k in sorted(set(old_edge_map) - set(new_edge_map))]

    old_chain_map = {p.nodes: p.to_dict() for p in old_paths.escalation_paths}
    new_chain_map = {p.nodes: p.to_dict() for p in new_paths.escalation_paths}
    added_chains = [new_chain_map[k] for k in sorted(set(new_chain_map) - set(old_chain_map))]
    removed_chains = [old_chain_map[k] for k in sorted(set(old_chain_map) - set(new_chain_map))]

    return PolicyDiffResult(
        old_path=old_policy.source_path,
        new_path=new_policy.source_path,
        added_types=sorted(new_types - old_types),
        removed_types=sorted(old_types - new_types),
        added_abilities=added_ab,
        removed_abilities=removed_ab,
        added_privileged_abilities=added_priv_ab,
        added_escalation_edges=added_edges,
        removed_escalation_edges=removed_edges,
        added_escalation_chains=added_chains,
        removed_escalation_chains=removed_chains,
        old_chain_count=len(old_paths.escalation_paths),
        new_chain_count=len(new_paths.escalation_paths),
    )
