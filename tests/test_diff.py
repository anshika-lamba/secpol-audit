"""Unit tests for policy-to-policy diff gate (`secpol-audit diff`)."""

from __future__ import annotations

from pathlib import Path

from secpol_audit.diff import diff_policies
from secpol_audit.parser_secpol import parse_secpol_file, parse_secpol_text

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_diff_adas_vulnerable_to_fixed_shrinks_privilege_surface() -> None:
    old = parse_secpol_file(REPO_ROOT / "examples/adas_12svc.secpol")
    new = parse_secpol_file(REPO_ROOT / "examples/adas_12svc_fixed.secpol")
    res = diff_policies(old, new)

    assert res.has_privilege_expansion is False
    assert res.old_chain_count == 1
    assert res.new_chain_count == 0
    assert res.chain_summary_line() == "-1 escalation chain (0 remaining)"
    assert len(res.removed_escalation_chains) == 1
    assert res.added_escalation_chains == []


def test_diff_m3_escalate_to_fixed_passes() -> None:
    old = parse_secpol_file(REPO_ROOT / "qnx_demo/mutants/M3_2hop_escalate.secpol")
    new = parse_secpol_file(REPO_ROOT / "qnx_demo/mutants/M3_fixed.secpol")
    res = diff_policies(old, new)

    assert res.has_privilege_expansion is False
    assert res.chain_summary_line() == "-1 escalation chain (0 remaining)"


def test_diff_detects_added_escalation_chain_as_expansion() -> None:
    old = parse_secpol_file(REPO_ROOT / "examples/adas_12svc_fixed.secpol")
    new = parse_secpol_file(REPO_ROOT / "examples/adas_12svc.secpol")
    res = diff_policies(old, new)

    assert res.has_privilege_expansion is True
    assert res.chain_summary_line() == "+1 escalation chain (1 remaining)"
    assert len(res.added_escalation_chains) == 1


def test_diff_detects_new_privileged_ability_without_new_chain() -> None:
    old = parse_secpol_text("type app_t;\nallow app_t self:ability able_create;\n", "old.secpol")
    new = parse_secpol_text(
        "type app_t;\nallow app_t self:ability { able_create mem_phys:sysram };\n",
        "new.secpol",
    )
    res = diff_policies(old, new)
    assert res.has_privilege_expansion is True
    assert len(res.added_privileged_abilities) == 1
    assert res.added_privileged_abilities[0]["type"] == "app_t"


def test_diff_detects_new_settypeid_edge_as_expansion() -> None:
    old = parse_secpol_text("type a_t;\ntype b_t;\n", "old.secpol")
    new = parse_secpol_text("type a_t;\ntype b_t;\nallow a_t self:ability settypeid:b_t;\n", "new.secpol")
    res = diff_policies(old, new)
    assert res.has_privilege_expansion is True
    assert len(res.added_escalation_edges) == 1


def test_diff_identical_policies_clean() -> None:
    pol = parse_secpol_file(REPO_ROOT / "examples/adas_12svc_fixed.secpol")
    res = diff_policies(pol, pol)
    assert res.has_privilege_expansion is False
    assert res.chain_summary_line() == "0 escalation chains (0 remaining)"
