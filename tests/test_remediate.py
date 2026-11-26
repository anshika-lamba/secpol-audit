"""Tests for Edmonds-Karp weighted min-cut auto-remediation (`secpol_audit.remediate` + `fix` CLI)."""

from __future__ import annotations

import json
from pathlib import Path

from secpol_audit.checks import run_all_checks
from secpol_audit.cli import main
from secpol_audit.parser_secpol import parse_secpol_text
from secpol_audit.paths import analyze_paths
from secpol_audit.remediate import _edmonds_karp_min_cut, remediate_policy_text

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_edmonds_karp_min_cut_bottleneck_and_diamond() -> None:
    # Diamond graph where bottleneck edge (b -> d, cap 5) + (c -> d, cap 4) = 9 < (a->b 20 + a->c 20)
    caps = {
        ("S", "a"): 10**9,
        ("a", "b"): 20,
        ("a", "c"): 20,
        ("b", "d"): 5,
        ("c", "d"): 4,
        ("d", "T"): 10**9,
    }
    flow, cut = _edmonds_karp_min_cut(caps, "S", "T")
    assert flow == 9
    assert sorted(cut) == [("b", "d"), ("c", "d")]


def test_edmonds_karp_min_cut_disconnected_returns_zero() -> None:
    caps = {
        ("S", "a"): 10**9,
        ("b", "T"): 10**9,
    }
    flow, cut = _edmonds_karp_min_cut(caps, "S", "T")
    assert flow == 0
    assert cut == []


def test_remediate_adas_12svc_cuts_min_edge_and_preserves_review_edges() -> None:
    src_path = REPO_ROOT / "examples/adas_12svc.secpol"
    orig_text = src_path.read_text(encoding="utf-8")
    before_pol = parse_secpol_text(orig_text, str(src_path))
    before_paths = analyze_paths(before_pol)

    res = remediate_policy_text(orig_text, str(src_path))
    assert not res.already_clean
    assert res.before_chains == 1
    assert res.after_chains == 0
    assert [(c.source, c.target) for c in res.cut_edges] == [("diag_helper_t", "can_hal_t")]
    assert res.total_cut_weight == 10
    assert res.preserved_review_edges == len(before_paths.review_edges)
    # Channel connect review-only edge must remain untouched in fixed text
    assert "allow ivi_ui_t diag_helper_t : channel connect;" in res.fixed_text
    assert "settypeid:can_hal_t" not in res.fixed_text
    # Orphaned gain_priv entries must be pruned
    assert "gain_priv:mem_phys,io" not in res.fixed_text
    assert "gain_priv:pathspace,settypeid" not in res.fixed_text

    # Re-parse and verify 0 escalation chains remain
    after_pol = parse_secpol_text(res.fixed_text, str(src_path))
    after_findings, after_paths = run_all_checks(after_pol)
    assert after_paths.escalation_paths == []
    assert not any(f.rule_id == "ESCALATION_CHAIN" for f in after_findings)


def test_remediate_m3_2hop_escalate_achieves_zero_chains() -> None:
    src_path = REPO_ROOT / "qnx_demo/mutants/M3_2hop_escalate.secpol"
    orig_text = src_path.read_text(encoding="utf-8")

    res = remediate_policy_text(orig_text, str(src_path))
    assert res.before_chains == 1
    assert res.after_chains == 0
    assert [(c.source, c.target) for c in res.cut_edges] == [("diag_helper_t", "can_hal_t")]
    assert "allow ivi_ui_t diag_helper_t : channel connect;" in res.fixed_text
    assert "allow planner_t can_hal_t : channel connect;" in res.fixed_text
    assert "--- a/" in res.unified_diff
    assert "+++ b/" in res.unified_diff

    after_pol = parse_secpol_text(res.fixed_text, str(src_path))
    assert analyze_paths(after_pol).escalation_paths == []


def test_remediate_already_clean_policy_is_noop() -> None:
    src_path = REPO_ROOT / "examples/adas_12svc_fixed.secpol"
    orig_text = src_path.read_text(encoding="utf-8")

    res = remediate_policy_text(orig_text, str(src_path))
    assert res.already_clean is True
    assert res.before_chains == 0
    assert res.after_chains == 0
    assert res.cut_edges == []
    assert res.unified_diff == ""
    assert res.fixed_text == orig_text


def test_remediate_diamond_multi_path_disconnects_all_branches() -> None:
    policy_text = """
type ui_t;
type mid_a_t;
type mid_b_t;
type hal_t;

allow hal_t self:ability { nonroot mem_phys:0x1000-0x2000 };
allow mid_a_t self:ability { nonroot settypeid:hal_t };
allow mid_b_t self:ability { nonroot settypeid:hal_t };
allow ui_t self:ability { nonroot settypeid:mid_a_t,mid_b_t };
allow ui_t hal_t : channel connect;
"""
    res = remediate_policy_text(policy_text, "diamond.secpol")
    assert res.before_chains >= 2
    assert res.after_chains == 0
    cut_pairs = {(c.source, c.target) for c in res.cut_edges}
    assert cut_pairs == {("mid_a_t", "hal_t"), ("mid_b_t", "hal_t")}
    # REVIEW_ONLY channel connect edge MUST survive untouched
    assert "allow ui_t hal_t : channel connect;" in res.fixed_text


def test_remediate_multi_tier_sink_chain_resolves_iteratively() -> None:
    # low_t -> mid_priv_t (io) -> high_priv_t (io + mem_phys)
    policy_text = """
type low_t;
type mid_priv_t;
type high_priv_t;

allow high_priv_t self:ability { nonroot mem_phys:0x1000-0x2000 io };
allow mid_priv_t self:ability { nonroot io settypeid:high_priv_t };
allow low_t self:ability { nonroot settypeid:mid_priv_t };
"""
    res = remediate_policy_text(policy_text, "multitier.secpol")
    assert res.before_chains >= 1
    assert res.after_chains == 0
    cut_pairs = {(c.source, c.target) for c in res.cut_edges}
    assert ("mid_priv_t", "high_priv_t") in cut_pairs
    assert ("low_t", "mid_priv_t") in cut_pairs
    # mid_priv_t must still keep its own `io` ability
    after_pol = parse_secpol_text(res.fixed_text, "multitier.secpol")
    assert analyze_paths(after_pol).escalation_paths == []
    assert "io" in res.fixed_text


def test_remediate_derive_type_and_default_spawn_type_edges() -> None:
    policy_text = """
type ui_t;
type helper_t;
type hal_t;

allow hal_t self:ability { nonroot mac_policy };
default_spawn_type ui_t helper_t;
derive_type helper_t -t hal_t;
allow helper_t self:ability { nonroot settypeid:hal_t };
"""
    res = remediate_policy_text(policy_text, "derive.secpol")
    assert res.before_chains >= 1
    assert res.after_chains == 0
    assert "derive_type" not in res.fixed_text
    assert "settypeid:hal_t" not in res.fixed_text
    assert analyze_paths(parse_secpol_text(res.fixed_text, "derive.secpol")).escalation_paths == []


def test_remediate_preserves_unaffected_member_of_shared_attribute() -> None:
    policy_text = """
attribute helper_a;
type good_helper_t, helper_a;
type bad_helper_t, helper_a;
type sink_t;
type safe_t;

allow sink_t self:ability { nonroot mem_phys:0x1000-0x2000 };
allow helper_a self:ability { nonroot settypeid:safe_t };
allow bad_helper_t self:ability { nonroot settypeid:sink_t };
"""
    res = remediate_policy_text(policy_text, "attr_split.secpol")
    assert res.before_chains == 1
    assert res.after_chains == 0
    assert "settypeid:safe_t" in res.fixed_text
    assert "settypeid:sink_t" not in res.fixed_text


def test_remediate_splits_attribute_when_only_one_member_is_cut() -> None:
    policy_text = """
attribute grp_a;
type low_t, grp_a;
type already_priv_t, grp_a;
type sink_t;

allow sink_t self:ability { nonroot mem_phys:0x1000-0x2000 };
allow already_priv_t self:ability { nonroot mem_phys:0x1000-0x2000 };
allow grp_a self:ability { nonroot settypeid:sink_t };
"""
    res = remediate_policy_text(policy_text, "attr_member.secpol")
    assert res.before_chains == 1
    assert res.after_chains == 0
    # low_t loses settypeid:sink_t while already_priv_t (same privilege) keeps its rule
    after_pol = parse_secpol_text(res.fixed_text, "attr_member.secpol")
    assert analyze_paths(after_pol).escalation_paths == []


def test_remediate_never_cuts_review_only_channel_connect() -> None:
    policy_text = """
type ui_t;
type hal_t;

allow_attach hal_t /dev/can_ctrl;
allow hal_t self:ability { nonroot mem_phys:0x1000-0x2000 };
allow ui_t hal_t : channel connect;
"""
    res = remediate_policy_text(policy_text, "review_only.secpol")
    assert res.already_clean is True
    assert res.cut_edges == []
    assert res.preserved_review_edges == 1
    assert "allow ui_t hal_t : channel connect;" in res.fixed_text


def test_cli_fix_out_patch_json_and_error_exit_codes(tmp_path: Path, capsys) -> None:
    fixed_out = tmp_path / "adas_remediated.secpol"
    rc = main(
        [
            "fix",
            str(REPO_ROOT / "examples/adas_12svc.secpol"),
            "--ifs",
            str(REPO_ROOT / "examples/adas_12svc.ifs"),
            "--out",
            str(fixed_out),
            "--format",
            "json",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert payload["verified_zero_escalation"] is True
    assert payload["before_escalation_chains"] == 1
    assert payload["after_escalation_chains"] == 0
    assert fixed_out.is_file()
    assert analyze_paths(parse_secpol_text(fixed_out.read_text(encoding="utf-8"), str(fixed_out))).escalation_paths == []

    # --patch mode prints unified diff and exits 0
    rc_patch = main(["fix", str(REPO_ROOT / "qnx_demo/mutants/M3_2hop_escalate.secpol"), "--patch"])
    patch_out = capsys.readouterr().out
    assert rc_patch == 0
    assert "--- a/" in patch_out
    assert "-    settypeid:can_hal_t" in patch_out

    # Already-clean policy exits 0
    rc_clean = main(["fix", str(REPO_ROOT / "examples/adas_12svc_fixed.secpol")])
    clean_out = capsys.readouterr().out
    assert rc_clean == 0
    assert "ALREADY CLEAN" in clean_out

    # Parse error -> exit 2
    bad_pol = tmp_path / "bad.secpol"
    bad_pol.write_text("type broken_no_semi\n", encoding="utf-8")
    rc_bad = main(["fix", str(bad_pol)])
    assert rc_bad == 2

    # Missing file -> exit 2
    rc_missing = main(["fix", str(tmp_path / "does_not_exist.secpol")])
    assert rc_missing == 2


def test_remediate_idempotent_on_second_pass() -> None:
    src_path = REPO_ROOT / "examples/adas_12svc.secpol"
    first = remediate_policy_text(src_path.read_text(encoding="utf-8"), str(src_path))
    assert first.after_chains == 0
    second = remediate_policy_text(first.fixed_text, str(src_path))
    assert second.already_clean is True
    assert second.cut_edges == []
    assert second.unified_diff == ""


def test_remediate_m3_sentry_escalate_preserves_custom_sentry_class() -> None:
    src_path = REPO_ROOT / "qnx_demo/mutants/M3_sentry_escalate.secpol"
    res = remediate_policy_text(src_path.read_text(encoding="utf-8"), str(src_path))
    assert res.before_chains == 1
    assert res.after_chains == 0
    assert "class sentry { read_events };" in res.fixed_text
    assert "allow audit_reader_t secpol_sentry_t : sentry read_events;" in res.fixed_text
    assert "allow_attach secpol_sentry_t /dev/name/local/_tracelog;" in res.fixed_text


def test_remediate_partial_gain_priv_pruning_keeps_reachable_nonpriv_ability() -> None:
    policy_text = """
type ui_t;
type helper_t;
type hal_t;

allow hal_t self:ability { nonroot mem_phys:0x1000-0x2000 };
allow helper_t self:ability { nonroot public_channel settypeid:hal_t };
allow ui_t self:ability { nonroot settypeid:helper_t gain_priv:mem_phys,public_channel };
"""
    res = remediate_policy_text(policy_text, "partial_gp.secpol")
    assert res.after_chains == 0
    assert "mem_phys" not in res.fixed_text.split("allow ui_t")[1]
    assert "gain_priv:public_channel" in res.fixed_text

