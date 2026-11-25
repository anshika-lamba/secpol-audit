"""Unit tests for the transitive privilege-escalation graph & path engine."""

from __future__ import annotations

from secpol_audit.parser_secpol import parse_secpol_text
from secpol_audit.paths import analyze_paths


def test_two_hop_transitive_escalation() -> None:
    pol = parse_secpol_text(
        """
        type ivi_ui_t;
        type diag_helper_t;
        type can_hal_t;
        allow ivi_ui_t self:ability { settypeid:diag_helper_t };
        allow diag_helper_t self:ability { settypeid:can_hal_t };
        allow can_hal_t self:ability { mem_phys:0xfe000000-0xfe010000 io };
        """,
        "two_hop.secpol",
    )
    res = analyze_paths(pol)
    assert len(res.escalation_paths) == 1
    ep = res.escalation_paths[0]
    assert ep.nodes == ("ivi_ui_t", "diag_helper_t", "can_hal_t")
    assert ep.hops == 2
    assert any("mem_phys" in r for r in ep.sink_reasons)
    assert any("io" in r for r in ep.sink_reasons)


def test_three_hop_transitive_escalation() -> None:
    pol = parse_secpol_text(
        """
        type t0;
        type t1;
        type t2;
        type t3;
        allow t0 self:ability settypeid:t1;
        allow t1 self:ability settypeid:t2;
        allow t2 self:ability settypeid:t3;
        allow t3 self:ability mac_policy;
        """,
        "three_hop.secpol",
    )
    res = analyze_paths(pol)
    assert len(res.escalation_paths) == 1
    assert res.escalation_paths[0].nodes == ("t0", "t1", "t2", "t3")
    assert res.escalation_paths[0].hops == 3


def test_cycles_terminate_cleanly_without_infinite_loop() -> None:
    pol = parse_secpol_text(
        """
        type a_t;
        type b_t;
        type c_t;
        allow a_t self:ability settypeid:b_t;
        allow b_t self:ability settypeid:c_t;
        allow c_t self:ability { settypeid:a_t mem_phys:sysram };
        """,
        "cycle.secpol",
    )
    res = analyze_paths(pol)
    assert len(res.escalation_paths) == 1
    assert res.escalation_paths[0].nodes == ("a_t", "b_t", "c_t")

    # Pure unprivileged cycle with no sink -> 0 escalation chains, no hang
    pol_no_sink = parse_secpol_text(
        """
        type x_t;
        type y_t;
        allow x_t self:ability settypeid:y_t;
        allow y_t self:ability settypeid:x_t;
        """,
        "cycle_nosink.secpol",
    )
    res2 = analyze_paths(pol_no_sink)
    assert res2.escalation_paths == []


def test_self_loop_never_produces_false_positive() -> None:
    pol = parse_secpol_text(
        """
        type a_t;
        allow a_t self:ability {
            settypeid:a_t
            mem_phys:sysram
            io
        };
        """,
        "self_loop.secpol",
    )
    res = analyze_paths(pol)
    assert res.escalation_paths == []


def test_attribute_mediated_escalation_chain() -> None:
    pol = parse_secpol_text(
        """
        attribute ui_grp;
        type a_t, ui_grp;
        type b_t;
        allow ui_grp self:ability { settypeid:b_t };
        allow b_t self:ability { setuid:0 };
        """,
        "attr_chain.secpol",
    )
    res = analyze_paths(pol)
    assert len(res.escalation_paths) == 1
    ep = res.escalation_paths[0]
    assert ep.nodes == ("a_t", "b_t")
    assert ep.edges[0].via_attribute == "ui_grp"


def test_diamond_graph_reports_both_distinct_simple_paths() -> None:
    pol = parse_secpol_text(
        """
        type a_t;
        type b_t;
        type c_t;
        type d_t;
        allow a_t self:ability { settypeid:b_t,c_t };
        allow b_t self:ability { settypeid:d_t };
        allow c_t self:ability { settypeid:d_t };
        allow d_t self:ability { prot_exec };
        """,
        "diamond.secpol",
    )
    res = analyze_paths(pol)
    chains = {p.nodes for p in res.escalation_paths}
    assert chains == {("a_t", "b_t", "d_t"), ("a_t", "c_t", "d_t")}


def test_review_only_channel_connect_and_allow_link_never_escalate() -> None:
    pol = parse_secpol_text(
        """
        type ivi_t;
        type can_t;
        allow_attach can_t /dev/can_ctrl;
        allow can_t self:ability { mem_phys:sysram io };
        allow ivi_t can_t : channel connect;
        allow ivi_t self:ability { channel_connect:can_t };
        allow_link ivi_t /dev/can_ctrl;
        """,
        "review_only.secpol",
    )
    res = analyze_paths(pol)
    assert res.escalation_edges == []
    assert res.escalation_paths == []
    assert len(res.review_edges) >= 2
    assert all(e.kind == "REVIEW_ONLY" for e in res.review_edges)
    mechs = {e.mechanism for e in res.review_edges}
    assert {"channel_connect", "allow_link"}.issubset(mechs)


def test_derive_type_and_default_spawn_type_edges_and_dangling_derive() -> None:
    pol = parse_secpol_text(
        """
        type a_t;
        type b_t;
        type c_t;
        type d_t;
        allow a_t self:ability { settypeid:b_t };
        derive_type a_t helper b_t;
        default_spawn_type b_t c_t;
        derive_type d_t stale c_t;
        allow c_t self:ability { pathspace };
        """,
        "transitions.secpol",
    )
    res = analyze_paths(pol)
    assert any(p.nodes == ("a_t", "b_t", "c_t") for p in res.escalation_paths)
    # `derive_type d_t stale c_t` lacks `settypeid:c_t` -> DANGLING_DERIVE_TYPE warning, NOT an escalation path
    assert not any(p.source == "d_t" for p in res.escalation_paths)
    assert any(f.rule_id == "DANGLING_DERIVE_TYPE" for f in res.findings)


def test_from_and_to_filters() -> None:
    pol = parse_secpol_text(
        """
        type ivi_ui_t;
        type diag_helper_t;
        type can_hal_t;
        allow ivi_ui_t self:ability settypeid:diag_helper_t;
        allow diag_helper_t self:ability settypeid:can_hal_t;
        allow can_hal_t self:ability io;
        """,
        "filter.secpol",
    )
    res = analyze_paths(pol, from_type="diag_helper_t", to_type="can_hal_t")
    assert len(res.escalation_paths) == 1
    assert res.escalation_paths[0].nodes == ("diag_helper_t", "can_hal_t")


def test_sink_classification_via_attach_path() -> None:
    pol = parse_secpol_text(
        """
        type low_t;
        type can_t;
        allow low_t self:ability settypeid:can_t;
        allow_attach can_t /dev/can_ctrl;
        """,
        "attach_sink.secpol",
    )
    res = analyze_paths(pol)
    assert len(res.escalation_paths) == 1
    assert res.escalation_paths[0].sink_reasons == ("attach:/dev/can_ctrl",)


def test_setuid_nonroot_is_not_root_sink_while_setuid_0_and_gain_priv_are() -> None:
    pol = parse_secpol_text(
        """
        type low_t;
        type nonroot_t;
        type root_t;
        type gp_t;
        allow low_t self:ability { settypeid:nonroot_t,root_t,gp_t };
        allow nonroot_t self:ability { setuid:4,6,23 };
        allow root_t self:ability { setuid:0 };
        allow gp_t self:ability { gain_priv:mem_phys,io };
        """,
        "setuid.secpol",
    )
    res = analyze_paths(pol)
    sinks = {p.sink for p in res.escalation_paths}
    assert "nonroot_t" not in sinks
    assert sinks == {"root_t", "gp_t"}


def test_equal_privilege_transition_not_reported_as_escalation() -> None:
    pol = parse_secpol_text(
        """
        type peer1_t;
        type peer2_t;
        allow peer1_t self:ability { io settypeid:peer2_t };
        allow peer2_t self:ability { io };
        """,
        "equal_priv.secpol",
    )
    res = analyze_paths(pol)
    assert res.escalation_paths == []

