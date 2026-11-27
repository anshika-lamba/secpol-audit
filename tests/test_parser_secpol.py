"""Unit tests for the fail-closed QNX 8.0 `.secpol` parser."""

from __future__ import annotations

from pathlib import Path

import pytest

from secpol_audit.ir import ParseDiagnostic
from secpol_audit.parser_secpol import parse_secpol_file, parse_secpol_text


def test_empty_and_comment_only_policy() -> None:
    ir_empty = parse_secpol_text("", "empty.secpol")
    assert len(ir_empty.types) == 0
    assert len(ir_empty.ability_rules) == 0

    ir_comments = parse_secpol_text("# comment 1\n   # comment 2\n\n", "comments.secpol")
    assert len(ir_comments.types) == 0
    assert len(ir_comments.attributes) == 0


def test_types_and_multiple_attributes() -> None:
    src = """
    attribute net_a;
    attribute drv_a;
    type can_hal_t, net_a, drv_a;
    type plain_t;
    """
    ir = parse_secpol_text(src, "types.secpol")
    assert set(ir.attributes.keys()) == {"net_a", "drv_a"}
    assert ir.types["can_hal_t"].attributes == ("net_a", "drv_a")
    assert ir.types["plain_t"].attributes == ()
    assert ir.types["can_hal_t"].span.line == 4
    assert ir.types["can_hal_t"].span.file == "types.secpol"


def test_inline_comments_inside_braces_and_whitespace_around_colon() -> None:
    src = """
    type a_t;
    type b_t;
    allow a_t b_t:channel connect;
    allow { a_t # inline comment
            b_t } b_t : channel connect;
    allow a_t self : ability {
        # comment inside ability block
        nonroot io # trailing inline comment
        mem_phys:0x1200000-0x24000000
        mem_phys:sysram
        setuid:0
        setuid:4,6,23
        setgid:10,20
        gain_priv:mem_phys,io,pathspace
        settypeid:a_t,b_t
        channel_connect:b_t
        noinherit able_create
        unlock prot_exec
        unlocked mac_policy
        procmgr_ability
    };
    """
    ir = parse_secpol_text(src, "complex.secpol")
    assert len(ir.connect_rules) == 2
    assert ir.connect_rules[1].sources == ("a_t", "b_t")
    assert len(ir.ability_rules) == 1
    specs = {s.name + (":" + s.raw_arg if s.raw_arg else ""): s for s in ir.ability_rules[0].abilities}
    assert specs["io"].modifiers == ("nonroot",)
    assert specs["mem_phys:0x1200000-0x24000000"].args == ("0x1200000-0x24000000",)
    assert specs["mem_phys:sysram"].args == ("sysram",)
    assert specs["setuid:4,6,23"].args == ("4", "6", "23")
    assert specs["gain_priv:mem_phys,io,pathspace"].args == ("mem_phys", "io", "pathspace")
    assert specs["settypeid:a_t,b_t"].args == ("a_t", "b_t")
    assert specs["able_create"].modifiers == ("noinherit",)
    assert specs["prot_exec"].has_unlock is True
    assert specs["mac_policy"].has_unlock is True


def test_single_ability_without_braces() -> None:
    src = """
    type t1;
    allow t1 self:ability io;
    allow t1 self:ability nonroot pathspace;
    """
    ir = parse_secpol_text(src, "single.secpol")
    assert len(ir.ability_rules) == 2
    assert ir.ability_rules[0].abilities[0].name == "io"
    assert ir.ability_rules[1].abilities[0].modifiers == ("nonroot",)
    assert ir.ability_rules[1].abilities[0].name == "pathspace"


def test_attach_link_derive_spawn_and_mount_point() -> None:
    src = """
    type drv_t;
    type cli_t;
    type chan_t;
    allow_attach drv_t { mount+:/system mount:/dev/fs *:/dev/foo /dev/io* /dev/sub/... } chan_t;
    allow_link { cli_t drv_t } { /dev/foo /system };
    derive_type cli_t helper_name drv_t;
    default_spawn_type cli_t drv_t;
    mount_point 0:0 { u::rwx g::rx o::rx } /dev;
    mount_point 0:0 0755 { /tmp /var/run };
    """
    ir = parse_secpol_text(src, "rules.secpol")
    assert len(ir.attach_rules) == 1
    assert ir.attach_rules[0].channel_type == "chan_t"
    ftypes = [(ap.ftype, ap.path) for ap in ir.attach_rules[0].paths]
    assert ftypes == [
        ("mount+", "/system"),
        ("mount", "/dev/fs"),
        ("*", "/dev/foo"),
        (None, "/dev/io*"),
        (None, "/dev/sub/..."),
    ]
    assert len(ir.link_rules) == 1
    assert ir.derive_rules[0].name == "helper_name"
    assert ir.default_spawn_rules[0].dst_type == "drv_t"
    assert len(ir.mount_point_rules) == 2
    assert ir.mount_point_rules[0].owner == "0:0"
    assert ir.mount_point_rules[1].paths == ("/tmp", "/var/run")


def test_default_rules_expansion_only_applies_to_types_with_allow() -> None:
    src = """
    type slogger2_t;
    type active_t;
    type idle_t;
    allow default_rules slogger2_t : channel connect;
    allow active_t self:ability io;
    """
    ir = parse_secpol_text(src, "default.secpol")
    active = ir.types_with_allow_rules()
    assert active == {"active_t"}
    expanded = [t for t, _ in ir.expand_subject("default_rules")]
    assert expanded == ["active_t"]
    assert "idle_t" not in expanded


def test_fail_closed_unknown_top_level_construct() -> None:
    src = "type a_t;\nallow_magic a_t b_t;\n"
    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_secpol_text(src, "bad.secpol")
    assert excinfo.value.code == "UNSUPPORTED_CONSTRUCT"
    assert excinfo.value.span.file == "bad.secpol"
    assert excinfo.value.span.line == 2
    assert excinfo.value.span.col == 1


def test_fail_closed_unsupported_allow_class() -> None:
    src = "type a_t;\ntype b_t;\nallow a_t b_t : file read;\n"
    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_secpol_text(src, "bad_class.secpol")
    assert excinfo.value.code == "UNSUPPORTED_CONSTRUCT"
    assert excinfo.value.span.line == 3


def test_fail_closed_unterminated_brace() -> None:
    src = "type a_t;\nallow a_t self:ability {\n  io\n"
    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_secpol_text(src, "unterm.secpol")
    assert excinfo.value.code == "PARSE_ERROR"
    assert "Unterminated" in excinfo.value.message


def test_fail_closed_missing_semicolon() -> None:
    src = "type a_t\ntype b_t;\n"
    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_secpol_text(src, "nosemi.secpol")
    assert excinfo.value.code == "PARSE_ERROR"


def test_fail_closed_duplicate_and_conflicting_declarations() -> None:
    with pytest.raises(ParseDiagnostic) as exc1:
        parse_secpol_text("type dup_t;\ntype dup_t;\n", "dup.secpol")
    assert exc1.value.code == "PARSE_ERROR"
    assert "Duplicate" in exc1.value.message

    with pytest.raises(ParseDiagnostic) as exc2:
        parse_secpol_text("attribute clash;\ntype clash;\n", "clash.secpol")
    assert exc2.value.code == "PARSE_ERROR"
    assert "Conflicting" in exc2.value.message


def test_fail_closed_malformed_ability_tokens() -> None:
    bad_cases = [
        "type a_t;\nallow a_t self:ability { settypeid: };\n",
        "type a_t;\nallow a_t self:ability { settypeid:a_t, };\n",
        "type a_t;\nallow a_t self:ability { unlock };\n",
        "type a_t;\nallow a_t self:ability { 123bad };\n",
        "type a_t;\nallow a_t self:ability { };\n",
        "type a_t;\nallow a_t self:ability { settypeid:a_t:b_t };\n",
    ]
    for case in bad_cases:
        with pytest.raises(ParseDiagnostic) as excinfo:
            parse_secpol_text(case, "malformed.secpol")
        assert excinfo.value.code == "PARSE_ERROR"


def test_fail_closed_missing_file() -> None:
    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_secpol_file("/nonexistent/path/missing.secpol")
    assert excinfo.value.code == "PARSE_ERROR"


def test_include_directive_resolves_relative_and_nested(tmp_path) -> None:
    sub = tmp_path / "inc"
    sub.mkdir()
    leaf = sub / "leaf.secpol"
    leaf.write_text(
        """
        type can_hal_t;
        allow_attach can_hal_t /dev/name/local/can_ctrl;
        allow can_hal_t self:ability {
            nonroot
            public_channel
            pathspace
            procmgr_ability
        };
        """,
        encoding="utf-8",
    )
    mid = tmp_path / "common.secpol"
    mid.write_text('include "inc/leaf.secpol";\ntype diag_helper_t;\n', encoding="utf-8")
    root = tmp_path / "main.secpol"
    root.write_text(
        """
        include "common.secpol";
        allow diag_helper_t can_hal_t : channel connect;
        """,
        encoding="utf-8",
    )

    ir = parse_secpol_file(root)
    assert set(ir.types.keys()) == {"can_hal_t", "diag_helper_t"}
    assert ir.types["can_hal_t"].span.file == str(leaf)
    ab_names = [spec.name for rule in ir.ability_rules for spec in rule.abilities]
    assert {"public_channel", "pathspace", "procmgr_ability"}.issubset(set(ab_names))


def test_include_circular_fails_closed(tmp_path) -> None:
    a = tmp_path / "a.secpol"
    b = tmp_path / "b.secpol"
    a.write_text('include "b.secpol";\n', encoding="utf-8")
    b.write_text('include "a.secpol";\n', encoding="utf-8")

    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_secpol_file(a)
    assert excinfo.value.code == "PARSE_ERROR"
    assert "Circular include" in excinfo.value.message

    self_inc = tmp_path / "self.secpol"
    self_inc.write_text('include "self.secpol";\n', encoding="utf-8")
    with pytest.raises(ParseDiagnostic) as exc2:
        parse_secpol_file(self_inc)
    assert exc2.value.code == "PARSE_ERROR"
    assert "Circular include" in exc2.value.message


def test_include_missing_file_fails_closed(tmp_path) -> None:
    root = tmp_path / "main.secpol"
    root.write_text('include "does_not_exist.secpol";\n', encoding="utf-8")
    with pytest.raises(ParseDiagnostic) as excinfo:
        parse_secpol_file(root)
    assert excinfo.value.code == "PARSE_ERROR"
    assert "not found" in excinfo.value.message


def test_qnx_sdp_common_abilities_public_channel_pathspace_procmgr() -> None:
    src = """
    type srv_t;
    allow srv_t self:ability {
        nonroot public_channel
        noinherit pathspace
        procmgr_ability
        procmgr_ability:custom_cap
    };
    """
    ir = parse_secpol_text(src, "sdp_abilities.secpol")
    specs = ir.ability_rules[0].abilities
    assert [(s.name, s.modifiers, s.args) for s in specs] == [
        ("public_channel", ("nonroot",), ()),
        ("pathspace", ("noinherit",), ()),
        ("procmgr_ability", (), ()),
        ("procmgr_ability", (), ("custom_cap",)),
    ]


def test_named_range_custom_ability_and_custom_class_declarations() -> None:
    src = """
    range gpu_mem;
    range dsp_sram;
    ability network/bind/privport;
    class ipc_bus { read write admin };

    type net_t;
    type gpu_t;
    type cli_t;

    allow net_t self:ability {
        nonroot network/bind/privport
    };
    allow gpu_t self:ability {
        mem_phys:gpu_mem
        mem_phys:0x10000000-0x10010000,dsp_sram
    };
    allow cli_t gpu_t : ipc_bus read;
    allow cli_t gpu_t : ipc_bus { read write };
    allow cli_t self:ability {
        settypeid:gpu_t
        gain_priv:ipc_bus:admin:gpu_t
        gain_priv:mem_phys,ipc_bus:write:gpu_t
    };
    """
    ir = parse_secpol_text(src, "qnx8_ext.secpol")
    assert set(ir.ranges.keys()) == {"gpu_mem", "dsp_sram"}
    assert set(ir.custom_abilities.keys()) == {"network/bind/privport"}
    assert "ipc_bus" in ir.classes
    assert ir.classes["ipc_bus"].permissions == ("read", "write", "admin")
    assert len(ir.class_rules) == 2
    assert ir.class_rules[0].permissions == ("read",)
    assert ir.class_rules[1].permissions == ("read", "write")

    # Verify mixed numeric + named ranges and gain_priv:class:perm:type parsed intact
    all_specs = [s for r in ir.ability_rules for s in r.abilities]
    mem_args = [s.args for s in all_specs if s.name == "mem_phys"]
    assert ("gpu_mem",) in mem_args
    assert ("0x10000000-0x10010000", "dsp_sram") in mem_args

    gp_args = [s.args for s in all_specs if s.name == "gain_priv"]
    assert ("ipc_bus:admin:gpu_t",) in gp_args
    assert ("mem_phys", "ipc_bus:write:gpu_t") in gp_args


def test_custom_class_and_gain_priv_fail_closed_validation() -> None:
    # Unknown permission for declared class -> PARSE_ERROR
    bad_perm = """
    class ipc_bus { read write };
    type a_t;
    type b_t;
    allow a_t b_t : ipc_bus delete;
    """
    with pytest.raises(ParseDiagnostic) as exc1:
        parse_secpol_text(bad_perm, "bad_perm.secpol")
    assert exc1.value.code == "PARSE_ERROR"

    # Duplicate range / ability / class declarations -> PARSE_ERROR
    with pytest.raises(ParseDiagnostic) as exc2:
        parse_secpol_text("range r1;\nrange r1;\n", "dup_range.secpol")
    assert exc2.value.code == "PARSE_ERROR"

    with pytest.raises(ParseDiagnostic) as exc3:
        parse_secpol_text("ability custom/a;\nability custom/a;\n", "dup_ab.secpol")
    assert exc3.value.code == "PARSE_ERROR"

    with pytest.raises(ParseDiagnostic) as exc4:
        parse_secpol_text("class c1 { r };\nclass c1 { r };\n", "dup_cls.secpol")
    assert exc4.value.code == "PARSE_ERROR"

    # Malformed gain_priv trailing or double colon -> PARSE_ERROR
    with pytest.raises(ParseDiagnostic) as exc5:
        parse_secpol_text("type a_t;\nallow a_t self:ability { gain_priv:cls::type };\n", "bad_gp.secpol")
    assert exc5.value.code == "PARSE_ERROR"

    # Truly unknown top-level keyword still fails closed with UNSUPPORTED_CONSTRUCT
    with pytest.raises(ParseDiagnostic) as exc6:
        parse_secpol_text("unknown_directive foo;\n", "bad_kw.secpol")
    assert exc6.value.code == "UNSUPPORTED_CONSTRUCT"


def test_real_stock_qnx8_secpolgenerate_policy_parses_with_zero_errors() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    gen_path = repo_root / "evidence/secpolgenerate/qnx8_generated.secpol"
    assert gen_path.is_file(), "Real stock QNX 8.0 qnx8_generated.secpol must exist"

    ir = parse_secpol_file(gen_path)
    assert {"can_hal_t", "pipe_t", "pipe_t__run", "random_t", "slogger2_t", "slogger2_t__run"}.issubset(
        set(ir.types.keys())
    )
    # Verify empty `allow default_rules self:ability {};` parsed cleanly
    assert any(r.sources == ("default_rules",) and r.abilities == () for r in ir.ability_rules)
    # Verify braced `allow_attach pipe_t { pipe:/ /dev/pipe };`
    pipe_attaches = [ap for r in ir.attach_rules if "pipe_t" in r.types for ap in r.paths]
    assert any(ap.ftype == "pipe" and ap.path == "/" for ap in pipe_attaches)
    assert any(ap.path == "/dev/pipe" for ap in pipe_attaches)
    # Verify `derive_type <src> run <dst>;` rules parsed cleanly
    derive_triples = {(d.src_type, d.name, d.dst_type) for d in ir.derive_rules}
    assert ("pipe_t", "run", "pipe_t__run") in derive_triples
    assert ("slogger2_t", "run", "slogger2_t__run") in derive_triples
    # Verify `channel_connect:slogger2_t` inside `random_t self:ability`
    random_abilities = [
        (s.name, s.args)
        for r in ir.ability_rules
        if "random_t" in r.sources
        for s in r.abilities
    ]
    assert ("channel_connect", ("slogger2_t",)) in random_abilities



