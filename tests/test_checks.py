"""Unit tests for static `.secpol` and cross-file `build.ifs` checks."""

from __future__ import annotations

from pathlib import Path

import pytest

from secpol_audit.checks import run_all_checks, run_ifs_checks, run_policy_checks
from secpol_audit.ir import Severity
from secpol_audit.parser_ifs import parse_ifs_file, parse_ifs_text
from secpol_audit.parser_secpol import parse_secpol_file, parse_secpol_text

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_ifs_pre_secpolpush_untyped_and_undefined_type() -> None:
    pol = parse_secpol_text("type slogger2_t;\ntype valid_t;\n", "p.secpol")
    ifs = parse_ifs_text(
        """
        [+script] startup-script = {
            early_daemon &
            secpolpush /etc/secpol.bin
            on -T slogger2_t slogger2
            untyped_daemon &
            on -T typo_t my_svc &
        }
        """,
        "b.ifs",
    )
    findings = run_ifs_checks(ifs, pol)
    by_rule = {f.rule_id: f for f in findings}
    assert "PRE_SECPOLPUSH_LAUNCH" in by_rule
    assert by_rule["PRE_SECPOLPUSH_LAUNCH"].severity == Severity.HIGH
    assert "UNTYPED_IFS_SERVICE" in by_rule
    assert by_rule["UNTYPED_IFS_SERVICE"].severity == Severity.HIGH
    assert "UNDEFINED_IFS_TYPE" in by_rule
    assert by_rule["UNDEFINED_IFS_TYPE"].severity == Severity.ERROR


def test_ifs_missing_secpolpush_and_duplicate_secpolpush() -> None:
    pol = parse_secpol_text("type svc_t;\n", "p.secpol")
    ifs_missing = parse_ifs_text(
        """
        [+script] startup-script = {
            on -T svc_t my_svc &
        }
        """,
        "missing.ifs",
    )
    f_missing = run_ifs_checks(ifs_missing, pol)
    assert any(f.rule_id == "MISSING_SECPOLPUSH" and f.severity == Severity.CRITICAL for f in f_missing)

    ifs_dup = parse_ifs_text(
        """
        [+script] startup-script = {
            secpolpush /etc/secpol.bin
            on -T svc_t my_svc &
            secpolpush /etc/secpol2.bin
        }
        """,
        "dup.ifs",
    )
    f_dup = run_ifs_checks(ifs_dup, pol)
    assert any(f.rule_id == "DUPLICATE_SECPOLPUSH" and f.severity == Severity.WARNING for f in f_dup)


def test_unlocked_privileged_ability_and_wildcard_ftype_attach() -> None:
    pol = parse_secpol_text(
        """
        type drv_t;
        type cli_t;
        allow_attach drv_t *:/dev/raw_hw;
        allow cli_t drv_t : channel connect;
        allow drv_t self:ability {
            unlock mem_phys:0x1000-0x2000
            unlocked prot_exec
        };
        """,
        "priv.secpol",
    )
    findings = run_policy_checks(pol)
    rule_ids = [f.rule_id for f in findings]
    assert rule_ids.count("UNLOCKED_PRIVILEGED_ABILITY") == 2
    assert rule_ids.count("WILDCARD_FTYPE_ATTACH") == 1


def test_dangling_targets_undeclared_refs_and_unreachable_server() -> None:
    pol = parse_secpol_text(
        """
        type cli_t;
        type srv_no_attach_t;
        type orphan_srv_t;
        allow_attach orphan_srv_t /dev/orphan;
        allow cli_t ghost_t : channel connect;
        allow cli_t srv_no_attach_t : channel connect;
        allow cli_t self:ability { settypeid:nonexistent_t };
        allow unknown_src_t self:ability io;
        """,
        "dangling.secpol",
    )
    findings = run_policy_checks(pol)
    rules_and_sev = [(f.rule_id, f.severity) for f in findings]
    assert ("DANGLING_CONNECT_TARGET", Severity.ERROR) in rules_and_sev
    assert ("DANGLING_CONNECT_TARGET", Severity.WARNING) in rules_and_sev
    assert ("DANGLING_SETTYPEID_TARGET", Severity.ERROR) in rules_and_sev
    assert ("UNDECLARED_TYPE_REFERENCE", Severity.ERROR) in rules_and_sev
    assert ("UNREACHABLE_ATTACHED_SERVER", Severity.INFO) in rules_and_sev


def test_adas_12svc_vulnerable_vs_fixed_examples() -> None:
    vuln_pol = parse_secpol_file(REPO_ROOT / "examples/adas_12svc.secpol")
    vuln_ifs = parse_ifs_file(REPO_ROOT / "examples/adas_12svc.ifs")
    vuln_findings, vuln_paths = run_all_checks(vuln_pol, ifs=vuln_ifs)
    vuln_rules = {f.rule_id for f in vuln_findings}
    assert {
        "ESCALATION_CHAIN",
        "PRE_SECPOLPUSH_LAUNCH",
        "UNTYPED_IFS_SERVICE",
        "UNDEFINED_IFS_TYPE",
    }.issubset(vuln_rules)
    assert len(vuln_paths.escalation_paths) == 1
    assert vuln_paths.escalation_paths[0].chain_str() == "ivi_ui_t -> diag_helper_t -> can_hal_t"

    fixed_pol = parse_secpol_file(REPO_ROOT / "examples/adas_12svc_fixed.secpol")
    fixed_ifs = parse_ifs_file(REPO_ROOT / "examples/adas_12svc_fixed.ifs")
    fixed_findings, fixed_paths = run_all_checks(fixed_pol, ifs=fixed_ifs)
    assert fixed_findings == []
    assert fixed_paths.escalation_paths == []


def test_attach_channel_type_override_satisfies_reachability() -> None:
    pol = parse_secpol_text(
        """
        type drv_t;
        type chan_t;
        type cli_t;
        allow_attach drv_t /dev/custom chan_t;
        allow cli_t chan_t : channel connect;
        """,
        "chan_override.secpol",
    )
    findings = run_policy_checks(pol)
    assert not any(f.rule_id == "UNREACHABLE_ATTACHED_SERVER" for f in findings)
    assert not any(f.rule_id == "DANGLING_CONNECT_TARGET" for f in findings)


def test_all_qnx_demo_mutants_static_predictions() -> None:
    m0_f, m0_p = run_all_checks(parse_secpol_file(REPO_ROOT / "qnx_demo/mutants/M0_clean.secpol"))
    assert m0_f == []
    assert m0_p.escalation_paths == []

    m1_f, m1_p = run_all_checks(parse_secpol_file(REPO_ROOT / "qnx_demo/mutants/M1_no_connect.secpol"))
    assert m1_p.escalation_paths == []

    m2_f, _ = run_all_checks(
        parse_secpol_file(REPO_ROOT / "qnx_demo/mutants/M0_clean.secpol"),
        ifs=parse_ifs_file(REPO_ROOT / "qnx_demo/mutants/M2_untyped_server.ifs"),
    )
    assert any(f.rule_id == "UNTYPED_IFS_SERVICE" and f.metadata.get("executable") == "can_server" for f in m2_f)

    m3_f, m3_p = run_all_checks(parse_secpol_file(REPO_ROOT / "qnx_demo/mutants/M3_2hop_escalate.secpol"))
    assert len(m3_p.escalation_paths) == 1
    assert m3_p.escalation_paths[0].chain_str() == "ivi_ui_t -> diag_helper_t -> can_hal_t"

    m3_fixed_f, m3_fixed_p = run_all_checks(parse_secpol_file(REPO_ROOT / "qnx_demo/mutants/M3_fixed.secpol"))
    assert m3_fixed_f == []
    assert m3_fixed_p.escalation_paths == []

    # Verify all mutant .secpol files align with name_attach(NULL, "can_ctrl", 0) -> /dev/name/local/can_ctrl
    for name in ("M0_clean.secpol", "M1_no_connect.secpol", "M3_2hop_escalate.secpol", "M3_fixed.secpol"):
        pol = parse_secpol_file(REPO_ROOT / "qnx_demo/mutants" / name)
        can_attaches = [ap.path for r in pol.attach_rules if "can_hal_t" in r.types for ap in r.paths]
        assert "/dev/name/local/can_ctrl" in can_attaches
        assert any("can_hal_t" in r.sources and "self" in r.targets for r in pol.connect_rules)


def test_child_ability_inheritance_leak_flagged_and_mitigated() -> None:
    vuln = parse_secpol_text(
        """
        type spawner_t;
        type child_t;
        allow spawner_t self:ability {
            nonroot
            mem_phys:0xfe000000-0xfe010000
            io
            settypeid:child_t
        };
        """,
        "leak.secpol",
    )
    findings = run_policy_checks(vuln)
    leak_f = [f for f in findings if f.rule_id == "CHILD_ABILITY_INHERITANCE_LEAK"]
    assert len(leak_f) == 1
    assert leak_f[0].severity == Severity.HIGH
    assert leak_f[0].metadata["type"] == "spawner_t"
    assert any("mem_phys" in a for a in leak_f[0].metadata["leaked_abilities"])
    assert any("io" in a for a in leak_f[0].metadata["leaked_abilities"])

    # Mitigated with `noinherit` on privileged abilities -> 0 CHILD_ABILITY_INHERITANCE_LEAK
    mitigated_noinherit = parse_secpol_text(
        """
        type spawner_t;
        type child_t;
        allow spawner_t self:ability {
            nonroot
            noinherit mem_phys:0xfe000000-0xfe010000
            noinherit io
            settypeid:child_t
        };
        """,
        "noinherit.secpol",
    )
    assert not any(
        f.rule_id == "CHILD_ABILITY_INHERITANCE_LEAK"
        for f in run_policy_checks(mitigated_noinherit)
    )

    # Mitigated with `default_spawn_type` -> 0 CHILD_ABILITY_INHERITANCE_LEAK
    mitigated_dst = parse_secpol_text(
        """
        type spawner_t;
        type child_t;
        default_spawn_type spawner_t child_t;
        allow spawner_t self:ability {
            nonroot
            mem_phys:0xfe000000-0xfe010000
            spawn
        };
        """,
        "dst.secpol",
    )
    assert not any(
        f.rule_id == "CHILD_ABILITY_INHERITANCE_LEAK"
        for f in run_policy_checks(mitigated_dst)
    )


def test_child_ability_inheritance_leak_covers_spawn_and_unprivileged_ignored() -> None:
    pol = parse_secpol_text(
        """
        type mgr_t;
        type ui_t;
        type worker_t;
        allow mgr_t self:ability { nonroot mac_policy prot_exec spawn };
        allow ui_t self:ability { nonroot public_channel settypeid:worker_t };
        """,
        "spawn.secpol",
    )
    leak_f = [f for f in run_policy_checks(pol) if f.rule_id == "CHILD_ABILITY_INHERITANCE_LEAK"]
    assert len(leak_f) == 1
    assert leak_f[0].metadata["type"] == "mgr_t"


def test_root_service_without_uid_drop_detects_missing_and_uid0() -> None:
    pol = parse_secpol_text(
        """
        type svc_a_t;
        type svc_b_t;
        type svc_c_t;
        type suid_mgr_t;
        allow svc_a_t self:ability { nonroot public_channel };
        allow svc_b_t self:ability { nonroot public_channel };
        allow svc_c_t self:ability { nonroot public_channel };
        allow suid_mgr_t self:ability { setuid:0 };
        """,
        "uid.secpol",
    )
    ifs = parse_ifs_text(
        """
        [+script] startup-script = {
            secpolpush /etc/secpol.bin
            on -T svc_a_t svc_a &
            on -T svc_b_t -u 0:0 svc_b &
            on -T svc_c_t -u 25:25 svc_c &
            on -T suid_mgr_t suid_mgr &
        }
        """,
        "uid.ifs",
    )
    findings = run_ifs_checks(ifs, pol)
    uid_findings = [f for f in findings if f.rule_id == "ROOT_SERVICE_WITHOUT_UID_DROP"]
    flagged_types = {f.metadata["type"] for f in uid_findings}
    assert flagged_types == {"svc_a_t", "svc_b_t"}
    assert all(f.severity == Severity.HIGH for f in uid_findings)
    # svc_c_t drops to 25:25 and suid_mgr_t legitimately needs root setuid:0
    assert "svc_c_t" not in flagged_types
    assert "suid_mgr_t" not in flagged_types


def test_nonroot_mount_acl_mismatch_across_posix_octal_and_qnx_acl() -> None:
    pol = parse_secpol_text(
        """
        type srv_t;
        type cli_blocked_t;
        type cli_allowed_t;
        type link_blocked_t;
        mount_point 0:0 rwxr-x--- /dev/secret;
        mount_point 0:0 0700 /var/priv;
        mount_point 0:0 { u::rwx g::rx u:31:rx o::--- } /dev/acl_dir;
        allow_attach srv_t /dev/secret/ctrl;
        allow_attach srv_t /dev/acl_dir/pipe;
        allow cli_blocked_t srv_t : channel connect;
        allow cli_allowed_t srv_t : channel connect;
        allow_link link_blocked_t /var/priv/sock;
        """,
        "acl.secpol",
    )
    ifs = parse_ifs_text(
        """
        [+script] startup-script = {
            secpolpush /etc/secpol.bin
            on -T srv_t -u 0:0 srv &
            on -T cli_blocked_t -u 25:25 cli_blocked &
            on -T cli_allowed_t -u 31:31 cli_allowed &
            on -T link_blocked_t -u 29:29 link_blocked &
        }
        """,
        "acl.ifs",
    )
    findings = run_ifs_checks(ifs, pol)
    acl_f = [f for f in findings if f.rule_id == "NONROOT_MOUNT_ACL_MISMATCH"]
    pairs = {(f.metadata["type"], f.metadata["mount_path"]) for f in acl_f}
    # cli_blocked_t (uid 25) is denied on BOTH /dev/secret (rwxr-x---) and /dev/acl_dir (only u:31:rx)
    assert ("cli_blocked_t", "/dev/secret") in pairs
    assert ("cli_blocked_t", "/dev/acl_dir") in pairs
    # cli_allowed_t (uid 31) is ALLOWED on /dev/acl_dir (u:31:rx) but DENIED on /dev/secret
    assert ("cli_allowed_t", "/dev/acl_dir") not in pairs
    assert ("cli_allowed_t", "/dev/secret") in pairs
    # link_blocked_t (uid 29) is denied on /var/priv (0700)
    assert ("link_blocked_t", "/var/priv") in pairs
    assert all(f.severity == Severity.MEDIUM for f in acl_f)
    assert all("mount_point" in f.remediation for f in acl_f)


@pytest.mark.parametrize(
    "priv_ability",
    ["mem_phys", "io", "mac_policy", "prot_exec", "able_create", "setuid", "pathspace"],
)
def test_child_ability_inheritance_leak_all_seven_privileged_abilities(priv_ability: str) -> None:
    pol = parse_secpol_text(
        f"""
        type parent_t;
        type child_t;
        allow parent_t self:ability {{ nonroot {priv_ability} settypeid:child_t }};
        """,
        "all7.secpol",
    )
    leaks = [f for f in run_policy_checks(pol) if f.rule_id == "CHILD_ABILITY_INHERITANCE_LEAK"]
    assert len(leaks) == 1
    assert leaks[0].metadata["type"] == "parent_t"


def test_root_service_without_uid_drop_named_root_and_bare_zero() -> None:
    pol = parse_secpol_text("type a_t;\ntype b_t;\n", "root.secpol")
    ifs = parse_ifs_text(
        """
        [+script] startup-script = {
            secpolpush /etc/secpol.bin
            on -T a_t -u root:root svc_a &
            on -T b_t -u 0 svc_b &
        }
        """,
        "root.ifs",
    )
    flagged = {f.metadata["type"] for f in run_ifs_checks(ifs, pol) if f.rule_id == "ROOT_SERVICE_WITHOUT_UID_DROP"}
    assert flagged == {"a_t", "b_t"}


def test_nonroot_mount_acl_group_match_and_exact_path_denial() -> None:
    pol = parse_secpol_text(
        """
        type srv_t;
        type grp_ok_t;
        type other_denied_t;
        mount_point 0:20 0750 /dev/grp_only;
        mount_point 0:0 rwx------ /dev/exact_ctrl;
        allow_attach srv_t /dev/grp_only/chan;
        allow_attach srv_t /dev/exact_ctrl;
        allow grp_ok_t srv_t : channel connect;
        allow other_denied_t srv_t : channel connect;
        """,
        "grp_acl.secpol",
    )
    ifs = parse_ifs_text(
        """
        [+script] startup-script = {
            secpolpush /etc/secpol.bin
            on -T srv_t -u 0:0 srv &
            on -T grp_ok_t -u 99:20 grp_ok &
            on -T other_denied_t -u 99:99 other_denied &
        }
        """,
        "grp_acl.ifs",
    )
    pairs = {
        (f.metadata["type"], f.metadata["mount_path"])
        for f in run_ifs_checks(ifs, pol)
        if f.rule_id == "NONROOT_MOUNT_ACL_MISMATCH"
    }
    # grp_ok_t has gid=20 matching 0:20 (0750 -> rx) -> allowed on /dev/grp_only, denied on /dev/exact_ctrl
    assert ("grp_ok_t", "/dev/grp_only") not in pairs
    assert ("grp_ok_t", "/dev/exact_ctrl") in pairs
    # other_denied_t (gid=99) is denied on both
    assert ("other_denied_t", "/dev/grp_only") in pairs
    assert ("other_denied_t", "/dev/exact_ctrl") in pairs




