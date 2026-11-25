"""Unit tests for static `.secpol` and cross-file `build.ifs` checks."""

from __future__ import annotations

from pathlib import Path

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


