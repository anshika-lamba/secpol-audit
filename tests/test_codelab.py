"""Tests for Workstream B: Standalone QNX 8.0 Codelab & Starter Kit."""

from __future__ import annotations

from pathlib import Path

from secpol_audit.checks import run_all_checks
from secpol_audit.parser_secpol import parse_secpol_file

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_codelab_docs_and_steps_exist_with_zero_external_urls() -> None:
    md_path = REPO_ROOT / "codelab" / "README.md"
    html_path = REPO_ROOT / "docs" / "codelab" / "index.html"
    assert md_path.is_file()
    assert html_path.is_file()

    md_text = md_path.read_text(encoding="utf-8")
    html_text = html_path.read_text(encoding="utf-8")

    for step in ("Step 0", "Step 1", "Step 2", "Step 3", "Step 4", "Step 5", "Step 6", "Step 7"):
        assert step in md_text, f"Missing {step} in codelab/README.md"
        assert step in html_text, f"Missing {step} in docs/codelab/index.html"

    assert "http://" not in html_text
    assert "https://" not in html_text


def test_codelab_starter_policies_parse_and_validate() -> None:
    vuln = parse_secpol_file(REPO_ROOT / "codelab" / "starter" / "vulnerable.secpol")
    vuln_findings, vuln_paths = run_all_checks(vuln, include_paths=True)
    assert len(vuln_paths.escalation_paths) >= 1
    assert any(f.rule_id == "ESCALATION_CHAIN" for f in vuln_findings)

    fixed = parse_secpol_file(REPO_ROOT / "codelab" / "starter" / "fixed.secpol")
    fixed_findings, fixed_paths = run_all_checks(fixed, include_paths=True)
    assert len(fixed_paths.escalation_paths) == 0
    assert not any(f.severity.value in ("CRITICAL", "WARNING") for f in fixed_findings)

    chal = parse_secpol_file(REPO_ROOT / "codelab" / "starter" / "challenge.secpol")
    chal_findings, chal_paths = run_all_checks(chal, include_paths=True)
    assert len(chal_paths.escalation_paths) >= 1
    assert any(f.rule_id == "ESCALATION_CHAIN" for f in chal_findings)

    sol = parse_secpol_file(REPO_ROOT / "codelab" / "starter" / "challenge_solution.secpol")
    sol_findings, sol_paths = run_all_checks(sol, include_paths=True)
    assert len(sol_paths.escalation_paths) == 0
    assert not any(f.rule_id == "ESCALATION_CHAIN" for f in sol_findings)
