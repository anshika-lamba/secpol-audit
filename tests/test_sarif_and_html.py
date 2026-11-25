"""Unit tests for SARIF 2.1.0 serializer and offline self-contained HTML workbench."""

from __future__ import annotations

import json
from pathlib import Path
import re

from secpol_audit.checks import run_all_checks
from secpol_audit.compile_wrap import CompileResult
from secpol_audit.graph_html import render_html_report, render_svg_preview
from secpol_audit.parser_ifs import parse_ifs_file
from secpol_audit.parser_secpol import parse_secpol_file
from secpol_audit.sarif import findings_to_sarif, findings_to_sarif_json
import xml.etree.ElementTree as ET

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_sarif_2_1_0_schema_and_structure() -> None:
    pol = parse_secpol_file(REPO_ROOT / "examples/adas_12svc.secpol")
    ifs = parse_ifs_file(REPO_ROOT / "examples/adas_12svc.ifs")
    findings, _ = run_all_checks(pol, ifs=ifs)

    raw_json = findings_to_sarif_json(findings, default_uri="examples/adas_12svc.secpol")
    doc = json.loads(raw_json)

    assert doc["version"] == "2.1.0"
    assert "sarif-2.1.0" in doc["$schema"]
    assert len(doc["runs"]) == 1

    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "secpol-audit"
    assert len(run["tool"]["driver"]["rules"]) >= 4
    assert len(run["results"]) == len(findings)

    for result in run["results"]:
        assert result["ruleId"]
        assert result["level"] in {"error", "warning", "note"}
        assert result["message"]["text"]
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"]
        assert loc["region"]["startLine"] >= 1


def test_sarif_empty_findings_valid() -> None:
    doc = findings_to_sarif([], default_uri="clean.secpol")
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


def test_html_workbench_contains_chain_and_zero_external_cdn_refs() -> None:
    pol = parse_secpol_file(REPO_ROOT / "examples/adas_12svc.secpol")
    ifs = parse_ifs_file(REPO_ROOT / "examples/adas_12svc.ifs")
    findings, path_res = run_all_checks(pol, ifs=ifs)

    compile_res = CompileResult(
        status="skipped",
        binary=None,
        returncode=None,
        stdout="",
        stderr="",
        message="secpolcompile not installed",
    )
    html_doc = render_html_report(
        path_res,
        findings=findings,
        policy_path="examples/adas_12svc.secpol",
        ifs_path="examples/adas_12svc.ifs",
        compile_result=compile_res,
    )

    assert "<!DOCTYPE html>" in html_doc
    assert "ivi_ui_t -> diag_helper_t -> can_hal_t" in html_doc
    assert "toggle-review-edges" in html_doc
    assert "REVIEW-ONLY" in html_doc
    assert "ESCALATION" in html_doc
    assert "status-skipped" in html_doc

    # Strictly zero external CDN <script>, <link>, or http(s) references
    assert not re.search(r"<script[^>]+src\s*=", html_doc, re.IGNORECASE)
    assert not re.search(r"<link[^>]+href\s*=", html_doc, re.IGNORECASE)
    assert "http://" not in html_doc
    assert "https://" not in html_doc


def test_html_workbench_renders_clean_policy_without_chains() -> None:
    pol = parse_secpol_file(REPO_ROOT / "examples/adas_12svc_fixed.secpol")
    ifs = parse_ifs_file(REPO_ROOT / "examples/adas_12svc_fixed.ifs")
    findings, path_res = run_all_checks(pol, ifs=ifs)

    html_doc = render_html_report(
        path_res,
        findings=findings,
        policy_path="examples/adas_12svc_fixed.secpol",
        ifs_path="examples/adas_12svc_fixed.ifs",
    )
    assert "No transitive privilege escalation chains detected" in html_doc
    assert "Zero findings detected" in html_doc
    assert "http://" not in html_doc
    assert "https://" not in html_doc


def test_static_svg_preview_valid_xml_and_highlights_chain() -> None:
    pol = parse_secpol_file(REPO_ROOT / "examples/adas_12svc.secpol")
    ifs = parse_ifs_file(REPO_ROOT / "examples/adas_12svc.ifs")
    findings, path_res = run_all_checks(pol, ifs=ifs)

    svg_doc = render_svg_preview(
        path_res,
        findings=findings,
        policy_path="examples/adas_12svc.secpol",
        ifs_path="examples/adas_12svc.ifs",
    )
    root = ET.fromstring(svg_doc)
    text_content = " ".join(root.itertext())
    assert "ivi_ui_t -> diag_helper_t -> can_hal_t" in text_content
    assert "Hop 1: settypeid" in text_content
    assert "Hop 2: settypeid" in text_content
    assert "ESCALATION" in text_content
    assert "REVIEW-ONLY" in text_content

