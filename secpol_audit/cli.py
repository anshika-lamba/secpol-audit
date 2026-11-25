"""Command-line interface for `secpol-audit`."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from secpol_audit import __version__
from secpol_audit.checks import run_all_checks
from secpol_audit.compile_wrap import CompileResult, run_secpolcompile
from secpol_audit.diff import PolicyDiffResult, diff_policies
from secpol_audit.graph_html import render_html_report, render_svg_preview
from secpol_audit.ir import Finding, ParseDiagnostic
from secpol_audit.parser_ifs import parse_ifs_file
from secpol_audit.parser_secpol import parse_secpol_file
from secpol_audit.paths import analyze_paths
from secpol_audit.runtime import parse_pidin_file, verify_runtime
from secpol_audit.sarif import findings_to_sarif_json


def _write_output(text: str, output_path: str | None) -> None:
    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def _format_findings_text(
    findings: list[Finding],
    *,
    header: str,
    compile_result: CompileResult | None = None,
) -> str:
    lines: list[str] = [header]
    if compile_result is not None:
        lines.append(f"secpolcompile: {compile_result.status} ({compile_result.message})")
    if not findings:
        lines.append("Result: PASS (0 findings)")
        return "\n".join(lines) + "\n"

    lines.append(f"Findings ({len(findings)}):")
    for f in findings:
        loc = f.span.format_loc() if f.span else "<unknown>"
        lines.append(f"  [{f.severity.value}] {f.rule_id} at {loc}: {f.message}")
        if f.remediation:
            lines.append(f"    remediation: {f.remediation}")
    return "\n".join(lines) + "\n"


def _format_diff_text(res: PolicyDiffResult) -> str:
    lines: list[str] = [
        f"Policy Diff: {res.old_path} -> {res.new_path}",
        f"Escalation chains: {res.chain_summary_line()}",
        f"Privilege expansion: {'YES (FAIL)' if res.has_privilege_expansion else 'NO (PASS)'}",
    ]
    if res.added_types:
        lines.append(f"  + Added types ({len(res.added_types)}): {', '.join(res.added_types)}")
    if res.removed_types:
        lines.append(f"  - Removed types ({len(res.removed_types)}): {', '.join(res.removed_types)}")
    if res.added_escalation_edges:
        lines.append(f"  + Added escalation edges ({len(res.added_escalation_edges)}):")
        for e in res.added_escalation_edges:
            lines.append(f"      + {e['src']} -> {e['dst']} ({e['mechanism']})")
    if res.removed_escalation_edges:
        lines.append(f"  - Removed escalation edges ({len(res.removed_escalation_edges)}):")
        for e in res.removed_escalation_edges:
            lines.append(f"      - {e['src']} -> {e['dst']} ({e['mechanism']})")
    if res.added_privileged_abilities:
        lines.append(f"  + Added privileged abilities ({len(res.added_privileged_abilities)}):")
        for a in res.added_privileged_abilities:
            lines.append(f"      + {a['type']}: {a['ability']}")
    if res.added_escalation_chains:
        lines.append(f"  + Added escalation chains ({len(res.added_escalation_chains)}):")
        for c in res.added_escalation_chains:
            lines.append(f"      + {c['chain']} ({', '.join(c['sink_reasons'])})")
    if res.removed_escalation_chains:
        lines.append(f"  - Removed escalation chains ({len(res.removed_escalation_chains)}):")
        for c in res.removed_escalation_chains:
            lines.append(f"      - {c['chain']} ({', '.join(c['sink_reasons'])})")
    return "\n".join(lines) + "\n"


def _cmd_check(args: argparse.Namespace) -> int:
    policy = parse_secpol_file(args.secpol)
    ifs = parse_ifs_file(args.ifs) if args.ifs else None

    findings, path_result = run_all_checks(policy, ifs=ifs, include_paths=True)

    if args.no_secpolcompile:
        compile_res = CompileResult(
            status="skipped",
            binary=None,
            returncode=None,
            stdout="",
            stderr="",
            message="secpolcompile skipped by --no-secpolcompile flag.",
        )
    else:
        compile_res = run_secpolcompile(
            args.secpol,
            secpolcompile_bin=args.secpolcompile_bin,
        )

    if args.format == "sarif":
        out = findings_to_sarif_json(findings, default_uri=str(args.secpol))
    elif args.format == "json":
        payload = {
            "policy": str(args.secpol),
            "ifs": str(args.ifs) if args.ifs else None,
            "secpolcompile": compile_res.to_dict(),
            "summary": {
                "total_types": len(policy.types),
                "total_findings": len(findings),
                "escalation_chains": len(path_result.escalation_paths),
                "review_edges": len(path_result.review_edges),
            },
            "findings": [f.to_dict() for f in findings],
            "escalation_paths": [p.to_dict() for p in path_result.escalation_paths],
        }
        out = json.dumps(payload, indent=2) + "\n"
    else:
        header = f"secpol-audit check: {args.secpol}" + (f" (IFS: {args.ifs})" if args.ifs else "")
        out = _format_findings_text(findings, header=header, compile_result=compile_res)

    _write_output(out, args.output)

    has_fail_findings = any(f.severity.is_failing for f in findings)
    if has_fail_findings or compile_res.status == "fail":
        return 1
    return 0


def _cmd_paths(args: argparse.Namespace) -> int:
    policy = parse_secpol_file(args.secpol)
    ifs = parse_ifs_file(args.ifs) if args.ifs else None

    if args.max_depth < 1:
        sys.stderr.write("ERROR: --max-depth must be >= 1\n")
        return 2

    all_findings, _ = run_all_checks(policy, ifs=ifs, include_paths=False)
    path_result = analyze_paths(
        policy,
        ifs=ifs,
        from_type=args.from_type,
        to_type=args.to_type,
        max_depth=args.max_depth,
    )
    combined_findings = sorted(
        all_findings + path_result.findings,
        key=lambda f: (f.severity.rank, f.span.file if f.span else "", f.span.line if f.span else 0, f.rule_id),
    )

    if args.no_secpolcompile:
        compile_res = CompileResult(
            status="skipped",
            binary=None,
            returncode=None,
            stdout="",
            stderr="",
            message="secpolcompile skipped by --no-secpolcompile flag.",
        )
    else:
        compile_res = run_secpolcompile(
            args.secpol,
            secpolcompile_bin=args.secpolcompile_bin,
        )

    if args.html:
        html_doc = render_html_report(
            path_result,
            findings=combined_findings,
            policy_path=str(args.secpol),
            ifs_path=str(args.ifs) if args.ifs else None,
            compile_result=compile_res,
        )
        html_out = Path(args.html)
        html_out.parent.mkdir(parents=True, exist_ok=True)
        html_out.write_text(html_doc, encoding="utf-8")

    if args.svg:
        svg_doc = render_svg_preview(
            path_result,
            findings=combined_findings,
            policy_path=str(args.secpol),
            ifs_path=str(args.ifs) if args.ifs else None,
        )
        svg_out = Path(args.svg)
        svg_out.parent.mkdir(parents=True, exist_ok=True)
        svg_out.write_text(svg_doc, encoding="utf-8")

    if args.format == "json":
        payload = {
            "policy": str(args.secpol),
            "ifs": str(args.ifs) if args.ifs else None,
            "secpolcompile": compile_res.to_dict(),
            "html_report": str(args.html) if args.html else None,
            "svg_report": str(args.svg) if args.svg else None,
            "escalation_edges": [e.to_dict() for e in path_result.escalation_edges],
            "review_edges": [e.to_dict() for e in path_result.review_edges],
            "escalation_paths": [p.to_dict() for p in path_result.escalation_paths],
        }
        out = json.dumps(payload, indent=2) + "\n"
    else:
        lines = [
            f"secpol-audit paths: {args.secpol}",
            f"Types: {len(path_result.nodes)} | Escalation edges: {len(path_result.escalation_edges)} | "
            f"Review-only edges: {len(path_result.review_edges)} | Escalation chains: {len(path_result.escalation_paths)}",
            f"secpolcompile: {compile_res.status}",
        ]
        if path_result.escalation_paths:
            lines.append("Escalation Chains:")
            for ep in path_result.escalation_paths:
                lines.append(f"  [CRITICAL] ({ep.hops}-hop) {ep.chain_str()}  [gains: {', '.join(ep.sink_reasons)}]")
        else:
            lines.append("Escalation Chains: 0 (clean)")
        if args.html:
            lines.append(f"Interactive HTML report written to: {args.html}")
        if args.svg:
            lines.append(f"Static SVG preview written to: {args.svg}")
        out = "\n".join(lines) + "\n"

    _write_output(out, args.output)
    return 1 if path_result.escalation_paths else 0


def _cmd_diff(args: argparse.Namespace) -> int:
    old_policy = parse_secpol_file(args.old_secpol)
    new_policy = parse_secpol_file(args.new_secpol)
    res = diff_policies(old_policy, new_policy)

    if args.format == "json":
        out = json.dumps(res.to_dict(), indent=2) + "\n"
    else:
        out = _format_diff_text(res)

    _write_output(out, args.output)
    return 1 if res.has_privilege_expansion else 0


def _cmd_verify_runtime(args: argparse.Namespace) -> int:
    policy = parse_secpol_file(args.policy)
    ifs = parse_ifs_file(args.ifs) if args.ifs else None
    processes = parse_pidin_file(args.pidin_log)

    diff = verify_runtime(
        processes,
        policy=policy,
        ifs=ifs,
        source_path=str(args.pidin_log),
    )

    if args.format == "sarif":
        out = findings_to_sarif_json(diff.findings, default_uri=str(args.pidin_log))
    elif args.format == "json":
        payload = {
            "pidin_log": str(args.pidin_log),
            "policy": str(args.policy),
            "ifs": str(args.ifs) if args.ifs else None,
            "observed_processes": len(diff.processes),
            "matched_processes": diff.matched,
            "findings": [f.to_dict() for f in diff.findings],
        }
        out = json.dumps(payload, indent=2) + "\n"
    else:
        header = (
            f"secpol-audit verify-runtime: {args.pidin_log} "
            f"(observed={len(diff.processes)}, matched={len(diff.matched)})"
        )
        out = _format_findings_text(diff.findings, header=header)

    _write_output(out, args.output)
    has_fail = any(f.severity.is_failing for f in diff.findings)
    return 1 if has_fail else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secpol-audit",
        description="Deterministic, fail-closed static & runtime QNX Neutrino 8.0 security policy auditor.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    # check
    p_check = sub.add_parser("check", help="Run static .secpol and build.ifs wiring & escalation checks")
    p_check.add_argument("secpol", help="Path to QNX 8.0 .secpol policy file")
    p_check.add_argument("--ifs", help="Optional path to matching QNX 8.0 build.ifs file")
    p_check.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Output format")
    p_check.add_argument("--output", "-o", help="Write output to file instead of stdout")
    p_check.add_argument("--secpolcompile-bin", help="Explicit path to QNX secpolcompile binary")
    p_check.add_argument("--no-secpolcompile", action="store_true", help="Skip invoking secpolcompile")
    p_check.set_defaults(func=_cmd_check)

    # paths
    p_paths = sub.add_parser("paths", help="Analyze transitive settypeid/transition privilege escalation paths")
    p_paths.add_argument("secpol", help="Path to QNX 8.0 .secpol policy file")
    p_paths.add_argument("--ifs", help="Optional path to matching QNX 8.0 build.ifs file")
    p_paths.add_argument("--from", dest="from_type", help="Filter chains starting at a specific source type")
    p_paths.add_argument("--to", dest="to_type", help="Filter chains ending at a specific sink type")
    p_paths.add_argument("--max-depth", type=int, default=6, help="Maximum hop depth (default: 6)")
    p_paths.add_argument("--html", help="Write self-contained interactive HTML/SVG graph report to path")
    p_paths.add_argument("--svg", help="Write static standalone SVG preview graph to path")
    p_paths.add_argument("--format", choices=("text", "json"), default="text", help="Console output format")
    p_paths.add_argument("--output", "-o", help="Write console output to file instead of stdout")
    p_paths.add_argument("--secpolcompile-bin", help="Explicit path to QNX secpolcompile binary")
    p_paths.add_argument("--no-secpolcompile", action="store_true", help="Skip invoking secpolcompile")
    p_paths.set_defaults(func=_cmd_paths)

    # diff
    p_diff = sub.add_parser("diff", help="Compare two .secpol policies and gate privilege expansions")
    p_diff.add_argument("old_secpol", help="Baseline .secpol policy file")
    p_diff.add_argument("new_secpol", help="Candidate/updated .secpol policy file")
    p_diff.add_argument("--format", choices=("text", "json"), default="text", help="Output format")
    p_diff.add_argument("--output", "-o", help="Write output to file instead of stdout")
    p_diff.set_defaults(func=_cmd_diff)

    # verify-runtime
    p_rt = sub.add_parser("verify-runtime", help="Diff runtime `pidin -f a_n` snapshot against .secpol & build.ifs")
    p_rt.add_argument("pidin_log", help="Path to captured QNX `pidin -f a_n` output or serial log")
    p_rt.add_argument("--policy", "--secpol", dest="policy", required=True, help="Path to QNX 8.0 .secpol policy")
    p_rt.add_argument("--ifs", help="Optional path to matching QNX 8.0 build.ifs file")
    p_rt.add_argument("--format", choices=("text", "json", "sarif"), default="text", help="Output format")
    p_rt.add_argument("--output", "-o", help="Write output to file instead of stdout")
    p_rt.set_defaults(func=_cmd_verify_runtime)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        return code

    try:
        return int(args.func(args))
    except ParseDiagnostic as diag:
        sys.stderr.write(f"ERROR [{diag.code}] {diag.span.format_loc()}: {diag.message}\n")
        if diag.span.snippet:
            sys.stderr.write(f"  | {diag.span.snippet}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
