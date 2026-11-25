"""Self-contained, offline interactive BloodHound-style HTML/SVG security workbench."""

from __future__ import annotations

from dataclasses import dataclass
import html
import json
import math
from typing import Any

from secpol_audit import __version__
from secpol_audit.compile_wrap import CompileResult
from secpol_audit.ir import Finding, PathAnalysisResult

TRUST_ZONES = ("Core", "Safety-Critical HAL", "Middleware", "Untrusted")

ZONE_META = {
    "Core": {"color": "#38bdf8", "bg": "rgba(56, 189, 248, 0.06)", "desc": "Boot / System Services"},
    "Safety-Critical HAL": {"color": "#f97316", "bg": "rgba(249, 115, 22, 0.07)", "desc": "High-Privilege Sinks & Hardware HAL"},
    "Middleware": {"color": "#a78bfa", "bg": "rgba(167, 139, 250, 0.06)", "desc": "IPC Bridges, Perception, OTA & Diagnostics"},
    "Untrusted": {"color": "#f43f5e", "bg": "rgba(244, 63, 94, 0.07)", "desc": "External / IVI / Untrusted Attack Surface"},
}

IFS_RULE_IDS = frozenset(
    {
        "PRE_SECPOLPUSH_LAUNCH",
        "MISSING_SECPOLPUSH",
        "DUPLICATE_SECPOLPUSH",
        "UNTYPED_IFS_SERVICE",
        "UNDEFINED_IFS_TYPE",
    }
)


def _safe_json_for_script(obj: Any) -> str:
    return json.dumps(obj, indent=None, separators=(",", ":")).replace("</", "<\\/")


def _compute_layout(path_result: PathAnalysisResult) -> dict[str, Any]:
    """Deterministically position nodes into layered trust-zone rows with zero overlap."""
    zone_nodes: dict[str, list[str]] = {z: [] for z in TRUST_ZONES}
    for name in sorted(path_result.nodes.keys()):
        z = path_result.nodes[name].get("trust_zone", "Middleware")
        if z not in zone_nodes:
            z = "Middleware"
        zone_nodes[z].append(name)

    node_w = 176
    node_h = 56
    h_gap = 36
    row_pad_y = 34
    band_header = 28
    band_gap = 18
    margin_x = 40
    margin_y = 24

    max_cols = max((len(v) for v in zone_nodes.values()), default=1)
    max_cols = max(max_cols, 3)
    # Wrap rows cleanly if a zone has more than 5 nodes
    cols_per_row = min(max(max_cols, 3), 5)
    canvas_w = max(980, margin_x * 2 + cols_per_row * node_w + (cols_per_row - 1) * h_gap + 40)

    positions: dict[str, dict[str, float]] = {}
    bands: list[dict[str, Any]] = []
    cur_y = margin_y

    for zone in TRUST_ZONES:
        members = zone_nodes[zone]
        rows = max(1, (len(members) + cols_per_row - 1) // cols_per_row)
        band_h = band_header + rows * node_h + (rows - 1) * 28 + row_pad_y * 2
        bands.append(
            {
                "zone": zone,
                "x": 16,
                "y": cur_y,
                "width": canvas_w - 32,
                "height": band_h,
                "color": ZONE_META[zone]["color"],
                "bg": ZONE_META[zone]["bg"],
                "desc": ZONE_META[zone]["desc"],
                "count": len(members),
            }
        )

        for idx, tname in enumerate(members):
            r = idx // cols_per_row
            c = idx % cols_per_row
            row_count = min(cols_per_row, len(members) - r * cols_per_row)
            row_total_w = row_count * node_w + (row_count - 1) * h_gap
            start_x = (canvas_w - row_total_w) / 2.0
            nx = start_x + c * (node_w + h_gap)
            ny = cur_y + band_header + row_pad_y + r * (node_h + 28)
            positions[tname] = {
                "x": round(nx, 1),
                "y": round(ny, 1),
                "w": node_w,
                "h": node_h,
                "cx": round(nx + node_w / 2.0, 1),
                "cy": round(ny + node_h / 2.0, 1),
            }

        cur_y += band_h + band_gap

    canvas_h = max(560, cur_y + margin_y)
    return {
        "width": canvas_w,
        "height": canvas_h,
        "bands": bands,
        "positions": positions,
    }


def render_html_report(
    path_result: PathAnalysisResult,
    *,
    findings: list[Finding] | None = None,
    policy_path: str = "",
    ifs_path: str | None = None,
    compile_result: CompileResult | None = None,
    verified_edges: set[tuple[str, str]] | None = None,
) -> str:
    """Render a single-file, zero-CDN interactive HTML/SVG privilege-escalation workbench."""
    all_findings = findings if findings is not None else path_result.findings
    ifs_errors = [f for f in all_findings if f.rule_id in IFS_RULE_IDS]
    compile_status = compile_result.status if compile_result is not None else "skipped"
    compile_msg = (
        compile_result.message
        if compile_result is not None
        else "secpolcompile not executed (skipped)"
    )
    verified_set: set[tuple[str, str]] = set(verified_edges) if verified_edges else set()

    layout = _compute_layout(path_result)

    # Identify edges participating in at least one active escalation chain
    chain_edge_pairs: set[tuple[str, str]] = set()
    for ep in path_result.escalation_paths:
        for i in range(len(ep.nodes) - 1):
            chain_edge_pairs.add((ep.nodes[i], ep.nodes[i + 1]))

    edges_payload: list[dict[str, Any]] = []
    edge_id = 0
    for e in path_result.escalation_edges:
        edge_id += 1
        chains_using = [
            ep.chain_str()
            for ep in path_result.escalation_paths
            if any(ep.nodes[i] == e.src and ep.nodes[i + 1] == e.dst for i in range(len(ep.nodes) - 1))
        ]
        edges_payload.append(
            {
                "id": f"e-{edge_id}",
                "src": e.src,
                "dst": e.dst,
                "kind": "ESCALATION",
                "mechanism": e.mechanism,
                "location": e.span.format_loc(),
                "raw": e.raw,
                "via_attribute": e.via_attribute,
                "in_chain": (e.src, e.dst) in chain_edge_pairs,
                "trace_verified": (e.src, e.dst) in verified_set,
                "chains": chains_using,
            }
        )
    for e in path_result.review_edges:
        edge_id += 1
        edges_payload.append(
            {
                "id": f"r-{edge_id}",
                "src": e.src,
                "dst": e.dst,
                "kind": "REVIEW_ONLY",
                "mechanism": e.mechanism,
                "location": e.span.format_loc(),
                "raw": e.raw,
                "via_attribute": e.via_attribute,
                "in_chain": False,
                "trace_verified": False,
                "chains": [],
            }
        )

    chains_payload = []
    for ep in path_result.escalation_paths:
        ep_dict = ep.to_dict()
        ep_pairs = [(ep.nodes[i], ep.nodes[i + 1]) for i in range(len(ep.nodes) - 1)]
        ep_dict["trace_verified"] = bool(ep_pairs) and all(p in verified_set for p in ep_pairs)
        chains_payload.append(ep_dict)
    findings_payload = [f.to_dict() for f in all_findings]

    graph_data = {
        "policy_path": policy_path,
        "ifs_path": ifs_path,
        "layout": layout,
        "nodes": path_result.nodes,
        "edges": edges_payload,
        "chains": chains_payload,
        "findings": findings_payload,
        "verified_edge_count": len(verified_set),
        "compile": {
            "status": compile_status,
            "message": compile_msg,
        },
    }

    esc_count = len(path_result.escalation_paths)
    type_count = len(path_result.nodes)
    ifs_err_count = len(ifs_errors)
    total_findings = len(all_findings)
    verified_count = len(verified_set)

    # Pre-render static HTML chain list so plain HTML inspection also sees exact chains
    if path_result.escalation_paths:
        chain_cards: list[str] = []
        for idx, ep in enumerate(path_result.escalation_paths):
            ep_pairs = [(ep.nodes[i], ep.nodes[i + 1]) for i in range(len(ep.nodes) - 1)]
            is_trace_verified = bool(ep_pairs) and all(p in verified_set for p in ep_pairs)
            tv_badge = (
                ' <span class="badge badge-trace">KERNEL TRACE VERIFIED</span>'
                if is_trace_verified
                else ""
            )
            chain_cards.append(
                f'<div class="chain-card" data-chain-idx="{idx}" onclick="selectChain({idx})">'
                f'<div class="chain-head"><span><span class="badge badge-crit">{ep.hops}-HOP ESCALATION</span>{tv_badge}</span>'
                f'<span class="chain-sink">Gains: {html.escape(", ".join(ep.sink_reasons))}</span></div>'
                f'<div class="chain-path">{html.escape(ep.chain_str())}</div>'
                f"</div>"
            )
        chain_items_html = "\n".join(chain_cards)
    else:
        chain_items_html = '<div class="empty-note">No transitive privilege escalation chains detected.</div>'

    if all_findings:
        finding_rows_html = "\n".join(
            f"<tr>"
            f'<td><span class="sev sev-{f.severity.value.lower()}">{html.escape(f.severity.value)}</span></td>'
            f"<td><code>{html.escape(f.rule_id)}</code></td>"
            f"<td><code>{html.escape(f.span.format_loc() if f.span else '-')}</code></td>"
            f"<td>{html.escape(f.message)}</td>"
            f"</tr>"
            for f in all_findings
        )
    else:
        finding_rows_html = '<tr><td colspan="4" class="empty-note">Zero findings detected — clean audit pass.</td></tr>'

    compile_badge_class = {
        "pass": "status-pass",
        "fail": "status-fail",
        "skipped": "status-skipped",
    }.get(compile_status, "status-skipped")

    data_json = _safe_json_for_script(graph_data)
    title_str = html.escape(f"secpol-audit Workbench — {policy_path or 'QNX 8.0 Policy'}")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>{title_str}</title>
<style>
  :root {{
    --bg: #0b1120;
    --panel: #0f172a;
    --panel-alt: #1e293b;
    --border: #334155;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --crimson: #ef4444;
    --crimson-glow: rgba(239, 68, 68, 0.35);
    --amber: #f59e0b;
    --green: #22c55e;
    --sky: #38bdf8;
    --slate-edge: #64748b;
    --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
    --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.45;
  }}
  header {{
    background: var(--panel);
    border-bottom: 1px solid var(--border);
    padding: 14px 22px;
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }}
  .brand {{
    display: flex;
    align-items: baseline;
    gap: 10px;
  }}
  .brand h1 {{
    margin: 0;
    font-size: 18px;
    font-family: var(--mono);
    letter-spacing: 0.4px;
    color: #f8fafc;
  }}
  .brand .sub {{
    color: var(--muted);
    font-size: 12px;
    font-family: var(--mono);
  }}
  .summary-bar {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 12px;
    padding: 14px 22px;
    background: #0d1526;
    border-bottom: 1px solid var(--border);
  }}
  .metric-card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px 14px;
  }}
  .metric-label {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    color: var(--muted);
  }}
  .metric-value {{
    font-size: 22px;
    font-weight: 700;
    font-family: var(--mono);
    margin-top: 2px;
  }}
  .metric-danger {{ color: var(--crimson); }}
  .metric-ok {{ color: var(--green); }}
  .metric-warn {{ color: var(--amber); }}
  .status-pill {{
    display: inline-block;
    padding: 2px 9px;
    border-radius: 999px;
    font-size: 12px;
    font-weight: 700;
    font-family: var(--mono);
    text-transform: uppercase;
    margin-top: 4px;
  }}
  .status-pass {{ background: rgba(34, 197, 94, 0.16); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.4); }}
  .status-fail {{ background: rgba(239, 68, 68, 0.18); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.45); }}
  .status-skipped {{ background: rgba(245, 158, 11, 0.16); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
  .toolbar {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    padding: 10px 22px;
    background: var(--panel);
    border-bottom: 1px solid var(--border);
  }}
  .toolbar-group {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 12px;
  }}
  .toggle-label {{
    display: inline-flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    font-size: 13px;
    color: var(--text);
    user-select: none;
  }}
  .search-input {{
    background: var(--bg);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 5px 10px;
    font-family: var(--mono);
    font-size: 12px;
    min-width: 210px;
  }}
  .btn {{
    background: var(--panel-alt);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
    cursor: pointer;
  }}
  .btn:hover {{ background: #273549; }}
  .legend {{
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 16px;
    font-size: 12px;
    color: var(--muted);
  }}
  .legend-item {{ display: inline-flex; align-items: center; gap: 6px; }}
  .swatch-esc {{ width: 22px; height: 3px; background: var(--crimson); display: inline-block; }}
  .swatch-rev {{ width: 22px; height: 0; border-top: 2px dashed var(--slate-edge); display: inline-block; }}
  .workspace {{
    display: grid;
    grid-template-columns: minmax(0, 1fr) 370px;
    min-height: 580px;
    border-bottom: 1px solid var(--border);
  }}
  @media (max-width: 1020px) {{
    .workspace {{ grid-template-columns: 1fr; }}
  }}
  .graph-stage {{
    position: relative;
    overflow: auto;
    background: radial-gradient(circle at 20% 20%, #111c33 0%, #0b1120 75%);
    padding: 12px;
  }}
  svg#policy-graph {{
    display: block;
    margin: 0 auto;
    transform-origin: top center;
    transition: transform 0.12s ease-out;
  }}
  .node-group {{ cursor: pointer; }}
  .node-rect {{
    transition: stroke-width 0.12s, filter 0.12s;
  }}
  .node-group:hover .node-rect {{ stroke-width: 2.5; }}
  .node-group.selected .node-rect {{ stroke: #38bdf8; stroke-width: 3; }}
  .node-group.dimmed {{ opacity: 0.22; }}
  .edge-path {{
    fill: none;
    cursor: pointer;
    transition: opacity 0.12s, stroke-width 0.12s;
  }}
  .edge-hit {{
    fill: none;
    stroke: transparent;
    stroke-width: 14;
    cursor: pointer;
  }}
  .edge-group.dimmed {{ opacity: 0.12; }}
  .edge-group.selected .edge-path {{ stroke-width: 3.8; }}
  .inspector {{
    background: var(--panel);
    border-left: 1px solid var(--border);
    padding: 16px;
    overflow-y: auto;
    max-height: 760px;
  }}
  .inspector h2 {{
    margin: 0 0 10px 0;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    color: var(--muted);
    border-bottom: 1px solid var(--border);
    padding-bottom: 6px;
  }}
  .insp-title {{
    font-family: var(--mono);
    font-size: 16px;
    font-weight: 700;
    color: #f8fafc;
    margin-bottom: 6px;
  }}
  .insp-section {{
    margin-top: 12px;
    padding-top: 10px;
    border-top: 1px solid #1e293b;
  }}
  .insp-label {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--muted);
    margin-bottom: 4px;
  }}
  .code-box {{
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 10px;
    font-family: var(--mono);
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-word;
    color: #cbd5e1;
  }}
  .chip {{
    display: inline-block;
    padding: 2px 7px;
    margin: 2px 4px 2px 0;
    border-radius: 5px;
    font-family: var(--mono);
    font-size: 11px;
    background: var(--panel-alt);
    border: 1px solid var(--border);
    color: #e2e8f0;
  }}
  .chip-priv {{
    background: rgba(239, 68, 68, 0.16);
    border-color: rgba(239, 68, 68, 0.45);
    color: #fca5a5;
  }}
  .chip-review {{
    background: rgba(100, 116, 139, 0.2);
    border-color: rgba(148, 163, 184, 0.4);
    color: #cbd5e1;
  }}
  .lower-panels {{
    display: grid;
    grid-template-columns: 1fr 1.35fr;
    gap: 16px;
    padding: 18px 22px 28px;
  }}
  @media (max-width: 1020px) {{
    .lower-panels {{ grid-template-columns: 1fr; }}
  }}
  .card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
  }}
  .card h3 {{
    margin: 0 0 12px 0;
    font-size: 14px;
    text-transform: uppercase;
    letter-spacing: 0.7px;
    color: var(--muted);
  }}
  .chain-card {{
    background: #131d33;
    border: 1px solid rgba(239, 68, 68, 0.42);
    border-radius: 7px;
    padding: 10px 12px;
    margin-bottom: 10px;
    cursor: pointer;
    transition: border-color 0.12s, background 0.12s;
  }}
  .chain-card:hover, .chain-card.active {{
    border-color: var(--crimson);
    background: #1b243c;
  }}
  .chain-head {{
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    gap: 6px;
    margin-bottom: 6px;
  }}
  .badge {{
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
    font-family: var(--mono);
  }}
  .badge-crit {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.45); }}
  .badge-trace {{ background: rgba(245, 158, 11, 0.24); color: #fde047; border: 1px solid rgba(250, 204, 21, 0.65); }}
  .chain-sink {{ font-size: 11px; font-family: var(--mono); color: #fca5a5; }}
  .chain-path {{
    font-family: var(--mono);
    font-size: 13px;
    font-weight: 600;
    color: #f8fafc;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 12.5px;
  }}
  th, td {{
    text-align: left;
    padding: 7px 8px;
    border-bottom: 1px solid #1e293b;
    vertical-align: top;
  }}
  th {{
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
  }}
  .sev {{
    display: inline-block;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 10.5px;
    font-weight: 700;
    font-family: var(--mono);
  }}
  .sev-critical {{ background: rgba(239, 68, 68, 0.22); color: #f87171; }}
  .sev-error, .sev-high {{ background: rgba(249, 115, 22, 0.22); color: #fb923c; }}
  .sev-medium, .sev-warning {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; }}
  .sev-info {{ background: rgba(56, 189, 248, 0.16); color: #38bdf8; }}
  .empty-note {{ color: var(--muted); font-style: italic; padding: 8px 0; }}
</style>
</head>
<body>
<header>
  <div class="brand">
    <h1>secpol-audit</h1>
    <span class="sub">v{html.escape(__version__)} &middot; QNX Neutrino 8.0 Privilege-Escalation Workbench</span>
  </div>
  <div class="sub">
    Policy: <code>{html.escape(policy_path or "-")}</code>
    {f' &middot; IFS: <code>{html.escape(ifs_path)}</code>' if ifs_path else ""}
  </div>
</header>

<section class="summary-bar">
  <div class="metric-card">
    <div class="metric-label">Total Types</div>
    <div class="metric-value">{type_count}</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">Critical Escalation Chains</div>
    <div class="metric-value {"metric-danger" if esc_count > 0 else "metric-ok"}">{esc_count}</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">IFS Wiring Errors</div>
    <div class="metric-value {"metric-danger" if ifs_err_count > 0 else "metric-ok"}">{ifs_err_count}</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">Total Audit Findings</div>
    <div class="metric-value {"metric-warn" if total_findings > 0 else "metric-ok"}">{total_findings}</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">secpolcompile Status</div>
    <div><span class="status-pill {compile_badge_class}" title="{html.escape(compile_msg)}">{html.escape(compile_status)}</span></div>
  </div>
  {f'<div class="metric-card"><div class="metric-label">Kernel Trace Verified Edges</div><div class="metric-value metric-danger">{verified_count}</div></div>' if verified_count > 0 else ""}
</section>

<section class="toolbar">
  <div class="toolbar-group">
    <label class="toggle-label">
      <input type="checkbox" id="toggle-review-edges" checked />
      Show Review-Only Edges (<code>channel_connect</code> / <code>allow_link</code>)
    </label>
    <input type="text" id="node-search" class="search-input" placeholder="Filter type name..." />
    <button class="btn" id="btn-reset">Reset Focus</button>
    <button class="btn" id="btn-zoom-in">Zoom +</button>
    <button class="btn" id="btn-zoom-out">Zoom &minus;</button>
  </div>
  <div class="legend">
    <span class="legend-item"><span class="swatch-esc"></span> <strong>ESCALATION</strong> (<code>settypeid</code> / <code>derive_type</code> / <code>default_spawn_type</code>)</span>
    <span class="legend-item"><span class="swatch-rev"></span> <strong>REVIEW-ONLY</strong> (<code>channel_connect</code> / <code>allow_link</code> — never escalated)</span>
  </div>
</section>

<main class="workspace">
  <div class="graph-stage" id="graph-stage">
    <svg id="policy-graph"></svg>
  </div>
  <aside class="inspector" id="inspector">
    <h2>Inspector</h2>
    <div id="inspector-body">
      <div class="empty-note">Click any security type node, escalation arrow, review-only arrow, or escalation chain below to inspect exact <code>file:line</code> rules, abilities, and paths.</div>
    </div>
  </aside>
</main>

<section class="lower-panels">
  <div class="card">
    <h3>Transitive Privilege Escalation Chains ({esc_count})</h3>
    <div id="chains-list">{chain_items_html}</div>
  </div>
  <div class="card">
    <h3>Static Policy &amp; IFS Findings ({total_findings})</h3>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Rule</th>
          <th>Location</th>
          <th>Message</th>
        </tr>
      </thead>
      <tbody>{finding_rows_html}</tbody>
    </table>
  </div>
</section>

<script>
const DATA = {data_json};
const SVG_NS = document.getElementById("policy-graph").namespaceURI;
let currentZoom = 1.0;
let activeChainIdx = null;
let selectedId = null;

function escHtml(str) {{
  return String(str == null ? "" : str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}}

function svgEl(tag, attrs) {{
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {{}})) {{
    el.setAttribute(k, String(v));
  }}
  return el;
}}

function buildEdgePath(srcPos, dstPos, curveBias) {{
  if (srcPos === dstPos) {{
    const x = srcPos.x + srcPos.w;
    const y = srcPos.cy;
    return `M ${{x}} ${{y - 10}} C ${{x + 42}} ${{y - 36}}, ${{x + 42}} ${{y + 36}}, ${{x}} ${{y + 10}}`;
  }}
  const dx = dstPos.cx - srcPos.cx;
  const dy = dstPos.cy - srcPos.cy;
  let sx = srcPos.cx;
  let sy = srcPos.cy;
  let ex = dstPos.cx;
  let ey = dstPos.cy;

  if (Math.abs(dy) >= Math.abs(dx) * 0.45) {{
    if (dy > 0) {{
      sy = srcPos.y + srcPos.h;
      ey = dstPos.y;
    }} else {{
      sy = srcPos.y;
      ey = dstPos.y + dstPos.h;
    }}
  }} else {{
    if (dx > 0) {{
      sx = srcPos.x + srcPos.w;
      ex = dstPos.x;
    }} else {{
      sx = srcPos.x;
      ex = dstPos.x + dstPos.w;
    }}
  }}

  const mx = (sx + ex) / 2;
  const my = (sy + ey) / 2;
  const len = Math.hypot(ex - sx, ey - sy) || 1;
  const nx = -(ey - sy) / len;
  const ny = (ex - sx) / len;
  const offset = curveBias * Math.min(48, Math.max(18, len * 0.14));
  const cx = mx + nx * offset;
  const cy = my + ny * offset;
  return `M ${{sx.toFixed(1)}} ${{sy.toFixed(1)}} Q ${{cx.toFixed(1)}} ${{cy.toFixed(1)}}, ${{ex.toFixed(1)}} ${{ey.toFixed(1)}}`;
}}

function renderGraph() {{
  const svg = document.getElementById("policy-graph");
  const layout = DATA.layout;
  svg.setAttribute("width", layout.width);
  svg.setAttribute("height", layout.height);
  svg.setAttribute("viewBox", `0 0 ${{layout.width}} ${{layout.height}}`);
  svg.innerHTML = "";

  const defs = svgEl("defs");

  const mkMarker = (id, color) => {{
    const m = svgEl("marker", {{
      id,
      viewBox: "0 0 10 10",
      refX: "8.5",
      refY: "5",
      markerWidth: "7",
      markerHeight: "7",
      orient: "auto-start-reverse",
    }});
    m.appendChild(svgEl("path", {{ d: "M 0 1.2 L 10 5 L 0 8.8 z", fill: color }}));
    return m;
  }};
  defs.appendChild(mkMarker("arrow-esc", "#ef4444"));
  defs.appendChild(mkMarker("arrow-rev", "#64748b"));
  svg.appendChild(defs);

  // Trust zone bands
  const bandLayer = svgEl("g", {{ id: "layer-bands" }});
  for (const b of layout.bands) {{
    bandLayer.appendChild(svgEl("rect", {{
      x: b.x, y: b.y, width: b.width, height: b.height, rx: 10,
      fill: b.bg, stroke: b.color, "stroke-opacity": "0.35", "stroke-width": 1,
    }}));
    const lbl = svgEl("text", {{
      x: b.x + 14, y: b.y + 19,
      fill: b.color, "font-size": 12, "font-weight": 700, "font-family": "var(--mono)",
    }});
    lbl.textContent = `${{b.zone.toUpperCase()}} — ${{b.desc}} (${{b.count}})`;
    bandLayer.appendChild(lbl);
  }}
  svg.appendChild(bandLayer);

  // Edges layer
  const edgeLayer = svgEl("g", {{ id: "layer-edges" }});
  const pairSeen = {{}};
  for (const e of DATA.edges) {{
    const sp = layout.positions[e.src];
    const dp = layout.positions[e.dst];
    if (!sp || !dp) continue;
    const pkey = [e.src, e.dst].sort().join("|");
    pairSeen[pkey] = (pairSeen[pkey] || 0) + 1;
    const bias = e.kind === "ESCALATION" ? (pairSeen[pkey] % 2 === 1 ? -1.1 : 1.1) : (pairSeen[pkey] % 2 === 1 ? 0.7 : -0.7);
    const d = buildEdgePath(sp, dp, bias);

    const g = svgEl("g", {{
      class: `edge-group edge-${{e.kind.toLowerCase()}}`,
      "data-id": e.id,
      "data-src": e.src,
      "data-dst": e.dst,
      "data-kind": e.kind,
    }});

    const pathAttrs = {{
      d,
      class: "edge-path",
      stroke: e.kind === "ESCALATION" ? "#ef4444" : "#64748b",
      "stroke-width": e.kind === "ESCALATION" ? (e.in_chain ? 3.0 : 2.1) : 1.4,
      "marker-end": e.kind === "ESCALATION" ? "url(#arrow-esc)" : "url(#arrow-rev)",
    }};
    if (e.kind === "REVIEW_ONLY") {{
      pathAttrs["stroke-dasharray"] = "5,5";
      pathAttrs["stroke-opacity"] = "0.75";
    }}
    const visiblePath = svgEl("path", pathAttrs);
    const hitPath = svgEl("path", {{ d, class: "edge-hit" }});
    const title = svgEl("title");
    const tvTag = e.trace_verified ? " [KERNEL TRACE VERIFIED]" : "";
    title.textContent = `${{e.src}} -> ${{e.dst}} [${{e.kind === "REVIEW_ONLY" ? "review-only: " + e.mechanism : "ESCALATION: " + e.mechanism}}]${{tvTag}} (${{e.location}})`;

    g.appendChild(visiblePath);
    g.appendChild(hitPath);
    g.appendChild(title);
    if (e.trace_verified) {{
      const mx = (sp.cx + dp.cx) / 2;
      const my = (sp.cy + dp.cy) / 2;
      const pill = svgEl("rect", {{
        x: mx - 76, y: my - 10, width: 152, height: 18, rx: 4,
        fill: "#422006", stroke: "#facc15", "stroke-width": 1.1,
      }});
      const ptxt = svgEl("text", {{
        x: mx, y: my + 3, "text-anchor": "middle",
        fill: "#fde047", "font-size": 9.5, "font-weight": 700, "font-family": "var(--mono)",
      }});
      ptxt.textContent = "KERNEL TRACE VERIFIED";
      g.appendChild(pill);
      g.appendChild(ptxt);
    }}
    g.addEventListener("click", (ev) => {{
      ev.stopPropagation();
      inspectEdge(e);
    }});
    edgeLayer.appendChild(g);
  }}
  svg.appendChild(edgeLayer);

  // Nodes layer
  const nodeLayer = svgEl("g", {{ id: "layer-nodes" }});
  for (const [name, meta] of Object.entries(DATA.nodes)) {{
    const pos = layout.positions[name];
    if (!pos) continue;
    const isSink = meta.is_sink;
    const inChain = (meta.escalation_chains || []).length > 0;
    const strokeColor = inChain ? "#ef4444" : (isSink ? "#f97316" : "#475569");
    const fillColor = inChain ? "#221220" : "#111c33";

    const g = svgEl("g", {{
      class: "node-group",
      "data-node": name,
    }});
    g.appendChild(svgEl("rect", {{
      x: pos.x, y: pos.y, width: pos.w, height: pos.h, rx: 8,
      fill: fillColor, stroke: strokeColor, "stroke-width": inChain ? 2.2 : 1.4,
      class: "node-rect",
    }}));

    const label = svgEl("text", {{
      x: pos.cx, y: pos.y + 24,
      "text-anchor": "middle",
      fill: "#f8fafc",
      "font-size": 12.5,
      "font-weight": 700,
      "font-family": "var(--mono)",
    }});
    label.textContent = name;
    g.appendChild(label);

    const sub = svgEl("text", {{
      x: pos.cx, y: pos.y + 42,
      "text-anchor": "middle",
      fill: isSink ? "#fca5a5" : "#94a3b8",
      "font-size": 10.5,
      "font-family": "var(--mono)",
    }});
    const privCount = (meta.abilities || []).filter((a) => a.privileged).length;
    sub.textContent = isSink
      ? `SINK · ${{privCount}} priv abil`
      : `${{(meta.abilities || []).length}} abil · ${{(meta.attaches || []).length}} attach`;
    g.appendChild(sub);

    g.addEventListener("click", (ev) => {{
      ev.stopPropagation();
      inspectNode(name);
    }});
    nodeLayer.appendChild(g);
  }}
  svg.appendChild(nodeLayer);
  applyFilters();
}}

function clearSelections() {{
  document.querySelectorAll(".node-group.selected, .edge-group.selected").forEach((el) => el.classList.remove("selected"));
  document.querySelectorAll(".chain-card.active").forEach((el) => el.classList.remove("active"));
}}

function inspectNode(name) {{
  const meta = DATA.nodes[name];
  if (!meta) return;
  clearSelections();
  selectedId = name;
  const ng = document.querySelector(`.node-group[data-node="${{CSS.escape(name)}}"]`);
  if (ng) ng.classList.add("selected");

  const loc = meta.location ? `${{meta.location.file}}:${{meta.location.line}}:${{meta.location.col}}` : "-";
  const abils = (meta.abilities || []).length
    ? meta.abilities.map((a) => `<span class="chip ${{a.privileged ? "chip-priv" : ""}}" title="${{escHtml(a.location)}}">${{escHtml(a.canonical)}}</span>`).join("")
    : '<span class="empty-note">None</span>';
  const attaches = (meta.attaches || []).length
    ? meta.attaches.map((a) => `<span class="chip">${{escHtml(a.raw)}}${{a.channel_type ? " (" + escHtml(a.channel_type) + ")" : ""}}</span>`).join("")
    : '<span class="empty-note">None</span>';
  const bindings = (meta.ifs_bindings || []).length
    ? meta.ifs_bindings.map((b) => `<div class="code-box">${{escHtml(b.location)}}<br/>${{escHtml(b.raw)}}</div>`).join("")
    : '<span class="empty-note">No build.ifs on -T binding recorded</span>';
  const chains = (meta.escalation_chains || []).length
    ? meta.escalation_chains.map((c) => `<div class="code-box" style="border-color:#ef4444;margin-bottom:6px;">${{escHtml(c)}}</div>`).join("")
    : '<span class="empty-note">Not on any escalation chain</span>';

  document.getElementById("inspector-body").innerHTML = `
    <div class="insp-title">${{escHtml(name)}}</div>
    <div><span class="chip">${{escHtml(meta.trust_zone)}}</span>${{meta.is_sink ? '<span class="chip chip-priv">HIGH-PRIVILEGE SINK</span>' : ""}}</div>
    <div class="insp-section">
      <div class="insp-label">Declaration Location</div>
      <div class="code-box">${{escHtml(loc)}}</div>
    </div>
    <div class="insp-section">
      <div class="insp-label">Abilities Held (${{(meta.abilities || []).length}})</div>
      <div>${{abils}}</div>
    </div>
    <div class="insp-section">
      <div class="insp-label">allow_attach Paths (${{(meta.attaches || []).length}})</div>
      <div>${{attaches}}</div>
    </div>
    <div class="insp-section">
      <div class="insp-label">build.ifs Bindings</div>
      <div>${{bindings}}</div>
    </div>
    <div class="insp-section">
      <div class="insp-label">Escalation Chains Passing Through</div>
      <div>${{chains}}</div>
    </div>
  `;
}}

function inspectEdge(edge) {{
  clearSelections();
  selectedId = edge.id;
  const eg = document.querySelector(`.edge-group[data-id="${{CSS.escape(edge.id)}}"]`);
  if (eg) eg.classList.add("selected");

  const badge = edge.kind === "ESCALATION"
    ? `<span class="chip chip-priv">ESCALATION (${{escHtml(edge.mechanism)}})</span>${{edge.trace_verified ? '<span class="badge badge-trace">KERNEL TRACE VERIFIED</span>' : ""}}`
    : `<span class="chip chip-review">REVIEW-ONLY (${{escHtml(edge.mechanism)}})</span>`;
  const chains = (edge.chains || []).length
    ? edge.chains.map((c) => `<div class="code-box" style="border-color:#ef4444;margin-bottom:6px;">${{escHtml(c)}}</div>`).join("")
    : (edge.kind === "REVIEW_ONLY"
        ? '<span class="empty-note">Review-only IPC/link edge — never traversed as privilege escalation.</span>'
        : '<span class="empty-note">Does not reach a higher-privilege sink.</span>');

  document.getElementById("inspector-body").innerHTML = `
    <div class="insp-title">${{escHtml(edge.src)}} &rarr; ${{escHtml(edge.dst)}}</div>
    <div>${{badge}}${{edge.via_attribute ? `<span class="chip">via ${{escHtml(edge.via_attribute)}}</span>` : ""}}</div>
    <div class="insp-section">
      <div class="insp-label">Rule Source Location</div>
      <div class="code-box">${{escHtml(edge.location)}}</div>
    </div>
    <div class="insp-section">
      <div class="insp-label">Raw Rule Snippet</div>
      <div class="code-box">${{escHtml(edge.raw)}}</div>
    </div>
    <div class="insp-section">
      <div class="insp-label">Escalation Chains</div>
      <div>${{chains}}</div>
    </div>
  `;
}}

function selectChain(idx) {{
  const chain = DATA.chains[idx];
  if (!chain) return;
  activeChainIdx = idx;
  clearSelections();
  const card = document.querySelector(`.chain-card[data-chain-idx="${{idx}}"]`);
  if (card) card.classList.add("active");

  const nodeSet = new Set(chain.nodes);
  const pairSet = new Set();
  for (let i = 0; i < chain.nodes.length - 1; i++) {{
    pairSet.add(`${{chain.nodes[i]}}->${{chain.nodes[i + 1]}}`);
  }}
  document.querySelectorAll(".node-group").forEach((el) => {{
    el.classList.toggle("dimmed", !nodeSet.has(el.getAttribute("data-node")));
  }});
  document.querySelectorAll(".edge-group").forEach((el) => {{
    const key = `${{el.getAttribute("data-src")}}->${{el.getAttribute("data-dst")}}`;
    const match = el.getAttribute("data-kind") === "ESCALATION" && pairSet.has(key);
    el.classList.toggle("dimmed", !match);
    if (match) el.classList.add("selected");
  }});

  const steps = chain.edges.map((e, i) => `
    <div class="code-box" style="margin-bottom:8px;">
      <strong>Hop ${{i + 1}}: ${{escHtml(e.src)}} &rarr; ${{escHtml(e.dst)}}</strong> (${{escHtml(e.mechanism)}})<br/>
      Location: ${{escHtml(e.location.file)}}:${{e.location.line}}:${{e.location.col}}<br/>
      ${{escHtml(e.raw)}}
    </div>
  `).join("");

  document.getElementById("inspector-body").innerHTML = `
    <div class="insp-title">${{escHtml(chain.chain)}}</div>
    <div><span class="chip chip-priv">${{chain.hops}}-HOP ESCALATION CHAIN</span></div>
    <div class="insp-section">
      <div class="insp-label">Gained Sink Privileges</div>
      <div>${{chain.sink_reasons.map((r) => `<span class="chip chip-priv">${{escHtml(r)}}</span>`).join("")}}</div>
    </div>
    <div class="insp-section">
      <div class="insp-label">Transition Hops</div>
      <div>${{steps}}</div>
    </div>
  `;
}}

function applyFilters() {{
  const showReview = document.getElementById("toggle-review-edges").checked;
  const query = document.getElementById("node-search").value.trim().toLowerCase();

  document.querySelectorAll(".edge-group").forEach((el) => {{
    if (el.getAttribute("data-kind") === "REVIEW_ONLY") {{
      el.style.display = showReview ? "" : "none";
    }}
  }});

  if (activeChainIdx === null) {{
    document.querySelectorAll(".node-group").forEach((el) => {{
      const name = (el.getAttribute("data-node") || "").toLowerCase();
      el.classList.toggle("dimmed", query !== "" && !name.includes(query));
    }});
    document.querySelectorAll(".edge-group").forEach((el) => {{
      const s = (el.getAttribute("data-src") || "").toLowerCase();
      const d = (el.getAttribute("data-dst") || "").toLowerCase();
      el.classList.toggle("dimmed", query !== "" && !s.includes(query) && !d.includes(query));
    }});
  }}
}}

document.getElementById("toggle-review-edges").addEventListener("change", applyFilters);
document.getElementById("node-search").addEventListener("input", () => {{
  activeChainIdx = null;
  clearSelections();
  applyFilters();
}});
document.getElementById("btn-reset").addEventListener("click", () => {{
  activeChainIdx = null;
  currentZoom = 1.0;
  document.getElementById("node-search").value = "";
  document.getElementById("policy-graph").style.transform = "scale(1)";
  clearSelections();
  applyFilters();
}});
document.getElementById("btn-zoom-in").addEventListener("click", () => {{
  currentZoom = Math.min(2.0, +(currentZoom + 0.15).toFixed(2));
  document.getElementById("policy-graph").style.transform = `scale(${{currentZoom}})`;
}});
document.getElementById("btn-zoom-out").addEventListener("click", () => {{
  currentZoom = Math.max(0.55, +(currentZoom - 0.15).toFixed(2));
  document.getElementById("policy-graph").style.transform = `scale(${{currentZoom}})`;
}});

renderGraph();
</script>
</body>
</html>
"""


def _svg_edge_curve(
    sp: dict[str, float],
    dp: dict[str, float],
    curve_bias: float,
) -> tuple[str, float, float]:
    """Compute a quadratic Bezier path string and midpoint label coordinates for static SVG."""
    if sp is dp:
        x = sp["x"] + sp["w"]
        y = sp["cy"]
        return f"M {x:.1f} {y - 10:.1f} C {x + 40:.1f} {y - 34:.1f}, {x + 40:.1f} {y + 34:.1f}, {x:.1f} {y + 10:.1f}", x + 36, y

    dx = dp["cx"] - sp["cx"]
    dy = dp["cy"] - sp["cy"]
    sx, sy = sp["cx"], sp["cy"]
    ex, ey = dp["cx"], dp["cy"]

    if abs(dy) >= abs(dx) * 0.45:
        if dy > 0:
            sy = sp["y"] + sp["h"]
            ey = dp["y"]
        else:
            sy = sp["y"]
            ey = dp["y"] + dp["h"]
    else:
        if dx > 0:
            sx = sp["x"] + sp["w"]
            ex = dp["x"]
        else:
            sx = sp["x"]
            ex = dp["x"] + dp["w"]

    mx = (sx + ex) / 2.0
    my = (sy + ey) / 2.0
    length = math.hypot(ex - sx, ey - sy) or 1.0
    nx = -(ey - sy) / length
    ny = (ex - sx) / length
    offset = curve_bias * min(54.0, max(20.0, length * 0.16))
    cx = mx + nx * offset
    cy = my + ny * offset
    # Quadratic Bezier midpoint at t=0.5
    lx = 0.25 * sx + 0.5 * cx + 0.25 * ex
    ly = 0.25 * sy + 0.5 * cy + 0.25 * ey
    return f"M {sx:.1f} {sy:.1f} Q {cx:.1f} {cy:.1f}, {ex:.1f} {ey:.1f}", lx, ly


def render_svg_preview(
    path_result: PathAnalysisResult,
    *,
    findings: list[Finding] | None = None,
    policy_path: str = "",
    ifs_path: str | None = None,
    include_review_edges: bool = True,
    verified_edges: set[tuple[str, str]] | None = None,
) -> str:
    """Render a standalone, crisp static SVG preview of the trust-zone escalation graph."""
    all_findings = findings if findings is not None else path_result.findings
    ifs_errors = [f for f in all_findings if f.rule_id in IFS_RULE_IDS]
    verified_set: set[tuple[str, str]] = set(verified_edges) if verified_edges else set()
    layout = _compute_layout(path_result)

    header_h = 74
    footer_h = 44
    width = int(layout["width"])
    height = int(layout["height"]) + header_h + footer_h

    # Map escalation chain hop labels and highlighted node/edge sets
    chain_nodes: set[str] = set()
    chain_hop_labels: dict[tuple[str, str], str] = {}
    for ep in path_result.escalation_paths:
        chain_nodes.update(ep.nodes)
        for idx, edge in enumerate(ep.edges, start=1):
            pair = (edge.src, edge.dst)
            if pair not in chain_hop_labels:
                chain_hop_labels[pair] = f"Hop {idx}: {edge.mechanism}"

    # Shift layout coordinates down by header_h
    positions: dict[str, dict[str, float]] = {}
    for name, pos in layout["positions"].items():
        positions[name] = {
            "x": pos["x"],
            "y": pos["y"] + header_h,
            "w": pos["w"],
            "h": pos["h"],
            "cx": pos["cx"],
            "cy": pos["cy"] + header_h,
        }

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<defs>",
        '  <linearGradient id="bg-grad" x1="0%" y1="0%" x2="100%" y2="100%">',
        '    <stop offset="0%" stop-color="#0f172a" />',
        '    <stop offset="100%" stop-color="#0b1120" />',
        "  </linearGradient>",
        '  <filter id="crimson-glow" x="-25%" y="-25%" width="150%" height="150%">',
        '    <feGaussianBlur stdDeviation="3" result="blur" />',
        '    <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>',
        "  </filter>",
        '  <marker id="arrow-esc" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="7.5" markerHeight="7.5" orient="auto-start-reverse">',
        '    <path d="M 0 1.2 L 10 5 L 0 8.8 z" fill="#ef4444" />',
        "  </marker>",
        '  <marker id="arrow-rev" viewBox="0 0 10 10" refX="8.5" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '    <path d="M 0 1.5 L 10 5 L 0 8.5 z" fill="#64748b" />',
        "  </marker>",
        "</defs>",
        # Card background
        f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="12" fill="url(#bg-grad)" stroke="#334155" stroke-width="1" />',
        # Header banner
        f'<rect x="1" y="1" width="{width - 2}" height="{header_h - 2}" rx="11" fill="#0f172a" />',
        f'<line x1="1" y1="{header_h}" x2="{width - 1}" y2="{header_h}" stroke="#1e293b" stroke-width="1" />',
        '<text x="24" y="30" fill="#f8fafc" font-size="16" font-weight="700" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">secpol-audit · QNX Neutrino 8.0 Privilege-Escalation Graph</text>',
        f'<text x="24" y="52" fill="#94a3b8" font-size="11.5" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">{html.escape(policy_path or "policy.secpol")}{("  +  " + html.escape(ifs_path)) if ifs_path else ""}</text>',
    ]

    # Top-right escalation banner pill
    if path_result.escalation_paths:
        hero = path_result.escalation_paths[0].chain_str()
        ep0 = path_result.escalation_paths[0]
        ep0_pairs = [(ep0.nodes[i], ep0.nodes[i + 1]) for i in range(len(ep0.nodes) - 1)]
        ep0_verified = bool(ep0_pairs) and all(p in verified_set for p in ep0_pairs)
        pill_prefix = "KERNEL TRACE VERIFIED · " if ep0_verified else f"CRITICAL {ep0.hops}-HOP: "
        pill_text = f"{pill_prefix}{hero}"
        pill_w = min(width - 400, max(300, len(pill_text) * 6.8 + 28))
        pill_x = width - pill_w - 20
        pill_stroke = "#facc15" if ep0_verified else "#ef4444"
        parts.append(
            f'<rect x="{pill_x}" y="18" width="{pill_w}" height="34" rx="7" fill="#3a121b" stroke="{pill_stroke}" stroke-width="1.5" />'
        )
        parts.append(
            f'<text x="{pill_x + pill_w / 2:.1f}" y="39" text-anchor="middle" fill="#fecaca" font-size="11.5" font-weight="700" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">{html.escape(pill_text)}</text>'
        )
    else:
        pill_w = 220
        pill_x = width - pill_w - 20
        parts.append(
            f'<rect x="{pill_x}" y="18" width="{pill_w}" height="34" rx="7" fill="#0f291e" stroke="#22c55e" stroke-width="1.2" />'
        )
        parts.append(
            f'<text x="{pill_x + pill_w / 2:.1f}" y="39" text-anchor="middle" fill="#86efac" font-size="11.5" font-weight="700" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">0 ESCALATION CHAINS (PASS)</text>'
        )

    # Trust zone bands
    for b in layout["bands"]:
        by = b["y"] + header_h
        parts.append(
            f'<rect x="{b["x"]}" y="{by}" width="{b["width"]}" height="{b["height"]}" rx="10" '
            f'fill="{b["bg"]}" stroke="{b["color"]}" stroke-opacity="0.38" stroke-width="1" />'
        )
        parts.append(
            f'<text x="{b["x"] + 14}" y="{by + 19}" fill="{b["color"]}" font-size="11.5" font-weight="700" '
            f'font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">'
            f'{html.escape(b["zone"].upper())} — {html.escape(b["desc"])} ({b["count"]})</text>'
        )

    # Layer 1: Subtle review-only edges (channel_connect / allow_link)
    if include_review_edges:
        seen_rev_pairs: set[tuple[str, str]] = set()
        for e in path_result.review_edges:
            if e.src == e.dst or (e.src, e.dst) in seen_rev_pairs:
                continue
            seen_rev_pairs.add((e.src, e.dst))
            sp = positions.get(e.src)
            dp = positions.get(e.dst)
            if not sp or not dp:
                continue
            d, _, _ = _svg_edge_curve(sp, dp, 0.55)
            parts.append(
                f'<path d="{d}" fill="none" stroke="#64748b" stroke-width="1.15" stroke-opacity="0.42" '
                f'stroke-dasharray="4,5" marker-end="url(#arrow-rev)" />'
            )

    # Layer 2: Nodes
    for name, meta in sorted(path_result.nodes.items()):
        pos = positions.get(name)
        if not pos:
            continue
        is_sink = bool(meta.get("is_sink"))
        in_chain = name in chain_nodes
        stroke = "#ef4444" if in_chain else ("#f97316" if is_sink else "#475569")
        fill = "#24111c" if in_chain else "#111c33"
        sw = 2.4 if in_chain else 1.3
        filt = ' filter="url(#crimson-glow)"' if in_chain else ""
        parts.append(
            f'<rect x="{pos["x"]}" y="{pos["y"]}" width="{pos["w"]}" height="{pos["h"]}" rx="8" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"{filt} />'
        )
        parts.append(
            f'<text x="{pos["cx"]}" y="{pos["y"] + 23}" text-anchor="middle" fill="#f8fafc" '
            f'font-size="12.5" font-weight="700" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">'
            f"{html.escape(name)}</text>"
        )
        priv_count = sum(1 for a in meta.get("abilities", []) if a.get("privileged"))
        if is_sink:
            sub_txt = f"SINK · {priv_count} priv abil"
            sub_fill = "#fca5a5"
        else:
            sub_txt = f"{len(meta.get('abilities', []))} abil · {len(meta.get('attaches', []))} attach"
            sub_fill = "#94a3b8"
        parts.append(
            f'<text x="{pos["cx"]}" y="{pos["y"] + 41}" text-anchor="middle" fill="{sub_fill}" '
            f'font-size="10" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">'
            f"{html.escape(sub_txt)}</text>"
        )

    # Layer 3: Prominent crimson ESCALATION edges on top with hop badges
    seen_esc_pairs: set[tuple[str, str]] = set()
    for e in path_result.escalation_edges:
        if e.src == e.dst or (e.src, e.dst) in seen_esc_pairs:
            continue
        seen_esc_pairs.add((e.src, e.dst))
        sp = positions.get(e.src)
        dp = positions.get(e.dst)
        if not sp or not dp:
            continue
        d, lx, ly = _svg_edge_curve(sp, dp, -1.15)
        in_chain = (e.src, e.dst) in chain_hop_labels
        is_verified = (e.src, e.dst) in verified_set
        sw = 3.2 if (in_chain or is_verified) else 2.2
        filt = ' filter="url(#crimson-glow)"' if (in_chain or is_verified) else ""
        parts.append(
            f'<path d="{d}" fill="none" stroke="#ef4444" stroke-width="{sw}" '
            f'marker-end="url(#arrow-esc)"{filt} />'
        )
        if in_chain or is_verified:
            base_lbl = chain_hop_labels.get((e.src, e.dst), e.mechanism)
            lbl = f"{base_lbl} · KERNEL TRACE VERIFIED" if is_verified else base_lbl
            bw = len(lbl) * 6.3 + 16
            pill_fill = "#422006" if is_verified else "#3a121b"
            pill_stroke = "#facc15" if is_verified else "#ef4444"
            pill_text_fill = "#fde047" if is_verified else "#fecaca"
            parts.append(
                f'<rect x="{lx - bw / 2:.1f}" y="{ly - 10:.1f}" width="{bw:.1f}" height="20" rx="4" '
                f'fill="{pill_fill}" stroke="{pill_stroke}" stroke-width="1.1" />'
            )
            parts.append(
                f'<text x="{lx:.1f}" y="{ly + 3.5:.1f}" text-anchor="middle" fill="{pill_text_fill}" '
                f'font-size="10" font-weight="700" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">'
                f"{html.escape(lbl)}</text>"
            )

    # Footer legend bar
    fy = height - footer_h
    parts.append(f'<line x1="1" y1="{fy}" x2="{width - 1}" y2="{fy}" stroke="#1e293b" stroke-width="1" />')
    parts.append(f'<line x1="24" y1="{fy + 22}" x2="54" y2="{fy + 22}" stroke="#ef4444" stroke-width="3" />')
    parts.append(
        f'<text x="62" y="{fy + 26}" fill="#e2e8f0" font-size="11" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">'
        "ESCALATION (settypeid / derive_type / default_spawn_type)</text>"
    )
    parts.append(
        f'<line x1="468" y1="{fy + 22}" x2="498" y2="{fy + 22}" stroke="#64748b" stroke-width="2" stroke-dasharray="4,4" />'
    )
    parts.append(
        f'<text x="506" y="{fy + 26}" fill="#94a3b8" font-size="11" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">'
        "REVIEW-ONLY (channel_connect / allow_link)</text>"
    )
    stats_text = (
        f"{len(path_result.nodes)} Types · {len(path_result.escalation_paths)} Escalation Chain"
        f"{'' if len(path_result.escalation_paths) == 1 else 's'} · {len(ifs_errors)} IFS Errors"
    )
    parts.append(
        f'<text x="{width - 20}" y="{fy + 26}" text-anchor="end" fill="#cbd5e1" font-size="11" font-weight="700" '
        f'font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace">{html.escape(stats_text)}</text>'
    )
    parts.append("</svg>\n")
    return "\n".join(parts)

