"""Reporting engine: JSON / CSV / HTML / Markdown with executive summary."""
from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from typing import Iterable

from ..core.models import ScanResult

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def summarize(findings) -> dict:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    level = "Clear"
    if counts["CRITICAL"] or counts["HIGH"] >= 2:
        level = "High risk"
    elif counts["HIGH"] or counts["MEDIUM"] >= 2:
        level = "Medium risk"
    elif counts["MEDIUM"] or counts["LOW"]:
        level = "Low risk"
    return {"counts": counts, "risk": level,
            "total": sum(counts.values()),
            "actionable": counts["CRITICAL"] + counts["HIGH"] + counts["MEDIUM"]}


def to_json(results: list[ScanResult]) -> str:
    return json.dumps({"toolkit": "tbh-security-toolkit", "results": [r.to_dict() for r in results],
                       "summary": summarize([f for r in results for f in r.findings])}, indent=2)


def to_csv(results: list[ScanResult]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["target", "module", "id", "title", "severity", "endpoint", "evidence", "remediation"])
    for r in results:
        for f in r.findings:
            w.writerow([r.target, f.module, f.id, f.title, f.severity, f.endpoint, f.evidence[:300], f.remediation[:300]])
    return buf.getvalue()


def to_markdown(results: list[ScanResult]) -> str:
    lines = ["# TBH Security Toolkit Report", ""]
    for r in results:
        s = summarize(r.findings)
        lines += [f"## {r.module} - {r.target}", f"- Started: {r.started_at} | Duration: {r.duration_s}s",
                  f"- Risk: **{s['risk']}** | Findings: {s['total']} (actionable {s['actionable']})", "",
                  "| Severity | Finding | Endpoint | Remediation |",
                  "|---|---|---|---|"]
        for f in sorted(r.findings, key=lambda x: -SEV_RANK.get(x.severity, 0)):
            lines.append(f"| {f.severity} | {f.title} | {f.endpoint[:60]} | {f.remediation[:80]} |")
        lines.append("")
    return "\n".join(lines)


def to_html(results: list[ScanResult]) -> str:
    parts = ["<!doctype html><html><head><meta charset=utf-8><title>TBH Toolkit Report</title>",
             "<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:24px}"
             ".crit{color:#ff5555}.high{color:#ff8855}.med{color:#ffcc55}.low{color:#55ccff}"
             "table{border-collapse:collapse;width:100%}td,th{border:1px solid #333;padding:6px;text-align:left}</style>",
             "</head><body><h1>TBH Security Toolkit - Scan Report</h1>"]
    for r in results:
        s = summarize(r.findings)
        parts.append(f"<h2>{html.escape(r.module)} - {html.escape(r.target)}</h2>"
                     f"<p>Started {html.escape(r.started_at)} | {r.duration_s}s | Risk: <b>{s['risk']}</b> "
                     f"| Counts: {html.escape(str(s['counts']))}</p>"
                     "<h3>Executive summary</h3>"
                     f"<p>Actionable findings: {s['actionable']} of {s['total']}. "
                     "Fix CRITICAL/HIGH first, then MEDIUM hardening.</p>"
                     "<table><tr><th>Severity</th><th>Finding</th><th>Evidence</th><th>Remediation</th></tr>")
        for f in sorted(r.findings, key=lambda x: -SEV_RANK.get(x.severity, 0)):
            cls = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med"}.get(f.severity, "low")
            parts.append(f"<tr><td class={cls}>{f.severity}</td><td>{html.escape(f.title)}<br><small>{html.escape(f.endpoint[:120])}</small><br><small>{html.escape(f.explanation[:200])}</small></td>"
                         f"<td><small>{html.escape(f.evidence[:300])}</small></td><td><small>{html.escape(f.remediation[:300])}</small></td></tr>")
        parts.append("</table>")
        if r.meta:
            parts.append(f"<h3>Scan configuration / technical details</h3><pre>{html.escape(json.dumps(r.meta, indent=2))}</pre>")
    return "".join(parts) + "</body></html>"


def write_report(results: list[ScanResult], fmt: str, output: str | Path) -> Path:
    fmt = fmt.lower()
    render = {"json": to_json, "csv": to_csv, "html": to_html, "md": to_markdown, "markdown": to_markdown}[fmt]
    out = Path(output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render(results), encoding="utf-8")
    return out
