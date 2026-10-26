"""Text, JSON, and HTML reports plus raw artifacts."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path

from infinityx import AUTHOR, DISCLAIMER, TOOL_NAME, TOOL_SUMMARY, __version__
from infinityx.analysis import counts, severity_counts
from infinityx.graph_html import correlation_graph_html
from infinityx.models import CheckResult, ScanOutcome
from infinityx.safety import clean_text

def write_reports(outcome: ScanOutcome, directory: Path, artifacts: dict[str, str]) -> dict[str, str]:
    """Write the three reports, raw outputs, and return their paths."""
    directory.mkdir(parents=True, exist_ok=True)
    raw_dir = directory / "raw_results"
    raw_dir.mkdir(exist_ok=True)
    (directory / "logs").mkdir(exist_ok=True)
    for name, content in artifacts.items():
        safe_name = Path(name).name
        (raw_dir / safe_name).write_text(clean_text(content, limit=200_000), encoding="utf-8")
    txt_path = directory / "report.txt"
    json_path = directory / "report.json"
    html_path = directory / "report.html"
    txt_path.write_text(_render_txt(outcome), encoding="utf-8")
    json_path.write_text(_render_json(outcome), encoding="utf-8")
    html_path.write_text(_render_html(outcome), encoding="utf-8")
    outcome.output_dir = str(directory)
    return {
        "directory": str(directory),
        "txt": str(txt_path),
        "json": str(json_path),
        "html": str(html_path),
        "raw": str(raw_dir),
        "logs": str(directory / "logs"),
    }


def _render_json(outcome: ScanOutcome) -> str:
    payload = {
        "tool": TOOL_NAME,
        "created_by": AUTHOR,
        "version": __version__,
        "description": TOOL_SUMMARY,
        "disclaimer": DISCLAIMER,
        "domain": outcome.domain,
        "started_at": outcome.started_at.isoformat(),
        "finished_at": outcome.finished_at.isoformat(),
        "authorization_confirmed": outcome.authorization_confirmed,
        "interrupted": outcome.interrupted,
        "output_dir": outcome.output_dir,
        "counts": counts(outcome.results),
        "severity_counts": severity_counts(outcome.results),
        "narratives": outcome.narratives,
        "historical_comparison": outcome.comparison,
        "security_analysis": outcome.analysis,
        "correlation": outcome.correlation,
        "security_audit": outcome.audit,
        "ai_summary": outcome.ai_summary,
        "plugins": [item.as_dict() for item in outcome.plugin_results],
        "history_id": outcome.history_id,
        "checks": [item.as_dict() for item in outcome.results],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False, default=str)


def _render_txt(outcome: ScanOutcome) -> str:
    status = counts(outcome.results)
    severity = severity_counts(outcome.results)
    lines = [
        TOOL_NAME,
        f"Created by {AUTHOR}",
        f"Version {__version__}",
        "",
        TOOL_SUMMARY,
        "",
        DISCLAIMER,
        "",
        f"Target domain: {outcome.domain}",
        f"Started: {outcome.started_at.isoformat()}",
        f"Finished: {outcome.finished_at.isoformat()}",
        f"Interrupted: {'yes' if outcome.interrupted else 'no'}",
        f"Authorization confirmed: {'yes' if outcome.authorization_confirmed else 'no'}",
        (
            f"Checks: {len(outcome.results)} total, {status['OK']} OK, {status['WARNING']} warning, "
            f"{status['FAILED']} failed, {status['SKIPPED']} skipped"
        ),
        "Severity counts: " + ", ".join(f"{key} {value}" for key, value in severity.items()),
        "",
        "=" * 78,
        "A. EXECUTIVE SUMMARY",
        "=" * 78,
        outcome.narratives.get("executive_summary", ""),
        "",
        "=" * 78,
        "B. COMPLETE FINDINGS",
        "=" * 78,
    ]
    for item in outcome.results:
        lines.extend(_check_block(item))
    for title, key in (
        ("C. DOMAIN INTELLIGENCE", "domain_intelligence"),
        ("D. WEBSITE ANALYSIS", "website_analysis"),
        ("E. TLS AND EMAIL SECURITY", "tls_email"),
        ("F. FINDINGS CLASSIFICATION", "classification"),
        ("G. FINAL OVERALL ASSESSMENT", "overall_assessment"),
        ("H. HISTORICAL COMPARISON", "historical_comparison"),
        ("I. SECURITY FINDINGS ANALYSIS", "security_analysis"),
        ("J. INTELLIGENCE CORRELATION", "correlation"),
        ("K. SECURITY AUDIT", "security_audit"),
        ("L. AI INTELLIGENCE (VERIFY AGAINST EVIDENCE)", "ai_intelligence"),
    ):
        lines.extend(["", "=" * 78, title, "=" * 78, outcome.narratives.get(key, "")])
    lines.extend(["", "=" * 78, "CONCLUSION", "=" * 78, outcome.narratives.get("conclusion", ""), ""])
    return "\n".join(lines)


def _check_block(item: CheckResult) -> list[str]:
    findings = "\n".join(f"  - {finding}" for finding in item.findings) or "  - none"
    overlaps = ", ".join(item.overlaps) or "none"
    return [
        "",
        f"{item.number}. {item.name}",
        f"Category: {item.category}",
        f"Status: {item.status}",
        f"Severity: {item.severity}",
        f"Observation type: {item.observation_type}",
        f"Duration: {item.duration_ms:.1f} ms",
        f"Method: {item.method}",
        f"Summary: {item.summary}",
        "Findings:",
        findings,
        f"Explanation: {item.explanation}",
        f"Why it may be useful: {item.usefulness}",
        f"Limitations: {item.limitations}",
        f"Evidence: {item.evidence}",
        f"Impact: {item.impact}",
        f"Confidence: {item.confidence}",
        f"Remediation: {item.remediation}",
        f"Error: {item.error or 'none'}",
        f"Overlaps: {overlaps}",
        f"Raw artifact: {item.raw_ref or 'none'}",
        "-" * 78,
    ]


def _render_html(outcome: ScanOutcome) -> str:
    status = counts(outcome.results)
    severity = severity_counts(outcome.results)
    cards = [
        ("Checks", str(len(outcome.results))),
        ("OK", str(status["OK"])),
        ("Warning", str(status["WARNING"])),
        ("Failed", str(status["FAILED"])),
        ("Skipped", str(status["SKIPPED"])),
        ("High", str(severity["HIGH"])),
        ("Medium", str(severity["MEDIUM"])),
        ("Low", str(severity["LOW"])),
    ]
    card_html = "\n".join(
        f'<article class="card"><p>{escape(label)}</p><strong>{escape(value)}</strong></article>'
        for label, value in cards
    )
    rows = "\n".join(_row(item) for item in outcome.results)
    details = "\n".join(_detail(item) for item in outcome.results)
    narrative = "\n".join(
        f"<section><h2>{escape(title)}</h2>{_paragraphs(outcome.narratives.get(key, ''))}</section>"
        for title, key in (
            ("Executive summary", "executive_summary"),
            ("Domain intelligence", "domain_intelligence"),
            ("Website analysis", "website_analysis"),
            ("TLS and email security", "tls_email"),
            ("Findings classification", "classification"),
            ("Overall assessment", "overall_assessment"),
            ("Historical comparison", "historical_comparison"),
            ("Security findings analysis", "security_analysis"),
            ("Intelligence correlation", "correlation"),
            ("Security audit", "security_audit"),
            ("AI intelligence", "ai_intelligence"),
        )
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escape(TOOL_NAME)} — {escape(outcome.domain)}</title>
<style>
:root {{ color-scheme: dark; --bg:#0d0d0f; --card:#17171c; --line:#2c2c34; --text:#f4f4f5; --muted:#b8b8c4; --red:#e10600; --green:#1f9d55; --yellow:#e6b325; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; font-family: Segoe UI, sans-serif; background:var(--bg); color:var(--text); line-height:1.5; }}
header {{ padding:32px 8vw 16px; border-bottom:4px solid var(--red); }}
h1 {{ margin:0 0 8px; font-size:2rem; }}
h2 {{ margin-top:2rem; }}
.by {{ color:var(--red); font-weight:700; letter-spacing:.04em; }}
.wrap {{ padding:8px 8vw 64px; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:12px; margin:20px 0; }}
.card {{ background:var(--card); border:1px solid var(--line); border-top:3px solid var(--red); padding:12px; }}
.card p {{ margin:0; color:var(--muted); font-size:.85rem; }}
.card strong {{ font-size:1.6rem; }}
.filters {{ display:flex; flex-wrap:wrap; gap:8px; margin:12px 0; }}
button {{ background:#111; color:var(--text); border:1px solid var(--line); padding:6px 10px; cursor:pointer; }}
button.active {{ border-color:var(--red); color:white; }}
table {{ width:100%; border-collapse:collapse; background:var(--card); }}
th, td {{ border-bottom:1px solid var(--line); text-align:left; padding:8px; vertical-align:top; font-size:.92rem; }}
.sev-HIGH,.sev-CRITICAL {{ color:#ff6b6b; font-weight:700; }}
.sev-MEDIUM {{ color:#ffb020; font-weight:700; }}
.sev-LOW {{ color:var(--yellow); }}
.sev-INFORMATIONAL {{ color:#8fd0a6; }}
.sev-UNASSESSED,.st-SKIPPED,.st-FAILED {{ color:var(--muted); }}
.st-OK {{ color:var(--green); }}
.st-WARNING {{ color:var(--yellow); }}
details {{ background:var(--card); border:1px solid var(--line); margin:8px 0; padding:8px 12px; }}
pre {{ white-space:pre-wrap; word-break:break-word; color:var(--muted); }}
footer {{ color:var(--muted); margin-top:32px; }}
</style>
</head>
<body>
<header>
<p class="by">CREATED BY {escape(AUTHOR.upper())}</p>
<h1>{escape(TOOL_NAME)}</h1>
<p>{escape(TOOL_SUMMARY)}</p>
<p>Target <strong>{escape(outcome.domain)}</strong> · started {escape(outcome.started_at.isoformat())} · finished {escape(outcome.finished_at.isoformat())}</p>
</header>
<main class="wrap">
<section class="cards">{card_html}</section>
{narrative}
<section>
<h2>Check results</h2>
<div class="filters">
<button type="button" data-filter="all" class="active">All</button>
<button type="button" data-filter="OK">OK</button>
<button type="button" data-filter="WARNING">Warning</button>
<button type="button" data-filter="FAILED">Failed</button>
<button type="button" data-filter="SKIPPED">Skipped</button>
<button type="button" data-filter="HIGH">High</button>
<button type="button" data-filter="MEDIUM">Medium</button>
<button type="button" data-filter="LOW">Low</button>
</div>
<table>
<thead><tr><th>#</th><th>Check</th><th>Category</th><th>Status</th><th>Severity</th><th>Summary</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
</section>
<section><h2>Technical details</h2>{details}</section>
<section><h2>Correlation graph</h2>{correlation_graph_html(outcome.correlation or {})}</section>
<section><h2>Conclusion</h2>{_paragraphs(outcome.narratives.get("conclusion", ""))}</section>
<footer>
<p>{escape(DISCLAIMER)}</p>
<p>{escape(TOOL_NAME)} version {escape(__version__)}. Created by {escape(AUTHOR)}.</p>
</footer>
</main>
<script>
document.querySelectorAll("[data-filter]").forEach(function(button) {{
  button.addEventListener("click", function() {{
    var filter = button.getAttribute("data-filter");
    document.querySelectorAll("[data-filter]").forEach(function(item) {{ item.classList.remove("active"); }});
    button.classList.add("active");
    document.querySelectorAll("tbody tr").forEach(function(row) {{
      var show = filter === "all" || row.getAttribute("data-status") === filter || row.getAttribute("data-severity") === filter;
      row.hidden = !show;
    }});
  }});
}});
</script>
</body>
</html>
"""


def _paragraphs(text: str) -> str:
    chunks = [chunk.strip() for chunk in text.split("\n\n") if chunk.strip()]
    if not chunks:
        chunks = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(f"<p>{escape(chunk)}</p>" for chunk in chunks)


def _row(item: CheckResult) -> str:
    return (
        f'<tr data-status="{escape(item.status)}" data-severity="{escape(item.severity)}">'
        f"<td>{item.number}</td><td>{escape(item.name)}</td><td>{escape(item.category)}</td>"
        f'<td class="st-{escape(item.status)}">{escape(item.status)}</td>'
        f'<td class="sev-{escape(item.severity)}">{escape(item.severity)}</td>'
        f"<td>{escape(item.summary)}</td></tr>"
    )


def _detail(item: CheckResult) -> str:
    findings = "".join(f"<li>{escape(finding)}</li>" for finding in item.findings) or "<li>None.</li>"
    return f"""<details>
<summary>{item.number}. {escape(item.name)} — {escape(item.status)} / {escape(item.severity)}</summary>
<p><strong>Category:</strong> {escape(item.category)}</p>
<p><strong>Method:</strong> {escape(item.method)}</p>
<p><strong>Duration:</strong> {item.duration_ms:.1f} ms</p>
<p><strong>Explanation:</strong> {escape(item.explanation)}</p>
<p><strong>Usefulness:</strong> {escape(item.usefulness)}</p>
<p><strong>Evidence:</strong> {escape(item.evidence)}</p>
<p><strong>Impact:</strong> {escape(item.impact)}</p>
<p><strong>Confidence:</strong> {escape(item.confidence)}</p>
<p><strong>Limitations:</strong> {escape(item.limitations)}</p>
<p><strong>Remediation:</strong> {escape(item.remediation)}</p>
<p><strong>Error:</strong> {escape(item.error or "none")}</p>
<ul>{findings}</ul>
</details>"""
