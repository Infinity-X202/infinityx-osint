"""Export scan comparisons to standalone files."""

from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

from infinityx.diffscan import comparison_text


def export_comparison(diff: dict[str, Any], folder: Path) -> dict[str, str]:
    folder.mkdir(parents=True, exist_ok=True)
    txt = folder / "comparison.txt"
    js = folder / "comparison.json"
    html = folder / "comparison.html"
    txt.write_text(comparison_text(diff) + "\n", encoding="utf-8")
    js.write_text(json.dumps(diff, indent=2, ensure_ascii=False), encoding="utf-8")
    html.write_text(_html(diff), encoding="utf-8")
    return {"directory": str(folder), "txt": str(txt), "json": str(js), "html": str(html)}


def _html(diff: dict[str, Any]) -> str:
    rows = []
    for section in diff.get("sections") or []:
        rows.append(
            f"<tr><td>{escape(section['name'])}</td><td>{escape(section.get('classification', section['status']))}</td>"
            f"<td>{escape(section.get('detail', ''))}</td></tr>"
        )
    body = "\n".join(rows)
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Comparison</title>
<style>body{{font-family:Segoe UI,sans-serif;background:#0d0d0f;color:#f4f4f5}}table{{width:100%;border-collapse:collapse}}
td,th{{border:1px solid #333;padding:8px}}</style></head><body>
<h1>Scan comparison — {escape(str(diff.get('domain','')))}</h1>
<p>{escape(' '.join(diff.get('notes') or []))}</p>
<table><thead><tr><th>Section</th><th>Result</th><th>Detail</th></tr></thead><tbody>{body}</tbody></table>
</body></html>"""
