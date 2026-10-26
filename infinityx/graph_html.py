"""Inline HTML graph view without external CDNs."""

from __future__ import annotations

from html import escape
from typing import Any


def correlation_graph_html(graph: dict[str, Any]) -> str:
    """Render a readable static graph section."""
    entities = graph.get("entities") or []
    relationships = graph.get("relationships") or []
    if not entities:
        return "<p>No correlation entities were recorded.</p>"
    node_lines = "".join(
        f"<li><strong>{escape(ent['kind'])}</strong> {escape(ent['value'])} "
        f"<span class='muted'>({escape(ent['source'])}, {escape(ent['confidence'])})</span></li>"
        for ent in entities[:80]
    )
    edge_lines = "".join(
        f"<li>{escape(rel['from_id'])} → {escape(rel['to_id'])} "
        f"<em>{escape(rel['type'])}</em> — {escape(rel.get('evidence', '')[:120])}</li>"
        for rel in relationships[:80]
        if rel["from_id"] != rel["to_id"] or rel["type"] not in {"authorized_target"}
    )
    extra = ""
    if len(entities) > 80 or len(relationships) > 80:
        extra = "<p class='muted'>Graph truncated for readability. See correlation.json for the full export.</p>"
    return f"<h3>Entities</h3><ul>{node_lines}</ul><h3>Relationships</h3><ul>{edge_lines}</ul>{extra}"
