"""Build an evidence-backed correlation graph from scan results."""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from infinityx.models import CheckResult
from infinityx.safety import clean_text


def build_correlation_graph(
    domain: str,
    results: list[CheckResult],
    *,
    subdomains: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Return entities, relationships, summary, and exportable graph data."""
    observed_at = datetime.now(timezone.utc).isoformat()
    index = {item.check_id: item for item in results}
    entities: dict[str, dict[str, Any]] = {}
    relationships: list[dict[str, Any]] = []
    rel_seen: set[tuple[str, str, str]] = set()

    def entity(kind: str, value: str, source: str, confidence: str = "high", **meta: Any) -> str:
        key = f"{kind}:{value.lower()}"
        if key not in entities:
            entities[key] = {
                "id": key,
                "kind": kind,
                "value": value,
                "source": source,
                "observed_at": observed_at,
                "confidence": confidence,
                "metadata": meta,
            }
        return key

    root = entity("domain", domain, "scan_target")
    _link(
        relationships,
        rel_seen,
        "scan_target",
        root,
        root,
        "authorized_target",
        "Operator input after confirmation",
        observed_at,
        "high",
        direct=True,
        evidence=f"Target domain {domain}",
    )

    _from_records(entity, index, "dns-a", "ip", "domain_resolves_to_ip", root, relationships, rel_seen, observed_at, "A")
    _from_records(entity, index, "dns-aaaa", "ip", "domain_resolves_to_ip", root, relationships, rel_seen, observed_at, "AAAA")
    _from_records(entity, index, "dns-ns", "nameserver", "domain_uses_nameserver", root, relationships, rel_seen, observed_at, "NS")
    _from_records(entity, index, "dns-mx", "mail_server", "domain_advertises_mail_server", root, relationships, rel_seen, observed_at, "MX")

    for ip in _ips(index):
        ip_id = entity("ip", ip, "dns/public-ips", confidence="high")
        _link(
            relationships,
            rel_seen,
            "dns/public-ips",
            root,
            ip_id,
            "domain_resolves_to_ip",
            "dns-a or public-ips",
            observed_at,
            "high",
            evidence=ip,
        )
        asn_item = index.get("asn-ownership")
        if asn_item and asn_item.status not in {"FAILED", "SKIPPED"}:
            for line in asn_item.findings:
                if line.lower().startswith("asn"):
                    asn_val = line.split(":", 1)[-1].strip()
                    asn_id = entity("asn", asn_val, "ripestat", confidence="medium")
                    _link(
                        relationships,
                        rel_seen,
                        "asn-ownership",
                        ip_id,
                        asn_id,
                        "ip_associated_with_asn",
                        "RIPEstat prefix lookup",
                        observed_at,
                        "medium",
                        evidence=line,
                        limitations="ASN holder names describe routing, not legal ownership of the website.",
                    )

    cert = index.get("cert-sans")
    if cert and cert.status not in {"FAILED", "SKIPPED"}:
        names = cert.data.get("sans") if isinstance(cert.data, dict) else []
        if isinstance(names, list):
            for name in names[:40]:
                host = str(name).lower().rstrip(".")
                if not host:
                    continue
                hid = entity("hostname", host, "tls/cert-sans", confidence="high")
                _link(
                    relationships,
                    rel_seen,
                    "cert-sans",
                    hid,
                    hid,
                    "certificate_contains_hostname",
                    "Leaf certificate SAN",
                    observed_at,
                    "high",
                    evidence=host,
                )
                if host != domain and host.endswith("." + domain):
                    sid = entity("subdomain", host, "tls/cert-sans", confidence="high")
                    _link(relationships, rel_seen, "cert-sans", sid, hid, "same_hostname", "SAN label", observed_at, "high", evidence=host)

    ct = index.get("cert-transparency")
    if ct and ct.status not in {"FAILED", "SKIPPED"} and isinstance(ct.data, dict):
        for name in ct.data.get("names") or []:
            host = str(name).lower().rstrip(".")
            if not host or not _in_scope(host, domain):
                continue
            hid = entity("hostname", host, "crt.sh", confidence="medium")
            _link(
                relationships,
                rel_seen,
                "cert-transparency",
                hid,
                hid,
                "certificate_transparency_name",
                "crt.sh query",
                observed_at,
                "medium",
                evidence=host,
                limitations="Historical CT names are not proof the host is live or under your control.",
            )

    if subdomains:
        for row in subdomains:
            host = str(row.get("hostname", "")).lower()
            if not host:
                continue
            sid = entity("subdomain", host, row.get("source", "subdomain_intel"), confidence=row.get("confidence", "medium"))
            _link(
                relationships,
                rel_seen,
                row.get("source", "subdomain_intel"),
                root,
                sid,
                "domain_has_subdomain",
                row.get("source", "subdomain_intel"),
                observed_at,
                row.get("confidence", "medium"),
                evidence=host,
                limitations=row.get("limitation", "Discovery does not prove the host is active."),
            )
            for ip in row.get("addresses") or []:
                ip_id = entity("ip", str(ip), "subdomain_dns", confidence="medium")
                _link(
                    relationships,
                    rel_seen,
                    "subdomain_dns",
                    sid,
                    ip_id,
                    "hostname_resolves_to_ip",
                    "Optional A lookup",
                    observed_at,
                    "medium",
                    evidence=f"{host} -> {ip}",
                )

    whatweb = index.get("whatweb")
    if whatweb and whatweb.status not in {"FAILED", "SKIPPED"}:
        tech = clean_text(whatweb.summary, 200)
        tid = entity("technology", tech, "whatweb", confidence="low")
        _link(
            relationships,
            rel_seen,
            "whatweb",
            root,
            tid,
            "host_exposes_technology",
            "WhatWeb aggression 1",
            observed_at,
            "low",
            evidence=tech,
            limitations="Technology names are hints, not verified vulnerabilities.",
        )

    for item in results:
        if item.severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} or item.observation_type == "verified_issue":
            fid = entity("finding", f"{item.number}:{item.check_id}", item.check_id, confidence=item.confidence)
            entities[fid]["metadata"] = {"severity": item.severity, "summary": item.summary}
            _link(
                relationships,
                rel_seen,
                item.check_id,
                fid,
                root,
                "finding_concerns_asset",
                item.check_id,
                observed_at,
                item.confidence,
                evidence=item.summary,
            )

    entity_list = list(entities.values())
    summary = _summary_text(domain, entity_list, relationships)
    return {
        "domain": domain,
        "generated_at": observed_at,
        "entities": entity_list,
        "relationships": relationships,
        "summary": summary,
        "limitations": [
            "Relationships are built only from observations in this scan.",
            "Shared IP, CDN, certificate, or ASN data does not imply common ownership.",
            "Inferred links are not created when evidence is missing.",
        ],
    }


def correlation_summary_text(graph: dict[str, Any]) -> str:
    return graph.get("summary", "")


def export_graph_json(graph: dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(graph, indent=2, ensure_ascii=False), encoding="utf-8")


def export_graph_dot(graph: dict[str, Any], path: Path) -> None:
    lines = ["digraph infinityx {", '  graph [rankdir=LR];', '  node [fontsize=10];']
    for ent in graph.get("entities") or []:
        label = f"{ent['kind']}\\n{ent['value'][:48]}"
        lines.append(f'  "{ent["id"]}" [label="{label}"];')
    for rel in graph.get("relationships") or []:
        if rel["from_id"] == rel["to_id"] and rel["type"] in {"authorized_target", "same_hostname", "certificate_contains_hostname", "certificate_transparency_name"}:
            continue
        lines.append(f'  "{rel["from_id"]}" -> "{rel["to_id"]}" [label="{rel["type"]}"];')
    lines.append("}")
    path.write_text("\n".join(lines), encoding="utf-8")


def render_graphviz_png(dot_path: Path, png_path: Path) -> str | None:
    dot = shutil.which("dot")
    if not dot:
        return "Graphviz dot is not installed. DOT export is still available."
    try:
        completed = subprocess.run(
            [dot, "-Tpng", str(dot_path), "-o", str(png_path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return str(exc)
    if completed.returncode != 0:
        return (completed.stderr or "Graphviz failed").strip()[:300]
    return None


def _from_records(
    entity: Callable[..., str],
    index: dict[str, CheckResult],
    check_id: str,
    kind: str,
    rel_type: str,
    root: str,
    relationships: list,
    rel_seen: set,
    observed_at: str,
    label: str,
) -> None:
    item = index.get(check_id)
    if item is None or item.status in {"FAILED", "SKIPPED"}:
        return
    records = item.data.get("records") if isinstance(item.data, dict) else None
    if not isinstance(records, list):
        return
    for raw in records:
        value = str(raw).strip()
        if not value or value == ".":
            continue
        eid = entity(kind, value, f"dns/{check_id}", confidence="high")
        _link(
            relationships,
            rel_seen,
            check_id,
            root,
            eid,
            rel_type,
            f"DNS {label}",
            observed_at,
            "high",
            evidence=value,
        )


def _ips(index: dict[str, CheckResult]) -> list[str]:
    item = index.get("public-ips")
    if item is None or item.status in {"FAILED", "SKIPPED"}:
        return []
    ips = item.data.get("ips") if isinstance(item.data, dict) else []
    return [str(ip) for ip in ips] if isinstance(ips, list) else []


def _in_scope(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _link(
    relationships: list,
    rel_seen: set,
    source: str,
    from_id: str,
    to_id: str,
    rel_type: str,
    evidence_source: str,
    observed_at: str,
    confidence: str,
    *,
    direct: bool = True,
    evidence: str = "",
    limitations: str = "",
) -> None:
    key = (from_id, to_id, rel_type)
    if key in rel_seen:
        return
    rel_seen.add(key)
    relationships.append(
        {
            "id": f"rel:{len(relationships)+1}",
            "type": rel_type,
            "from_id": from_id,
            "to_id": to_id,
            "source": evidence_source,
            "observed_at": observed_at,
            "confidence": confidence,
            "direct": direct,
            "evidence": evidence,
            "limitations": limitations,
        }
    )


def _summary_text(domain: str, entities: list[dict], relationships: list[dict]) -> str:
    counts: dict[str, int] = {}
    for ent in entities:
        counts[ent["kind"]] = counts.get(ent["kind"], 0) + 1
    parts = [f"Correlation for {domain} from {len(entities)} entities and {len(relationships)} relationships."]
    for kind in ("ip", "subdomain", "hostname", "nameserver", "mail_server", "asn", "technology", "finding"):
        if counts.get(kind):
            parts.append(f"{kind}: {counts[kind]}")
    parts.append(
        "Shared hosting or CDN addresses are linked as observations only. "
        "They are not treated as proof that separate domains belong to the same owner."
    )
    return " ".join(parts)