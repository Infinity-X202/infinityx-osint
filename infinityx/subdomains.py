"""Passive subdomain discovery from public sources."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from infinityx.context import ScanContext
from infinityx.net import query_dns
from infinityx.safety import ip_is_public


def hostname_in_scope(hostname: str, domain: str) -> bool:
    """True when the name is the apex or a subdomain of the authorized domain."""
    host = hostname.lower().rstrip(".")
    base = domain.lower().rstrip(".")
    if not host or ".." in host or host.startswith(".") or host.endswith("."):
        return False
    return host == base or host.endswith("." + base)


def discover_subdomains(
    ctx: ScanContext,
    *,
    resolve_dns: bool = True,
    max_resolve: int = 25,
    resolve_delay: float = 0.2,
) -> dict[str, Any]:
    """Collect hostnames from CT and optional DNS, without brute force."""
    domain = ctx.domain
    discovered: dict[str, dict[str, Any]] = {}
    errors: list[str] = []

    rows, ct_error = ctx.certificate_transparency()
    if ct_error:
        errors.append(f"crt.sh: {ct_error}")
    for row in rows:
        for key in ("name_value", "common_name"):
            raw = row.get(key)
            if not raw:
                continue
            for piece in str(raw).split("\n"):
                host = piece.strip().lower().rstrip(".")
                if not hostname_in_scope(host, domain) or host == domain:
                    continue
                _add(discovered, host, "certificate_transparency", "medium", "Historical CT entry. Not proof the host is live.")

    whois = ctx.whois()
    if whois.ok:
        for ns in whois.nameservers:
            host = ns.lower().rstrip(".")
            if hostname_in_scope(host, domain) and host != domain:
                _add(discovered, host, "whois_nameserver", "low", "Nameserver hostname in WHOIS, not a site discovery.")

    resolved_count = 0
    if resolve_dns:
        for host in sorted(discovered):
            if resolved_count >= max_resolve:
                discovered[host]["resolution"] = "not_attempted"
                discovered[host]["limitation"] = "Resolution cap reached for this run."
                continue
            answer = query_dns("A", host, resolver="1.1.1.1")
            resolved_count += 1
            time.sleep(resolve_delay)
            if answer.status in {"timeout", "error"}:
                discovered[host]["resolution"] = "error"
                discovered[host]["error"] = answer.error or answer.status
            elif not answer.records:
                discovered[host]["resolution"] = "unresolved"
            else:
                public = [ip for ip in answer.records if ip_is_public(ip)]
                discovered[host]["resolution"] = "resolved" if public else "private_only"
                discovered[host]["addresses"] = public
            discovered[host]["resolved_at"] = datetime.now(timezone.utc).isoformat()

    hosts = list(discovered.values())
    return {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": len(hosts),
        "hosts": hosts,
        "errors": errors,
        "limitations": [
            "No wordlist brute force was used.",
            "A name in CT or a certificate does not prove the host is active.",
            "Only names inside the authorized domain scope were kept.",
        ],
    }


def subdomain_table_text(payload: dict[str, Any]) -> str:
    lines = [f"Passive subdomain intelligence for {payload.get('domain')}: {payload.get('count', 0)} hostname(s)."]
    for err in payload.get("errors") or []:
        lines.append(f"Source note: {err}")
    for row in payload.get("hosts") or []:
        lines.append(
            f"- {row.get('hostname')} [{row.get('source')}] resolution={row.get('resolution', 'unknown')} "
            f"addresses={', '.join(row.get('addresses') or []) or 'none'}"
        )
    return "\n".join(lines)


def write_subdomain_report(folder: Path, payload: dict[str, Any]) -> dict[str, str]:
    base = Path(folder)
    base.mkdir(parents=True, exist_ok=True)
    json_path = base / "subdomains.json"
    txt_path = base / "subdomains.txt"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    txt_path.write_text(subdomain_table_text(payload) + "\n", encoding="utf-8")
    return {"directory": str(base), "json": str(json_path), "txt": str(txt_path)}


def _add(store: dict[str, dict[str, Any]], host: str, source: str, confidence: str, limitation: str) -> None:
    if host not in store:
        store[host] = {
            "hostname": host,
            "source": source,
            "sources": [source],
            "confidence": confidence,
            "limitation": limitation,
            "discovered_at": datetime.now(timezone.utc).isoformat(),
            "resolution": "unverified",
        }
    elif source not in store[host]["sources"]:
        store[host]["sources"].append(source)

