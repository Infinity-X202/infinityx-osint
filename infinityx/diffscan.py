"""Compare two stored snapshots. This does not run checks again."""

from __future__ import annotations

from typing import Any


def compare_snapshots(
    older: dict[str, Any],
    newer: dict[str, Any],
    *,
    older_label: str,
    newer_label: str,
    domain: str,
) -> dict[str, Any]:
    """Report added, removed, and changed public facts. Missing data stays uncompared."""
    sections = [
        _set_section("DNS A records", older.get("dns", {}).get("a"), newer.get("dns", {}).get("a")),
        _set_section("DNS AAAA records", older.get("dns", {}).get("aaaa"), newer.get("dns", {}).get("aaaa")),
        _set_section("DNS MX records", older.get("dns", {}).get("mx"), newer.get("dns", {}).get("mx")),
        _set_section("DNS NS records", older.get("dns", {}).get("ns"), newer.get("dns", {}).get("ns")),
        _set_section("DNS TXT records", older.get("dns", {}).get("txt"), newer.get("dns", {}).get("txt")),
        _set_section("DNS CAA records", older.get("dns", {}).get("caa"), newer.get("dns", {}).get("caa")),
        _set_section("DNS SOA record", older.get("dns", {}).get("soa"), newer.get("dns", {}).get("soa")),
        _set_section("IP addresses", older.get("ips"), newer.get("ips")),
        _set_section("Subdomains and certificate names", older.get("names"), newer.get("names")),
        _tls_section(older.get("tls") or {}, newer.get("tls") or {}),
        _header_section(older.get("headers") or {}, newer.get("headers") or {}),
    ]
    notes = [
        f"Compared {older_label} with {newer_label} for {domain}.",
        "Added means it appears only in the later scan. Removed means it appears only in the earlier scan.",
        "A failed or skipped check is not compared, so a missing result is not reported as a removal.",
    ]
    if older.get("interrupted") or newer.get("interrupted"):
        notes.append("At least one scan was interrupted. Unfinished checks stay uncompared.")
    return {
        "domain": domain,
        "older_label": older_label,
        "newer_label": newer_label,
        "notes": notes,
        "sections": sections,
    }


def comparison_text(diff: dict[str, Any] | None) -> str:
    """Render a comparison for the text and HTML reports."""
    if not diff:
        return (
            "No earlier completed snapshot of this domain is stored on this computer, "
            "so no historical comparison was made. This scan is saved locally and can be compared next time."
        )
    lines = list(diff.get("notes") or [])
    for section in diff.get("sections") or []:
        lines.append("")
        lines.append(f"{section['name']}: {section['status'].replace('_', ' ')}")
        if section.get("detail"):
            lines.append(section["detail"])
        for label in ("added", "removed"):
            values = section.get(label) or []
            if values:
                lines.append(f"{label.capitalize()}: " + ", ".join(values))
        for change in section.get("changed") or []:
            lines.append(f"Changed {change['field']}: {change['before']} -> {change['after']}")
    return "\n".join(lines)


def _set_section(name: str, older: dict[str, Any] | None, newer: dict[str, Any] | None) -> dict[str, Any]:
    before = older or {"state": "unavailable", "values": []}
    after = newer or {"state": "unavailable", "values": []}
    if before.get("state") != "present" or after.get("state") != "present":
        return _section(name, "not_compared", detail="One or both scans did not collect this fact.")
    old_values = set(before.get("values") or [])
    new_values = set(after.get("values") or [])
    added = sorted(new_values - old_values)
    removed = sorted(old_values - new_values)
    if not added and not removed:
        return _section(name, "unchanged")
    status = "changed" if added and removed else "added" if added else "removed"
    detail = ""
    sources = after.get("sources") or before.get("sources")
    if sources:
        detail = "Names come only from " + " and ".join(sources) + ". No extra name was guessed."
    return _section(name, status, added=added, removed=removed, detail=detail)


def _tls_section(older: dict[str, Any], newer: dict[str, Any]) -> dict[str, Any]:
    if older.get("state") != "present" or newer.get("state") != "present":
        return _section("TLS certificate", "not_compared", detail="One or both scans did not collect a leaf certificate.")
    changes = []
    for field in ("issuer", "subject", "fingerprint", "not_after"):
        if older.get(field) != newer.get(field):
            changes.append({"field": field, "before": older.get(field) or "", "after": newer.get(field) or ""})
    old_sans = set(older.get("sans") or [])
    new_sans = set(newer.get("sans") or [])
    added = sorted(new_sans - old_sans)
    removed = sorted(old_sans - new_sans)
    if not changes and not added and not removed:
        return _section("TLS certificate", "unchanged")
    return _section("TLS certificate", "changed", added=added, removed=removed, changed=changes)


def _header_section(older: dict[str, Any], newer: dict[str, Any]) -> dict[str, Any]:
    if older.get("state") != "present" or newer.get("state") != "present":
        return _section("HTTP headers", "not_compared", detail="One or both scans did not store homepage headers.")
    before = older.get("values") or {}
    after = newer.get("values") or {}
    added = sorted(set(after) - set(before))
    removed = sorted(set(before) - set(after))
    changed = [
        {"field": key, "before": before[key], "after": after[key]}
        for key in sorted(set(before) & set(after))
        if before[key] != after[key]
    ]
    if not added and not removed and not changed:
        return _section("HTTP headers", "unchanged")
    status = "changed" if changed or (added and removed) else "added" if added else "removed"
    return _section("HTTP headers", status, added=added, removed=removed, changed=changed)


def _section(
    name: str,
    status: str,
    *,
    added: list[str] | None = None,
    removed: list[str] | None = None,
    changed: list[dict[str, str]] | None = None,
    detail: str = "",
) -> dict[str, Any]:
    classification = _classify(status, added, removed, changed)
    return {
        "name": name,
        "status": status,
        "classification": classification,
        "added": added or [],
        "removed": removed or [],
        "changed": changed or [],
        "detail": detail,
    }


def _classify(
    status: str,
    added: list[str] | None,
    removed: list[str] | None,
    changed: list[dict[str, str]] | None,
) -> str:
    if status == "not_compared":
        return "UNKNOWN"
    if status == "unchanged":
        return "UNCHANGED"
    if changed:
        return "CHANGED"
    if added and removed:
        return "CHANGED"
    if added:
        return "ADDED"
    if removed:
        return "REMOVED"
    if status == "changed":
        return "CHANGED"
    return "UNKNOWN"
