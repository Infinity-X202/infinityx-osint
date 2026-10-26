"""Pull comparable facts out of a finished scan. Nothing here contacts the network."""

from __future__ import annotations

import json
from typing import Any

from infinityx.models import CheckResult


def extract_snapshot(results: list[CheckResult], interrupted: bool) -> dict[str, Any]:
    """Build the small record used for history and later comparison."""
    index = {item.check_id: item for item in results}
    return {
        "interrupted": interrupted,
        "dns": {
            "a": _records(index.get("dns-a")),
            "aaaa": _records(index.get("dns-aaaa")),
            "mx": _records(index.get("dns-mx")),
            "ns": _records(index.get("dns-ns")),
            "txt": _records(index.get("dns-txt")),
            "caa": _records(index.get("dns-caa")),
            "soa": _records(index.get("dns-soa")),
        },
        "ips": _string_list(index.get("public-ips"), "ips"),
        "names": _certificate_names(index.get("cert-sans"), index.get("cert-transparency")),
        "tls": _tls(index),
        "headers": _headers(index.get("response-headers")),
    }


def _records(item: CheckResult | None) -> dict[str, Any]:
    if item is None or item.status in {"FAILED", "SKIPPED"}:
        return {"state": "unavailable", "values": []}
    records = item.data.get("records") if isinstance(item.data, dict) else None
    if not isinstance(records, list):
        return {"state": "unavailable", "values": []}
    return {"state": "present", "values": [_flat(value) for value in records]}


def _string_list(item: CheckResult | None, key: str) -> dict[str, Any]:
    if item is None or item.status in {"FAILED", "SKIPPED"}:
        return {"state": "unavailable", "values": []}
    values = item.data.get(key) if isinstance(item.data, dict) else None
    if not isinstance(values, list):
        return {"state": "unavailable", "values": []}
    return {"state": "present", "values": [_flat(value) for value in values]}


def _certificate_names(sans: CheckResult | None, transparency: CheckResult | None) -> dict[str, Any]:
    """Use only names already stored on the certificate or in the transparency response."""
    collected: list[str] = []
    sources: list[str] = []
    available = False
    for item, label, key in (
        (sans, "certificate SAN", "sans"),
        (transparency, "crt.sh", "names"),
    ):
        if item is None or item.status in {"FAILED", "SKIPPED"}:
            continue
        values = item.data.get(key) if isinstance(item.data, dict) else None
        if not isinstance(values, list):
            continue
        available = True
        sources.append(label)
        for value in values:
            text = _flat(value).lower().rstrip(".")
            if text and text not in collected:
                collected.append(text)
    if not available:
        return {"state": "unavailable", "values": [], "sources": []}
    return {"state": "present", "values": collected, "sources": sources}


def _tls(index: dict[str, CheckResult]) -> dict[str, Any]:
    issuer = index.get("cert-issuer")
    subject = index.get("cert-subject")
    validity = index.get("cert-validity")
    sans = index.get("cert-sans")
    if issuer is None or issuer.status in {"FAILED", "SKIPPED"}:
        return {"state": "unavailable"}
    fingerprint = issuer.data.get("fingerprint_sha256") if isinstance(issuer.data, dict) else None
    if not fingerprint:
        return {"state": "unavailable"}
    payload: dict[str, Any] = {
        "state": "present",
        "issuer": _flat(issuer.data.get("issuer")),
        "fingerprint": _flat(fingerprint),
        "subject": "",
        "not_after": "",
        "sans": [],
    }
    if subject is not None and subject.status not in {"FAILED", "SKIPPED"} and isinstance(subject.data, dict):
        payload["subject"] = _flat(subject.data.get("subject"))
    if validity is not None and validity.status not in {"FAILED", "SKIPPED"} and isinstance(validity.data, dict):
        payload["not_after"] = _flat(validity.data.get("not_after"))
    if sans is not None and sans.status not in {"FAILED", "SKIPPED"} and isinstance(sans.data, dict):
        names = sans.data.get("sans")
        if isinstance(names, list):
            payload["sans"] = [_flat(name).lower() for name in names]
    return payload


def _headers(item: CheckResult | None) -> dict[str, Any]:
    if item is None or item.status in {"FAILED", "SKIPPED"}:
        return {"state": "unavailable", "values": {}}
    headers = item.data.get("headers") if isinstance(item.data, dict) else None
    if not isinstance(headers, dict):
        return {"state": "unavailable", "values": {}}
    cleaned = {str(key).lower(): _flat(value) for key, value in headers.items()}
    return {"state": "present", "values": cleaned}


def _flat(value: Any) -> str:
    if isinstance(value, str):
        return value.strip()
    if value is None:
        return ""
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
