"""Normalize and validate the single domain a scan is allowed to assess."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from infinityx.safety import hostname_blocked

_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


@dataclass(frozen=True)
class NormalizedDomain:
    """A public hostname accepted as the scan target."""

    hostname: str
    unicode_name: str
    raw_input: str
    discarded_path: str | None = None


def normalize_domain(raw: str) -> NormalizedDomain:
    """Turn user input into one public hostname.

    Schemes, paths, queries, and ports are removed. The result must be a
    dotted public name, not an IP address, localhost name, or internal name.
    """
    original = raw or ""
    if len(original) > 500:
        raise ValueError("The input is too long. Enter a domain such as example.com.")
    text = original.strip().strip("\"'").strip()
    if not text or any(char.isspace() for char in text):
        raise ValueError("Enter one domain without spaces, such as example.com.")

    discarded: str | None = None
    if "://" in text:
        parsed = urlsplit(text)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only a domain, or an http or https URL, is accepted.")
        host = parsed.hostname
        if host is None:
            raise ValueError("The URL does not contain a hostname.")
        if parsed.path not in {"", "/"} or parsed.query:
            discarded = (parsed.path or "/") + (("?" + parsed.query) if parsed.query else "")
        text = host
    else:
        text = text.split("/")[0]
        if text.count(":") == 1:
            host_part, port = text.rsplit(":", 1)
            if port.isdigit():
                text = host_part

    text = text.strip().rstrip(".").lower()
    if not text:
        raise ValueError("Enter a domain such as example.com.")
    blocked = hostname_blocked(text)
    if blocked:
        raise ValueError(blocked)
    try:
        ascii_name = text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("The domain could not be converted to a DNS name.") from exc
    ascii_name = ascii_name.rstrip(".").lower()
    if len(ascii_name) > 253 or "." not in ascii_name:
        raise ValueError("Enter a full domain name such as example.com.")
    labels = ascii_name.split(".")
    if any(not _LABEL.match(label) for label in labels):
        raise ValueError("The domain contains a label that is not a valid hostname label.")
    try:
        unicode_name = ascii_name.encode("ascii").decode("idna")
    except UnicodeError:
        unicode_name = ascii_name
    blocked_ascii = hostname_blocked(ascii_name)
    if blocked_ascii:
        raise ValueError(blocked_ascii)
    return NormalizedDomain(
        hostname=ascii_name,
        unicode_name=unicode_name,
        raw_input=original.strip(),
        discarded_path=discarded,
    )
