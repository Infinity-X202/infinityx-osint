"""InfinityX OSINT Scanner, created by Infinity.

Passive, authorized information gathering for a single public domain.
The package collects public records and responses, then explains them.
It does not exploit services or prove that a site is safe or compromised.
"""

from __future__ import annotations

__version__ = "1.0.0"
TOOL_NAME = "InfinityX OSINT Scanner"
AUTHOR = "Infinity"
TOOL_SUMMARY = (
    "InfinityX OSINT Scanner is a passive information-gathering tool created by Infinity. "
    "You give it one domain you own or are allowed to assess. It collects public WHOIS, DNS, "
    "website, certificate, infrastructure, and email-authentication information, shows progress "
    "in the terminal, and writes an explained text report, a JSON report, and an HTML report. "
    "It does not guess passwords, exploit vulnerabilities, scan ports, or prove that a website "
    "is secure or compromised."
)
DISCLAIMER = (
    "Results describe what was publicly visible at scan time. They do not prove that the "
    "website is secure, and they do not prove that it has been compromised. A banner, a "
    "technology name, or a missing HTTP header is an observation, not proof of a vulnerability."
)
