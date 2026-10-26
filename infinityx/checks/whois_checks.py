"""Domain syntax and public WHOIS checks.

Checks that share one WHOIS conversation say so. They do not send extra queries
and they do not repeat the full WHOIS record as if it were a new discovery.
"""

from __future__ import annotations

from datetime import datetime, timezone

from infinityx.context import ScanContext
from infinityx.models import CheckResult
from infinityx.models import build_result as result
from infinityx.validation import normalize_domain

_SHARED = (
    "This field comes from the single public WHOIS conversation shared with the other "
    "WHOIS checks. It is not a separate discovery or a second query."
)


def check_normalize(ctx: ScanContext) -> CheckResult:
    """Confirm that the operator input is one public hostname."""
    try:
        parsed = normalize_domain(ctx.raw_input)
    except ValueError as exc:
        return result(
            status="FAILED",
            severity="UNASSESSED",
            summary="The domain could not be validated.",
            findings=[str(exc)],
            data={"raw_input": ctx.raw_input},
            method="Local hostname validation. No network query.",
            explanation="InfinityX only scans a single public hostname. The input did not pass that check, so no further assessment of this value was attempted.",
            usefulness="Stopping here prevents the scanner from treating a URL path, an internal name, or an address literal as a normal public website.",
            limitations="Syntax validation does not prove that the domain is registered or reachable.",
            evidence=str(exc),
            impact="No scan of this input was performed.",
            confidence="high",
            remediation="Enter the bare domain, such as example.com.",
            observation_type="unavailable",
            error=str(exc),
        )
    findings = [
        f"Normalized hostname: {parsed.hostname}",
        f"Unicode name: {parsed.unicode_name}",
    ]
    if parsed.discarded_path:
        findings.append(f"Discarded URL path or query: {parsed.discarded_path}")
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"{parsed.hostname} is a syntactically valid public hostname.",
        findings=findings,
        data={
            "hostname": parsed.hostname,
            "unicode_name": parsed.unicode_name,
            "discarded_path": parsed.discarded_path,
        },
        method="Local validation: strip scheme, path, query, and port; convert IDNA; reject IP literals, localhost, and internal names. No network query.",
        explanation="The scanner will use this hostname for every later check. A valid name only means the text is a public-style domain, not that any service is correctly configured.",
        usefulness="Every later result is tied to one explicit hostname instead of an unchecked string.",
        limitations="This check does not query DNS or WHOIS. A syntactically valid name can still be unregistered or pointed at an address InfinityX will refuse to contact.",
        evidence=parsed.hostname,
        impact="None. This is a gate for the rest of the scan.",
        confidence="high",
        remediation="No action is required when the displayed hostname is the site you intended to assess.",
    )


def check_whois_record(ctx: ScanContext) -> CheckResult:
    """Retrieve and summarize the public WHOIS conversation."""
    info = ctx.whois()
    if not info.ok:
        return _whois_failed(info.error or "WHOIS lookup failed.")
    if info.error:
        return result(
            status="WARNING",
            severity="UNASSESSED",
            summary=info.error,
            findings=[info.error, f"Servers queried: {', '.join(info.servers) or 'none'}"],
            data={"servers": info.servers, "match": False},
            method="WHOIS port 43 query to whois.iana.org, then the referred registry server, then the registrar server when one is published.",
            explanation="The WHOIS servers answered, but the text did not contain a normal matching registration. Some registries redact or withhold details, and some names are not registered.",
            usefulness="Knowing that registration data was not published prevents later checks from inventing a registrar or a date.",
            limitations=_SHARED + " WHOIS text is untrusted and is not a cryptographic proof of ownership.",
            evidence=info.error,
            impact="Registration details could not be assessed from WHOIS.",
            confidence="medium",
            remediation="Compare the name with the registrar account if you are the operator. A missing public WHOIS record can be normal for some TLDs.",
            observation_type="unavailable",
            raw_ref="whois.txt",
            overlaps=["registrar", "creation-date", "expiration-date", "updated-date", "whois-nameservers", "domain-status"],
        )
    present = []
    if info.registrar:
        present.append("registrar")
    if info.creation_raw:
        present.append("creation date")
    if info.expiration_raw:
        present.append("expiration date")
    if info.updated_raw:
        present.append("updated date")
    if info.nameservers:
        present.append("nameservers")
    if info.statuses:
        present.append("status codes")
    summary = "A public WHOIS record was retrieved."
    if present:
        summary += " Visible fields: " + ", ".join(present) + "."
    else:
        summary += " No common registration fields were recognized in the text."
    return result(
        status="OK" if present else "WARNING",
        severity="INFORMATIONAL" if present else "UNASSESSED",
        summary=summary,
        findings=[
            f"WHOIS servers: {', '.join(info.servers)}",
            "Individual fields are reported by the following WHOIS checks and are not repeated here as new discoveries.",
        ],
        data={"servers": info.servers, "fields_present": present},
        method="WHOIS port 43 query to whois.iana.org, then the referred registry server, then the registrar server when one is published. The raw text is stored in raw_results/whois.txt.",
        explanation="WHOIS is a public registration record. It can identify the sponsoring registrar and the dates the registry chose to publish. It is not a security test of the website.",
        usefulness="Operators use it to confirm which registrar publishes the domain and which dates and nameservers are visible to the public.",
        limitations=_SHARED + " Formats differ by registry. A missing field often means it was not published, not that it does not exist.",
        evidence=", ".join(info.servers) if info.servers else "No server list was recorded.",
        impact="Informational. The record discloses whatever the registry and registrar already publish.",
        confidence="medium",
        remediation="If a published field is wrong, correct it through the registrar. Do not treat a successful WHOIS lookup as proof that the website is secure.",
        raw_ref="whois.txt",
        overlaps=["registrar", "creation-date", "expiration-date", "updated-date", "whois-nameservers", "domain-status"],
    )


def check_registrar(ctx: ScanContext) -> CheckResult:
    """Report the registrar name when WHOIS published one."""
    info = ctx.whois()
    if not info.ok:
        return _whois_failed(info.error or "WHOIS lookup failed.")
    if not info.registrar:
        return result(
            status="WARNING",
            severity="UNASSESSED",
            summary="No registrar name was published in the WHOIS text.",
            findings=["The shared WHOIS text did not contain a recognizable Registrar field."],
            data={"registrar": None},
            method="Parse the Registrar field from the shared WHOIS text. No additional query.",
            explanation="Many registries publish the sponsoring registrar. This response did not include a value InfinityX could recognize, or the registry does not publish one.",
            usefulness="The registrar name tells an administrator where the domain is managed.",
            limitations=_SHARED,
            evidence="Registrar field not present.",
            impact="The managing registrar could not be confirmed from public WHOIS.",
            confidence="medium",
            remediation="Check the registrar control panel if you operate the domain. Absence from WHOIS is not a vulnerability.",
            observation_type="unavailable",
            overlaps=["whois-record"],
            raw_ref="whois.txt",
        )
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"Published registrar: {info.registrar}",
        findings=[info.registrar],
        data={"registrar": info.registrar},
        method="Parse the Registrar field from the shared WHOIS text. No additional query.",
        explanation="The registrar is the organization that sponsors the domain in the registry. The name is an administrative fact, not a measurement of website security.",
        usefulness="It shows where an authorized administrator would change nameservers, contacts, or renewal settings.",
        limitations=_SHARED + " The string is copied from WHOIS and can be a display name rather than a legal entity check.",
        evidence=info.registrar,
        impact="Informational disclosure that is inherent to public WHOIS.",
        confidence="medium",
        remediation="Confirm that this is the registrar you expect. Move or lock the domain at that registrar if it is not.",
        overlaps=["whois-record"],
        raw_ref="whois.txt",
    )


def check_creation_date(ctx: ScanContext) -> CheckResult:
    """Report the published creation date."""
    info = ctx.whois()
    if not info.ok:
        return _whois_failed(info.error or "WHOIS lookup failed.")
    return _date_result(
        label="Creation date",
        raw=info.creation_raw,
        parsed=info.creation,
        check_explanation="The creation date is when the registry says the current registration began. It can help an administrator recognize a newly registered or long-lived name. It does not describe the website content.",
    )


def check_expiration_date(ctx: ScanContext) -> CheckResult:
    """Report the published expiration date and how close it is."""
    info = ctx.whois()
    if not info.ok:
        return _whois_failed(info.error or "WHOIS lookup failed.")
    if not info.expiration_raw:
        return _missing_date("Expiration date")
    if info.expiration is None:
        return _unparsed_date("Expiration date", info.expiration_raw)
    days = int((info.expiration - datetime.now(timezone.utc)).total_seconds() // 86400)
    if days < 0:
        status, severity, observation = "WARNING", "HIGH", "verified_issue"
        summary = f"The published expiration date is in the past ({info.expiration_raw}, about {abs(days)} days ago)."
        impact = "If this date is accurate, the registration may have expired or be in a grace period. Mail and website resolution can stop or be taken over when a name lapses."
        remediation = "Renew the domain at the registrar immediately if you still operate it, and confirm the public date after renewal."
        confidence = "medium"
    elif days <= 7:
        status, severity, observation = "WARNING", "HIGH", "configuration_observation"
        summary = f"The published expiration date is within 7 days ({info.expiration_raw})."
        impact = "A registration this close to expiry can lapse if auto-renew fails."
        remediation = "Confirm auto-renew and the registrar billing contact."
        confidence = "medium"
    elif days <= 30:
        status, severity, observation = "WARNING", "MEDIUM", "configuration_observation"
        summary = f"The published expiration date is within 30 days ({info.expiration_raw})."
        impact = "The name should be renewed soon if it is still in use."
        remediation = "Confirm the renewal date in the registrar account."
        confidence = "medium"
    else:
        status, severity, observation = "OK", "INFORMATIONAL", "informational"
        summary = f"Published expiration date: {info.expiration_raw} (about {days} days remaining)."
        impact = "No near-term expiry was calculated from the published date."
        remediation = "Keep renewal monitoring in the registrar account."
        confidence = "medium"
    return result(
        status=status,
        severity=severity,
        summary=summary,
        findings=[f"Raw value: {info.expiration_raw}", f"Days relative to this scan: {days}"],
        data={"expiration_raw": info.expiration_raw, "days_remaining": days},
        method="Parse the expiry field from the shared WHOIS text and calculate the difference from the scan time. No additional query.",
        explanation="Registries publish an expiry date so the public can see when the registration term ends. InfinityX compares that parsed date with the clock on this computer.",
        usefulness="A close or past expiry is one of the few registration findings that can need prompt administrative action.",
        limitations=_SHARED + " The calculation is only as good as the published string. Grace periods and auto-renew are not visible here. Timezone-less dates were read as UTC.",
        evidence=info.expiration_raw,
        impact=impact,
        confidence=confidence,
        remediation=remediation,
        observation_type=observation,
        overlaps=["whois-record"],
        raw_ref="whois.txt",
    )


def check_updated_date(ctx: ScanContext) -> CheckResult:
    """Report the published last-updated date."""
    info = ctx.whois()
    if not info.ok:
        return _whois_failed(info.error or "WHOIS lookup failed.")
    return _date_result(
        label="Updated date",
        raw=info.updated_raw,
        parsed=info.updated,
        check_explanation="The updated date is when the registry last recorded a change to the published registration. A recent date can match an intentional nameserver or contact change. It is not evidence of a compromise by itself.",
    )


def check_whois_nameservers(ctx: ScanContext) -> CheckResult:
    """Report nameservers published in WHOIS."""
    info = ctx.whois()
    if not info.ok:
        return _whois_failed(info.error or "WHOIS lookup failed.")
    if not info.nameservers:
        return result(
            status="WARNING",
            severity="UNASSESSED",
            summary="WHOIS did not publish nameservers.",
            findings=["No name-server lines were recognized."],
            data={"nameservers": []},
            method="Parse name-server lines from the shared WHOIS text. No additional query.",
            explanation="Delegation nameservers are often listed in WHOIS. None were recognized in this response.",
            usefulness="Nameservers show which DNS operator the registry is advertising.",
            limitations=_SHARED + " The DNS NS check later queries the DNS itself. A difference between the two is explained there and is not automatically a fault.",
            evidence="No nameserver lines.",
            impact="Public WHOIS did not show where DNS is delegated.",
            confidence="medium",
            remediation="Compare the registrar's nameserver settings with the DNS NS check.",
            observation_type="unavailable",
            overlaps=["whois-record", "dns-ns"],
            raw_ref="whois.txt",
        )
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary="WHOIS published " + str(len(info.nameservers)) + " nameserver(s): " + ", ".join(info.nameservers),
        findings=info.nameservers,
        data={"nameservers": info.nameservers},
        method="Parse name-server lines from the shared WHOIS text. No additional query.",
        explanation="These are the nameservers the WHOIS text advertised. The DNS NS check asks the DNS for the live delegation. Those are related views, not two independent delegations.",
        usefulness="An operator can confirm that the registry is advertising the intended DNS provider.",
        limitations=_SHARED + " Hostnames are normalized to lower case without a trailing dot.",
        evidence=", ".join(info.nameservers),
        impact="Informational. Nameserver hostnames are public delegation data.",
        confidence="medium",
        remediation="If an unexpected nameserver appears, review the registrar delegation. Do not treat a familiar provider name as proof of account security.",
        overlaps=["whois-record", "dns-ns"],
        raw_ref="whois.txt",
    )


def check_domain_status(ctx: ScanContext) -> CheckResult:
    """Report EPP-style status codes when WHOIS published them."""
    info = ctx.whois()
    if not info.ok:
        return _whois_failed(info.error or "WHOIS lookup failed.")
    if not info.statuses:
        return result(
            status="WARNING",
            severity="UNASSESSED",
            summary="WHOIS did not publish domain status codes.",
            findings=["No Domain Status lines were recognized."],
            data={"statuses": []},
            method="Parse Domain Status lines from the shared WHOIS text. No additional query.",
            explanation="Status codes such as clientTransferProhibited describe registry locks and lifecycle states. This text did not include a recognizable code.",
            usefulness="Lock codes are a useful administrative signal when they are published.",
            limitations=_SHARED + " Missing codes are not proof that a lock is absent.",
            evidence="No status codes.",
            impact="The public lock and lifecycle state could not be assessed.",
            confidence="medium",
            remediation="Review status codes in the registrar account if transfer locks matter for this domain.",
            observation_type="unavailable",
            overlaps=["whois-record"],
            raw_ref="whois.txt",
        )
    interesting = [item for item in info.statuses if "prohibited" in item or "hold" in item or "redemption" in item]
    status = "OK"
    severity = "INFORMATIONAL"
    observation = "informational"
    summary = "Published status codes: " + ", ".join(info.statuses)
    impact = "Informational. Status codes describe registry state, not a tested website flaw."
    remediation = "Confirm that the lock state matches your intention. clientTransferProhibited is commonly a deliberate transfer lock."
    if any("hold" in item or "redemption" in item or "pendingdelete" in item for item in info.statuses):
        status = "WARNING"
        severity = "HIGH"
        observation = "configuration_observation"
        summary = "WHOIS published a hold, redemption, or pending-delete status: " + ", ".join(info.statuses)
        impact = "These lifecycle states can mean the domain is not in normal operation or is close to deletion."
        remediation = "Review the domain immediately in the registrar account and with the registry if you still operate it."
    elif interesting:
        summary = "Published status codes include lock or prohibition values: " + ", ".join(info.statuses)
    return result(
        status=status,
        severity=severity,
        summary=summary,
        findings=info.statuses,
        data={"statuses": info.statuses},
        method="Parse Domain Status lines from the shared WHOIS text. No additional query.",
        explanation="EPP status codes are the registry's labels for locks, holds, and pending changes. InfinityX reports the codes it could read and does not add codes that were not present.",
        usefulness="A transfer lock is relevant to domain-takeover resistance at the registrar. A hold or redemption code is relevant to availability of the name.",
        limitations=_SHARED + " Codes can be abbreviated differently by registries. InfinityX does not send an EPP command of its own.",
        evidence=", ".join(info.statuses),
        impact=impact,
        confidence="medium",
        remediation=remediation,
        observation_type=observation,
        overlaps=["whois-record"],
        raw_ref="whois.txt",
    )


def _whois_failed(error: str) -> CheckResult:
    return result(
        status="FAILED",
        severity="UNASSESSED",
        summary="The shared WHOIS lookup did not complete.",
        findings=[error],
        data={},
        method="Shared WHOIS port 43 lookup. This check did not send a second query.",
        explanation="This field could not be read because the shared WHOIS lookup failed. The failure is the same event for every WHOIS field check.",
        usefulness="Recording the failure avoids presenting an invented registrar or date.",
        limitations=_SHARED,
        evidence=error,
        impact="Public registration data was not assessed.",
        confidence="high",
        remediation="Retry later from a network that can reach WHOIS port 43, or check the registrar account directly.",
        observation_type="unavailable",
        error=error,
        overlaps=["whois-record"],
    )


def _missing_date(label: str) -> CheckResult:
    return result(
        status="WARNING",
        severity="UNASSESSED",
        summary=f"No {label.lower()} was published in WHOIS.",
        findings=[f"The shared WHOIS text had no recognizable {label.lower()}."],
        data={"raw": None, "parsed": None},
        method=f"Parse the {label.lower()} from the shared WHOIS text. No additional query.",
        explanation=f"The {label.lower()} is reported only when the registry text contains a recognizable field. It was not present here.",
        usefulness="An explicit absence stops the report from guessing how old the registration is.",
        limitations=_SHARED,
        evidence="Field not present.",
        impact=f"The {label.lower()} could not be assessed.",
        confidence="medium",
        remediation="Use the registrar account if you need the authoritative date. A withheld WHOIS date is not a vulnerability.",
        observation_type="unavailable",
        overlaps=["whois-record"],
        raw_ref="whois.txt",
    )


def _unparsed_date(label: str, raw: str) -> CheckResult:
    return result(
        status="WARNING",
        severity="UNASSESSED",
        summary=f"The {label.lower()} was published but could not be parsed: {raw}",
        findings=[raw],
        data={"raw": raw, "parsed": None},
        method=f"Parse the {label.lower()} from the shared WHOIS text. No additional query.",
        explanation="The raw string is preserved. InfinityX did not invent a normalized date because the format was not recognized.",
        usefulness="The raw registry text is still available in the WHOIS artifact.",
        limitations=_SHARED + " No age or countdown was calculated.",
        evidence=raw,
        impact="No countdown was calculated from this field.",
        confidence="low",
        remediation="Read the raw value in raw_results/whois.txt and compare it with the registrar account.",
        observation_type="unavailable",
        overlaps=["whois-record"],
        raw_ref="whois.txt",
    )


def _date_result(label: str, raw: str | None, parsed: datetime | None, check_explanation: str) -> CheckResult:
    if not raw:
        return _missing_date(label)
    if parsed is None:
        return _unparsed_date(label, raw)
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"{label}: {raw}",
        findings=[f"Raw value: {raw}", f"Parsed as UTC: {parsed.strftime('%Y-%m-%d %H:%M:%S UTC')}"],
        data={"raw": raw, "parsed_utc": parsed.strftime("%Y-%m-%dT%H:%M:%SZ")},
        method=f"Parse the {label.lower()} from the shared WHOIS text. No additional query.",
        explanation=check_explanation,
        usefulness="The date is an administrative fact published by the registry or registrar.",
        limitations=_SHARED + " If the source string had no timezone, InfinityX assumed UTC.",
        evidence=raw,
        impact="Informational registration metadata.",
        confidence="medium",
        remediation="Correct the registration at the registrar if the published date is inconsistent with your records.",
        overlaps=["whois-record"],
        raw_ref="whois.txt",
    )
