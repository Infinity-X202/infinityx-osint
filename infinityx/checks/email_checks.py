"""SPF, DMARC, and DKIM guidance.

DKIM selectors are not guessed and no selector._domainkey name is queried.
"""

from __future__ import annotations

from infinityx.context import ScanContext
from infinityx.models import CheckResult
from infinityx.models import build_result as result


def analyze_spf(records: list[str]) -> dict[str, object]:
    """Interpret apex TXT records that start with v=spf1."""
    policies = [item.strip() for item in records if item.lower().startswith("v=spf1")]
    assessment: dict[str, object] = {
        "records": policies,
        "count": len(policies),
        "all_qualifier": None,
        "mechanisms": [],
    }
    if len(policies) != 1:
        return assessment
    parts = policies[0].split()
    mechanisms = parts[1:]
    assessment["mechanisms"] = mechanisms
    for part in mechanisms:
        if part.lower() in {"+all", "-all", "~all", "?all", "all"}:
            assessment["all_qualifier"] = "all" if part.lower() == "all" else part.lower()
    return assessment


def analyze_dmarc(records: list[str]) -> dict[str, object]:
    """Interpret TXT records at _dmarc that start with v=DMARC1."""
    policies = [item.strip() for item in records if item.upper().startswith("V=DMARC1")]
    parsed: dict[str, str] = {}
    if len(policies) == 1:
        body = policies[0].split(";", 1)[1] if ";" in policies[0] else ""
        for piece in body.split(";"):
            if "=" not in piece:
                continue
            key, value = piece.split("=", 1)
            parsed[key.strip().lower()] = value.strip()
    return {"records": policies, "count": len(policies), "tags": parsed, "policy": parsed.get("p")}


def check_spf(ctx: ScanContext) -> CheckResult:
    """Analyze the apex SPF record without expanding includes."""
    answer = ctx.dns("TXT")
    if answer.status in {"timeout", "error"}:
        return result(
            status="FAILED",
            severity="UNASSESSED",
            summary="SPF could not be assessed because the TXT query failed.",
            findings=[answer.error or answer.status],
            data={},
            method="Read v=spf1 from the apex TXT query already sent to 1.1.1.1. Includes are not expanded.",
            explanation="SPF lives in TXT. The TXT lookup failed, so no policy was invented.",
            usefulness="SPF tells receivers which hosts may send mail for the domain.",
            limitations="No include was resolved and the 10-lookup limit was not walked.",
            evidence=answer.error or answer.status,
            impact="Mail authentication policy was not assessed.",
            confidence="high",
            remediation="Retry the DNS query. A failed lookup is not an SPF result.",
            observation_type="unavailable",
            error=answer.error,
            overlaps=["dns-txt"],
        )
    analyzed = analyze_spf(answer.records)
    count = int(analyzed["count"])
    if count == 0:
        return result(
            status="WARNING",
            severity="LOW",
            summary="No SPF record was published.",
            findings=["No apex TXT record starts with v=spf1."],
            data=analyzed,
            method="Read v=spf1 from the apex TXT query already sent to 1.1.1.1. No second TXT query and no include expansion.",
            explanation="SPF is a mail-authorization policy. A missing record means receivers are not given this domain's list of permitted senders. That is a configuration gap for email, not proof that the website has been compromised or that spoofed mail was sent.",
            usefulness="Publishing SPF is a normal control when a domain sends mail. Knowing it is absent tells an administrator what to add.",
            limitations="This check does not prove that anyone is spoofing the domain. The TXT check reports the same raw records.",
            evidence="No v=spf1 TXT record.",
            impact="Receivers have no SPF policy from this domain. Messages may be easier to spoof, depending on the receiver.",
            confidence="high",
            remediation="If the domain sends mail, publish one SPF TXT record that ends in -all or ~all after listing real senders. If it does not send mail, publish v=spf1 -all.",
            observation_type="configuration_observation",
            overlaps=["dns-txt"],
        )
    if count > 1:
        return result(
            status="WARNING",
            severity="MEDIUM",
            summary="More than one SPF record was published.",
            findings=list(analyzed["records"]),
            data=analyzed,
            method="Read v=spf1 from the apex TXT query already sent to 1.1.1.1.",
            explanation="A domain is expected to publish one SPF record. Multiple v=spf1 TXT records make SPF evaluation fail at receivers. This is a verified DNS configuration error, not a statement that an attacker sent mail.",
            usefulness="Receivers may ignore SPF until the duplicate is removed.",
            limitations="Includes were not expanded.",
            evidence=" | ".join(analyzed["records"]),
            impact="SPF evaluation can return a permanent error, so the intended sender list may not be enforced.",
            confidence="high",
            remediation="Keep a single v=spf1 TXT record and merge any legitimate senders into it.",
            observation_type="verified_issue",
            overlaps=["dns-txt"],
        )
    qualifier = analyzed["all_qualifier"]
    record = analyzed["records"][0]
    if qualifier in {"+all", "all"}:
        status, severity, observation = "WARNING", "MEDIUM", "verified_issue"
        summary = "SPF ends in +all, which explicitly permits any sender."
        impact = "A receiver that honors SPF is told that every host is authorized to send mail for this domain. That defeats SPF as a restriction."
        remediation = "Replace +all with the real sending sources and end the record in -all or, during testing, ~all."
    elif qualifier == "-all":
        status, severity, observation = "OK", "INFORMATIONAL", "informational"
        summary = "SPF is published and ends in -all."
        impact = "Receivers are told to treat non-matching senders as a hard fail. Delivery still depends on the receiver and on alignment with DKIM and DMARC."
        remediation = "Keep the included senders current when mail providers change."
    elif qualifier == "~all":
        status, severity, observation = "OK", "INFORMATIONAL", "informational"
        summary = "SPF is published and ends in ~all (soft fail)."
        impact = "Non-matching senders are marked rather than rejected by SPF alone. That is a common testing posture, not a verified incident."
        remediation = "Move to -all after legitimate senders are known and DMARC monitoring looks clean."
    elif qualifier == "?all":
        status, severity, observation = "WARNING", "LOW", "configuration_observation"
        summary = "SPF is published but ends in ?all, which gives receivers no recommendation."
        impact = "The sender list is published, yet the neutral qualifier does not ask receivers to treat other senders as unauthorized."
        remediation = "Use ~all while testing and -all when the sender list is complete."
    else:
        status, severity, observation = "WARNING", "LOW", "configuration_observation"
        summary = "SPF is published but has no recognizable all mechanism."
        impact = "Receivers may not get a clear default for senders that do not match the listed mechanisms."
        remediation = "End the single SPF record with ~all or -all."
    return result(
        status=status,
        severity=severity,
        summary=summary,
        findings=[record, f"all mechanism: {qualifier or 'not present'}"],
        data=analyzed,
        method="Read v=spf1 from the apex TXT query already sent to 1.1.1.1. Included domains were not resolved, so the 10-DNS-lookup limit was not fully counted.",
        explanation="SPF lists hosts and included domains allowed to send mail. InfinityX reads only the published apex record. " + summary,
        usefulness="The qualifier shows whether the published policy restricts senders, soft-fails them, or permits everyone.",
        limitations="Includes, redirects, and the 10-lookup limit were not walked. The raw TXT is the same record reported by the TXT check.",
        evidence=record,
        impact=impact,
        confidence="high",
        remediation=remediation,
        observation_type=observation,
        overlaps=["dns-txt"],
    )


def check_dmarc(ctx: ScanContext) -> CheckResult:
    """Analyze the _dmarc TXT record."""
    name = "_dmarc." + ctx.domain
    answer = ctx.dns("TXT", name=name)
    if answer.status in {"timeout", "error"}:
        return result(
            status="FAILED",
            severity="UNASSESSED",
            summary="DMARC could not be assessed because the TXT query failed.",
            findings=[answer.error or answer.status],
            data={"name": name},
            method=f"DNS TXT query to 1.1.1.1 for {name}.",
            explanation="DMARC is published at the _dmarc label. The query failed, so no policy was invented.",
            usefulness="DMARC tells receivers what to do when SPF or DKIM alignment fails, and where to send reports.",
            limitations="No rua mailbox was contacted.",
            evidence=answer.error or answer.status,
            impact="DMARC was not assessed.",
            confidence="high",
            remediation="Retry the DNS query.",
            observation_type="unavailable",
            error=answer.error,
        )
    analyzed = analyze_dmarc(answer.records)
    count = int(analyzed["count"])
    if answer.status == "nxdomain" or count == 0:
        return result(
            status="WARNING",
            severity="LOW",
            summary="No DMARC record was published.",
            findings=[f"No TXT record at {name} starts with v=DMARC1."],
            data=analyzed,
            method=f"DNS TXT query to 1.1.1.1 for {name}.",
            explanation="A missing DMARC record means this domain is not publishing a receiver policy for failed mail authentication. That is a configuration gap, not confirmation of fraudulent mail or a website compromise.",
            usefulness="Operators usually add DMARC, often starting at p=none, so receivers can send reports before enforcement.",
            limitations="A parent organizational domain's DMARC record was not queried. Some receivers apply a related organizational policy that this check did not retrieve.",
            evidence=f"No v=DMARC1 TXT at {name}.",
            impact="Receivers are not given this domain's DMARC policy. Spoofed mail may face fewer domain-specific instructions.",
            confidence="medium",
            remediation="Publish a DMARC TXT record at _dmarc. Start with p=none and a rua mailbox you control, then move to quarantine or reject after reviewing reports.",
            observation_type="configuration_observation",
        )
    if count > 1:
        return result(
            status="WARNING",
            severity="MEDIUM",
            summary="More than one DMARC record was published.",
            findings=list(analyzed["records"]),
            data=analyzed,
            method=f"DNS TXT query to 1.1.1.1 for {name}.",
            explanation="Multiple DMARC records make the policy invalid. Receivers can ignore it. This is a verified publication error, not evidence of a compromise.",
            usefulness="Mail authentication will not behave as the operator expects until one record remains.",
            limitations="Parent-domain DMARC was not queried.",
            evidence=" | ".join(analyzed["records"]),
            impact="The domain's DMARC policy may be ignored.",
            confidence="high",
            remediation="Leave one v=DMARC1 TXT record at the _dmarc name.",
            observation_type="verified_issue",
        )
    policy = str(analyzed["policy"] or "")
    record = analyzed["records"][0]
    tags = analyzed["tags"]
    if policy == "reject":
        status, severity = "OK", "INFORMATIONAL"
        summary = "DMARC is published with p=reject."
        impact = "Receivers that honor DMARC are asked to reject mail that fails alignment. This does not prove every receiver does so."
        remediation = "Keep rua reports monitored so legitimate mail is not rejected after a provider change."
        observation = "informational"
    elif policy == "quarantine":
        status, severity = "OK", "INFORMATIONAL"
        summary = "DMARC is published with p=quarantine."
        impact = "Receivers are asked to treat alignment failures as suspicious. This is a published policy, not a test of mailbox filtering."
        remediation = "Review aggregate reports and consider p=reject when legitimate mail aligns."
        observation = "informational"
    elif policy == "none":
        status, severity = "OK", "INFORMATIONAL"
        summary = "DMARC is published with p=none."
        impact = "The domain asks for reporting, or at least publishes a policy, but does not ask receivers to quarantine or reject failed mail. That is a monitoring posture, not a verified incident."
        remediation = "Review rua reports, then move the policy to quarantine or reject when ready."
        observation = "informational"
    else:
        status, severity = "WARNING", "LOW"
        summary = "A DMARC record is published but the p= tag is missing or unrecognized."
        impact = "Receivers may not apply a domain policy if the required p= tag is absent."
        remediation = "Publish one record in the form v=DMARC1; p=none; rua=mailto:you@your-domain."
        observation = "configuration_observation"
    findings = [record]
    if isinstance(tags, dict) and tags.get("rua"):
        findings.append("Aggregate report destination: " + str(tags.get("rua")))
    return result(
        status=status,
        severity=severity,
        summary=summary,
        findings=findings,
        data=analyzed,
        method=f"DNS TXT query to 1.1.1.1 for {name}. The record was parsed locally.",
        explanation="DMARC builds on SPF and DKIM alignment. InfinityX reads the published tag and does not submit mail or contact the rua address. " + summary,
        usefulness="The p= value is the clearest public statement of how the operator wants failed authentication handled.",
        limitations="The organizational-domain fallback was not queried. DKIM alignment was not tested because selectors are not guessed. rua mailboxes were not validated.",
        evidence=record,
        impact=impact,
        confidence="high",
        remediation=remediation,
        observation_type=observation,
    )


def check_dkim_guidance(ctx: ScanContext) -> CheckResult:
    """Explain how an administrator can find DKIM without probing selectors."""
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary="DKIM selectors were not queried. DKIM deployment was not verified.",
        findings=[
            "No selector._domainkey name was queried.",
            "Selector guessing was intentionally not performed.",
            "An administrator can read the s= tag from a legitimate message's DKIM-Signature header and then look up that selector at selector._domainkey." + ctx.domain + " as a TXT record.",
        ],
        data={"queried_selectors": [], "deployment_verified": False},
        method="No DNS query. DKIM selectors are not guessed, and no authentication is attempted.",
        explanation="DKIM public keys are stored under a selector chosen by the mail system. Trying common selectors would be an incomplete wordlist and would not prove that DKIM is absent. This check therefore gives the operator the lookup method and records that deployment is unknown.",
        usefulness="It prevents a false 'DKIM is missing' conclusion and shows the authorized next step.",
        limitations="This scan cannot say whether DKIM is deployed. A missing result here is not a finding about the mail system.",
        evidence="Zero selector queries.",
        impact="DKIM remains unassessed. No negative or positive mail-authentication conclusion should be drawn from this check.",
        confidence="high",
        remediation="From a real message your system sent, copy the DKIM s= selector and publish or verify the matching TXT record. Do not add selectors by guessing inside this scanner.",
        observation_type="unavailable",
    )
