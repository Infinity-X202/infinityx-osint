"""TLS certificate observations from one pinned handshake."""

from __future__ import annotations

from datetime import datetime, timezone

from infinityx.context import ScanContext
from infinityx.models import CertInfo, CheckResult
from infinityx.models import build_result as result


def hostname_matches(hostname: str, names: list[str]) -> bool:
    """Return True when hostname matches a certificate DNS name or leftmost wildcard."""
    host = hostname.lower().rstrip(".")
    for pattern in names:
        if _one_match(host, pattern.lower().rstrip(".")):
            return True
    return False


def expiration_assessment(not_after: datetime, now: datetime | None = None) -> dict[str, object]:
    """Classify certificate expiry. Dates in the past are a verified observation."""
    current = now or datetime.now(timezone.utc)
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)
    days = int((not_after - current).total_seconds() // 86400)
    if days < 0:
        return {
            "days": days,
            "status": "WARNING",
            "severity": "HIGH",
            "observation_type": "verified_issue",
            "summary": f"The certificate expired about {abs(days)} days ago.",
            "impact": "Clients that validate dates should reject this certificate. Visitors may see warnings, and some clients will refuse the connection. This does not by itself show why the certificate was allowed to expire.",
            "remediation": "Install a current certificate for this hostname and confirm the new expiry from an external network.",
        }
    if days <= 14:
        severity, summary = "MEDIUM", f"The certificate expires in about {days} days."
    elif days <= 30:
        severity, summary = "LOW", f"The certificate expires in about {days} days."
    else:
        return {
            "days": days,
            "status": "OK",
            "severity": "INFORMATIONAL",
            "observation_type": "informational",
            "summary": f"The certificate is not inside the 30-day warning window ({days} days remaining).",
            "impact": "No near-term expiry was calculated from the leaf certificate presented to this scanner.",
            "remediation": "Keep renewal automated and confirm the replacement certificate still names this hostname.",
        }
    return {
        "days": days,
        "status": "WARNING",
        "severity": severity,
        "observation_type": "configuration_observation",
        "summary": summary,
        "impact": "If renewal does not happen before the end date, clients will start rejecting the certificate.",
        "remediation": "Renew the certificate and confirm the new dates are visible from outside the origin network.",
    }


def check_issuer(ctx: ScanContext) -> CheckResult:
    """Report the certificate issuer."""
    info = ctx.certificate()
    if not info.ok or not info.issuer:
        return _cert_failed(info, "Certificate issuer")
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"Issuer: {info.issuer}",
        findings=[info.issuer, f"SHA-256 fingerprint: {info.fingerprint_sha256}"],
        data={"issuer": info.issuer, "fingerprint_sha256": info.fingerprint_sha256, "trusted": info.trusted},
        method="TLS handshake to the pinned public address with the domain as SNI. The leaf issuer is read from the certificate. Trust is a separate result from the local trust store.",
        explanation="The issuer is the authority that signed the leaf. A familiar issuer name is informational. InfinityX does not judge the organization's reputation beyond whether the local trust store accepted the chain.",
        usefulness="Operators can confirm that the expected certificate authority issued the leaf presented to visitors on this path.",
        limitations="Only the leaf was parsed. The chain was accepted or rejected as a whole by the local trust store. A CDN can present a different certificate in another region.",
        evidence=info.issuer,
        impact="Informational. The issuer name is public data inside the certificate.",
        confidence="high",
        remediation="If the issuer is not the one you purchased or automated, review the CDN and origin certificate configuration.",
        overlaps=["cert-subject", "cert-validity", "cert-sans"],
        raw_ref="certificate.pem",
    )


def check_subject(ctx: ScanContext) -> CheckResult:
    """Report the certificate subject."""
    info = ctx.certificate()
    if not info.ok or not info.subject:
        return _cert_failed(info, "Certificate subject")
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"Subject: {info.subject}",
        findings=[info.subject, f"Common name: {info.common_name or 'not present'}"],
        data={"subject": info.subject, "common_name": info.common_name},
        method="Read the leaf subject from the same pinned TLS handshake as the issuer check. No second connection is used when the certificate is cached.",
        explanation="The subject identifies the leaf. Modern hostname checks use subject alternative names, which are reported separately. The common name is shown so an operator can recognize an old certificate style.",
        usefulness="The subject helps match the presented certificate to the one in your certificate account.",
        limitations="This is the same leaf certificate as the other TLS field checks, not a second certificate.",
        evidence=info.subject,
        impact="Informational.",
        confidence="high",
        remediation="Reissue the certificate if the subject is from an old name or a default device certificate.",
        overlaps=["cert-issuer", "cert-hostname", "cert-sans"],
        raw_ref="certificate.pem",
    )


def check_validity(ctx: ScanContext) -> CheckResult:
    """Report the certificate validity window and trust result."""
    info = ctx.certificate()
    if not info.ok or info.not_before is None or info.not_after is None:
        return _cert_failed(info, "Certificate validity")
    now = datetime.now(timezone.utc)
    not_yet = now < info.not_before
    expired = now > info.not_after
    findings = [
        f"Not before: {info.not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Not after: {info.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"TLS version observed: {info.tls_version or 'unavailable'}",
        f"Cipher observed: {info.cipher or 'unavailable'}",
        f"Signature hash: {info.signature_algorithm or 'unavailable'}",
        "Local trust store accepted the handshake." if info.trusted else f"Local trust store rejected the handshake: {info.trust_error}",
    ]
    weak = (info.signature_algorithm or "").lower() in {"md5", "sha1"}
    if not_yet:
        status, severity, observation = "WARNING", "HIGH", "verified_issue"
        summary = "The certificate is not valid yet."
        impact = "Clients that check dates should reject a certificate whose start date is in the future."
        remediation = "Install a certificate whose validity window includes today, and check the scanner clock if the dates look right to you."
    elif expired or weak or info.trusted is False:
        status = "WARNING"
        severity = "HIGH" if expired or (info.signature_algorithm or "").lower() == "md5" else "MEDIUM"
        observation = "verified_issue" if expired or weak else "configuration_observation"
        summary = "The certificate dates or the local trust evaluation need attention."
        if expired:
            summary = "The certificate validity window has ended."
        elif weak:
            summary = f"The leaf signature hash is {info.signature_algorithm}."
        elif info.trusted is False:
            summary = "The local trust store did not accept the certificate."
        impact = "Clients may warn or refuse this handshake. A trust failure can also be caused by interception, an incomplete chain, or a name mismatch. The trust error is the evidence, not a guess about the cause."
        remediation = "Read the trust error, then reinstall a publicly trusted certificate that matches this hostname. The expiry warning check restates the date threshold from these same dates."
    else:
        status, severity, observation = "OK", "INFORMATIONAL", "informational"
        summary = "The certificate is inside its validity window and the local trust store accepted it."
        impact = "This handshake was acceptable to this computer's trust store at scan time. That is not a full application security assessment."
        remediation = "Continue normal renewal. The separate expiry warning check applies the 30-day and 14-day windows."
    return result(
        status=status,
        severity=severity,
        summary=summary,
        findings=findings,
        data={
            "not_before": info.not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "not_after": info.not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "trusted": info.trusted,
            "trust_error": info.trust_error,
            "tls_version": info.tls_version,
            "cipher": info.cipher,
            "signature_algorithm": info.signature_algorithm,
        },
        method="Pinned TLS handshake for the leaf dates, then a second handshake using the default trust store and hostname verification. Cipher and version come from the observation handshake.",
        explanation="Validity dates bound when the leaf may be used. The trust result says whether this computer accepted the chain and hostname. Those are related observations from the same certificate, and the expiry warning check uses these dates rather than opening a third connection.",
        usefulness="Operators can see the exact window and whether a normal client trust store on this machine accepted the handshake.",
        limitations="The trust store is the one on the scanning machine. Corporate interception or an incomplete local store can change the trust result. No online revocation lookup was required.",
        evidence=summary,
        impact=impact,
        confidence="high" if info.trusted is not None else "medium",
        remediation=remediation,
        observation_type=observation,
        overlaps=["cert-expiration-warning", "cert-issuer", "cert-hostname"],
        raw_ref="certificate.pem",
    )


def check_hostname(ctx: ScanContext) -> CheckResult:
    """Compare the domain with the certificate names."""
    info = ctx.certificate()
    if not info.ok:
        return _cert_failed(info, "Certificate hostname")
    names = list(info.sans)
    used_cn = False
    if not names and info.common_name:
        names = [info.common_name]
        used_cn = True
    if not names:
        return result(
            status="WARNING",
            severity="UNASSESSED",
            summary="The certificate has no DNS subject alternative name or common name to compare.",
            findings=["No DNS names were parsed from the leaf."],
            data={"sans": info.sans, "common_name": info.common_name},
            method="Compare the domain with DNS SANs from the cached leaf. The common name is used only when no DNS SAN exists.",
            explanation="Hostname matching needs a name in the certificate. None was available, so InfinityX did not claim a match or a mismatch.",
            usefulness="A match tells you the certificate was issued for this hostname rather than only for another property.",
            limitations="IP SANs and URI SANs were not used as website hostname matches.",
            evidence="No DNS name in the certificate.",
            impact="Hostname coverage could not be assessed.",
            confidence="low",
            remediation="Reissue the certificate with a DNS SAN for this hostname.",
            observation_type="unavailable",
            overlaps=["cert-sans", "cert-subject"],
        )
    matched = hostname_matches(ctx.domain, names)
    if matched:
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary=f"The certificate names match {ctx.domain}.",
            findings=[f"Compared names: {', '.join(names[:20])}", "Legacy common-name fallback was used." if used_cn else "Matched against DNS subject alternative names."],
            data={"match": True, "names": names, "used_common_name_fallback": used_cn},
            method="Local comparison of the domain with the cached certificate names. A wildcard matches one leftmost label only.",
            explanation="The presented leaf includes this hostname under the usual wildcard rule. This is a name match, not a statement that the site is secure.",
            usefulness="It confirms that visitors should not get a hostname mismatch from this certificate on this path.",
            limitations="A different address in an anycast or CDN setup can present another certificate. Only one pinned address was tested."
            + (" The common name was used because no DNS SAN was present; some clients ignore the common name." if used_cn else ""),
            evidence=ctx.domain,
            impact="Informational positive name match for the tested handshake.",
            confidence="high",
            remediation="No name change is required from this result. Keep the name on the certificate when you renew.",
            overlaps=["cert-sans"],
        )
    return result(
        status="WARNING",
        severity="HIGH",
        summary=f"The certificate presented for {ctx.domain} does not include that hostname.",
        findings=[f"Certificate names: {', '.join(names[:20])}", f"Requested hostname: {ctx.domain}"],
        data={"match": False, "names": names, "used_common_name_fallback": used_cn},
        method="Local comparison of the domain with DNS SANs, or the common name only if no DNS SAN exists.",
        explanation="The leaf presented on this connection does not match the hostname under a single leftmost-label wildcard. Clients that verify names should warn or stop. Possible explanations include the wrong virtual host, a CDN default certificate, or interception. This scan does not decide which explanation is true.",
        usefulness="A mismatch is a concrete TLS configuration problem for this hostname on the tested path.",
        limitations="Only one resolved address was tested. Another location could present a matching certificate.",
        evidence=f"{ctx.domain} not in {', '.join(names[:12])}",
        impact="Visitors can receive certificate warnings, and automated clients may refuse to connect. Traffic interception cannot be confirmed or ruled out from this observation alone.",
        confidence="high",
        remediation="Install a certificate whose DNS SAN includes this exact hostname, or serve the correct certificate on the virtual host and CDN.",
        observation_type="verified_issue",
        overlaps=["cert-sans", "cert-validity"],
    )


def check_sans(ctx: ScanContext) -> CheckResult:
    """List subject alternative names."""
    info = ctx.certificate()
    if not info.ok:
        return _cert_failed(info, "Certificate subject alternative names")
    if not info.sans:
        return result(
            status="WARNING",
            severity="LOW",
            summary="The leaf certificate has no DNS subject alternative names.",
            findings=["No DNS SAN extension was parsed."],
            data={"sans": []},
            method="Read the DNS subject alternative name extension from the cached leaf certificate.",
            explanation="Modern certificates list every hostname in the SAN extension. None was present. Hostname matching may fall back to the common name, which many clients no longer use.",
            usefulness="The SAN list is the authoritative public list of names on this certificate.",
            limitations="This is the same certificate as the hostname check. Non-DNS SAN types were not listed.",
            evidence="No DNS SAN.",
            impact="Clients may not accept the certificate for this website even if the common name looks right.",
            confidence="high",
            remediation="Reissue the certificate with DNS SANs for every hostname it should serve.",
            observation_type="configuration_observation",
            overlaps=["cert-hostname"],
        )
    preview = info.sans[:30]
    extra = len(info.sans) - len(preview)
    findings = preview + ([f"{extra} additional names were omitted from the summary."] if extra else [])
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"The certificate lists {len(info.sans)} DNS subject alternative name(s).",
        findings=findings,
        data={"sans": preview, "count": len(info.sans)},
        method="Read DNS SANs from the cached leaf certificate. No extra TLS connection.",
        explanation="Each name is a hostname the certificate is allowed to represent. Historical or unrelated names on a shared CDN certificate are informational. They are not evidence that those hosts are under your control, and they are not a vulnerability by themselves.",
        usefulness="Operators can see whether extra names, wildcards, or old brands are still on the live certificate.",
        limitations="The list is capped in the summary. It is the same leaf used by the hostname check, not a second certificate.",
        evidence=", ".join(preview),
        impact="Informational name disclosure inside a public certificate.",
        confidence="high",
        remediation="Reissue without unused names if the certificate should be narrower. Do not treat an extra CDN name as an incident.",
        overlaps=["cert-hostname", "cert-transparency"],
    )


def check_expiration_warning(ctx: ScanContext) -> CheckResult:
    """Apply expiry warning thresholds to the dates already collected."""
    info = ctx.certificate()
    if not info.ok or info.not_after is None:
        return _cert_failed(info, "Certificate expiration warning")
    assessment = expiration_assessment(info.not_after)
    return result(
        status=str(assessment["status"]),
        severity=str(assessment["severity"]),
        summary=str(assessment["summary"]),
        findings=[
            f"Not after: {info.not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"Days remaining, negative if expired: {assessment['days']}",
            "Thresholds: warning at 30 days, stronger warning at 14 days, and a high finding when the date is in the past.",
        ],
        data={"days_remaining": assessment["days"], "not_after": info.not_after.strftime("%Y-%m-%dT%H:%M:%SZ")},
        method="Compare the cached leaf not-after date with the scanner clock. No additional TLS connection.",
        explanation="This check is the warning view of the validity dates already collected. It is not a second certificate and not a second handshake. " + str(assessment["summary"]),
        usefulness="It turns a raw end date into a clear renewal signal.",
        limitations="Clock skew on this computer changes the day count. Revocation and replacement certificates elsewhere were not searched, except for the separate transparency lookup.",
        evidence=info.not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
        impact=str(assessment["impact"]),
        confidence="high",
        remediation=str(assessment["remediation"]),
        observation_type=str(assessment["observation_type"]),
        overlaps=["cert-validity"],
    )


def check_ct(ctx: ScanContext) -> CheckResult:
    """Query crt.sh for public certificate-transparency rows."""
    rows, error = ctx.certificate_transparency()
    if error and not rows:
        return result(
            status="FAILED",
            severity="UNASSESSED",
            summary="Certificate-transparency records were not retrieved.",
            findings=[error],
            data={"source": "https://crt.sh/"},
            method="HTTPS GET https://crt.sh/?q=<domain>&output=json with a 20 second timeout and a response cap. No API key is used.",
            explanation="crt.sh is a public search front end for certificate-transparency logs. It did not return a usable list. That does not mean the domain has no certificates.",
            usefulness="CT logs can show names and issuers that appeared on certificates for this domain, including historical ones.",
            limitations="crt.sh can be slow, incomplete, or temporarily unavailable. A failed query is not a security result.",
            evidence=error,
            impact="Historical certificate names were not assessed.",
            confidence="high",
            remediation="Retry later or search the domain in a certificate-transparency log viewer. Do not infer a problem from this failure.",
            observation_type="unavailable",
            error=error,
            raw_ref="crtsh.json",
        )
    names: list[str] = []
    for row in rows:
        for part in str(row.get("name_value", "")).splitlines():
            item = part.strip().lower().lstrip("*.")
            if item and item not in names:
                names.append(item)
        common = str(row.get("common_name", "")).strip().lower()
        if common and common not in names:
            names.append(common)
    preview = names[:40]
    note = "The log response was truncated." if error else "The returned rows may include historical certificates."
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"crt.sh returned {len(rows)} row(s) and {len(names)} unique name(s) for this query.",
        findings=[note, *preview, "A name in a transparency log is not proof that the host is live or that it belongs to this scan's operator."],
        data={"row_count": len(rows), "names": preview, "name_count": len(names), "note": error},
        method="HTTPS GET https://crt.sh/?q=<domain>&output=json. Names were extracted from common_name and name_value.",
        explanation="Certificate transparency is a public log of certificates that participating authorities submitted. InfinityX lists names from the crt.sh response for this exact query. It does not claim those names are vulnerable, current, or under the operator's control.",
        usefulness="Historical names can remind an administrator of old hosts, wildcards, or unexpected certificates issued for the domain.",
        limitations="Logs are not a complete live inventory. The query is the exact domain, not a wildcard crawl of every subdomain. Results were capped. " + (error or ""),
        evidence=f"{len(rows)} crt.sh rows",
        impact="Informational public-log disclosure. No misuse was verified.",
        confidence="medium",
        remediation="If an unexpected name appears, compare it with your certificate inventory and your certificate-authority account. Do not treat a log entry alone as an incident.",
        raw_ref="crtsh.json",
    )


def _one_match(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        rest = pattern[2:]
        if "." not in host or "*" in host:
            return False
        label, _, suffix = host.partition(".")
        return bool(label) and suffix == rest
    return host == pattern


def _cert_failed(info: CertInfo, label: str) -> CheckResult:
    return result(
        status="FAILED",
        severity="UNASSESSED",
        summary=f"{label} was not available.",
        findings=[info.error or "No certificate details."],
        data={"trusted": info.trusted, "trust_error": info.trust_error},
        method="Pinned TLS connection to port 443 on one public address. This field uses the cached handshake when it succeeded.",
        explanation="The certificate detail was not parsed, so InfinityX did not invent an issuer, date, or name.",
        usefulness="A TLS failure explains why certificate conclusions are absent.",
        limitations="Port 443 on one address was tested. Another address or port was not.",
        evidence=info.error or "No certificate.",
        impact=f"{label} was not assessed.",
        confidence="high",
        remediation="Confirm that the hostname serves TLS on port 443 at the resolved public address.",
        observation_type="unavailable",
        error=info.error,
        overlaps=["https-status"],
    )
