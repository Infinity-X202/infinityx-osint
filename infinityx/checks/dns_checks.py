"""Public DNS checks against 1.1.1.1 and 8.8.8.8."""

from __future__ import annotations

from infinityx.context import ScanContext
from infinityx.models import CheckResult, DnsAnswer
from infinityx.models import build_result as result
from infinityx.safety import ip_is_public

_DNS_LIMIT = (
    "The answer is what the selected public resolver returned at scan time. "
    "Authoritative DNS can change, and a resolver can cache a previous answer."
)


def check_a(ctx: ScanContext) -> CheckResult:
    """Collect IPv4 addresses for the domain."""
    answer = ctx.dns("A")
    return _address_result("A", "IPv4 address", answer, "dns-a")


def check_aaaa(ctx: ScanContext) -> CheckResult:
    """Collect IPv6 addresses for the domain."""
    answer = ctx.dns("AAAA")
    return _address_result("AAAA", "IPv6 address", answer, "dns-aaaa")


def check_mx(ctx: ScanContext) -> CheckResult:
    """Collect published mail exchangers."""
    answer = ctx.dns("MX")
    failed = _dns_failure("MX", answer, "Mail exchanger query to 1.1.1.1.")
    if failed:
        return failed
    if answer.status in {"noanswer", "nxdomain"} or not answer.records:
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary="No MX records were published.",
            findings=["1.1.1.1 returned no MX records."],
            data={"records": []},
            method="DNS MX query to 1.1.1.1 for the target domain.",
            explanation="MX records name the hosts that accept mail for the domain, in preference order. No MX record means this scan did not see a published mail exchanger. Mail delivery might still use an address record as a fallback; that fallback was not tested.",
            usefulness="An operator can see whether public DNS advertises inbound mail servers.",
            limitations=_DNS_LIMIT + " The hosts were not connected to, and SMTP was not tested.",
            evidence="No MX records.",
            impact="Inbound mail configuration could not be confirmed from DNS. This is not a statement about website security.",
            confidence="high",
            remediation="Publish MX records if the domain should receive mail. Leave them absent if it should not.",
            raw_ref="resolution.txt",
        )
    ordered = sorted(answer.structured, key=lambda item: item.get("preference", 0))
    findings = [f"{item.get('preference')} {item.get('exchange')}" for item in ordered]
    if ordered and all(item.get("null_mx") or item.get("exchange") in {".", ""} for item in ordered):
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary="A null MX is published. The domain advertises that it does not accept mail.",
            findings=["0 .", "A target of '.' is the null MX from RFC 7505, not a mail server named 0."],
            data={"records": ordered, "null_mx": True},
            method="DNS MX query to 1.1.1.1 for the target domain.",
            explanation="A null MX uses preference 0 and the root name '.'. It tells senders that the domain does not accept email. InfinityX did not open an SMTP connection. This is a mail-routing statement, not a website vulnerability.",
            usefulness="It explains why the domain may have SPF or DMARC for sending policy while refusing inbound mail.",
            limitations=_DNS_LIMIT + " SMTP was not tested.",
            evidence="0 .",
            impact="Mail servers that honor the null MX should not deliver mail to this domain.",
            confidence="high",
            remediation="Remove the null MX and publish real MX hosts if the domain should receive mail. Leave it in place if inbound mail is intentionally disabled.",
        )
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary="Published MX records: " + "; ".join(findings),
        findings=findings,
        data={"records": ordered},
        method="DNS MX query to 1.1.1.1 for the target domain.",
        explanation="Lower preference numbers are tried first by mail servers. InfinityX lists the published hosts and does not open SMTP connections to them.",
        usefulness="The MX list shows which provider is advertised for inbound mail and can be compared with SPF and DMARC.",
        limitations=_DNS_LIMIT + " A published MX host was not checked for whether it actually accepts mail.",
        evidence="; ".join(findings),
        impact="Informational. MX hostnames are public mail-routing data.",
        confidence="high",
        remediation="If a hostname is unexpected, review the DNS zone at the DNS provider. Do not infer a mailbox compromise from an MX name.",
    )


def check_ns(ctx: ScanContext) -> CheckResult:
    """Collect DNS delegation names and compare them with WHOIS nameservers."""
    answer = ctx.dns("NS")
    failed = _dns_failure("NS", answer, "DNS NS query to 1.1.1.1.")
    if failed:
        return failed
    whois_ns = []
    if ctx._whois is not None and ctx._whois.ok:
        whois_ns = ctx._whois.nameservers
    dns_ns = sorted({item.rstrip(".").lower() for item in answer.records})
    if answer.status == "nxdomain":
        return _nxdomain("NS")
    if not dns_ns:
        return result(
            status="WARNING",
            severity="UNASSESSED",
            summary="No NS records were returned.",
            findings=["1.1.1.1 did not return NS records for this name."],
            data={"records": [], "whois_nameservers": whois_ns},
            method="DNS NS query to 1.1.1.1. WHOIS nameservers, if already collected, are compared and not queried again.",
            explanation="NS records are the delegation. Without them, public resolvers may be serving the name from another layer, or the name may not be delegated.",
            usefulness="The NS set identifies the advertised DNS operator.",
            limitations=_DNS_LIMIT,
            evidence="No NS records.",
            impact="The live DNS delegation was not visible from this resolver.",
            confidence="medium",
            remediation="Check the delegation at the registrar and the DNS provider.",
            observation_type="unavailable",
            overlaps=["whois-nameservers"],
        )
    dns_set = set(dns_ns)
    whois_set = {item.rstrip(".").lower() for item in whois_ns}
    findings = list(dns_ns)
    overlap_note = "WHOIS nameservers were not available for comparison."
    if whois_set:
        if dns_set == whois_set:
            overlap_note = "The DNS NS set matches the WHOIS nameserver set. That is one delegation seen two ways, not two discoveries."
        else:
            overlap_note = (
                "The DNS NS set and the WHOIS nameserver set differ. "
                f"DNS: {', '.join(sorted(dns_set))}. WHOIS: {', '.join(sorted(whois_set))}. "
                "Differences can come from formatting, a recent change, or a registry versus resolver view. This is not automatically a fault."
            )
        findings.append(overlap_note)
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary="DNS nameservers: " + ", ".join(dns_ns),
        findings=findings,
        data={"records": dns_ns, "whois_nameservers": whois_ns, "sets_match": bool(whois_set) and dns_set == whois_set},
        method="DNS NS query to 1.1.1.1, compared with nameservers already parsed from the shared WHOIS text.",
        explanation="NS records tell recursive resolvers which servers publish the zone. " + overlap_note,
        usefulness="Operators use the NS set to confirm that the intended DNS provider is delegated.",
        limitations=_DNS_LIMIT + " InfinityX did not query the authoritative servers directly and did not attempt a zone transfer.",
        evidence=", ".join(dns_ns),
        impact="Informational delegation data.",
        confidence="high",
        remediation="If a nameserver is unexpected, review the registrar delegation. A provider name alone is not proof of a vulnerability.",
        overlaps=["whois-nameservers"],
    )


def check_txt(ctx: ScanContext) -> CheckResult:
    """Collect TXT records and point SPF to the dedicated SPF check."""
    answer = ctx.dns("TXT")
    failed = _dns_failure("TXT", answer, "DNS TXT query to 1.1.1.1.")
    if failed:
        return failed
    if answer.status == "nxdomain":
        return _nxdomain("TXT")
    if not answer.records:
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary="No TXT records were published at the zone apex.",
            findings=["1.1.1.1 returned no TXT records."],
            data={"records": []},
            method="DNS TXT query to 1.1.1.1 for the target domain.",
            explanation="TXT records carry arbitrary public text, including site-verification tokens and SPF. None were returned at the apex. SPF is assessed separately and will report the same absence rather than invent a policy.",
            usefulness="TXT records often show which providers have been given a verification token.",
            limitations=_DNS_LIMIT + " Values are truncated in the report. SPF policy quality is interpreted in the SPF check, not here.",
            evidence="No TXT records.",
            impact="No apex TXT data was visible. That can be normal.",
            confidence="high",
            remediation="Add a TXT record only if a provider or mail policy requires one.",
            overlaps=["spf"],
        )
    clipped = [item[:500] for item in answer.records]
    spf = [item for item in clipped if item.lower().startswith("v=spf1")]
    findings = clipped
    if spf:
        findings.append("An SPF record is present. The SPF check interprets it and is the same DNS text, not a second publication.")
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"{len(clipped)} TXT record(s) were published at the apex.",
        findings=findings,
        data={"records": clipped, "spf_present": bool(spf)},
        method="DNS TXT query to 1.1.1.1 for the target domain.",
        explanation="Each TXT string is public DNS data. Verification tokens identify a relationship the operator created with a provider. They are not vulnerabilities by themselves.",
        usefulness="Administrators can inventory public verification records and see whether SPF is published before reading the SPF analysis.",
        limitations=_DNS_LIMIT + " Long records are truncated. InfinityX does not call third-party verification APIs to test a token.",
        evidence=" | ".join(clipped)[:1500],
        impact="Informational public DNS text. Tokens can identify linked services.",
        confidence="high",
        remediation="Remove verification records that are no longer needed. Interpret mail policy in the SPF and DMARC checks.",
        overlaps=["spf"],
    )


def check_soa(ctx: ScanContext) -> CheckResult:
    """Collect the SOA record."""
    answer = ctx.dns("SOA")
    failed = _dns_failure("SOA", answer, "DNS SOA query to 1.1.1.1.")
    if failed:
        return failed
    if not answer.structured:
        empty = answer.status == "nxdomain"
        return result(
            status="WARNING" if empty else "OK",
            severity="UNASSESSED" if empty else "INFORMATIONAL",
            summary="No SOA record was returned." if not empty else "The name does not exist according to 1.1.1.1 (NXDOMAIN), so no SOA was returned.",
            findings=[answer.error or answer.status],
            data={"status": answer.status},
            method="DNS SOA query to 1.1.1.1.",
            explanation="The SOA names the primary nameserver, a contact-style RNAME, and timers. It was not returned for this name.",
            usefulness="The SOA serial and timers help an operator compare zone copies. They were not available here.",
            limitations=_DNS_LIMIT,
            evidence=answer.status,
            impact="SOA metadata was not assessed.",
            confidence="medium",
            remediation="If the domain should exist, check the delegation. NXDOMAIN means this resolver says the name is not in the DNS.",
            observation_type="unavailable",
        )
    soa = answer.structured[0]
    rname = str(soa.get("rname", ""))
    mailbox_hint = rname.replace(".", "@", 1) if "." in rname else rname
    findings = [
        f"Primary nameserver: {soa.get('mname')}",
        f"RNAME: {rname}",
        f"RNAME with the first dot turned into @: {mailbox_hint}. This is a conventional reading, not a confirmed mailbox.",
        f"Serial: {soa.get('serial')}",
        f"Refresh/retry/expire/minimum: {soa.get('refresh')}/{soa.get('retry')}/{soa.get('expire')}/{soa.get('minimum')}",
    ]
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"SOA primary {soa.get('mname')}, serial {soa.get('serial')}.",
        findings=findings,
        data=soa,
        method="DNS SOA query to 1.1.1.1.",
        explanation="The SOA is the zone's administrative record. The serial usually increases when the zone changes. The RNAME looks like a contact but the first-dot rule is ambiguous, so InfinityX does not claim it is a working mailbox.",
        usefulness="The primary nameserver and serial help an administrator see which DNS host is advertised as primary and whether the zone has a current serial.",
        limitations=_DNS_LIMIT + " Timers are not a security boundary. InfinityX did not compare serials across providers.",
        evidence=answer.records[0] if answer.records else "",
        impact="Informational zone metadata.",
        confidence="high",
        remediation="If the primary nameserver is unexpected, review the zone at the DNS provider.",
    )


def check_caa(ctx: ScanContext) -> CheckResult:
    """Collect CAA records."""
    answer = ctx.dns("CAA")
    failed = _dns_failure("CAA", answer, "DNS CAA query to 1.1.1.1.")
    if failed:
        return failed
    if answer.status == "nxdomain":
        return _nxdomain("CAA")
    if not answer.records:
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary="No CAA records were published.",
            findings=["1.1.1.1 returned no CAA records. Certificate authorities are not given an extra DNS restriction by this domain."],
            data={"records": []},
            method="DNS CAA query to 1.1.1.1.",
            explanation="CAA records can limit which certificate authorities may issue for a name. No CAA record is common. It is an observation about DNS policy, not proof that a certificate is unauthorized.",
            usefulness="An operator who wants issuance restricted to a chosen authority can see that no such restriction is published.",
            limitations=_DNS_LIMIT + " Parent-zone CAA was not evaluated. A missing CAA record is not a vulnerability finding.",
            evidence="No CAA records.",
            impact="Any publicly trusted authority that otherwise validates the domain may still be eligible to issue. That is the normal default.",
            confidence="high",
            remediation="Publish CAA if you want to restrict issuance. Do not treat a missing CAA record as evidence that a bad certificate exists.",
            observation_type="informational",
        )
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary="CAA records: " + "; ".join(answer.records),
        findings=answer.records,
        data={"records": answer.structured},
        method="DNS CAA query to 1.1.1.1.",
        explanation="Each CAA record names a tag such as issue, issuewild, or iodef and a value. InfinityX reports the published policy and does not test whether every authority honors it.",
        usefulness="Operators can confirm that the intended certificate authority is the one published in DNS.",
        limitations=_DNS_LIMIT + " InfinityX did not walk parent zones and did not attempt issuance.",
        evidence="; ".join(answer.records),
        impact="Informational. CAA is a publication, not a test that issuance controls work.",
        confidence="high",
        remediation="Update the CAA record when you change certificate providers. Confirm iodef mailboxes separately if one is published.",
    )


def check_second_resolver(ctx: ScanContext) -> CheckResult:
    """Compare address answers from 1.1.1.1 and 8.8.8.8."""
    primary_a = ctx.dns("A", resolver="primary")
    secondary_a = ctx.dns("A", resolver="secondary")
    primary_aaaa = ctx.dns("AAAA", resolver="primary")
    secondary_aaaa = ctx.dns("AAAA", resolver="secondary")
    if primary_a.status in {"timeout", "error"} and secondary_a.status in {"timeout", "error"}:
        return result(
            status="FAILED",
            severity="UNASSESSED",
            summary="Both public resolvers failed the A query.",
            findings=[primary_a.error or primary_a.status, secondary_a.error or secondary_a.status],
            data={},
            method="DNS A and AAAA queries to 1.1.1.1 and 8.8.8.8.",
            explanation="The comparison could not be made because neither resolver returned an A answer.",
            usefulness="A second resolver can reveal differences caused by CDNs, geo-DNS, or a resolver failure.",
            limitations=_DNS_LIMIT,
            evidence="Both A queries failed.",
            impact="Cross-resolver comparison was not assessed.",
            confidence="high",
            remediation="Retry from a network that can reach 1.1.1.1 and 8.8.8.8 on DNS.",
            observation_type="unavailable",
            error=primary_a.error or secondary_a.error,
            overlaps=["dns-a", "dns-aaaa"],
        )
    left = set(primary_a.records)
    right = set(secondary_a.records)
    left6 = set(primary_aaaa.records)
    right6 = set(secondary_aaaa.records)
    private = [ip for ip in left | right | left6 | right6 if not ip_is_public(ip)]
    findings = [
        f"1.1.1.1 A: {', '.join(sorted(left)) or primary_a.status}",
        f"8.8.8.8 A: {', '.join(sorted(right)) or secondary_a.status}",
        f"1.1.1.1 AAAA: {', '.join(sorted(left6)) or primary_aaaa.status}",
        f"8.8.8.8 AAAA: {', '.join(sorted(right6)) or secondary_aaaa.status}",
    ]
    same = left == right and left6 == right6
    if private:
        findings.append("At least one resolver returned a non-public address. InfinityX will not connect to it.")
        return result(
            status="WARNING",
            severity="MEDIUM",
            summary="A public resolver returned a non-public address for this name.",
            findings=findings,
            data={"cloudflare_a": sorted(left), "google_a": sorted(right), "private": private},
            method="DNS A and AAAA queries to 1.1.1.1 and 8.8.8.8. The A records from 1.1.1.1 are the same lookup used by the A-record check.",
            explanation="Public DNS normally returns public addresses. A private or link-local answer can be intentional split-horizon data that leaked, or a filtering resolver. This scan cannot decide which, and it does not treat the result as proof of compromise.",
            usefulness="Internal addresses in public DNS tell an administrator that internal numbering may be visible.",
            limitations=_DNS_LIMIT + " No connection was made to the non-public address.",
            evidence=", ".join(private),
            impact="Internal addressing may be disclosed. Services on those addresses were not tested.",
            confidence="medium",
            remediation="If the private address was not meant to be public, remove it from the public zone and review split-horizon DNS.",
            observation_type="configuration_observation",
            overlaps=["dns-a", "dns-aaaa", "public-ips"],
        )
    if same:
        summary = "1.1.1.1 and 8.8.8.8 returned the same address sets."
        explanation = "The two resolvers agree. The addresses themselves are reported by the A and AAAA checks; this check only adds the comparison."
    else:
        summary = "1.1.1.1 and 8.8.8.8 did not return the same address sets."
        explanation = (
            "Different public answers can be normal for CDNs and location-based DNS. "
            "They can also come from cache timing. InfinityX cannot tell those cases apart from a resolver inconsistency, so this is not labeled as hijacking."
        )
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=summary,
        findings=findings,
        data={"cloudflare_a": sorted(left), "google_a": sorted(right), "cloudflare_aaaa": sorted(left6), "google_aaaa": sorted(right6), "match": same},
        method="DNS A and AAAA queries to 1.1.1.1 and 8.8.8.8. Address values overlap the A and AAAA checks; the comparison is the additional information.",
        explanation=explanation,
        usefulness="Agreement increases confidence that the address set is not unique to one resolver. A difference is a reason to look at the DNS provider's routing policy.",
        limitations=_DNS_LIMIT + " Only two resolvers were asked, once each.",
        evidence=summary,
        impact="Informational resolver comparison. No compromise conclusion is drawn from a difference.",
        confidence="medium",
        remediation="If the sets differ and that is unexpected, compare them with the DNS provider's geo-routing or CDN configuration.",
        overlaps=["dns-a", "dns-aaaa"],
    )


def check_ptr(ctx: ScanContext) -> CheckResult:
    """Reverse-resolve the public addresses already found for the domain."""
    ips, note = _public_ips_from_dns(ctx)
    if not ips:
        return result(
            status="WARNING",
            severity="UNASSESSED",
            summary="No public address was available for reverse DNS.",
            findings=[note or "A and AAAA queries did not produce a public address."],
            data={"map": {}},
            method="PTR query to 1.1.1.1 for each public A or AAAA result. Not run because there was no public address.",
            explanation="Reverse DNS maps an address back to a name. Without a public address from the forward lookup, there was nothing to reverse.",
            usefulness="PTR names can show a hosting provider's naming scheme.",
            limitations="This is the same PTR method used later by the infrastructure reverse-DNS check.",
            evidence=note or "No public addresses.",
            impact="Reverse DNS was not assessed.",
            confidence="high",
            remediation="Resolve the forward DNS issue first. If the name is meant to be offline, no PTR is expected.",
            observation_type="unavailable",
            overlaps=["reverse-dns", "dns-a", "dns-aaaa"],
        )
    mapping: dict[str, list[str]] = {}
    errors: list[str] = []
    for ip in ips[:6]:
        answer = ctx.ptr(ip)
        if answer.status == "ok":
            mapping[ip] = answer.records
        elif answer.status in {"noanswer", "nxdomain"}:
            mapping[ip] = []
        else:
            errors.append(f"{ip}: {answer.error or answer.status}")
            mapping[ip] = []
    findings = []
    for ip, names in mapping.items():
        findings.append(f"{ip} -> {', '.join(names) if names else 'no PTR'}")
    if errors:
        findings.extend(errors)
    any_name = any(mapping.values())
    return result(
        status="WARNING" if errors and not any_name else "OK",
        severity="INFORMATIONAL" if not errors else "UNASSESSED",
        summary="Reverse DNS collected for " + str(len(mapping)) + " address(es).",
        findings=findings,
        data={"map": mapping, "errors": errors},
        method="PTR query to 1.1.1.1 using the in-addr.arpa or ip6.arpa name of each public address, capped at 6 addresses.",
        explanation="A PTR record is a name chosen by whoever controls the reverse zone, often the hosting provider. It may not match the website domain. A missing PTR is common and is not a vulnerability.",
        usefulness="Provider hostnames can corroborate the ASN and hosting observation.",
        limitations=_DNS_LIMIT + " The infrastructure reverse-DNS check repeats this evidence and labels it as the same lookup when the cache is warm.",
        evidence="; ".join(findings)[:1500],
        impact="Informational. PTR names can disclose a provider hostname.",
        confidence="high" if not errors else "low",
        remediation="Ask the address owner to set a PTR if you need a specific mail or provider name. Do not treat a missing PTR as a verified security issue.",
        overlaps=["reverse-dns"],
    )


def check_dnssec(ctx: ScanContext) -> CheckResult:
    """Report published DNSSEC material and the resolver AD flag."""
    data = ctx.dnssec()
    ds = data.get("ds") or []
    dnskey = data.get("dnskey") or []
    ad = data.get("ad")
    errors = data.get("errors") or []
    if errors and not ds and not dnskey and ad is None:
        return result(
            status="FAILED",
            severity="UNASSESSED",
            summary="DNSSEC information could not be collected.",
            findings=list(errors),
            data=data,
            method="DNS DS and DNSKEY queries to 1.1.1.1, plus an A query with the DO bit to read the AD flag. No local chain validation.",
            explanation="The resolver did not return enough information to say whether DNSSEC is published.",
            usefulness="DNSSEC status tells an operator whether signed DNS is visible to a public resolver.",
            limitations="InfinityX does not validate the signature chain itself.",
            evidence="; ".join(errors),
            impact="DNSSEC was not assessed.",
            confidence="high",
            remediation="Retry the DNSSEC queries later. A failure of this check is not a statement that the zone is unsigned or broken.",
            observation_type="unavailable",
            error="; ".join(errors),
        )
    findings = [
        f"DS records returned: {len(ds)}",
        f"DNSKEY records returned: {len(dnskey)}",
        "AD flag on A query to 1.1.1.1: " + ("set" if ad else "not set" if ad is False else "not available"),
    ]
    findings.extend(ds[:5])
    findings.extend(dnskey[:3])
    if errors:
        findings.extend(errors)
    if ds and ad:
        summary = "DNSSEC material is published and 1.1.1.1 set the AD flag."
        explanation = "The DS record is the parent's hash of the zone key, and the AD flag means this resolver considers its A answer authenticated. InfinityX did not rebuild or verify that chain locally."
        status = "OK"
        severity = "INFORMATIONAL"
    elif ds or dnskey:
        summary = "Some DNSSEC material was returned, but validation was not completed."
        explanation = "Seeing a DS or DNSKEY means signed-DNS data is published or cached. A missing counterpart can be an incomplete deployment or a resolver limitation. InfinityX does not call that a break in DNSSEC."
        status = "WARNING"
        severity = "UNASSESSED"
    else:
        summary = "No DS or DNSKEY records were returned, and the AD flag was not set."
        explanation = "From this resolver, the zone does not show deployed DNSSEC. Many domains are unsigned. Unsigned DNS is an observation, not proof that an answer was forged during this scan."
        status = "OK"
        severity = "INFORMATIONAL"
    return result(
        status=status,
        severity=severity,
        summary=summary,
        findings=findings,
        data={"ds_count": len(ds), "dnskey_count": len(dnskey), "ad": ad, "errors": errors},
        method="DNS DS and DNSKEY queries to 1.1.1.1, plus an A query with the DO bit to read the AD flag. No local chain validation.",
        explanation=explanation,
        usefulness="Operators can see whether public resolvers are being given DNSSEC material for the zone.",
        limitations="No signature was validated locally. The AD flag is one resolver's claim. Parent DS latency and cache can change the picture.",
        evidence=summary,
        impact="Informational DNS-authentication posture as seen from 1.1.1.1. No forgery was demonstrated.",
        confidence="medium",
        remediation="If DNSSEC is intended, confirm DS publication at the registrar and DNSKEY publication in the zone. If it is not intended, no action is required from this observation.",
        observation_type="informational" if severity == "INFORMATIONAL" else "unavailable",
    )


def _public_ips_from_dns(ctx: ScanContext) -> tuple[list[str], str | None]:
    addresses: list[str] = []
    notes: list[str] = []
    for rtype in ("A", "AAAA"):
        answer = ctx.dns(rtype)
        if answer.status in {"timeout", "error"}:
            notes.append(f"{rtype}: {answer.error or answer.status}")
            continue
        for ip in answer.records:
            if ip_is_public(ip) and ip not in addresses:
                addresses.append(ip)
    return addresses, "; ".join(notes) if notes else None


def _address_result(rtype: str, label: str, answer: DnsAnswer, check_id: str) -> CheckResult:
    failed = _dns_failure(rtype, answer, f"DNS {rtype} query to 1.1.1.1.")
    if failed:
        return failed
    if answer.status == "nxdomain":
        return _nxdomain(rtype)
    findings = list(answer.records)
    if answer.cnames:
        findings.append("CNAME encountered: " + ", ".join(answer.cnames))
    private = [ip for ip in answer.records if not ip_is_public(ip)]
    if not answer.records:
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary=f"No {label} records were published.",
            findings=findings or [f"1.1.1.1 returned no {rtype} records."],
            data={"records": [], "cnames": answer.cnames},
            method=f"DNS {rtype} query to 1.1.1.1. A CNAME query is included when collecting A records.",
            explanation=f"No {label} was returned. The name may be unpublished for this family, or it may exist only as the other address family. This is not a vulnerability.",
            usefulness=f"The {rtype} set is the address list HTTP and infrastructure checks will consider.",
            limitations=_DNS_LIMIT,
            evidence=f"No {rtype} records.",
            impact=f"Clients that only use {label} records will not reach this name through this answer.",
            confidence="high",
            remediation=f"Publish {rtype} records if this address family is intended. Otherwise no action is required.",
            overlaps=["public-ips", "dns-second-resolver"],
        )
    status = "WARNING" if private else "OK"
    severity = "MEDIUM" if private else "INFORMATIONAL"
    summary = f"{rtype} records: " + ", ".join(answer.records)
    if private:
        summary = f"{rtype} records include a non-public address: " + ", ".join(private)
    return result(
        status=status,
        severity=severity,
        summary=summary,
        findings=findings,
        data={"records": answer.records, "cnames": answer.cnames, "non_public": private},
        method=f"DNS {rtype} query to 1.1.1.1.",
        explanation=(
            f"These are the {label} records returned for the domain. "
            + ("A non-public address was included. InfinityX will not connect to it. " if private else "")
            + "The public-IP check later filters this same set; it is not a second resolution."
        ),
        usefulness="The address set shows where the DNS is sending clients and is the input for ASN, geolocation, and reverse DNS.",
        limitations=_DNS_LIMIT + " Only the first public address is used for the later pinned HTTP and TLS connections.",
        evidence=", ".join(answer.records),
        impact="Informational routing data." if not private else "A non-public address in public DNS can disclose internal numbering. No connection to it was made.",
        confidence="high",
        remediation="Remove unintended private addresses from the public zone." if private else "If an address is unexpected, review the DNS provider or CDN configuration.",
        observation_type="configuration_observation" if private else "informational",
        overlaps=["public-ips", "dns-second-resolver"],
    )


def _dns_failure(rtype: str, answer: DnsAnswer, method: str) -> CheckResult | None:
    if answer.status not in {"timeout", "error"}:
        return None
    return result(
        status="FAILED",
        severity="UNASSESSED",
        summary=f"The {rtype} query failed.",
        findings=[answer.error or answer.status],
        data={"status": answer.status},
        method=method,
        explanation=f"The {rtype} lookup did not return an answer. InfinityX does not invent records when a resolver times out or errors.",
        usefulness="A recorded failure shows that this part of DNS was not assessed.",
        limitations=_DNS_LIMIT,
        evidence=answer.error or answer.status,
        impact=f"{rtype} data was not assessed.",
        confidence="high",
        remediation="Retry from a network that can reach the public resolver on port 53.",
        observation_type="unavailable",
        error=answer.error or answer.status,
    )


def _nxdomain(rtype: str) -> CheckResult:
    return result(
        status="WARNING",
        severity="MEDIUM",
        summary="1.1.1.1 returned NXDOMAIN for this domain.",
        findings=[f"The {rtype} query returned NXDOMAIN, which means this resolver says the name does not exist."],
        data={"status": "nxdomain"},
        method=f"DNS {rtype} query to 1.1.1.1.",
        explanation="NXDOMAIN is a resolver statement that the name is not delegated in the DNS it can see. Later HTTP and TLS checks will have no public address to contact. This is a availability observation, not proof of a compromise.",
        usefulness="It tells the operator that public resolution of the website name failed at scan time.",
        limitations=_DNS_LIMIT + " A different resolver or a very new delegation could disagree. The second-resolver check tests one additional resolver.",
        evidence="NXDOMAIN",
        impact="Clients using this answer cannot resolve the website name.",
        confidence="medium",
        remediation="If the domain should resolve, check registration, delegation, and the zone at the DNS provider.",
        observation_type="configuration_observation",
    )
