"""Public IP, ASN, geolocation, reverse DNS, and optional traceroute."""

from __future__ import annotations

import shutil
import subprocess

from infinityx.checks.dns_checks import _public_ips_from_dns
from infinityx.context import ScanContext
from infinityx.models import CheckResult
from infinityx.models import build_result as result
from infinityx.safety import ip_is_public


def check_public_ips(ctx: ScanContext) -> CheckResult:
    """Summarize public addresses from the DNS checks and confirm the safety filter."""
    ips, note = _public_ips_from_dns(ctx)
    resolved, resolve_note = ctx.addresses()
    combined = list(dict.fromkeys([*ips, *[ip for ip in resolved if ip_is_public(ip)]]))
    findings = [f"Public addresses: {', '.join(combined) or 'none'}"]
    if note:
        findings.append(note)
    if resolve_note:
        findings.append(resolve_note)
    findings.append("These addresses come from the A and AAAA lookups. This check adds the public-address filter; it is not a second discovery of the same records.")
    if not combined:
        return result(
            status="WARNING",
            severity="MEDIUM",
            summary="No public IP address was available for this domain.",
            findings=findings,
            data={"ips": []},
            method="Filter A and AAAA answers from 1.1.1.1, and the two-resolver safety resolution, to public unicast addresses.",
            explanation="HTTP, TLS, ASN, and geolocation checks need a public address. None passed the filter, so those network connections were not given a target.",
            usefulness="It makes the lack of a connectable address explicit instead of hiding it inside the DNS list.",
            limitations="Private answers, if any, stay in the DNS checks and are not contacted.",
            evidence="No public addresses.",
            impact="The website cannot be reached through the public answers collected here.",
            confidence="medium",
            remediation="Publish the intended public address or CDN address if the site should be online.",
            observation_type="configuration_observation",
            overlaps=["dns-a", "dns-aaaa", "dns-second-resolver"],
        )
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary="Public addresses: " + ", ".join(combined),
        findings=findings,
        data={"ips": combined},
        method="Filter A and AAAA answers already collected from public resolvers. Non-public addresses are excluded.",
        explanation="A public address is one that is not loopback, private, link-local, reserved, or otherwise blocked by the scanner rules. Later checks pin connections to one of these addresses.",
        usefulness="The list is the infrastructure identity used for hosting lookups.",
        limitations="CDNs and anycast addresses are the edge the resolver returned, not necessarily the origin server. Only the first IPv4 address is pinned for HTTP and TLS.",
        evidence=", ".join(combined),
        impact="Informational. Public DNS already discloses these addresses.",
        confidence="high",
        remediation="If an address is unexpected, review the DNS provider, CDN, and origin firewall.",
        overlaps=["dns-a", "dns-aaaa"],
    )


def check_asn(ctx: ScanContext) -> CheckResult:
    """Ask RIPEstat for ASN and prefix data."""
    ips, _note = _public_ips_from_dns(ctx)
    if not ips:
        return _no_ip("ASN and prefix", "https://stat.ripe.net/data/prefix-overview/data.json?resource=<ip>")
    rows = []
    errors = []
    for ip in ips[:3]:
        item = ctx.ripe(ip)
        payload = item.get("payload") or {}
        data = payload.get("data") if isinstance(payload, dict) else None
        if item.get("error") and not data:
            errors.append(f"{ip}: {item.get('error')}")
            continue
        asns = []
        if isinstance(data, dict):
            for asn in data.get("asns") or []:
                if isinstance(asn, dict):
                    asns.append({"asn": asn.get("asn"), "holder": asn.get("holder")})
            block = data.get("block") or {}
            rows.append({"ip": ip, "asns": asns, "prefix": block.get("resource"), "holder_block": block.get("desc") or block.get("name")})
    if not rows and errors:
        return result(
            status="FAILED",
            severity="UNASSESSED",
            summary="RIPEstat did not return ASN data.",
            findings=errors,
            data={"errors": errors},
            method="HTTPS GET to RIPEstat prefix-overview for up to three public addresses. No API key.",
            explanation="ASN data describes which network announces the address. The public source did not answer, so no owner was invented.",
            usefulness="The ASN holder usually identifies the hosting or CDN network.",
            limitations="RIPEstat is a third party. Sending it a public IP is documented here. Registration names can be legal entities rather than the website brand.",
            evidence="; ".join(errors),
            impact="Network ownership was not assessed.",
            confidence="high",
            remediation="Retry later or look up the address in a regional internet registry.",
            observation_type="unavailable",
            error="; ".join(errors),
        )
    findings = []
    for row in rows:
        holders = ", ".join(f"AS{item.get('asn')} {item.get('holder')}" for item in row["asns"]) or "no ASN parsed"
        findings.append(f"{row['ip']}: {holders}; prefix {row.get('prefix')}")
    if len(ips) > 3:
        findings.append("Additional addresses were not sent to RIPEstat.")
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary="RIPEstat prefix data was collected for " + str(len(rows)) + " address(es).",
        findings=findings,
        data={"results": rows},
        method="HTTPS GET https://stat.ripe.net/data/prefix-overview/data.json?resource=<ip> for up to three public addresses.",
        explanation="An autonomous system number identifies a routing domain. The holder string is the name RIPEstat published for that ASN. It often names a cloud or CDN provider. It does not prove a legal relationship beyond what the registry data says, and it is not a vulnerability.",
        usefulness="Operators can confirm that the domain resolves to the network they expect, such as their CDN or cloud account.",
        limitations="Anycast and CDN edges are not the origin. RIPEstat data can lag routing changes. At most three addresses were queried. This source received the public IP address.",
        evidence="; ".join(findings)[:1500],
        impact="Informational network identity.",
        confidence="medium",
        remediation="If the ASN is unexpected, review DNS and CDN configuration before assuming the account was changed.",
        raw_ref="ripe_" + ips[0].replace(":", "_") + ".json",
    )


def check_geo(ctx: ScanContext) -> CheckResult:
    """Ask RIPEstat for an approximate location and state the accuracy limit."""
    ips, _note = _public_ips_from_dns(ctx)
    if not ips:
        return _no_ip("IP geolocation", "https://stat.ripe.net/data/geoloc/data.json?resource=<ip>")
    rows = []
    errors = []
    for ip in ips[:3]:
        item = ctx.geo(ip)
        payload = item.get("payload") or {}
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            errors.append(f"{ip}: {item.get('error') or 'no geolocation object'}")
            continue
        locations = []
        for resource in data.get("located_resources") or []:
            if isinstance(resource, dict):
                for location in resource.get("locations") or []:
                    if isinstance(location, dict):
                        locations.append(
                            {
                                "country": location.get("country"),
                                "city": location.get("city"),
                                "latitude": location.get("latitude"),
                                "longitude": location.get("longitude"),
                            }
                        )
        rows.append({"ip": ip, "locations": locations[:3]})
    if not rows:
        return result(
            status="FAILED",
            severity="UNASSESSED",
            summary="RIPEstat did not return geolocation data.",
            findings=errors or ["No location object was parsed."],
            data={},
            method="HTTPS GET https://stat.ripe.net/data/geoloc/data.json?resource=<ip> for up to three public addresses.",
            explanation="The geolocation source did not return a usable estimate. No city or country was invented.",
            usefulness="A coarse location can hint at the edge or provider region. It is often wrong for CDNs.",
            limitations="City-level IP geolocation is an estimate, frequently inaccurate, and especially unreliable for anycast and CDN addresses.",
            evidence="; ".join(errors) or "No data.",
            impact="Location was not assessed.",
            confidence="high",
            remediation="Do not make an operational decision from missing geolocation. Use the ASN and your hosting console instead.",
            observation_type="unavailable",
            error="; ".join(errors) if errors else None,
        )
    findings = [
        "Accuracy caveat: this is an estimate from RIPEstat, not a measurement of the server's physical location. CDN and anycast addresses often geolocate to an edge, not the origin."
    ]
    for row in rows:
        if not row["locations"]:
            findings.append(f"{row['ip']}: no location in the response.")
            continue
        for location in row["locations"]:
            findings.append(f"{row['ip']}: {location.get('city') or 'unknown city'}, {location.get('country') or 'unknown country'}")
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary="Approximate geolocation was returned for " + str(len(rows)) + " address(es). Treat it as a low-confidence estimate.",
        findings=findings,
        data={"results": rows, "accuracy": "estimate"},
        method="HTTPS GET https://stat.ripe.net/data/geoloc/data.json?resource=<ip>. The public IP is sent to RIPEstat.",
        explanation="RIPEstat returns a location estimate for the address prefix. InfinityX reports it with the caveat that city-level IP geolocation is often wrong, particularly for CDNs, VPNs, and anycast networks. It is not evidence of where the organization is based.",
        usefulness="It can still hint at a region when the address belongs to a single hosting site rather than a global edge.",
        limitations="Low confidence by design. At most three addresses were queried. Coordinates are estimates from the upstream dataset, not GPS.",
        evidence="; ".join(findings[1:])[:1500] or "No city was returned.",
        impact="Informational and uncertain. Do not use it as proof of server location.",
        confidence="low",
        remediation="Use your hosting or CDN console for the real region. Do not block or attribute an owner from this estimate.",
    )


def check_reverse_dns(ctx: ScanContext) -> CheckResult:
    """Repeat the PTR evidence only to compare it with the earlier reverse lookup."""
    ips, _note = _public_ips_from_dns(ctx)
    if not ips:
        return _no_ip("Reverse DNS", "PTR query to 1.1.1.1")
    findings = [
        "This infrastructure check uses the PTR cache from the DNS reverse-lookup check when that check already ran. It is the same evidence, not a new discovery."
    ]
    mapping = {}
    for ip in ips[:6]:
        answer = ctx.ptr(ip)
        mapping[ip] = answer.records if answer.status == "ok" else []
        label = ", ".join(mapping[ip]) if mapping[ip] else "no PTR"
        findings.append(f"{ip} -> {label}")
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary="Reverse DNS matches the earlier PTR check for " + str(len(mapping)) + " address(es).",
        findings=findings,
        data={"map": mapping, "duplicate_of": "dns-ptr"},
        method="PTR lookup through 1.1.1.1, served from the scan cache when the DNS reverse-lookup check already queried the same address.",
        explanation="Reverse DNS is the name in the address's PTR record. Hosting providers often set it to their own hostname. A difference from the website name is normal. Because this is the same query as the DNS PTR check, the report does not count it as a second independent source.",
        usefulness="Seeing the provider hostname next to the ASN helps confirm hosting.",
        limitations="The reverse zone is controlled by the address holder, not necessarily by the website operator. Results are cached from the earlier check when available.",
        evidence="; ".join(findings[1:])[:1500],
        impact="Informational provider naming.",
        confidence="high",
        remediation="Request a PTR change from the IP provider if a specific reverse name is required for mail. A missing PTR is not a website vulnerability.",
        overlaps=["dns-ptr"],
    )


def check_traceroute(ctx: ScanContext) -> CheckResult:
    """Run traceroute only when the operator enabled it and the command exists."""
    command = ["traceroute", "-n", "-m", "12", "-w", "1", "-q", "1", ctx.domain]
    shown = "traceroute -n -m 12 -w 1 -q 1 <domain>"
    if not ctx.enable_traceroute:
        return result(
            status="SKIPPED",
            severity="UNASSESSED",
            summary="Traceroute is disabled by default.",
            findings=["Re-run with --enable-traceroute only if you are authorized to send traceroute probes."],
            data={"enabled": False, "executed": False},
            method=shown + ". The command was not executed.",
            explanation="Traceroute sends probe packets beyond a normal web request. InfinityX leaves it off unless the operator opts in. No path was invented.",
            usefulness="A path can show the first few network hops toward the resolved address.",
            limitations="Traceroute is not a map of application security, and many networks hide hops.",
            evidence="Not executed.",
            impact="The network path was not assessed.",
            confidence="high",
            remediation="Install traceroute and pass --enable-traceroute if this authorized diagnostic is wanted.",
            observation_type="unavailable",
        )
    binary = shutil.which("traceroute")
    if not binary:
        return result(
            status="SKIPPED",
            severity="UNASSESSED",
            summary="The traceroute command is not installed.",
            findings=["--enable-traceroute was set, but traceroute was not found on PATH."],
            data={"enabled": True, "executed": False},
            method=shown + ". The command was not executed.",
            explanation="The optional system package is missing, so the check was skipped instead of failing the whole scan.",
            usefulness="When present, traceroute lists hops toward the destination.",
            limitations="No Windows tracert fallback is used. The Kali traceroute package is the expected command.",
            evidence="traceroute not found.",
            impact="The network path was not assessed.",
            confidence="high",
            remediation="Install the traceroute package on Kali and rerun with --enable-traceroute.",
            observation_type="unavailable",
        )
    try:
        completed = subprocess.run(
            [binary, "-n", "-m", "12", "-w", "1", "-q", "1", ctx.domain],
            capture_output=True,
            text=True,
            timeout=25,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return result(
            status="FAILED",
            severity="UNASSESSED",
            summary="Traceroute did not finish.",
            findings=[str(exc)[:400]],
            data={"executed": True},
            method=shown,
            explanation="The traceroute process timed out or could not start. No path was invented.",
            usefulness="A finished traceroute would list responsive hops.",
            limitations="Networks often rate-limit or hide traceroute responses.",
            evidence=str(exc)[:400],
            impact="The network path was not assessed.",
            confidence="high",
            remediation="Run the same command manually if you need the path.",
            observation_type="unavailable",
            error=str(exc)[:400],
        )
    output = ((completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else ""))[:8000]
    ctx.store("traceroute.txt", output)
    hops = [line for line in output.splitlines() if line.strip()][:20]
    return result(
        status="OK" if completed.returncode == 0 else "WARNING",
        severity="INFORMATIONAL",
        summary=f"Traceroute finished with exit code {completed.returncode}.",
        findings=hops or ["Traceroute produced no hop lines."],
        data={"returncode": completed.returncode, "hop_lines": len(hops)},
        method=shown + ". Probes were capped at 12 hops, one probe per hop, and a 25 second process timeout.",
        explanation="Each line is a hop that answered or timed out. Hidden hops are normal. The path is a network diagnostic and is not evidence of a vulnerability.",
        usefulness="It can show an unexpected upstream when compared with the hosting provider you expect.",
        limitations="ICMP or UDP probes can be filtered. The destination itself may not answer. Output is truncated.",
        evidence=f"exit {completed.returncode}, {len(hops)} lines",
        impact="Informational path disclosure from networks that answered probes.",
        confidence="low",
        remediation="Compare unexpected hops with your hosting provider. Do not treat a timeout hop as an attack.",
        raw_ref="traceroute.txt",
    )


def _no_ip(label: str, method: str) -> CheckResult:
    return result(
        status="WARNING",
        severity="UNASSESSED",
        summary=f"{label} was not queried because no public address was available.",
        findings=["The DNS checks did not provide a public address."],
        data={},
        method=method + ". The request was not sent.",
        explanation="InfinityX does not send infrastructure lookups without a public address from the target resolution.",
        usefulness="ASN and location data only make sense for the address the domain publishes.",
        limitations="This is the same resolution result as the public-IP check.",
        evidence="No public IP.",
        impact=f"{label} was not assessed.",
        confidence="high",
        remediation="Correct public DNS first, then rerun the scan.",
        observation_type="unavailable",
        overlaps=["public-ips"],
    )
