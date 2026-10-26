"""Website and HTTP observations.

Missing security headers are reported as observations. They are not labeled as
proof that the site is vulnerable.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from html.parser import HTMLParser

from infinityx.context import ScanContext
from infinityx.models import CheckResult, HttpSnapshot
from infinityx.models import build_result as result

SECURITY_HEADER_NOTES = {
    "strict-transport-security": "Tells browsers to keep using HTTPS for a period of time.",
    "content-security-policy": "Restricts which sources a browser may load for this response.",
    "x-content-type-options": "Asks browsers not to MIME-sniff a response away from the declared type.",
    "x-frame-options": "Gives a legacy hint about whether other sites may frame this response.",
    "referrer-policy": "Limits how much of the URL is sent as a referrer.",
    "permissions-policy": "Limits browser features such as camera or geolocation for this response.",
    "cross-origin-opener-policy": "Isolates the browsing context from cross-origin windows.",
    "cross-origin-resource-policy": "Limits which origins may load this response as a resource.",
    "cross-origin-embedder-policy": "Restricts embedded cross-origin resources.",
}


class PageParser(HTMLParser):
    """Extract a title, description, and canonical link from untrusted HTML."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._in_title = False
        self._title: list[str] = []
        self.description: str | None = None
        self.canonical: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        mapping = {key.lower(): (value or "") for key, value in attrs}
        if tag.lower() == "title":
            self._in_title = True
        if tag.lower() == "meta" and self.description is None:
            name = (mapping.get("name") or mapping.get("property") or "").lower()
            if name in {"description", "og:description"}:
                self.description = mapping.get("content", "")[:500]
        if tag.lower() == "link" and self.canonical is None:
            rel = mapping.get("rel", "").lower().split()
            if "canonical" in rel:
                self.canonical = mapping.get("href", "")[:500]

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title and sum(len(part) for part in self._title) < 300:
            self._title.append(data)

    @property
    def title(self) -> str:
        text = " ".join("".join(self._title).split())
        text = re.sub(r"<[^>]{0,80}>", "", text)
        return " ".join(text.split())[:300]


def parse_page(html: str) -> dict[str, str | None]:
    """Parse a bounded HTML body. Parser errors become empty fields, not crashes."""
    parser = PageParser()
    try:
        parser.feed(html[:512_000])
        parser.close()
    except Exception:
        return {"title": None, "description": None, "canonical": None}
    return {
        "title": parser.title or None,
        "description": parser.description,
        "canonical": parser.canonical,
    }


def classify_security_headers(headers: dict[str, str]) -> dict[str, object]:
    """Compare response headers with a fixed observation list."""
    lowered = {key.lower(): value for key, value in headers.items()}
    present = {name: lowered[name] for name in SECURITY_HEADER_NOTES if name in lowered}
    absent = [name for name in SECURITY_HEADER_NOTES if name not in lowered]
    return {"present": present, "absent": absent}


def check_http_status(ctx: ScanContext) -> CheckResult:
    """Request the site over HTTP and record the status."""
    snapshot = ctx.http("http")
    return _status_result(snapshot, "HTTP", "http-status")


def check_https_status(ctx: ScanContext) -> CheckResult:
    """Request the site over HTTPS and record the status."""
    snapshot = ctx.http("https")
    return _status_result(snapshot, "HTTPS", "https-status")


def check_http_to_https(ctx: ScanContext) -> CheckResult:
    """See whether the HTTP response moves clients to HTTPS."""
    snapshot = ctx.http("http")
    if snapshot.blocked_reason and snapshot.status_code is None:
        return _transport_blocked("HTTP", snapshot)
    locations = [item.get("location") for item in snapshot.chain if item.get("location")]
    https_locations = [item for item in locations if str(item).lower().startswith("https://")]
    final = (snapshot.final_url or "").lower()
    if https_locations or final.startswith("https://"):
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary="HTTP points clients at HTTPS.",
            findings=[f"Location values: {locations or ['none']}", f"Recorded destination: {snapshot.final_url}"],
            data={"locations": locations, "final_url": snapshot.final_url, "status": snapshot.status_code},
            method="GET http://<domain>/ with redirects followed only when they stay on the domain. System proxies are ignored.",
            explanation="The HTTP response either redirected to an https URL or the same-site chain ended on HTTPS. That is a positive transport observation. It does not measure application security.",
            usefulness="Administrators can confirm that a clear-text request does not remain on HTTP.",
            limitations="Only the site root was requested. A different path could behave differently. Off-site redirects were recorded and not fetched.",
            evidence=str(https_locations[0] if https_locations else snapshot.final_url),
            impact="A browser that follows this redirect moves to HTTPS for the tested root URL.",
            confidence="medium",
            remediation="Keep a permanent redirect from HTTP to HTTPS and consider HSTS after you have confirmed HTTPS is stable.",
            overlaps=["redirect-destination", "http-status"],
        )
    if not snapshot.ok and snapshot.status_code is None:
        return _transport_blocked("HTTP", snapshot)
    return result(
        status="WARNING",
        severity="LOW",
        summary="The HTTP root did not show a redirect to HTTPS.",
        findings=[
            f"HTTP status: {snapshot.status_code}",
            f"Final recorded URL: {snapshot.final_url}",
            f"Block or stop reason: {snapshot.blocked_reason or 'none'}",
        ],
        data={"status": snapshot.status_code, "final_url": snapshot.final_url, "chain": snapshot.chain},
        method="GET http://<domain>/ with same-site redirects only.",
        explanation="The tested HTTP URL did not move to HTTPS. Visitors who use the http scheme may stay on clear text for this URL. This is a configuration observation, not proof of a vulnerability or of intercepted traffic.",
        usefulness="It tells an administrator that the canonical entry point may still be available without TLS.",
        limitations="A firewall, CDN rule, or method other than GET could differ. Only the root path was tested.",
        evidence=f"HTTP {snapshot.status_code} at {snapshot.final_url}",
        impact="Traffic that stays on HTTP can be read or changed on the network path. This scan did not observe that happening.",
        confidence="medium",
        remediation="Redirect HTTP to HTTPS with a 301 or 308 response, then evaluate HSTS separately.",
        observation_type="configuration_observation",
        overlaps=["redirect-destination", "http-status"],
    )


def check_redirect_destination(ctx: ScanContext) -> CheckResult:
    """Report where the HTTP and HTTPS root requests ended."""
    http_snapshot = ctx.http("http")
    https_snapshot = ctx.http("https")
    findings = [
        f"HTTP chain: {_chain_text(http_snapshot)}",
        f"HTTPS chain: {_chain_text(https_snapshot)}",
    ]
    if http_snapshot.blocked_reason:
        findings.append("HTTP stop reason: " + http_snapshot.blocked_reason)
    if https_snapshot.blocked_reason:
        findings.append("HTTPS stop reason: " + https_snapshot.blocked_reason)
    blocked = bool(http_snapshot.blocked_reason or https_snapshot.blocked_reason)
    return result(
        status="WARNING" if blocked else "OK",
        severity="LOW" if blocked else "INFORMATIONAL",
        summary="Redirect destinations were recorded for the HTTP and HTTPS root requests.",
        findings=findings,
        data={"http_final": http_snapshot.final_url, "https_final": https_snapshot.final_url, "http_chain": http_snapshot.chain, "https_chain": https_snapshot.chain},
        method="Same fetches as the HTTP and HTTPS status checks. Off-site, credentialed, private, and non-HTTP redirects are not followed.",
        explanation="The destination is the last URL InfinityX either fetched on the same site or recorded without fetching. A blocked destination was not contacted.",
        usefulness="Operators can see whether the public name canonicalizes to an expected host.",
        limitations="These are the same HTTP exchanges as the status checks, not a second crawl. Only the root path was followed, and only up to five same-site hops.",
        evidence=f"HTTP -> {http_snapshot.final_url}; HTTPS -> {https_snapshot.final_url}",
        impact="Informational unless a redirect was blocked by the public-target rules. A blocked private or metadata redirect was not used as a connection target.",
        confidence="medium",
        remediation="If the recorded destination is not your intended host, review the CDN or web-server redirect rules.",
        observation_type="configuration_observation" if blocked else "informational",
        overlaps=["http-status", "https-status", "http-https-redirect"],
    )


def check_headers(ctx: ScanContext) -> CheckResult:
    """List response headers from the preferred homepage fetch."""
    snapshot = _preferred_page(ctx)
    if snapshot is None:
        return _no_page("Response headers")
    if not snapshot.headers:
        return result(
            status="WARNING",
            severity="UNASSESSED",
            summary="No response headers were available.",
            findings=[snapshot.error or snapshot.blocked_reason or "The response had no stored headers."],
            data={},
            method="Read headers from the shared homepage fetch. Cookie and authorization values are omitted.",
            explanation="Headers could not be listed because the homepage fetch did not produce any.",
            usefulness="Response headers show cache, server, and security policy choices the site chose to send.",
            limitations="Cookie and authorization values are never stored.",
            evidence=snapshot.error or "No headers.",
            impact="Header-based observations were not assessed.",
            confidence="high",
            remediation="Retry the HTTPS request if this was a transport failure.",
            observation_type="unavailable",
            error=snapshot.error,
            overlaps=["https-status", "server-header", "content-type", "content-length", "security-headers"],
        )
    findings = [f"{key}: {value}" for key, value in list(snapshot.headers.items())[:40]]
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"{len(snapshot.headers)} response header(s) were stored from the homepage fetch.",
        findings=findings,
        data={"headers": snapshot.headers, "source": snapshot.final_url or snapshot.requested_url},
        method="Read headers from the shared homepage fetch, preferring HTTPS. Set-Cookie, Cookie, and Authorization values are replaced with [omitted].",
        explanation="These are the headers the server sent for the tested URL. Individual headers of interest are interpreted by later checks and are not separate discoveries.",
        usefulness="The header set is the evidence for server disclosure, content type, length, and security-header observations.",
        limitations="Headers can differ by path, method, and CDN pop. Values are truncated. Sensitive header values were omitted.",
        evidence=f"{len(snapshot.headers)} headers from {snapshot.final_url or snapshot.requested_url}",
        impact="Informational. Headers disclose what the server chose to send.",
        confidence="high",
        remediation="Review any header that reveals more detail than you intend, especially product versions.",
        overlaps=["server-header", "content-type", "content-length", "security-headers", "https-status"],
    )


def check_server_header(ctx: ScanContext) -> CheckResult:
    """Report the Server header when the site sends one."""
    snapshot = _preferred_page(ctx)
    if snapshot is None or not snapshot.headers:
        return _no_page("Server header")
    value = _header(snapshot, "server")
    if not value:
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary="No Server header was disclosed.",
            findings=["The homepage response did not include a Server header."],
            data={"server": None},
            method="Read the Server header from the shared homepage response.",
            explanation="A missing Server header means the response did not name a product. That is informational. It does not prove the server is hardened, and a present header would not prove a vulnerability either.",
            usefulness="Operators can see whether the public response is advertising a server product.",
            limitations="The product can still be inferred by other means. This is the same response as the header check.",
            evidence="Server header absent.",
            impact="No product name was disclosed in this header.",
            confidence="high",
            remediation="No action is required from this observation.",
            overlaps=["response-headers"],
        )
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"Server header: {value}",
        findings=[value, "A product or version name is an observation, not proof of a vulnerability."],
        data={"server": value},
        method="Read the Server header from the shared homepage response.",
        explanation="The Server header is voluntary text. InfinityX does not map it to an exploit and does not try a version-specific attack.",
        usefulness="It can hint at the proxy or web server an administrator expects to see, such as a CDN or nginx.",
        limitations="The value can be rewritten by a CDN and can be false. It is not authenticated.",
        evidence=value,
        impact="Informational product disclosure. No weakness was verified from the name.",
        confidence="high",
        remediation="If the header includes a version you do not want to publish, remove or generalize it at the web server or CDN. Do not treat the name alone as an incident.",
        overlaps=["response-headers"],
    )


def check_content_type(ctx: ScanContext) -> CheckResult:
    """Report the Content-Type header."""
    snapshot = _preferred_page(ctx)
    if snapshot is None or not snapshot.headers:
        return _no_page("Content-Type")
    value = _header(snapshot, "content-type")
    if not value:
        return result(
            status="WARNING",
            severity="UNASSESSED",
            summary="No Content-Type header was disclosed.",
            findings=["The homepage response did not include Content-Type."],
            data={"content_type": None},
            method="Read Content-Type from the shared homepage response.",
            explanation="Without a declared type, clients guess how to handle the body. InfinityX does not treat that guess as a verified content-sniffing issue.",
            usefulness="The declared type says whether the root response is HTML, a redirect, or another format.",
            limitations="This is one response, not a site-wide content inventory.",
            evidence="Content-Type absent.",
            impact="Browsers may sniff the response. That possibility was not demonstrated.",
            confidence="medium",
            remediation="Send an explicit Content-Type for the homepage, commonly text/html; charset=utf-8.",
            observation_type="configuration_observation",
            overlaps=["response-headers"],
        )
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"Content-Type: {value}",
        findings=[value],
        data={"content_type": value},
        method="Read Content-Type from the shared homepage response.",
        explanation="Content-Type tells the client how the body is labeled. The page-title check uses the body only as text and does not execute it.",
        usefulness="It confirms whether the root URL is presenting an HTML page or another kind of response.",
        limitations="A CDN can vary the type. The header is not proof of the actual bytes beyond this response.",
        evidence=value,
        impact="Informational.",
        confidence="high",
        remediation="Align the charset and media type with the real homepage if they differ from what you expect.",
        overlaps=["response-headers", "page-title"],
    )


def check_content_length(ctx: ScanContext) -> CheckResult:
    """Report a disclosed Content-Length without confusing it with bytes the scanner read."""
    snapshot = _preferred_page(ctx)
    if snapshot is None or not snapshot.headers:
        return _no_page("Content-Length")
    value = _header(snapshot, "content-length")
    findings = [f"Bytes read by InfinityX before the cap: {snapshot.bytes_read}"]
    if snapshot.truncated:
        findings.append("The body read was truncated at the scanner limit of 512 KiB.")
    if not value:
        findings.append("The server did not disclose a Content-Length header.")
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary="Content-Length was not disclosed. The scanner read " + str(snapshot.bytes_read) + " bytes.",
            findings=findings,
            data={"content_length": None, "bytes_read": snapshot.bytes_read, "truncated": snapshot.truncated},
            method="Read Content-Length from the shared homepage response and record how many decoded bytes InfinityX stored.",
            explanation="Absence of Content-Length is normal for chunked responses. The byte count is how much this scanner chose to read, not necessarily the full object.",
            usefulness="It separates a disclosed length from the scanner's own cap.",
            limitations="A truncated read cannot be used as the page's true size.",
            evidence="Content-Length absent.",
            impact="Informational.",
            confidence="high",
            remediation="No action is required merely because a chunked response omits Content-Length.",
            overlaps=["response-headers"],
        )
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"Content-Length: {value}",
        findings=[f"Disclosed Content-Length: {value}", *findings],
        data={"content_length": value, "bytes_read": snapshot.bytes_read, "truncated": snapshot.truncated},
        method="Read Content-Length from the shared homepage response.",
        explanation="The header is the length the server declared. The scanner may have stored fewer bytes because of its response cap or because compression was decoded.",
        usefulness="A very large declared length is a reason to avoid downloading the whole object. InfinityX already caps the read.",
        limitations="The declared number was not treated as a reliable integer beyond display, and it was not compared byte-for-byte with the body.",
        evidence=value,
        impact="Informational.",
        confidence="medium",
        remediation="No action is required from a normal Content-Length value.",
        overlaps=["response-headers"],
    )


def check_timing(ctx: ScanContext) -> CheckResult:
    """Report the homepage round-trip time already measured."""
    snapshot = _preferred_page(ctx)
    if snapshot is None or snapshot.elapsed_ms <= 0 and not snapshot.ok:
        return _no_page("Response timing")
    elapsed = round(snapshot.elapsed_ms, 1)
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"Homepage response time: {elapsed} ms.",
        findings=[f"{elapsed} ms for {snapshot.requested_url}", "This is one sample from this computer, not a benchmark."],
        data={"elapsed_ms": elapsed, "url": snapshot.requested_url},
        method="Elapsed time of the shared homepage request, including connection setup. No extra request is sent for timing.",
        explanation="The number is how long this scan waited for the tested response. Latency depends on the network path, DNS cache, and CDN location. It is not a vulnerability measurement.",
        usefulness="A very long timeout versus a fast response helps explain later failed or slow checks.",
        limitations="One sample is not a performance test. The same exchange is used by the HTTPS or HTTP status check.",
        evidence=f"{elapsed} ms",
        impact="Informational performance sample.",
        confidence="low",
        remediation="Use a dedicated measurement from the regions you care about if performance is the question. Do not infer capacity or a vulnerability from one sample.",
        overlaps=["https-status", "http-status"],
    )


def check_title(ctx: ScanContext) -> CheckResult:
    """Extract the HTML title."""
    return _html_field(ctx, "title", "Page title", "The title is the text in the HTML title element, if the body was HTML.")


def check_description(ctx: ScanContext) -> CheckResult:
    """Extract a meta description."""
    return _html_field(
        ctx,
        "description",
        "Meta description",
        "The description is taken from a meta description or og:description attribute. It is marketing or summary text, not a security claim.",
    )


def check_canonical(ctx: ScanContext) -> CheckResult:
    """Extract a canonical link without fetching it when it is off-site."""
    parsed = _page_fields(ctx)
    if parsed is None:
        return _no_page("Canonical URL")
    value = parsed.get("canonical")
    if not value:
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary="No canonical URL was found in the homepage HTML.",
            findings=["No rel=canonical link was parsed."],
            data={"canonical": None},
            method="Parse the shared homepage body with an HTML parser. The canonical target was not fetched.",
            explanation="A canonical link tells search engines which URL the operator prefers. None was found in the bounded HTML. That is common for some sites and is not a defect by itself.",
            usefulness="When present, it shows the URL the site presents as preferred.",
            limitations="Scripts that add the tag in a browser were not executed. Only the first canonical link in the stored HTML was read.",
            evidence="No canonical link.",
            impact="Informational.",
            confidence="medium",
            remediation="Add a rel=canonical link if search engines should prefer a specific URL.",
            overlaps=["page-title", "https-status"],
        )
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"Canonical URL: {value}",
        findings=[value, "The canonical target was not fetched, even if it is on the same site."],
        data={"canonical": value},
        method="Parse rel=canonical from the shared homepage HTML. No request was sent to the canonical URL.",
        explanation="The site declared a preferred URL in the HTML. InfinityX reports that declaration and does not crawl it.",
        usefulness="Operators can confirm that the public homepage points at the intended canonical host.",
        limitations="The link was not validated by requesting it. HTML is untrusted and was truncated.",
        evidence=str(value),
        impact="Informational URL disclosure inside the page.",
        confidence="medium",
        remediation="Change the canonical link if it names an old or unexpected host.",
        overlaps=["page-title"],
    )


def check_robots(ctx: ScanContext) -> CheckResult:
    """Fetch robots.txt and list any sitemap hints."""
    snapshot = ctx.fetch_path("/robots.txt")
    if snapshot.status_code is None:
        return _path_failed("robots.txt", snapshot)
    if snapshot.status_code == 404:
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary="robots.txt was not published (HTTP 404).",
            findings=["HTTP 404 for /robots.txt."],
            data={"status": 404, "sitemaps": []},
            method="GET https://<domain>/robots.txt, falling back to HTTP only if HTTPS did not connect. Same-site redirects only.",
            explanation="A missing robots.txt means the site is not publishing crawl rules at the conventional path. That is normal for many sites and is not a security finding.",
            usefulness="When the file exists, it shows paths the operator asked crawlers to avoid and can point to a sitemap.",
            limitations="Robots rules are not access control. A 404 is only about this URL.",
            evidence="HTTP 404",
            impact="No crawl policy was published at this path.",
            confidence="high",
            remediation="Publish robots.txt only if you want to communicate crawl preferences. Do not use it to hide sensitive URLs.",
        )
    body = snapshot.body[:20_000]
    sitemaps = []
    for line in body.splitlines():
        if line.lower().startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip()[:500])
    looks_like = "user-agent" in body.lower() or "disallow" in body.lower() or "sitemap:" in body.lower()
    status = "OK" if snapshot.status_code and snapshot.status_code < 400 else "WARNING"
    return result(
        status=status,
        severity="INFORMATIONAL",
        summary=f"robots.txt returned HTTP {snapshot.status_code}.",
        findings=[f"HTTP {snapshot.status_code}", f"Looks like a robots file: {'yes' if looks_like else 'no'}", f"Sitemap hints: {sitemaps or ['none']}"],
        data={"status": snapshot.status_code, "sitemaps": sitemaps[:10], "looks_like_robots": looks_like, "excerpt": body[:1500]},
        method="GET https://<domain>/robots.txt with the public-target and same-site redirect rules.",
        explanation="robots.txt is a public request to cooperating crawlers. It is not authentication. Sitemap hints found here are input to the sitemap check and are not a second discovery of the same URL.",
        usefulness="Administrators can see which paths are being advertised or discouraged to crawlers.",
        limitations="The body was capped. Rules were not tested by requesting disallowed paths.",
        evidence=f"HTTP {snapshot.status_code}",
        impact="Informational. Paths named in the file are public because the file is public.",
        confidence="high",
        remediation="Remove any sensitive path names from robots.txt. Use real access control for content that should not be public.",
        overlaps=["sitemap"],
        raw_ref="path_robots.txt",
    )


def check_sitemap(ctx: ScanContext) -> CheckResult:
    """Look for a sitemap in robots.txt and at /sitemap.xml without crawling the site."""
    robots = ctx.fetch_path("/robots.txt")
    hints: list[str] = []
    for line in robots.body.splitlines():
        if line.lower().startswith("sitemap:"):
            hints.append(line.split(":", 1)[1].strip())
    snapshot = ctx.fetch_path("/sitemap.xml")
    found = snapshot.status_code == 200
    findings = [f"/sitemap.xml status: {snapshot.status_code}", f"Sitemap hints in robots.txt: {hints[:10] or ['none']}"]
    if found:
        findings.append("The /sitemap.xml body was stored, capped, and not used as a crawl queue.")
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary="A sitemap was found at /sitemap.xml." if found else "No sitemap document was retrieved from /sitemap.xml.",
        findings=findings,
        data={"sitemap_status": snapshot.status_code, "robots_hints": hints[:10], "fetched": found},
        method="Read Sitemap lines already fetched with robots.txt, then GET /sitemap.xml once. Hint URLs on other sites were not fetched.",
        explanation="A sitemap is a list of URLs the operator wants indexed. InfinityX checks the conventional file and records hints. It does not crawl the listed URLs.",
        usefulness="Operators can see whether a public URL list is being advertised.",
        limitations="A sitemap at another path is reported only as a hint unless it is exactly /sitemap.xml. Off-site hint URLs were not requested.",
        evidence=f"/sitemap.xml HTTP {snapshot.status_code}",
        impact="Informational. A public sitemap discloses the URLs it lists.",
        confidence="medium",
        remediation="Remove URLs that should not be advertised. A missing sitemap is not a vulnerability.",
        overlaps=["robots-txt"],
    )


def check_security_txt(ctx: ScanContext) -> CheckResult:
    """Look for a security.txt contact file."""
    snapshot = ctx.fetch_path("/.well-known/security.txt")
    if snapshot.status_code == 404 or (snapshot.status_code is None and snapshot.error):
        alternate = ctx.fetch_path("/security.txt")
    else:
        alternate = None
    chosen = snapshot if snapshot.status_code == 200 else alternate
    if chosen is None or chosen.status_code != 200:
        status_note = snapshot.status_code if snapshot.status_code is not None else snapshot.error
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary="security.txt was not published.",
            findings=[f"/.well-known/security.txt: {status_note}", f"/security.txt: {alternate.status_code if alternate else 'not requested'}"],
            data={"found": False},
            method="GET /.well-known/security.txt and, if that is not HTTP 200, GET /security.txt.",
            explanation="security.txt is an optional file for vulnerability-disclosure contacts. Its absence is informational. It is not proof that the operator ignores security reports, and its presence would not prove a vulnerability.",
            usefulness="When published, it gives a contact and an expiry for security reports.",
            limitations="Only the two conventional URLs were requested.",
            evidence="No HTTP 200 security.txt.",
            impact="No public disclosure contact was found at the conventional paths.",
            confidence="medium",
            remediation="Publish /.well-known/security.txt if you want researchers to have a contact and policy URL.",
        )
    fields = {}
    for line in chosen.body.splitlines():
        if ":" in line and not line.strip().startswith("#"):
            key, value = line.split(":", 1)
            fields.setdefault(key.strip().lower(), value.strip()[:300])
    expired_note = fields.get("expires")
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary="security.txt was published.",
        findings=[f"{key}: {value}" for key, value in list(fields.items())[:12]] or ["The file was empty or had no recognizable fields."],
        data={"fields": fields, "expires": expired_note, "url": chosen.final_url},
        method="GET the conventional security.txt paths and parse Contact, Expires, and Policy lines locally.",
        explanation="The file advertises how the operator wants to receive security reports. InfinityX does not send a report and does not treat the file as evidence of a weakness. Expires is shown as published text; it was not converted into a verified expiry finding unless the field is missing.",
        usefulness="Researchers and administrators can see the published contact without guessing an email address.",
        limitations="The contact was not tested. A stale Expires value should be checked by the operator against RFC 9116.",
        evidence=chosen.final_url or "security.txt",
        impact="Informational contact disclosure.",
        confidence="medium",
        remediation="Keep Contact and Expires current if this file is intentional. Remove it if it points at an old address.",
        raw_ref="path_.well-known_security.txt",
    )


def check_security_headers(ctx: ScanContext) -> CheckResult:
    """Observe common security headers without calling a missing header a vulnerability."""
    snapshot = _preferred_page(ctx)
    if snapshot is None or not snapshot.headers:
        return _no_page("Security headers")
    classified = classify_security_headers(snapshot.headers)
    present = classified["present"]
    absent = classified["absent"]
    findings = [f"Present {name}: {value}" for name, value in present.items()]
    findings.append("Not present on this response: " + (", ".join(absent) if absent else "none from the observation list"))
    findings.append("A missing header is an observation about this response. It is not proof of a vulnerability.")
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"{len(present)} observed security header(s) present; {len(absent)} from the list not present.",
        findings=findings,
        data=classified,
        method="Compare the shared homepage headers with a fixed list: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, and COEP.",
        explanation="Each header is a browser instruction. InfinityX records whether this response included it. Missing headers can matter in a broader review, but this tool does not convert absence into a verified vulnerability or a severity above informational.",
        usefulness="Administrators get a checklist of what this particular response already sends and what it does not.",
        limitations="Headers can be set only on some paths. Report-only CSP and framework defaults were not scored. No browser was instrumented.",
        evidence=f"Present: {', '.join(present) or 'none'}. Absent: {', '.join(absent) or 'none'}.",
        impact="Informational. No exploit or browser behavior was demonstrated.",
        confidence="high",
        remediation=(
            "If this is the public HTML response, an administrator can consider HSTS after HTTPS is stable, a Content-Security-Policy that matches the site, "
            "X-Content-Type-Options: nosniff, a framing policy, and a Referrer-Policy. Add them only when they match how the site works. "
            "Do not treat this checklist as a vulnerability scan."
        ),
        overlaps=["response-headers"],
    )


def check_whatweb(ctx: ScanContext) -> CheckResult:
    """Run WhatWeb only when the command is installed."""
    binary = shutil.which("whatweb")
    url = f"https://{ctx.domain}/"
    command = [binary or "whatweb", "--color=never", "--no-errors", "--aggression=1", "--max-threads=1", url]
    shown = " ".join(command)
    if not binary:
        return result(
            status="SKIPPED",
            severity="UNASSESSED",
            summary="WhatWeb is not installed.",
            findings=["The whatweb command was not found on PATH. No technology fingerprint was invented."],
            data={"installed": False},
            method=shown + ". The command was not executed.",
            explanation="WhatWeb is an optional local program. InfinityX skips it cleanly when it is absent.",
            usefulness="When installed, it adds a passive-leaning technology hint at aggression level 1.",
            limitations="Technology names are not vulnerabilities. This scan did not download WhatWeb.",
            evidence="whatweb not found.",
            impact="Technology fingerprinting was not assessed.",
            confidence="high",
            remediation="Install WhatWeb on Kali if you want this optional check, then rerun the scan.",
            observation_type="unavailable",
        )
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=40,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return result(
            status="FAILED",
            severity="UNASSESSED",
            summary="WhatWeb did not finish.",
            findings=[str(exc)[:400]],
            data={},
            method=shown,
            explanation="The optional WhatWeb process timed out or could not be started. No technology list was invented.",
            usefulness="A successful run would list recognizable technologies.",
            limitations="Aggression 1 is not a vulnerability scan, and this run did not complete.",
            evidence=str(exc)[:400],
            impact="Technology fingerprinting was not assessed.",
            confidence="high",
            remediation="Run WhatWeb manually against the same URL if you need its output.",
            observation_type="unavailable",
            error=str(exc)[:400],
        )
    output = (completed.stdout or "")[:4000]
    error_text = (completed.stderr or "")[:1000]
    ctx.store("whatweb.txt", output + ("\n" + error_text if error_text else ""))
    if completed.returncode != 0 and not output.strip():
        return result(
            status="WARNING",
            severity="UNASSESSED",
            summary=f"WhatWeb exited {completed.returncode} without a result.",
            findings=[error_text or "No output."],
            data={"returncode": completed.returncode},
            method=shown,
            explanation="WhatWeb ran but did not produce a usable identification. That is a tool failure, not a statement about the website.",
            usefulness="No technology name should be inferred from an empty run.",
            limitations="WhatWeb's own plugins can be wrong even when it succeeds.",
            evidence=error_text or f"exit {completed.returncode}",
            impact="Technology fingerprinting was not assessed.",
            confidence="low",
            remediation="Review the raw_results/whatweb.txt artifact if it exists and rerun WhatWeb manually if needed.",
            observation_type="unavailable",
            raw_ref="whatweb.txt",
        )
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary="WhatWeb completed at aggression 1.",
        findings=[output.strip()[:1500] or "WhatWeb produced no textual identification.", "Technology names are observations, not verified vulnerabilities."],
        data={"returncode": completed.returncode, "output": output[:2000]},
        method=shown,
        explanation="WhatWeb compared the response with its signatures. A named product or version is a hint. InfinityX does not turn that hint into an exploit or a vulnerability finding.",
        usefulness="Operators can compare the detected stack with the stack they believe they deployed.",
        limitations="Signatures produce false positives and false negatives. Only the site root was passed to WhatWeb. Aggression was capped at 1 and threads at 1.",
        evidence=output.strip()[:1500] or "empty output",
        impact="Informational technology disclosure. No weakness was verified.",
        confidence="low",
        remediation="If a version is more specific than you intend, remove version banners at the server. Do not patch solely because a signature matched.",
        raw_ref="whatweb.txt",
    )


def _preferred_page(ctx: ScanContext) -> HttpSnapshot | None:
    https = ctx.http("https")
    if https.ok and https.headers:
        return https
    http = ctx.http("http")
    if http.ok and (http.headers or http.status_code):
        return http
    if https.status_code or https.headers:
        return https
    if http.status_code or http.headers:
        return http
    return https if https.error or https.blocked_reason else http


def _page_fields(ctx: ScanContext) -> dict[str, str | None] | None:
    snapshot = _preferred_page(ctx)
    if snapshot is None or not snapshot.body:
        return None
    return parse_page(snapshot.body)


def _html_field(ctx: ScanContext, key: str, label: str, explanation: str) -> CheckResult:
    snapshot = _preferred_page(ctx)
    if snapshot is None or (not snapshot.body and not snapshot.ok):
        return _no_page(label)
    parsed = parse_page(snapshot.body or "")
    value = parsed.get(key)
    if not value:
        return result(
            status="OK",
            severity="INFORMATIONAL",
            summary=f"No {label.lower()} was found in the stored HTML.",
            findings=["The bounded body did not contain this field. It may be non-HTML or the tag may be added by JavaScript."],
            data={key: None, "source": snapshot.final_url},
            method="Parse the shared homepage body with the Python HTML parser. Scripts were not executed.",
            explanation=explanation + " Nothing was found in the stored bytes.",
            usefulness=f"The {label.lower()} is a human-readable label for the page when the server sends it in HTML.",
            limitations="Browser-side rendering was not performed. The body is capped at 512 KiB.",
            evidence="Field not present in stored HTML.",
            impact="Informational.",
            confidence="medium",
            remediation="No action is required unless you expected this tag in the server-rendered HTML.",
            overlaps=["https-status", "content-type"],
        )
    return result(
        status="OK",
        severity="INFORMATIONAL",
        summary=f"{label}: {value}",
        findings=[str(value)],
        data={key: value, "source": snapshot.final_url},
        method="Parse the shared homepage body with the Python HTML parser. Scripts were not executed.",
        explanation=explanation,
        usefulness="It identifies the page the server returned and can reveal a default install page or an unexpected brand.",
        limitations="HTML is untrusted and was truncated. A title can be changed by JavaScript after load, which this scanner does not see.",
        evidence=str(value),
        impact="Informational page content.",
        confidence="medium",
        remediation="Update the HTML if the text is outdated or belongs to a default page you did not intend to publish.",
        overlaps=["https-status"],
    )


def _status_result(snapshot: HttpSnapshot, label: str, overlap: str) -> CheckResult:
    if snapshot.blocked_reason and snapshot.status_code is None:
        return _transport_blocked(label, snapshot)
    if snapshot.status_code is None:
        return result(
            status="FAILED",
            severity="UNASSESSED",
            summary=f"{label} did not return a status code.",
            findings=[snapshot.error or "No status code."],
            data={"error": snapshot.error, "resolved_ips": snapshot.resolved_ips},
            method=f"GET {label.lower()}://<domain>/ pinned to a public address from 1.1.1.1 or 8.8.8.8. Redirects are manual. Proxies from the environment are ignored.",
            explanation=f"The {label} request failed before a status code was available. No page content was invented.",
            usefulness="A transport failure explains why later HTML checks may be empty.",
            limitations="A local network policy could block the scanner while the site is fine for other users. One path, the root, was tested.",
            evidence=snapshot.error or "No status.",
            impact=f"{label} availability was not confirmed from this network.",
            confidence="medium",
            remediation="Confirm reachability from another network and confirm that the name resolves to the intended public address.",
            observation_type="unavailable",
            error=snapshot.error,
        )
    ok_http = snapshot.status_code < 400
    return result(
        status="OK" if ok_http else "WARNING",
        severity="INFORMATIONAL" if ok_http else "LOW",
        summary=f"{label} status: {snapshot.status_code}",
        findings=[
            f"Requested: {snapshot.requested_url}",
            f"Status: {snapshot.status_code}",
            f"Landed or recorded URL: {snapshot.final_url}",
            f"Pinned address: {snapshot.pinned_ip}",
        ],
        data={
            "status": snapshot.status_code,
            "final_url": snapshot.final_url,
            "pinned_ip": snapshot.pinned_ip,
            "resolved_ips": snapshot.resolved_ips,
        },
        method=f"GET {snapshot.requested_url} with connection pinned to {snapshot.pinned_ip}. Same-site redirects only.",
        explanation=f"The status code is the server's response to one root request over {label}. Codes in the 400s and 500s mean this URL did not return success. They are not, by themselves, a vulnerability.",
        usefulness="It shows whether the public root URL answers and which address was actually contacted.",
        limitations="Only / was requested. The pinned address is one of the public addresses, so a different CDN address could answer differently.",
        evidence=f"{snapshot.status_code} {snapshot.final_url}",
        impact="Informational availability of the tested URL." if ok_http else "The tested URL returned an error status to this scanner.",
        confidence="medium",
        remediation="If the status is unexpected, review the web server, CDN, and TLS configuration for this hostname.",
        observation_type="informational" if ok_http else "configuration_observation",
        overlaps=[overlap],
    )


def _transport_blocked(label: str, snapshot: HttpSnapshot) -> CheckResult:
    return result(
        status="WARNING",
        severity="MEDIUM",
        summary=f"{label} was not contacted: {snapshot.blocked_reason or snapshot.error}",
        findings=[snapshot.blocked_reason or snapshot.error or "Blocked."],
        data={"blocked_reason": snapshot.blocked_reason, "resolved_ips": snapshot.resolved_ips},
        method="Resolve on 1.1.1.1 and 8.8.8.8 and refuse non-public, local, and metadata destinations before connecting.",
        explanation="InfinityX stopped because the safety check rejected the destination or the resolution. The refusal is intentional. It is not a vulnerability proof, and the blocked address was not used as a connection target.",
        usefulness="It shows that the name does not currently pass the public-target rules from this scanner.",
        limitations="A split-horizon or filtering resolver can cause this result.",
        evidence=snapshot.blocked_reason or snapshot.error or "blocked",
        impact="The content behind this URL was not retrieved.",
        confidence="medium",
        remediation="If you operate the name, check public DNS for private or metadata addresses and remove them if they are unintentional.",
        observation_type="configuration_observation",
        error=snapshot.error,
    )


def _no_page(label: str) -> CheckResult:
    return result(
        status="FAILED",
        severity="UNASSESSED",
        summary=f"{label} could not be read because no homepage response was available.",
        findings=["The shared HTTP and HTTPS fetches did not produce a usable response."],
        data={},
        method="Uses the shared homepage fetch. No additional request was sent solely for this field.",
        explanation="This check depends on the homepage response already attempted by the HTTP and HTTPS checks. That response was not available, so the field was not invented.",
        usefulness="Leaving the field empty avoids a false description of the page.",
        limitations="This is the same transport result as the status checks, not a separate outage.",
        evidence="No homepage response.",
        impact=f"{label} was not assessed.",
        confidence="high",
        remediation="Correct the HTTP or HTTPS connectivity issue and rerun the scan.",
        observation_type="unavailable",
        overlaps=["http-status", "https-status"],
    )


def _path_failed(path: str, snapshot: HttpSnapshot) -> CheckResult:
    return result(
        status="FAILED",
        severity="UNASSESSED",
        summary=f"{path} could not be fetched.",
        findings=[snapshot.error or snapshot.blocked_reason or "No status code."],
        data={"error": snapshot.error},
        method=f"GET https://<domain>{path} with the same public-address rules as the homepage.",
        explanation="The request failed before a document could be read. A missing document was not invented.",
        usefulness="The failure is recorded so the report does not claim the file exists or does not exist.",
        limitations="A network block can look like a missing file. Those cases are distinguished only when an HTTP status is present.",
        evidence=snapshot.error or "request failed",
        impact=f"{path} was not assessed.",
        confidence="medium",
        remediation="Retry the URL manually from this network.",
        observation_type="unavailable",
        error=snapshot.error,
    )


def _header(snapshot: HttpSnapshot, name: str) -> str | None:
    for key, value in snapshot.headers.items():
        if key.lower() == name:
            return value
    return None


def _chain_text(snapshot: HttpSnapshot) -> str:
    if not snapshot.chain:
        return snapshot.error or "no response"
    parts = []
    for item in snapshot.chain:
        parts.append(f"{item.get('status')} {item.get('url')}")
    if snapshot.final_url and snapshot.final_url not in str(parts):
        parts.append("recorded " + str(snapshot.final_url))
    return " -> ".join(parts)
