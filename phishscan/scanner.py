"""URL scan main flow"""
import os
import re
from urllib.parse import urlparse
from .infra import host_intel, ssl_intel
from .reputation import urlscan_lookup, vt_url
from .urlcheck import analyze_url_static
from .util import is_official
from .web import MOBILE_UA, analyze_html, fetch, screenshot
from . import files, intel


def scan_url(url, rep, args, depth=0, label="URL"):
    if not re.match(r"(?i)^[a-z]+:", url):
        url = "http://" + url
    analyze_url_static(url, rep, label)
    host = urlparse(url).hostname or ""
    if args.no_fetch:
        if not args.offline:
            host_intel(host, rep)
            if not is_official(host):
                urlscan_lookup(host, rep)
                vt_url(url, rep)
                if depth == 0 and getattr(args, "related", True):
                    intel.gather_related(host, rep, next(iter(rep.brands), None))
        return
    chain, body = fetch(url, rep)[:2]
    last = chain[-1] if chain else {}
    if isinstance(last.get("status"), int) and last["status"] in (401, 403, 404, 406, 410, 429, 451, 503):
        first_status = last["status"]
        rep.info("Site response", "Desktop browser", f"HTTP {first_status}" + (f" -- {last['note']}" if last.get("note") else ""))
        m_chain, m_body = fetch(url, rep, ua=MOBILE_UA)[:2]
        m_last = m_chain[-1] if m_chain else {}
        rep.info("Site response", "Mobile browser", f"HTTP {m_last.get('status')}")
        if m_last.get("status") == 200:
            rep.add(20, "Cloaking", f"Cloaking: shows {first_status} to desktop, real page to mobile -- targeting phone users only")
            chain, body = m_chain, m_body
        elif last.get("note") == "Cloudflare bot-check page" or last.get("cf"):
            rep.add(5, "Cloaking", "Cloudflare bot-check blocked scanner -- page content not visible")
            rep.info("Site response", "Suggestion", "Check previous scans on urlscan.io, or try --screenshot in a VM")
        elif first_status in (403, 451):
            rep.add(10, "Cloaking", f"Site blocking scanner/this IP (HTTP {first_status}) -- common phishing cloaking sign")
            rep.info("Site response", "Suggestion", "Turn off VPN and try from local IP (inside VM); or use --no-fetch for infrastructure only")
        elif first_status in (404, 410):
            rep.info("Site response", "Note", "Page is gone -- may have been taken down after report. Domain/IP info still below")
    rep.sections.setdefault("Redirect chain", [])
    for i, c in enumerate(chain):
        rep.info("Redirect chain", f"{i + 1}. [{c.get('status')}]", f"{c['url']}" + (f"  (IP {c['ip']})" if c.get("ip") else "") + (f"  -- {c['note']}" if c.get("note") else "") + (f"  -- {c['detail']}" if c.get("detail") else ""))
    hosts = []
    for c in chain:
        h = (urlparse(c["url"]).hostname or "").lower()
        if h and h not in hosts:
            hosts.append(h)
    if len(chain) > 3:
        rep.add(8, "Redirect", f"{len(chain) - 1} redirects -- trying to hide real destination")
    final = chain[-1]["url"] if chain else url
    if final != url and depth == 0:
        analyze_url_static(final, rep, "Final URL")
    for h in hosts:
        host_intel(h, rep)
    fh = urlparse(final).hostname
    if fh and urlparse(final).scheme == "https":
        ssl_intel(fh, urlparse(final).port, rep)
    if fh and not is_official(fh):
        urlscan_lookup(fh, rep)
        if depth == 0 and getattr(args, "related", True):
            intel.gather_related(fh, rep, next(iter(rep.brands), None))
    vt_url(final, rep)
    if isinstance(body, (bytes, bytearray)) and body:
        name = os.path.basename(urlparse(final).path) or "download.bin"
        rep.info("Downloaded file", "Name", name)
        files.analyze_bytes(name, bytes(body), rep, args, depth + 1)
    elif isinstance(body, str):
        analyze_html(body, final, rep)
        if args.evidence_dir:
            with open(os.path.join(args.evidence_dir, "page.html"), "w", encoding="utf-8") as f:
                f.write(body)
    if args.screenshot and args.evidence_dir:
        screenshot(final, args.evidence_dir, rep)
