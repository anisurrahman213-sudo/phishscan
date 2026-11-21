"""
Related infrastructure lookup (Certificate Transparency / crt.sh).

Finds *other domains and hidden subdomains* created by the same scammer,
so they can all be reported and taken down together. Completely free, no API key needed.
Source: crt.sh (public Certificate Transparency logs, powered by SSLMate).
"""
import re

from .util import api_json, is_official, reg_domain

CRTSH = "https://crt.sh/?output=json&q="
_SKIP = re.compile(r"(?i)(cloudflare|sni\.cloudflaressl|amazonaws|googleusercontent|azure|sucuri|"
                   r"herokuapp|netlify|vercel|pages\.dev|workers\.dev|github\.io|\.local|example\.)")


def _names_from_crt(rows, limit=4000):
    names = set()
    for row in rows[:limit]:
        for field in ("name_value", "common_name"):
            val = row.get(field) or ""
            for n in str(val).splitlines():
                n = n.strip().lower().lstrip("*.")
                if n and "." in n and " " not in n and not n.startswith("@"):
                    names.add(n)
    return names


def crtsh_subdomains(domain, rep, cap=40):
    """Find all (hidden) subdomains of the scanned domain -- e.g. login., admin., panel."""
    rd = reg_domain(domain)
    if not rd or is_official(rd):
        return
    rows = api_json(CRTSH + rd)
    if not rows or not isinstance(rows, list):
        return
    subs = sorted(n for n in _names_from_crt(rows) if n == rd or n.endswith("." + rd))
    if len(subs) <= 1:
        return
    sec = "Related subdomains (Certificate Transparency)"
    rep.info(sec, "Total found", len(subs))
    rep.info(sec, "List", subs[:cap] + (["... more", len(subs) - cap] if len(subs) > cap else []))
    for s in subs:
        rep.iocs["domains"].add(s)
    interesting = [s for s in subs if re.search(r"(?i)(login|signin|secure|verify|account|wallet|admin|panel|pay|bank|otp|update|cpanel|mail|webmail)", s)]
    if interesting:
        rep.info(sec, "Suspicious subdomains", interesting[:cap])
    if len(subs) >= 8:
        rep.add(6, "Infra", f"{len(subs)} subdomains on this domain -- phishing kit may be running multiple pages")


def crtsh_brand_hunt(brand, rep, cap=60):
    """
    Search Certificate Transparency logs for other suspicious domains
    impersonating the same brand -- for reporting them all together.
    """
    brand = (brand or "").strip().lower()
    if len(brand) < 4:
        return
    rows = api_json(CRTSH + "%25" + brand + "%25")     # %25 = URL-encoded %
    if not rows or not isinstance(rows, list):
        return
    cand = set()
    for n in _names_from_crt(rows):
        rd = reg_domain(n)
        if not rd or is_official(rd) or _SKIP.search(rd):
            continue
        if brand in rd.replace("-", "").replace(".", ""):
            cand.add(rd)
    cand.discard("")
    if not cand:
        return
    sec = f"Other domains impersonating '{brand}' (crt.sh)"
    out = sorted(cand)
    rep.related.extend(d for d in out[:cap] if d not in rep.related)
    rep.info(sec, "Suspected fake domains", out[:cap] + (["... more", len(out) - cap] if len(out) > cap else []))
    rep.info(sec, "Note", "These are found by name matching -- verify each separately, then report together")


def gather_related(host, rep, brand=None):
    """Called from scanner -- subdomains + (if brand found) brand hunt."""
    try:
        crtsh_subdomains(host, rep)
        if brand:
            crtsh_brand_hunt(brand, rep)
    except Exception as e:
        rep.info("Related domains", "Note", f"Could not fetch from crt.sh: {str(e)[:80]}")
