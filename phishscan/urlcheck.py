"""Static analysis of URLs (no internet required)"""
import os
import re
from urllib.parse import parse_qs, unquote, urlparse
from .data import BAD_TLDS, BRANDS, DANGER_EXT, PLATFORMS, SHORTENERS, TYPO_TARGETS, URL_KEYWORDS
from .util import brand_in, entropy, is_official, is_public_ip, levenshtein, reg_domain, skeleton


def analyze_url_static(url, rep, label="URL", _depth=0):
    p = urlparse(url)
    host = (p.hostname or "").lower()
    rep.iocs["urls"].add(url)
    if host:
        rep.iocs["domains"].add(host)
    sec = f"{label}: {url[:80]}"
    rep.info(sec, "Scheme", p.scheme)
    rep.info(sec, "Host", host)
    rep.info(sec, "Registered domain", reg_domain(host))

    if p.scheme in ("javascript", "data", "vbscript"):
        rep.add(30, "URL", f"{p.scheme}: URI — executes code/data directly", "malware_delivery")
        return
    if p.scheme == "http":
        rep.add(3, "URL", "No HTTPS — data is not encrypted")
    if "@" in (p.netloc or ""):
        rep.add(25, "URL", f"'@' trick in URL: real destination is '{host}', the part before it is deceptive")
    if is_public_ip(host):
        rep.add(20, "URL", "Direct IP address instead of domain — legitimate organizations don't do this")
        rep.iocs["ips"].add(host)
    if p.port and p.port not in (80, 443):
        rep.add(8, "URL", f"Unusual port {p.port}")

    # Punycode / homograph
    try:
        uni = host.encode("ascii").decode("idna") if "xn--" in host else host
    except Exception:
        uni = host
    if "xn--" in host or any(ord(ch) > 127 for ch in host):
        rep.add(25, "Homograph", f"Punycode/Unicode domain: '{uni}' — looks like the real one but uses different characters", "brand_impersonation")
        rep.info(sec, "Unicode form", uni)

    rd = reg_domain(host)
    rd_label = rd.split(".")[0] if rd else ""
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in BAD_TLDS:
        rep.add(8, "URL", f"Risky/cheap TLD '.{tld}' — commonly used in phishing")
    if any(host == s or host.endswith("." + s) for s in SHORTENERS):
        rep.add(6, "URL", "Short link — real destination is hidden (check redirect chain)")
    for pl in PLATFORMS:
        if host.endswith("." + pl) or host == pl:
            rep.add(12, "Hosting", f"Free hosting/platform '{pl}' — frequently used by phishers")
            break
    if host.count(".") >= 4:
        rep.add(8, "URL", f"Too many subdomains ({host.count('.')} dots) — technique to hide the real domain")
    if len(url) > 120:
        rep.add(3, "URL", f"Very long URL ({len(url)} characters)")
    if host.count("-") >= 3:
        rep.add(5, "URL", "Many hyphens in domain (e.g. secure-login-verify-...)")
    if len(rd_label) >= 12 and entropy(rd_label) > 3.6:
        rep.add(5, "URL", "Random domain name (may be auto-generated)")
    pct = url.count("%")
    if pct > 10:
        rep.add(6, "URL", f"Excessive URL-encoding ({pct} % signs) — attempt to hide content")

    low = unquote(url).lower()
    kws = [k for k in URL_KEYWORDS if k in low]
    if kws:
        rep.add(min(12, 3 * len(kws)), "URL", f"Suspicious keywords: {', '.join(kws[:6])}")

    # Brand impersonation / typosquatting
    if not is_official(host):
        sk_host = skeleton(uni)
        sk_path = skeleton(unquote(p.path + "?" + (p.query or "")))
        host_tokens = set(re.split(r"[.\-_]", skeleton(uni.replace("-", "."))))
        for brand, offs in BRANDS.items():
            if brand_in(brand, sk_host, host_tokens):
                rep.brands.add(brand)
                rep.add(30, "Brand", f"Uses '{brand}' name but domain is not official (real: {', '.join(offs[:3])})", "brand_impersonation")
                if brand not in uni.lower().replace("-", ""):
                    rep.add(15, "Homoglyph", f"Impersonates '{brand}' using character substitution (e.g. o->0, l->1, rn->m)", "brand_impersonation")
                break
            if len(brand) >= 5 and re.search(rf"(?<![a-z]){brand}(?![a-z])", sk_path):
                rep.add(12, "Brand", f"'{brand}' found in URL path — not an official domain", "brand_impersonation")
                break
        if rd_label and len(rd_label) >= 4 and not any(r[2] == "Brand" for r in rep.findings):
            sk = skeleton(rd_label)
            for off in TYPO_TARGETS:
                ol = off.split(".")[0]
                if ol == rd_label:
                    continue
                d = levenshtein(sk, ol)
                # leet/homoglyph exact match (g00gle) or 1 char diff (>=6 chars) or 2 chars (>=9 chars)
                if (d == 0 and sk != rd_label) or (d == 1 and len(ol) >= 6) or (d == 2 and len(ol) >= 9):
                    rep.add(25 if d <= 1 else 15, "Typosquat", f"'{rd}' looks very similar to '{off}' (possible typosquatting, {d} character difference)", "brand_impersonation")
                    break

    # open redirect / another URL in parameters
    qs = parse_qs(p.query)
    for k, vals in qs.items():
        for v in vals:
            if re.match(r"(?i)^(https?:)?//", v):
                inner_host = (urlparse(v if v.startswith("http") else "http:" + v).hostname or "").lower()
                if inner_host and reg_domain(inner_host) != reg_domain(host):
                    official_outer = is_official(host)
                    rep.add(4 if official_outer else 10, "Redirect",
                            f"Parameter '{k}' redirects to another site: {v[:80]}" + (" (uses a known site's redirector to hide the real link)" if official_outer else ""))
                    rep.iocs["urls"].add(v)
                    if _depth < 2:
                        analyze_url_static(v if v.startswith("http") else "http:" + v, rep, "Inner real link", _depth + 1)
    for m in re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", unquote(url)):
        rep.add(6, "URL", f"Email address in URL ({m}) — targeted link, pre-fills the form")
        rep.iocs["emails"].add(m)
    if re.search(r"(?i)(oauth2?/(v2\.0/)?authorize|/o/oauth2/|consent|client_id=)", url):
        if re.search(r"(?i)(mail|files|offline_access|\.readwrite|gmail|drive)", unquote(url)):
            rep.add(20, "OAuth", "OAuth permission link requesting mail/file access — may be consent phishing", "oauth_consent")
            rep.info(sec, "OAuth client_id", (qs.get("client_id") or [""])[0])
    ext = os.path.splitext(p.path.lower())[1]
    if ext in DANGER_EXT - {".html", ".htm", ".shtml", ".url"}:
        rep.add(25, "Download", f"Link directly downloads a '{ext}' file", "android_stealer" if ext == ".apk" else "malware_delivery")
