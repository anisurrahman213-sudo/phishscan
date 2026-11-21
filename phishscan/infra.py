"""Infrastructure: DNS, RDAP/WHOIS, IP geolocation, SSL"""
import datetime as dt
import re
import shutil
import socket
import ssl
import subprocess
from .util import api_json, is_official, is_public_ip, reg_domain


def rdap_abuse(obj):
    """Extract abuse email and name from RDAP entities"""
    found = []

    def walk(ents):
        for e in ents or []:
            roles = e.get("roles", [])
            vc = e.get("vcardArray", [None, []])[1] if e.get("vcardArray") else []
            name = email_ = None
            for item in vc:
                if item[0] == "fn":
                    name = item[3]
                if item[0] == "email":
                    email_ = item[3]
            found.append((roles, name, email_))
            walk(e.get("entities"))
    walk(obj.get("entities"))
    return found


def whois_cli(domain):
    if not shutil.which("whois"):
        return {}
    try:
        out = subprocess.run(["whois", domain], capture_output=True, text=True, timeout=20).stdout
    except Exception:
        return {}
    res = {}
    for pat, key in [(r"(?im)^\s*(creation date|created|registered on|registration time|domain create date)\s*:\s*(.+)$", "created"),
                     (r"(?im)^\s*registrar\s*:\s*(.+)$", "registrar"),
                     (r"(?im)^\s*registrar abuse contact email\s*:\s*(.+)$", "abuse"),
                     (r"(?im)^\s*(registrant country|country)\s*:\s*(.+)$", "country")]:
        m = re.search(pat, out)
        if m:
            res[key] = m.groups()[-1].strip()
    return res


def parse_date(s):
    if not s:
        return None
    s = s.strip()
    try:
        d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)
    except Exception:
        pass
    for fmt in ("%d-%b-%Y", "%Y.%m.%d", "%d/%m/%Y", "%Y-%m-%d %H:%M:%S", "%d.%m.%Y"):
        try:
            return dt.datetime.strptime(s.split(" (")[0][:20].strip(), fmt).replace(tzinfo=dt.timezone.utc)
        except Exception:
            continue
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", s)
    if m:
        return dt.datetime(*map(int, m.groups()), tzinfo=dt.timezone.utc)
    return None


def domain_intel(host, rep):
    rd = reg_domain(host)
    if not rd or is_public_ip(rd):
        return {}
    info = {"registered_domain": rd}
    data = api_json(f"https://rdap.org/domain/{rd}")
    if data:
        for ev in data.get("events", []):
            if ev.get("eventAction") == "registration":
                info["created"] = ev.get("eventDate")
            if ev.get("eventAction") == "expiration":
                info["expires"] = ev.get("eventDate")
        info["nameservers"] = [n.get("ldhName", "").lower() for n in data.get("nameservers", [])]
        for roles, name, em in rdap_abuse(data):
            if "registrar" in roles and name:
                info["registrar"] = name
            if "abuse" in roles and em:
                info["registrar_abuse"] = em
            if "registrant" in roles and name and "redacted" not in name.lower():
                info["registrant"] = name
        info["status"] = data.get("status")
    else:
        w = whois_cli(rd)
        info.update({k: v for k, v in {"created": w.get("created"), "registrar": w.get("registrar"),
                                        "registrar_abuse": w.get("abuse"), "registrant_country": w.get("country")}.items() if v})
    created = parse_date(info.get("created"))
    if created:
        age = (dt.datetime.now(dt.timezone.utc) - created).days
        info["age_days"] = age
        if age < 30:
            rep.add(25, "Domain", f"Domain registered only {age} days ago -- new domain is a major phishing indicator")
        elif age < 180:
            rep.add(10, "Domain", f"Domain is new ({age} days)")
    if info.get("registrar_abuse"):
        rep.abuse[info["registrar_abuse"]] = f"Domain registrar ({info.get('registrar', '')}) -- to suspend domain {rd}"
    return info


def ip_intel(ip, rep):
    info = {"ip": ip}
    g = api_json(f"https://ipinfo.io/{ip}/json")
    if g:
        info.update({"country": g.get("country"), "region": g.get("region"), "city": g.get("city"),
                     "org_asn": g.get("org"), "reverse_dns": g.get("hostname"), "loc": g.get("loc")})
    else:
        g = api_json(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,reverse,lat,lon,proxy,hosting")
        if g and g.get("status") == "success":
            info.update({"country": g.get("country"), "region": g.get("regionName"), "city": g.get("city"),
                         "org_asn": f"{g.get('as')} ({g.get('isp')})", "reverse_dns": g.get("reverse"),
                         "loc": f"{g.get('lat')},{g.get('lon')}", "proxy_vpn": g.get("proxy"), "hosting": g.get("hosting")})
    r = api_json(f"https://rdap.org/ip/{ip}")
    if r:
        info["netname"] = r.get("name")
        info["net_country"] = r.get("country")
        for roles, _name, em in rdap_abuse(r):
            if "abuse" in roles and em:
                info["hosting_abuse"] = em
                break
    org = (info.get("org_asn") or "") + " " + (info.get("netname") or "")
    for cdn in ("Cloudflare", "Akamai", "Fastly", "Amazon CloudFront", "Incapsula", "Sucuri", "DDoS-Guard"):
        if cdn.lower() in org.lower():
            info["note"] = f"{cdn} -- real server IP hidden; report abuse to {cdn}"
    if info.get("hosting_abuse"):
        rep.abuse[info["hosting_abuse"]] = f"Hosting ({info.get('org_asn', '')}) -- to take down site on IP {ip}"
    return info


def host_intel(host, rep):
    if not host or host in rep.seen_hosts:
        return
    rep.seen_hosts.add(host)
    entry = {"host": host}
    ips = []
    if is_public_ip(host):
        ips = [host]
    else:
        try:
            ips = sorted({a[4][0] for a in socket.getaddrinfo(host, None)})
        except Exception:
            entry["dns"] = "DNS resolution failed (site may be down or DNS blocked)"
        if not is_official(host):
            entry["domain"] = domain_intel(host, rep)
    entry["ips"] = []
    for ip in ips[:3]:
        rep.iocs["ips"].add(ip)
        if is_public_ip(ip):
            entry["ips"].append(ip_intel(ip, rep))
    rep.infra.append(entry)


def ssl_intel(host, port, rep):
    sec = f"SSL Certificate: {host}"
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port or 443), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subj = dict(x[0] for x in cert.get("subject", []))
        rep.info(sec, "Issuer", issuer.get("organizationName") or issuer.get("commonName"))
        rep.info(sec, "Subject", subj.get("commonName"))
        rep.info(sec, "Valid from", cert.get("notBefore"))
        rep.info(sec, "Valid to", cert.get("notAfter"))
        sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
        rep.info(sec, "SAN (other domains)", ", ".join(sans[:15]) + (" ..." if len(sans) > 15 else ""))
        nb = cert.get("notBefore")
        if nb:
            try:
                age = (dt.datetime.now(dt.timezone.utc) - dt.datetime.strptime(nb, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)).days
                if age < 7:
                    rep.add(8, "SSL", f"Certificate issued only {age} days ago")
            except Exception:
                pass
        if "let's encrypt" in str(issuer).lower() or "zerossl" in str(issuer).lower():
            rep.info(sec, "Note", "Free certificate -- not bad by itself, but padlock does not mean safe")
    except ssl.SSLCertVerificationError as e:
        rep.add(10, "SSL", f"Invalid SSL certificate: {e.verify_message}")
    except Exception as e:
        rep.info(sec, "Error", str(e)[:120])
