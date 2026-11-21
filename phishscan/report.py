"""Report collection and output (terminal, JSON, HTML)"""
import datetime as dt
import html as htmlmod
from . import VERSION
from .console import C
from .data import ATTACK_TYPES
from .util import defang


class Report:
    def __init__(self, target):
        self.target = target
        self.started = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        self.findings = []        # (weight, severity, category, message)
        self.types = set()
        self.sections = {}        # name -> list[(key, value)]
        self.iocs = {"urls": set(), "domains": set(), "ips": set(), "emails": set(),
                     "hashes": set(), "telegram_bots": set(), "wallets": set()}
        self.abuse = {}           # contact -> reason
        self.infra = []           # dicts per host
        self.related = []         # related domains from crt.sh
        self.brands = set()       # impersonated brands (for crt.sh hunt)
        self.seen_hosts = set()

    def fingerprint(self):
        """
        Campaign fingerprint — builds a short signature from exfil channels + hosting.
        Same signature = likely same group/kit. Works offline too.
        """
        import hashlib
        parts = []
        for bot in sorted(self.iocs["telegram_bots"]):
            parts.append("tg:" + bot.split(":")[0])          # bot ID (not token)
        for w in sorted(self.iocs["wallets"]):
            parts.append("wallet:" + w)
        from urllib.parse import urlparse
        from .util import reg_domain
        for u in sorted(self.iocs["urls"]):
            h = urlparse(u if "://" in u else "http://" + u).hostname or ""
            if h and any(k in u.lower() for k in ("/next.php", "/post.php", "/gate.php", "webhook", "/sendmessage", "formspree", "apps_script", "script.google")):
                parts.append("exfil:" + reg_domain(h))
        for e in self.infra:
            for ipi in e.get("ips", []):
                if ipi.get("org_asn"):
                    parts.append("asn:" + ipi["org_asn"].split()[0])
                    break
            break
        parts = sorted(set(parts))
        if not parts:
            return None
        sig = hashlib.sha1("|".join(parts).encode()).hexdigest()[:12]
        return {"id": sig, "signals": parts}

    def add(self, weight, cat, msg, atype=None):
        sev = "HIGH" if weight >= 20 else "MED" if weight >= 8 else "LOW" if weight > 0 else "INFO"
        key = (cat, msg)
        if any((f[2], f[3]) == key for f in self.findings):
            return
        self.findings.append((weight, sev, cat, msg))
        if atype:
            self.types.add(atype)

    def info(self, section, key, value):
        if value in (None, "", [], {}):
            return
        self.sections.setdefault(section, []).append((key, value))

    def score(self):
        return min(100, sum(f[0] for f in self.findings))

    def verdict(self):
        s = self.score()
        if s >= 70:
            return "Critical phishing / malicious", C.R
        if s >= 40:
            return "Highly suspicious", C.R
        if s >= 15:
            return "Suspicious — be careful", C.Y
        return "Low risk (but not proven safe)", C.G

    def to_dict(self):
        return {
            "tool": f"PhishScan {VERSION}", "target": self.target, "scanned_utc": self.started,
            "score": self.score(), "verdict": self.verdict()[0],
            "attack_types": [{"id": t, "name": ATTACK_TYPES[t][0], "goal": ATTACK_TYPES[t][1],
                              "impact": ATTACK_TYPES[t][2]} for t in sorted(self.types)],
            "findings": [{"weight": w, "severity": s, "category": c, "message": m}
                         for w, s, c, m in sorted(self.findings, key=lambda x: -x[0])],
            "sections": {k: [[a, b] for a, b in v] for k, v in self.sections.items()},
            "infrastructure": self.infra,
            "related_domains": self.related,
            "campaign_fingerprint": self.fingerprint(),
            "iocs": {k: sorted(v) for k, v in self.iocs.items()},
            "iocs_defanged": {k: sorted(defang(x) for x in v) for k, v in self.iocs.items() if k in ("urls", "domains", "ips")},
            "report_to": self.abuse,
        }


def fmt_val(v):
    if isinstance(v, dict):
        return "; ".join(f"{k}={x}" for k, x in v.items())
    if isinstance(v, (list, tuple, set)):
        return ", ".join(str(x) for x in v)
    return str(v)


def print_report(rep):
    line = "=" * 70
    verdict, col = rep.verdict()
    print(f"\n{C.BO}{line}\n  PhishScan {VERSION} — Phishing Analysis Report\n{line}{C.X}")
    print(f"  Target : {rep.target}")
    print(f"  Time (UTC): {rep.started}")
    print(f"  Risk Score: {col}{C.BO}{rep.score()}/100 — {verdict}{C.X}\n")

    if rep.types:
        print(f"{C.BO}{C.M}> Attack Type, Purpose & Potential Damage{C.X}")
        for t in sorted(rep.types):
            n, g, i = ATTACK_TYPES[t]
            print(f"  {C.BO}* {n}{C.X}\n      Goal  : {g}\n      Impact: {i}")
        print()

    print(f"{C.BO}{C.M}> Evidence / Indicators{C.X}")
    for w, s, cat, m in sorted(rep.findings, key=lambda x: -x[0]):
        c = C.R if s == "HIGH" else C.Y if s == "MED" else C.D
        print(f"  {c}[{s:4}] +{w:<2}{C.X} ({cat}) {m}")
    if not rep.findings:
        print("  Nothing notable found")
    print()

    if rep.infra:
        print(f"{C.BO}{C.M}> Infrastructure & Location{C.X}")
        for e in rep.infra:
            print(f"  {C.BO}{e['host']}{C.X}" + (f"  {C.D}{e.get('dns')}{C.X}" if e.get("dns") else ""))
            dom = e.get("domain") or {}
            for k in ("registered_domain", "created", "age_days", "registrar", "registrant", "registrant_country", "nameservers", "registrar_abuse"):
                if dom.get(k):
                    print(f"      {k:18}: {fmt_val(dom[k])}")
            for ipi in e.get("ips", []):
                loc = ", ".join(x for x in (ipi.get("city"), ipi.get("region"), ipi.get("country")) if x)
                print(f"      IP {ipi.get('ip')}: {C.B}{loc or 'Location unknown'}{C.X}")
                for k in ("org_asn", "netname", "reverse_dns", "loc", "proxy_vpn", "hosting_abuse", "note"):
                    if ipi.get(k) not in (None, ""):
                        print(f"         {k:14}: {ipi[k]}")
        print(f"  {C.D}Note: This is the SERVER location, not the scammer's home address.{C.X}\n")

    for sec, items in rep.sections.items():
        print(f"{C.BO}{C.B}> {sec}{C.X}")
        for k, v in items:
            print(f"  {k}: {fmt_val(v)[:300]}")
        print()

    iocs = {k: v for k, v in rep.iocs.items() if v}
    if iocs:
        print(f"{C.BO}{C.M}> IOCs (for blocking/reporting){C.X}")
        for k, v in iocs.items():
            print(f"  {k}: {', '.join(sorted(v)[:25])}")
        print()

    fp = rep.fingerprint()
    if fp:
        print(f"{C.BO}{C.M}> Campaign Fingerprint{C.X}")
        print(f"  ID: {C.BO}{fp['id']}{C.X}  (same ID = likely same scammer group/kit)")
        print(f"  Based on: {', '.join(fp['signals'])}")
        print(f"  {C.D}Scan multiple phishing links and compare this ID to find linked campaigns.{C.X}\n")

    print(f"{C.BO}{C.G}> What To Do / Where To Report{C.X}")
    for em, why in rep.abuse.items():
        print(f"  * {em}  -- {why}")
    print("  * Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/")
    print("  * Netcraft: https://report.netcraft.com/report")
    print("  * APWG: reportphishing@apwg.org (forward the email)")
    print("  * Bangladesh: BGD e-GOV CIRT (cirt.gov.bd), DMP Cyber Crime Unit (CTTC)")
    print("  * If bKash/Nagad/bank name used, report to their official helpline")
    if rep.score() >= 40:
        print(f"  {C.Y}* If you already entered info: change password NOW, logout all devices, enable 2FA, call your bank.{C.X}")
    print(f"{line}\n")


def html_report(rep, path):
    d = rep.to_dict()
    e = htmlmod.escape
    verdict, _ = rep.verdict()
    col = "#c0392b" if rep.score() >= 40 else "#d68910" if rep.score() >= 15 else "#1e8449"
    parts = [f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishScan — {e(rep.target[:60])}</title><style>
body{{font-family:'Segoe UI','Noto Sans',sans-serif;max-width:1000px;margin:auto;padding:20px;background:#f6f7f9;color:#222}}
h1{{font-size:22px}} h2{{font-size:17px;border-bottom:2px solid #ddd;padding-bottom:4px;margin-top:28px}}
.score{{font-size:26px;font-weight:700;color:{col}}} .card{{background:#fff;border-radius:8px;padding:14px 18px;margin:10px 0;box-shadow:0 1px 3px #0001}}
table{{border-collapse:collapse;width:100%}} td{{border-bottom:1px solid #eee;padding:5px 8px;vertical-align:top;word-break:break-all;font-size:14px}}
.HIGH{{color:#c0392b;font-weight:700}} .MED{{color:#b9770e;font-weight:700}} .LOW{{color:#777}} .INFO{{color:#999}} code{{background:#eee;padding:1px 4px}}
</style></head><body><h1>PhishScan Phishing Analysis Report</h1>
<div class="card"><div>Target: <code>{e(rep.target)}</code></div><div>Scanned (UTC): {e(rep.started)}</div>
<div class="score">{rep.score()}/100 — {e(verdict)}</div></div>"""]
    if d["attack_types"]:
        parts.append("<h2>Attack Type, Goal & Impact</h2>")
        for t in d["attack_types"]:
            parts.append(f"<div class='card'><b>{e(t['name'])}</b><br>Goal: {e(t['goal'])}<br>Impact: {e(t['impact'])}</div>")
    parts.append("<h2>Evidence / Indicators</h2><div class='card'><table>")
    for f in d["findings"]:
        parts.append(f"<tr><td class='{f['severity']}'>{f['severity']} +{f['weight']}</td><td>{e(f['category'])}</td><td>{e(f['message'])}</td></tr>")
    parts.append("</table></div>")
    if d["infrastructure"]:
        parts.append("<h2>Infrastructure & Location</h2>")
        for inf in d["infrastructure"]:
            parts.append(f"<div class='card'><b>{e(inf['host'])}</b><table>")
            for k, v in (inf.get("domain") or {}).items():
                parts.append(f"<tr><td>{e(k)}</td><td>{e(fmt_val(v))}</td></tr>")
            for ipi in inf.get("ips", []):
                for k, v in ipi.items():
                    if v not in (None, ""):
                        parts.append(f"<tr><td>{e(k)}</td><td>{e(fmt_val(v))}</td></tr>")
            parts.append("</table></div>")
    for sec, items in d["sections"].items():
        parts.append(f"<h2>{e(sec)}</h2><div class='card'><table>")
        for k, v in items:
            parts.append(f"<tr><td>{e(str(k))}</td><td>{e(fmt_val(v))}</td></tr>")
        parts.append("</table></div>")
    if d.get("campaign_fingerprint"):
        fp = d["campaign_fingerprint"]
        parts.append(f"<h2>Campaign Fingerprint</h2><div class='card'><b>{e(fp['id'])}</b> "
                     "<span style='color:#888'>(same ID = likely same scammer)</span><br>"
                     f"Based on: <code>{e(', '.join(fp['signals']))}</code></div>")
    parts.append("<h2>IOC</h2><div class='card'><table>")
    for k, v in d["iocs"].items():
        if v:
            parts.append(f"<tr><td>{e(k)}</td><td>{e(', '.join(v))}</td></tr>")
    parts.append("</table></div><h2>Report To</h2><div class='card'><ul>")
    for em, why in d["report_to"].items():
        parts.append(f"<li><code>{e(em)}</code> — {e(why)}</li>")
    parts.append("<li>Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/</li><li>Netcraft: https://report.netcraft.com/report</li>"
                 "<li>Bangladesh: BGD e-GOV CIRT (cirt.gov.bd), DMP Cyber Crime Unit (CTTC)</li></ul></div>"
                 f"<p style='color:#888;font-size:12px'>Generated by PhishScan {VERSION}. IP location is server location, not the scammer's personal address.</p></body></html>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("".join(parts))
