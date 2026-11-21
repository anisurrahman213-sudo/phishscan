"""Third-party reputation: VirusTotal, urlscan.io"""
import base64
import os
import sys
import time
from .console import C
from .util import api_json, api_problem


VT_CALLS = []
VT_LIMIT = {"max": 8}


def vt_allowed(rep):
    """Free API: 4/min -- respects limits, max --vt-max calls per scan"""
    if len(VT_CALLS) >= VT_LIMIT["max"]:
        rep.info("VirusTotal", "Limit", f"Max {VT_LIMIT['max']} VT checks per scan (increase with --vt-max)")
        return False
    recent = [t for t in VT_CALLS if time.time() - t < 60]
    if len(recent) >= 4:
        wait = 61 - (time.time() - recent[0])
        print(f"{C.D}[*] VirusTotal free limit -- waiting {int(wait)}s...{C.X}", file=sys.stderr)
        time.sleep(max(0, wait))
    VT_CALLS.append(time.time())
    return True


def vt_url(url, rep):
    key = os.environ.get("VT_API_KEY")
    if not key or not vt_allowed(rep):
        return
    uid = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vurl = f"https://www.virustotal.com/api/v3/urls/{uid}"
    d = api_json(vurl, {"x-apikey": key})
    sec = "VirusTotal"
    if not d:
        rep.info(sec, url[:60], api_problem(vurl, "VirusTotal") or "No record (not previously scanned)")
        return
    a = d.get("data", {}).get("attributes", {})
    st = a.get("last_analysis_stats", {})
    rep.info(sec, url[:60], f"malicious={st.get('malicious', 0)} suspicious={st.get('suspicious', 0)} harmless={st.get('harmless', 0)}")
    bad = st.get("malicious", 0) + st.get("suspicious", 0)
    if bad:
        rep.add(min(40, 10 + bad * 3), "Reputation", f"VirusTotal: {bad} security engines flagged this as malicious")
    names = [r.get("result") for r in a.get("last_analysis_results", {}).values() if r.get("category") == "malicious"]
    if names:
        rep.info(sec, "Labels", ", ".join(sorted(set(n for n in names if n))[:8]))


def vt_hash(sha256, rep):
    key = os.environ.get("VT_API_KEY")
    if not key or not vt_allowed(rep):
        return
    vurl = f"https://www.virustotal.com/api/v3/files/{sha256}"
    d = api_json(vurl, {"x-apikey": key})
    if not d:
        rep.info("VirusTotal", sha256[:16], api_problem(vurl, "VirusTotal") or "File not previously seen on VirusTotal")
        return
    a = d.get("data", {}).get("attributes", {})
    st = a.get("last_analysis_stats", {})
    bad = st.get("malicious", 0)
    rep.info("VirusTotal", sha256[:16], f"malicious={bad}, type={a.get('type_description')}, name={a.get('popular_threat_classification', {}).get('suggested_threat_label')}")
    if bad:
        rep.add(min(50, 15 + bad * 2), "Reputation", f"VirusTotal: {bad} antivirus engines flagged this as malware", "malware_delivery")


def urlscan_lookup(host, rep):
    hdr = {"Accept": "application/json"}
    if os.environ.get("URLSCAN_API_KEY"):
        hdr["API-Key"] = os.environ["URLSCAN_API_KEY"]
    uurl = f"https://urlscan.io/api/v1/search/?q=domain:{host}&size=5"
    d = api_json(uurl, hdr)
    if not d:
        prob = api_problem(uurl, "urlscan.io")
        if prob:
            rep.info("urlscan.io", host, prob)
        return
    res = d.get("results", [])
    rep.info("urlscan.io", host, f"{d.get('total', 0)} previous scans")
    for r in res[:3]:
        rep.info("urlscan.io", r.get("task", {}).get("time", "")[:10], r.get("result", "").replace("/api/v1/result/", "/result/"))
        if r.get("verdicts", {}).get("overall", {}).get("malicious"):
            rep.add(25, "Reputation", "urlscan.io flagged this domain as malicious")
