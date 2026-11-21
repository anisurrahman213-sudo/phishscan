"""
অনলাইন অংশের টেস্ট — নকল (mock) সার্ভার উত্তর দিয়ে, ইন্টারনেট লাগে না।
RDAP, IP লোকেশন, VirusTotal, urlscan.io-র উত্তর ঠিকমতো পড়া হচ্ছে কিনা যাচাই করে।
"""
import datetime as dt
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishscan import infra, report, reputation, util  # noqa: E402
from phishscan.report import Report  # noqa: E402

NEW_DATE = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")

RDAP_DOMAIN = {
    "events": [{"eventAction": "registration", "eventDate": NEW_DATE},
               {"eventAction": "expiration", "eventDate": "2027-11-18T00:00:00Z"}],
    "nameservers": [{"ldhName": "NS1.CHEAPHOST.EXAMPLE"}],
    "status": ["client transfer prohibited"],
    "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Cheap Registrar LLC"]]],
                  "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@cheap-registrar.example"]]]}]}],
}
IPINFO = {"ip": "203.0.113.9", "city": "Moscow", "region": "Moscow", "country": "RU",
          "org": "AS64500 Bulletproof Hosting Ltd", "hostname": "srv9.bp-host.example", "loc": "55.75,37.61"}
RDAP_IP = {"name": "BP-NET", "country": "RU",
           "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@bp-host.example"]]]}]}
CF_IPINFO = {"ip": "104.16.1.1", "city": "San Francisco", "country": "US", "org": "AS13335 Cloudflare, Inc."}


@pytest.fixture
def fake_net(monkeypatch):
    calls = []

    def fake_api_json(url, headers=None):
        calls.append(url)
        if "rdap.org/domain/" in url:
            return RDAP_DOMAIN
        if "ipinfo.io/104.16.1.1" in url:
            return CF_IPINFO
        if "ipinfo.io/" in url:
            return IPINFO
        if "rdap.org/ip/" in url:
            return RDAP_IP
        return None

    def fake_getaddrinfo(host, port, *a, **k):
        ip = "104.16.1.1" if "cf-" in host else "203.0.113.9"
        return [(2, 1, 6, "", (ip, 0))]

    monkeypatch.setattr(infra, "api_json", fake_api_json)
    monkeypatch.setattr(infra.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(infra, "is_public_ip", lambda s: s.count(".") == 3 and s.replace(".", "").isdigit())
    return calls


def test_host_intel_full(fake_net):
    rep = Report("t")
    infra.host_intel("login.bkash-verify.top", rep)
    e = rep.infra[0]
    assert e["domain"]["registrar"] == "Cheap Registrar LLC"
    assert e["domain"]["age_days"] <= 4
    assert e["domain"]["nameservers"] == ["ns1.cheaphost.example"]
    ip = e["ips"][0]
    assert ip["country"] == "RU" and ip["city"] == "Moscow" and "Bulletproof" in ip["org_asn"]
    assert ip["hosting_abuse"] == "abuse@bp-host.example"
    assert "abuse@cheap-registrar.example" in rep.abuse and "abuse@bp-host.example" in rep.abuse
    assert any("দিন আগে কেনা" in f[3] and f[0] == 25 for f in rep.findings)


def test_host_intel_cloudflare_note(fake_net):
    rep = Report("t")
    infra.host_intel("cf-phish.example", rep)
    assert "Cloudflare" in rep.infra[0]["ips"][0]["note"]


def test_host_intel_official_skips_whois(fake_net):
    rep = Report("t")
    infra.host_intel("www.bkash.com", rep)
    assert "domain" not in rep.infra[0]
    assert not any("rdap.org/domain" in c for c in fake_net)


def test_host_intel_dedup(fake_net):
    rep = Report("t")
    infra.host_intel("a.example", rep)
    infra.host_intel("a.example", rep)
    assert len(rep.infra) == 1


def test_parse_date_formats():
    assert infra.parse_date("2024-01-02T03:04:05Z").year == 2024
    assert infra.parse_date("02-Jan-2024").month == 1
    assert infra.parse_date("2024.01.02").day == 2
    assert infra.parse_date("nonsense") is None


# ─────────── VirusTotal / urlscan ───────────
@pytest.fixture
def vt_env(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    reputation.VT_CALLS.clear()
    reputation.VT_LIMIT["max"] = 8
    yield
    reputation.VT_CALLS.clear()


def test_vt_url_malicious(monkeypatch, vt_env):
    seen = {}

    def fake(url, headers=None):
        seen["h"] = headers
        return {"data": {"attributes": {
            "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 60},
            "last_analysis_results": {"A": {"category": "malicious", "result": "phishing"}}}}}
    monkeypatch.setattr(reputation, "api_json", fake)
    rep = Report("t")
    reputation.vt_url("https://bad.example/", rep)
    assert seen["h"] == {"x-apikey": "test-key"}
    assert any(f[2] == "Reputation" and f[0] == 34 for f in rep.findings)   # 10 + 8*3
    assert "phishing" in str(rep.sections["VirusTotal"])


def test_vt_bad_key_message(monkeypatch, vt_env):
    def fake(url, headers=None):
        util.API_STATUS[url] = 401
        return None
    monkeypatch.setattr(reputation, "api_json", fake)
    rep = Report("t")
    reputation.vt_url("https://x.example/", rep)
    assert "key ভুল" in str(rep.sections["VirusTotal"])


def test_vt_quota_message(monkeypatch, vt_env):
    def fake(url, headers=None):
        util.API_STATUS[url] = 429
        return None
    monkeypatch.setattr(reputation, "api_json", fake)
    rep = Report("t")
    reputation.vt_hash("a" * 64, rep)
    assert "সীমা শেষ" in str(rep.sections["VirusTotal"])


def test_vt_hash_malware(monkeypatch, vt_env):
    monkeypatch.setattr(reputation, "api_json", lambda u, h=None: {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 40}, "type_description": "Android",
        "popular_threat_classification": {"suggested_threat_label": "trojan.banker/sms"}}}})
    rep = Report("t")
    reputation.vt_hash("b" * 64, rep)
    assert "malware_delivery" in rep.types and "trojan.banker" in str(rep.sections["VirusTotal"])


def test_vt_rate_limit_cap(monkeypatch, vt_env):
    monkeypatch.setattr(reputation, "api_json", lambda u, h=None: None)
    monkeypatch.setattr(reputation.time, "sleep", lambda s: None)
    reputation.VT_LIMIT["max"] = 2
    rep = Report("t")
    for i in range(4):
        reputation.vt_url(f"https://x{i}.example/", rep)
    assert len(reputation.VT_CALLS) == 2
    assert "সীমা" in str(rep.sections["VirusTotal"])


def test_vt_waits_after_4_per_minute(monkeypatch, vt_env):
    slept = []
    monkeypatch.setattr(reputation, "api_json", lambda u, h=None: None)
    monkeypatch.setattr(reputation.time, "sleep", lambda s: slept.append(s))
    rep = Report("t")
    for i in range(5):
        reputation.vt_url(f"https://y{i}.example/", rep)
    assert slept and slept[0] > 50


def test_no_vt_key_no_calls(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.setattr(reputation, "api_json", lambda *a, **k: pytest.fail("কল হওয়া উচিত নয়"))
    reputation.vt_url("https://x.example/", Report("t"))


def test_urlscan_malicious(monkeypatch):
    monkeypatch.setattr(reputation, "api_json", lambda u, h=None: {"total": 3, "results": [
        {"task": {"time": "2026-11-01T10:00:00Z"}, "result": "https://urlscan.io/api/v1/result/abc/",
         "verdicts": {"overall": {"malicious": True}}}]})
    rep = Report("t")
    reputation.urlscan_lookup("bad.example", rep)
    assert any(f[2] == "Reputation" for f in rep.findings)
    assert "https://urlscan.io/result/abc/" in str(rep.sections["urlscan.io"])


# ─────────── রিপোর্ট আউটপুট ───────────
def test_print_and_html_report(fake_net, tmp_path, capsys):
    rep = Report("hxxp://bad[.]top <script>")
    infra.host_intel("bad.top", rep)
    rep.add(30, "Brand", "টেস্ট লক্ষণ", "brand_impersonation")
    rep.info("সেকশন", "কী", ["a", "b"])
    rep.iocs["urls"].add("http://bad.top/x")
    report.print_report(rep)
    out = capsys.readouterr().out
    for must in ("ঝুঁকি স্কোর", "ব্র্যান্ড নকল", "Moscow", "abuse@bp-host.example", "IOC", "রিপোর্ট করবেন"):
        assert must in out, must
    path = tmp_path / "r.html"
    report.html_report(rep, str(path))
    html = path.read_text(encoding="utf-8")
    assert "Moscow" in html and "<script>" not in html and "&lt;script&gt;" in html
    d = rep.to_dict()
    assert d["iocs_defanged"]["urls"] == ["hxxp://bad[.]top/x"]
