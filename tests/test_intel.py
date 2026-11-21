"""crt.sh সম্পর্কিত-ডোমেইন ও ক্যাম্পেইন ফিঙ্গারপ্রিন্টের টেস্ট — নকল উত্তর দিয়ে, ইন্টারনেট লাগে না।"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from phishscan import intel  # noqa: E402
from phishscan.report import Report  # noqa: E402

# crt.sh স্টাইলের নকল উত্তর
CRT_SUBS = [
    {"name_value": "bkash-verify.top\nlogin.bkash-verify.top"},
    {"name_value": "*.bkash-verify.top"},
    {"common_name": "admin.bkash-verify.top"},
    {"name_value": "panel.bkash-verify.top\nwww.bkash-verify.top"},
    {"name_value": "cdn.bkash-verify.top\nimg.bkash-verify.top"},
    {"name_value": "pay.bkash-verify.top\notp.bkash-verify.top"},
    {"name_value": "mail.bkash-verify.top\nwebmail.bkash-verify.top"},
]
CRT_BRAND = [
    {"name_value": "bkash-verify.top"},
    {"name_value": "bkash-login.xyz"},
    {"name_value": "secure-bkash.click"},
    {"name_value": "sni.cloudflaressl.com"},          # বাদ পড়বে
    {"name_value": "www.bkash.com"},                  # অফিসিয়াল — বাদ
    {"name_value": "something-else.com"},             # ব্র্যান্ড নেই — বাদ
]


@pytest.fixture
def fake_crt(monkeypatch):
    def api(url, headers=None):
        if "%25bkash%25" in url:
            return CRT_BRAND
        if "bkash-verify.top" in url:
            return CRT_SUBS
        return None
    monkeypatch.setattr(intel, "api_json", api)


def test_subdomains_found(fake_crt):
    rep = Report("t")
    intel.crtsh_subdomains("login.bkash-verify.top", rep)
    sec = dict(rep.sections["সম্পর্কিত সাবডোমেইন (Certificate Transparency)"])
    assert sec["মোট পাওয়া গেছে"] >= 8
    assert "admin.bkash-verify.top" in rep.iocs["domains"]
    assert any("login" in s for s in sec["সন্দেহজনক সাবডোমেইন"])
    assert any(f[2] == "Infra" for f in rep.findings)


def test_subdomains_skip_official(fake_crt):
    rep = Report("t")
    intel.crtsh_subdomains("www.bkash.com", rep)
    assert not rep.sections


def test_brand_hunt(fake_crt):
    rep = Report("t")
    intel.crtsh_brand_hunt("bkash", rep)
    assert "bkash-login.xyz" in rep.related
    assert "secure-bkash.click" in rep.related
    assert "www.bkash.com" not in rep.related            # অফিসিয়াল বাদ
    assert "sni.cloudflaressl.com" not in rep.related     # CDN বাদ
    assert "something-else.com" not in rep.related        # ব্র্যান্ড নেই


def test_brand_hunt_short_skipped(fake_crt):
    rep = Report("t")
    intel.crtsh_brand_hunt("ab", rep)
    assert not rep.related


def test_gather_related_handles_none(monkeypatch):
    monkeypatch.setattr(intel, "api_json", lambda u, h=None: None)
    rep = Report("t")
    intel.gather_related("bad.top", rep, "bkash")   # ক্র্যাশ করবে না
    assert rep.related == []


def test_gather_related_survives_error(monkeypatch):
    def boom(u, h=None):
        raise RuntimeError("network down")
    monkeypatch.setattr(intel, "api_json", boom)
    rep = Report("t")
    intel.gather_related("bad.top", rep, "bkash")
    assert "crt.sh" in str(rep.sections.get("সম্পর্কিত ডোমেইন", []))


# ─────────── ক্যাম্পেইন ফিঙ্গারপ্রিন্ট ───────────
def test_fingerprint_stable_and_matches():
    r1 = Report("site1.top")
    r1.iocs["telegram_bots"].add("1234567890:AAFakeTokenFakeTokenFakeToken1234567")
    r1.iocs["urls"].add("https://evil-collector.ru/next.php")
    r2 = Report("site2.xyz")   # ভিন্ন ডোমেইন, একই exfil চ্যানেল
    r2.iocs["telegram_bots"].add("1234567890:DIFFERENTtokenDIFFERENTtoken1234567")
    r2.iocs["urls"].add("https://evil-collector.ru/next.php")
    fp1, fp2 = r1.fingerprint(), r2.fingerprint()
    assert fp1 and fp2
    assert fp1["id"] == fp2["id"]          # একই বট আইডি + exfil → একই ক্যাম্পেইন
    assert any("tg:1234567890" in s for s in fp1["signals"])


def test_fingerprint_token_not_leaked():
    r = Report("t")
    r.iocs["telegram_bots"].add("9999:SECRETtokenSECRETtokenSECRETtoken123")
    fp = r.fingerprint()
    assert "SECRET" not in str(fp)          # টোকেন ফাঁস হবে না, শুধু বট আইডি
    assert fp["signals"] == ["tg:9999"]


def test_fingerprint_none_when_empty():
    assert Report("t").fingerprint() is None


def test_fingerprint_in_report_dict():
    r = Report("t")
    r.iocs["wallets"].add("0x1111111111111111111111111111111111111111")
    d = r.to_dict()
    assert d["campaign_fingerprint"]["signals"][0].startswith("wallet:")
    assert "related_domains" in d
