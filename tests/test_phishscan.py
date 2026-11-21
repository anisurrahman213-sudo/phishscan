"""
PhishScan টেস্ট — ইন্টারনেট লাগে না (--offline)।
চালান:  python3 -m pytest -q
"""
import json
import os
import subprocess
import sys
from types import SimpleNamespace

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(__file__))

import phishscan as ps  # noqa: E402  (প্যাকেজ)
import make_samples  # noqa: E402

CMD = [sys.executable, "-m", "phishscan"]
ENV = dict(os.environ, PYTHONPATH=ROOT + os.pathsep + os.environ.get("PYTHONPATH", ""))


@pytest.fixture(scope="session")
def samples(tmp_path_factory):
    return make_samples.write_all(str(tmp_path_factory.mktemp("samples")))


def run(target, tmp_path, *extra, subprocess_mode=False, online=False):
    """
    CLI চালিয়ে JSON রিপোর্ট ফেরত দেয়। ডিফল্টে একই প্রসেসে (coverage মাপা যায়);
    --brands-এর মতো গ্লোবাল অবস্থা বদলানো টেস্টে subprocess_mode=True।
    """
    out = tmp_path / "r.json"
    argv = [target, "--quiet", "--json", str(out), "--html", str(tmp_path / "r.html"),
            "--evidence", str(tmp_path / "ev"), *extra]
    if not online:
        argv.insert(1, "--offline")
    if subprocess_mode:
        env = dict(ENV, NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost", VT_API_KEY="")
        proc = subprocess.run([*CMD, *argv], capture_output=True, text=True, timeout=180, env=env)
        assert "Traceback" not in proc.stderr, proc.stderr
        code = proc.returncode
    else:
        from phishscan import cli, reputation
        reputation.VT_CALLS.clear()
        old_argv, old_env = sys.argv, dict(os.environ)
        sys.argv = ["phishscan", *argv]
        os.environ.update(NO_PROXY="127.0.0.1,localhost", no_proxy="127.0.0.1,localhost", VT_API_KEY="")
        try:
            cli.main()
            code = 0
        except SystemExit as e:
            code = e.code
        finally:
            sys.argv = old_argv
            os.environ.clear()
            os.environ.update(old_env)
    assert out.exists(), f"রিপোর্ট তৈরি হয়নি (exit {code})"
    rep = json.loads(out.read_text(encoding="utf-8"))
    rep["_exit"] = code
    rep["_types"] = {t["id"] for t in rep["attack_types"]}
    return rep


# ─────────── ইউনিট টেস্ট ───────────
@pytest.mark.parametrize("host,expected", [
    ("www.bkash.com", "bkash.com"),
    ("login.nagad.com.bd", "nagad.com.bd"),
    ("evil.pages.dev", "evil.pages.dev"),
    ("a.b.evil.co.uk", "evil.co.uk"),
    ("8.8.8.8", "8.8.8.8"),
    ("login.microsoftonline.com.secure-auth.xyz", "secure-auth.xyz"),
])
def test_reg_domain(host, expected):
    assert ps.reg_domain(host) == expected


def test_official_and_not():
    assert ps.is_official("accounts.google.com")
    assert ps.is_official("www.bkash.com")
    assert not ps.is_official("bkash.com.verify-login.top")


def test_refang():
    assert ps.refang("hxxps://bad-site[.]top/login") == "https://bad-site.top/login"
    assert ps.refang("bad(.)com") == "bad.com"


def test_short_brand_no_false_positive():
    assert not ps.brand_in("dhl", "adhlogistics")
    assert ps.brand_in("dhl", "dhl-track", {"dhl", "track"})


@pytest.mark.parametrize("url,must_type", [
    ("https://g00gle.com/signin", "brand_impersonation"),
    ("https://paypai.com/login", "brand_impersonation"),
    ("https://facebok.com", "brand_impersonation"),
    ("https://xn--pypal-4ve.com/login", "brand_impersonation"),
    ("http://faceb00k-login.com", "brand_impersonation"),
    ("https://login.microsoftonline.com.secure-auth.xyz/common", "brand_impersonation"),
    ("hxxp://bkash-verify[.]top/pin", "brand_impersonation"),
])
def test_bad_urls(url, must_type, tmp_path):
    # অফলাইনে শুধু URL দেখে — তাই এখানে "সন্দেহজনক" (≥২৫) যথেষ্ট; অনলাইনে ডোমেইনের বয়স/কনটেন্ট যোগ হয়ে স্কোর বাড়ে
    r = run(url, tmp_path)
    assert must_type in r["_types"], r["findings"]
    assert r["score"] >= 25, r["findings"]


def test_facebook_redirector_unwrapped(tmp_path):
    r = run("https://l.facebook.com/l.php?u=https%3A%2F%2Fbkash-bonus.top%2Fclaim&h=AT0", tmp_path)
    assert "brand_impersonation" in r["_types"] and "bkash-bonus.top" in r["iocs"]["domains"]


def test_facebook_redirector_legit_low(tmp_path):
    r = run("https://l.facebook.com/l.php?u=https%3A%2F%2Fen.wikipedia.org%2Fwiki%2FDhaka&h=AT0", tmp_path)
    assert r["score"] < 15, r["findings"]


def test_at_trick_and_ip(tmp_path):
    r = run("http://www.bkash.com@103.4.5.6/bank", tmp_path)
    msgs = " ".join(f["message"] for f in r["findings"])
    assert "@" in msgs and r["score"] >= 40


@pytest.mark.parametrize("url", [
    "https://www.google.com/",
    "https://www.bkash.com/",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://github.com/",
    "https://ample.com/",
    "https://officer.com/",
    "https://www.goodreads.com/",
    "https://www.paypalobjects.com/",
])
def test_legit_urls_low(url, tmp_path):
    r = run(url, tmp_path)
    assert r["score"] < 15, r["findings"]
    assert r["_exit"] == 0


# ─────────── ফাইল টেস্ট ───────────
def test_phishing_email(samples, tmp_path):
    r = run(samples["phish_email.eml"], tmp_path)
    assert r["score"] >= 70 and r["_exit"] == 2
    for t in ("email_spoof", "credential_harvest", "otp_payment", "brand_impersonation"):
        assert t in r["_types"], t
    assert r["iocs"]["telegram_bots"]
    assert "45.133.1.20" in r["iocs"]["ips"]
    assert "abuse@telegram.org" in r["report_to"]
    if "qr.png" in open(samples["phish_email.eml"], "rb").read().decode("latin-1"):
        try:
            import pyzbar  # noqa: F401
            assert "quishing" in r["_types"]
        except ImportError:
            pass


def test_legit_email_low(samples, tmp_path):
    r = run(samples["legit_email.eml"], tmp_path)
    assert r["score"] < 15, r["findings"]


def test_pdf(samples, tmp_path):
    r = run(samples["phish_doc.pdf"], tmp_path)
    assert "malware_delivery" in r["_types"] and r["score"] >= 40


def test_clean_pdf(samples, tmp_path):
    assert run(samples["clean.pdf"], tmp_path)["score"] < 15


def test_apk(samples, tmp_path):
    r = run(samples["bkash_update.apk"], tmp_path)
    assert "android_stealer" in r["_types"] and r["iocs"]["telegram_bots"]
    apk = dict(r["sections"]["APK বিশ্লেষণ"])
    assert "READ_SMS" in apk and "BIND_ACCESSIBILITY_SERVICE" in apk, apk
    assert r["score"] >= 70


def test_clickfix(samples, tmp_path):
    r = run(samples["captcha.html"], tmp_path)
    assert {"clickfix", "html_smuggling"} <= r["_types"]


def test_macro_docx(samples, tmp_path):
    r = run(samples["macro_invoice.docx"], tmp_path)
    msgs = " ".join(f["message"] for f in r["findings"])
    assert "malware_delivery" in r["_types"] and "template" in msgs


def test_zip_double_ext(samples, tmp_path):
    r = run(samples["invoice.zip"], tmp_path)
    msgs = " ".join(f["message"] for f in r["findings"])
    assert "দ্বৈত এক্সটেনশন" in msgs and r["score"] >= 40


def test_svg(samples, tmp_path):
    r = run(samples["voicemail.svg"], tmp_path)
    assert r["score"] >= 40


def test_crypto(samples, tmp_path):
    r = run(samples["airdrop.html"], tmp_path)
    assert "crypto_drainer" in r["_types"]
    assert r["iocs"]["wallets"]


def test_legit_html_low(samples, tmp_path):
    assert run(samples["recipe.html"], tmp_path)["score"] < 15


def test_plain_image_low(samples, tmp_path):
    if "photo.png" not in samples:
        pytest.skip("Pillow নেই")
    assert run(samples["photo.png"], tmp_path)["score"] < 15


def test_url_list_txt(tmp_path):
    f = tmp_path / "links.txt"
    f.write_text("# comment\nhxxp://paypal-secure[.]top/login\nhttps://www.google.com\n", encoding="utf-8")
    r = run(str(f), tmp_path)
    assert "brand_impersonation" in r["_types"]


def test_missing_file(tmp_path):
    p = subprocess.run([*CMD, str(tmp_path / "nope.pdf"), "--offline"],
                       capture_output=True, text=True, env=ENV)
    assert p.returncode == 1 and "পাওয়া যায়নি" in p.stdout


def test_html_report_escapes(tmp_path):
    r = run('http://evil.top/<script>alert(1)</script>', tmp_path)
    html = (tmp_path / "r.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert r["score"] >= 0


def test_official_login_page_not_flagged():
    rep = ps.Report("t")
    ps.analyze_html("<html><title>Facebook</title><form action='/login'><input name=email>"
                    "<input type=password name=pass></form></html>", "https://www.facebook.com/login", rep)
    assert rep.score() < 15, rep.findings


# ─────────── লোকাল সার্ভার দিয়ে অনলাইন অংশের টেস্ট (ইন্টারনেট লাগে না) ───────────
import threading  # noqa: E402
from http.server import BaseHTTPRequestHandler, HTTPServer  # noqa: E402

PHISH_PAGE = (b"<html><title>bKash Login</title><form action='/next.php' method=post>"
              b"<input name=phone><input type=password name=pin placeholder='PIN'></form></html>")


class _H(BaseHTTPRequestHandler):
    def do_GET(self):
        ua = self.headers.get("User-Agent", "")
        if self.path == "/r1":
            self.send_response(302); self.send_header("Location", "/r2"); self.end_headers(); return
        if self.path == "/r2":
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
            self.wfile.write(b"<meta http-equiv='refresh' content='0;url=/page'>"); return
        if self.path == "/page" or (self.path == "/mobile" and "Mobile" in ua):
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
            self.wfile.write(PHISH_PAGE); return
        if self.path == "/download":
            self.send_response(200); self.send_header("Content-Disposition", "attachment; filename=update.apk"); self.end_headers()
            self.wfile.write(b"PK\x03\x04"); return
        self.send_response(403); self.end_headers(); self.wfile.write(b"Forbidden")

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def run_online(url, tmp_path):
    # --no-related: লোকাল সার্ভার টেস্টে বাইরের crt.sh-এ যেন কল না যায় (টেস্ট হারমেটিক রাখা)
    return run(url, tmp_path, "--no-related", online=True)


def test_redirect_chain_and_meta_refresh(server, tmp_path):
    r = run_online(server + "/r1", tmp_path)
    chain = " ".join(str(v) for k, v in r["sections"].get("রিডাইরেক্ট চেইন", []))
    assert "/r2" in chain and "/page" in chain
    assert {"credential_harvest", "otp_payment"} <= r["_types"]


def test_mobile_cloaking(server, tmp_path):
    r = run_online(server + "/mobile", tmp_path)
    msgs = " ".join(f["message"] for f in r["findings"])
    assert "Cloaking" in msgs and "otp_payment" in r["_types"]


def test_blocked_403(server, tmp_path):
    r = run_online(server + "/blocked", tmp_path)
    assert any(f["category"] == "Cloaking" for f in r["findings"])


def test_attachment_download(server, tmp_path):
    r = run_online(server + "/download", tmp_path)
    assert "malware_delivery" in r["_types"]



# ─────────── কনফিগ ও Python API ───────────
def test_brands_config(tmp_path):
    cfg = tmp_path / "brands.json"
    cfg.write_text('{"shapnobank": ["shapnobank.com.bd"]}', encoding="utf-8")
    r = run("https://shapnobank-secure-login.top/", tmp_path, "--brands", str(cfg), subprocess_mode=True)
    assert "brand_impersonation" in r["_types"]
    r2 = run("https://www.shapnobank.com.bd/", tmp_path, "--brands", str(cfg), subprocess_mode=True)
    assert r2["score"] < 15


def test_example_config_is_valid(tmp_path):
    cfg = os.path.join(ROOT, "config", "brands.example.json")
    r = run("https://shapnobank-login.top/", tmp_path, "--brands", cfg, subprocess_mode=True)
    assert "brand_impersonation" in r["_types"]
    from phishscan import data
    before = dict(data.BRANDS)
    data.load_brand_file(cfg, strict=True)
    try:
        assert not any(k.startswith("_") for k in data.BRANDS)
    finally:
        for k in list(data.BRANDS):
            if k not in before:
                del data.BRANDS[k]


def test_bad_brands_file(tmp_path):
    cfg = tmp_path / "bad.json"
    cfg.write_text("[1,2,3]", encoding="utf-8")
    p = subprocess.run([*CMD, "https://x.com", "--offline", "--brands", str(cfg)], capture_output=True, text=True, env=ENV)
    assert p.returncode == 1 and "--brands" in p.stdout


def test_python_api(samples):
    r = ps.scan(samples["phish_email.eml"], offline=True)
    assert r["score"] >= 70 and r["attack_types"]
    r2 = ps.scan("hxxp://bkash-verify[.]top/pin", offline=True)
    assert any(t["id"] == "brand_impersonation" for t in r2["attack_types"])


def test_version_flag():
    p = subprocess.run([*CMD, "--version"], capture_output=True, text=True, env=ENV)
    assert p.stdout.strip() == "PhishScan " + ps.VERSION


def test_version_consistent():
    import re as _re
    toml = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert _re.search(r'^version = "([^"]+)"', toml, _re.M).group(1) == ps.VERSION
    assert f"[{ps.VERSION}]" in open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()


# ─────────── ইন্টার‍্যাক্টিভ / পাইপ মোড ───────────
def _pipe(stdin_text, tmp_path, *extra):
    return subprocess.run([*CMD, "--offline", "--quiet", "--evidence", str(tmp_path / "ev"), *extra],
                          input=stdin_text, capture_output=True, text=True, timeout=120, env=ENV)


def test_pipe_scans_each_line(tmp_path):
    p = _pipe("hxxps://bkash-verify[.]top/pin\nhttps://www.google.com\n", tmp_path)
    assert p.returncode == 0
    assert p.stdout.count("/100") == 2            # দুটি লাইন = দুটি স্ক্যান
    assert "খুব সন্দেহজনক" in p.stdout


def test_pipe_skips_quit_and_comments(tmp_path):
    p = _pipe("# comment\nhxxps://g00gle[.]top/login\nquit\n", tmp_path)
    assert p.stdout.count("/100") == 1            # শুধু লিংকটি, quit/comment বাদ


def test_no_args_empty_stdin_shows_help(tmp_path):
    p = _pipe("", tmp_path)
    assert "usage: phishscan" in p.stdout and p.returncode == 0


def test_no_args_interactive_help_available():
    # argparse-এ target ঐচ্ছিক — target ছাড়া চালালে এরর নয়
    p = subprocess.run([*CMD, "--help"], capture_output=True, text=True, env=ENV)
    assert "ইন্টার‍্যাক্টিভ মোড" in p.stdout and p.returncode == 0


def test_launcher_script_runs(tmp_path):
    launcher = os.path.join(ROOT, "phishscan.sh")
    assert os.access(launcher, os.X_OK), "phishscan.sh executable হওয়া উচিত"
    p = subprocess.run([launcher, "--version"], capture_output=True, text=True,
                       env=dict(os.environ, PYTHONPATH=ROOT))
    assert p.stdout.strip() == "PhishScan " + ps.VERSION


def test_interactive_loop(monkeypatch, tmp_path, capsys):
    """interactive() সরাসরি — input mock করে।"""
    from phishscan import cli
    feed = iter(["hxxps://g00gle[.]top/login", "", "quit"])
    monkeypatch.setattr("builtins.input", lambda *a: next(feed))
    args = SimpleNamespace(offline=True, no_fetch=True, screenshot=False, related=False,
                           max_links=10, quiet=True, evidence=str(tmp_path / "ev"), json=None, html=None)
    n = cli.interactive(args)
    out = capsys.readouterr().out
    assert n == 1                       # শুধু লিংকটি; খালি লাইন ও quit বাদ
    assert "/100" in out and "বিদায়" in out


def test_interactive_mode_question_switches_to_passive(monkeypatch, tmp_path, capsys):
    from phishscan import cli
    feed = iter(["n", "quit"])          # সক্রিয় মোডে প্রথমে মোড জিজ্ঞাসা
    monkeypatch.setattr("builtins.input", lambda *a: next(feed))
    args = SimpleNamespace(offline=False, no_fetch=False, screenshot=False, related=False,
                           max_links=10, quiet=True, evidence=str(tmp_path / "ev"), json=None, html=None)
    cli.interactive(args)
    assert args.no_fetch is True        # 'n' → নিরাপদ মোড


def test_interactive_eof_exits_cleanly(monkeypatch, tmp_path):
    from phishscan import cli
    def raise_eof(*a):
        raise EOFError
    monkeypatch.setattr("builtins.input", raise_eof)
    args = SimpleNamespace(offline=True, no_fetch=True, screenshot=False, related=False,
                           max_links=10, quiet=True, evidence=str(tmp_path / "ev"), json=None, html=None)
    assert cli.interactive(args) == 0   # ক্র্যাশ করবে না


def test_doctor_runs(tmp_path):
    p = subprocess.run([*CMD, "--doctor"], capture_output=True, text=True, env=ENV)
    assert "সেটআপ পরীক্ষা" in p.stdout
    assert "requests" in p.stdout
    assert "নকল bkash লিংক শনাক্ত" in p.stdout     # কার্যকারিতা পরীক্ষা চলেছে
    assert p.returncode in (0, 1)
