"""Page fetch, redirect chain, HTML content analysis, screenshot"""
import html as htmlmod
import os
import re
import shutil
import subprocess
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from .data import ALL_OFFICIAL, BRANDS, MAX_BODY, UA, URGENCY
from .util import brand_in, extract_urls, http_get, is_official, reg_domain, skeleton


MOBILE_UA = ("Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/131.0 Mobile Safari/537.36")


def fetch(url, rep, ua=None):
    chain = []
    cur = url
    body, final_ct = "", ""
    for _ in range(12):
        try:
            r = http_get(cur, allow_redirects=False, stream=True, verify=False,
                         headers={"User-Agent": ua or UA, "Accept-Language": "bn-BD,bn;q=0.9,en;q=0.8",
                                  "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
        except Exception as e:
            chain.append({"url": cur, "status": "ERROR", "detail": str(e)[:150]})
            break
        if r.status_code >= 400:
            entry0 = {"url": cur, "status": r.status_code, "server": r.headers.get("Server"),
                      "cf": r.headers.get("cf-mitigated") or ("cloudflare" if "cloudflare" in (r.headers.get("Server") or "").lower() else None)}
            try:
                peek = r.raw.read(20000, decode_content=True).decode("utf-8", "replace")
            except Exception:
                peek = ""
            r.close()
            if re.search(r"(?i)just a moment|cf-chl|challenge-platform|attention required", peek):
                entry0["note"] = "Cloudflare bot-check page"
            chain.append(entry0)
            return chain, peek, r.headers.get("Content-Type", "")
        entry = {"url": cur, "status": r.status_code, "server": r.headers.get("Server"),
                 "content_type": r.headers.get("Content-Type"), "ip": None}
        try:
            entry["ip"] = r.raw._connection.sock.getpeername()[0]
        except Exception:
            pass
        chain.append(entry)
        loc = r.headers.get("Location")
        if r.is_redirect and loc:
            cur = urljoin(cur, loc)
            r.close()
            continue
        data = b""
        for chunk in r.iter_content(65536):
            data += chunk
            if len(data) > MAX_BODY:
                break
        r.close()
        final_ct = r.headers.get("Content-Type", "")
        rep.info("HTTP headers (final page)", "Headers", {k: v for k, v in r.headers.items()
                                                     if k.lower() in ("server", "x-powered-by", "set-cookie", "content-type", "cf-ray", "x-served-by", "via", "content-disposition", "last-modified")})
        cd = r.headers.get("Content-Disposition", "")
        if "attachment" in cd.lower():
            rep.add(20, "Download", f"Page directly downloads a file: {cd}", "malware_delivery")
            return chain, data, final_ct
        enc = r.encoding or "utf-8"
        body = data.decode(enc, errors="replace") if "text" in final_ct or "html" in final_ct or "json" in final_ct or not final_ct else data
        # Follow meta refresh / JS redirect once
        if isinstance(body, str):
            m = re.search(r"""(?is)<meta[^>]+http-equiv=["']?refresh["']?[^>]+content=["']?\s*\d+\s*;\s*url=([^"'>\s]+)""", body)
            if m and len(chain) < 12:
                nxt = urljoin(cur, htmlmod.unescape(m.group(1)))
                if nxt != cur:
                    chain[-1]["note"] = "meta-refresh redirect"
                    cur = nxt
                    continue
            m = re.search(r"""(?is)(?:window\.|document\.)?location(?:\.href)?\s*=\s*["'](https?://[^"']+)["']""", body)
            if m and len(body) < 4000:
                chain[-1]["note"] = f"JavaScript redirect -> {m.group(1)}"
                rep.iocs["urls"].add(m.group(1))
        break
    return chain, body, final_ct


# ───────────────────────── HTML/page content analysis ─────────────────────────
class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms, self.inputs, self.scripts, self.links, self.iframes, self.anchors = [], [], [], [], [], []
        self.title, self._in_title, self._cur_a, self.text = "", False, None, []
        self._cur_form = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur_form = {"action": a.get("action", ""), "method": a.get("method", "get").lower(), "inputs": []}
            self.forms.append(self._cur_form)
        elif tag in ("input", "select", "textarea"):
            inp = {"type": a.get("type", "text").lower(), "name": (a.get("name", "") + " " + a.get("id", "") + " " + a.get("placeholder", "") + " " + a.get("autocomplete", "")).lower()}
            self.inputs.append(inp)
            if self._cur_form is not None:
                self._cur_form["inputs"].append(inp)
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag in ("a", "area"):
            self._cur_a = {"href": a.get("href", ""), "text": "", "download": "download" in a}
            self.anchors.append(self._cur_a)
            self.links.append(a.get("href", ""))
        elif tag in ("iframe", "frame", "embed", "object"):
            self.iframes.append(a.get("src") or a.get("data", ""))
        elif tag == "title":
            self._in_title = True
        elif tag == "link" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "img" and a.get("src"):
            self.links.append(a["src"])

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        if tag == "form":
            self._cur_form = None
        if tag in ("a", "area"):
            self._cur_a = None

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        if self._cur_a is not None:
            self._cur_a["text"] += data
        self.text.append(data)


def analyze_html(text, base_url, rep, label="Page"):
    if not isinstance(text, str) or not text.strip():
        return
    pp = PageParser()
    try:
        pp.feed(text)
    except Exception:
        pass
    base_host = (urlparse(base_url).hostname or "").lower() if base_url else ""
    plain = " ".join(pp.text).lower()
    sec = f"{label} content"
    rep.info(sec, "Title", pp.title.strip()[:150])
    rep.info(sec, "Forms count", len(pp.forms))
    rep.info(sec, "External scripts", list(dict.fromkeys(pp.scripts))[:15])
    rep.info(sec, "iframe", [i for i in pp.iframes if i][:10])

    # Brand mentions
    pw = any(i["type"] == "password" for i in pp.inputs)
    local = not base_url          # attachment/local HTML — no real organization sends login forms as files
    untrusted = local or (base_host and not is_official(base_host))
    mentioned = [b for b in BRANDS if brand_in(b, skeleton(pp.title)) or re.search(rf"\b{b}\b", plain)]
    if mentioned and ((base_host and not is_official(base_host)) or (local and pw)):
        rep.add(15, "Brand", f"Page shows '{', '.join(mentioned[:4])}' brand(s) but site is not official", "brand_impersonation")

    # Forms and inputs
    otp = [i for i in pp.inputs if re.search(r"otp|one.?time|verification.?code|\bpin\b|pin.?code|sms.?code|2fa|mfa", i["name"])]
    card = [i for i in pp.inputs if re.search(r"card|cvv|cvc|expir|cc-number|ccnum|security.?code", i["name"])]
    seed = re.search(r"(seed|recovery|secret|mnemonic) ?phrase|12.?word|24.?word|private.?key", plain)
    if pw:
        rep.add(25 if untrusted else 5, "Form", "Password input found — collecting login credentials" + (" (login form in a local HTML file!)" if local else ""), "credential_harvest")
    if otp:
        rep.add(25, "Form", "Requesting OTP/PIN — real organizations never ask for PIN on a website", "otp_payment")
    if card:
        rep.add(20, "Form", "Requesting card number/CVV", "otp_payment")
    if seed:
        rep.add(35, "Crypto", "Requesting wallet seed phrase/private key — 100% scam", "crypto_drainer")
    for f in pp.forms:
        act = f["action"].strip()
        full = urljoin(base_url or "", act) if act else (base_url or "")
        ah = (urlparse(full).hostname or "").lower()
        rep.info(sec, "Form action", f"{f['method'].upper()} -> {full or '(same page)'}")
        if ah and base_host and reg_domain(ah) != reg_domain(base_host):
            rep.add(20, "Exfil", f"Form data goes to a different domain: {ah}", "credential_harvest")
            rep.iocs["domains"].add(ah)
        if act.lower().startswith("mailto:"):
            rep.add(15, "Exfil", f"Form data sent via email: {act}")

    # Data exfiltration destinations
    for tok in set(re.findall(r"api\.telegram\.org/bot(\d{6,12}:[A-Za-z0-9_-]{30,})", text)):
        rep.add(30, "Exfil", f"Stolen data sent to Telegram bot (bot id {tok.split(':')[0]})", "credential_harvest")
        rep.iocs["telegram_bots"].add(tok)
        rep.abuse["abuse@telegram.org"] = f"Telegram bot {tok.split(':')[0]} collecting phishing data"
    for pat, name in [(r"discord(?:app)?\.com/api/webhooks/\d+/[\w-]+", "Discord webhook"),
                      (r"formspree\.io/f/\w+", "Formspree"), (r"submit-form\.com/\w+", "submit-form"),
                      (r"script\.google\.com/macros/s/[\w-]+", "Google Apps Script"),
                      (r"webhook\.site/[\w-]+", "webhook.site"), (r"api\.emailjs\.com", "EmailJS"),
                      (r"getform\.io/f/\w+", "Getform"), (r"formsubmit\.co/[\w@.-]+", "FormSubmit"),
                      (r"pipedream\.net", "Pipedream"), (r"workers\.dev", "Cloudflare Worker")]:
        for m in set(re.findall(pat, text)):
            rep.add(25, "Exfil", f"Data sent to {name}: {m[:90]}", "credential_harvest")
            rep.iocs["urls"].add("https://" + m)
    posts = set(re.findall(r"""(?:fetch|\$\.(?:post|ajax)|axios\.post|\.open\(\s*["']POST["']\s*,)\s*\(?\s*["']([^"']+)["']""", text))
    for u in posts:
        h = urlparse(urljoin(base_url or "", u)).hostname or ""
        rep.info(sec, "JS POST destination", u[:120])
        if h and base_host and reg_domain(h) != reg_domain(base_host):
            rep.add(12, "Exfil", f"JavaScript sends data to another domain: {h}")

    # Client-side tricks
    obf = []
    for pat, nm in [(r"\beval\s*\(", "eval()"), (r"\batob\s*\(", "atob()"), (r"\bunescape\s*\(", "unescape()"),
                    (r"String\.fromCharCode", "fromCharCode"), (r"_0x[a-f0-9]{4,6}", "javascript-obfuscator"),
                    (r"document\.write\s*\(\s*(unescape|atob|decodeURIComponent)", "document.write(decoded)"),
                    (r"[A-Za-z0-9+/]{3000,}={0,2}", "large base64 block")]:
        if re.search(pat, text):
            obf.append(nm)
    if obf:
        rep.add(min(20, 5 * len(obf)), "Obfuscation", f"Code hidden/encoded: {', '.join(obf)}")
    if re.search(r"new\s+Blob\s*\(", text) and re.search(r"createObjectURL|msSaveOrOpenBlob|\.download\s*=", text):
        rep.add(35, "Smuggling", "HTML smuggling: builds and downloads a file inside the browser", "html_smuggling")
    if re.search(r"clipboard\.writeText|execCommand\(\s*['\"]copy", text) and \
       re.search(r"(?i)powershell|mshta|cmd(\.exe)?\s*/c|curl\s+.*\|\s*(ba)?sh|iex\s*\(|invoke-expression|bitsadmin|certutil", text):
        rep.add(45, "ClickFix", "Copies malicious command to clipboard — ClickFix attack. Never paste into Win+R/Terminal", "clickfix")
    elif re.search(r"(?i)(windows\s*(key)?\s*\+\s*r|win\s*\+\s*r|ctrl\s*\+\s*v.*enter|press.*windows.*r)", plain) and re.search(r"(?i)verif|captcha|robot|human", plain):
        rep.add(30, "ClickFix", "Page asks to press Win+R and paste — fake CAPTCHA", "clickfix")
    if re.search(r"eth_requestAccounts|ethereum\.request|setApprovalForAll|walletconnect|seaport|increaseAllowance|\bpermit\s*\(", text, re.I):
        rep.add(20, "Crypto", "Wallet connect/approval code — may be a crypto drainer", "crypto_drainer")
    for w in set(re.findall(r"\b(0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,60}|T[A-Za-z1-9]{33})\b", text)):
        rep.iocs["wallets"].add(w)
    anti = []
    if re.search(r"contextmenu", text) and re.search(r"preventDefault|return\s+false", text):
        anti.append("Right-click disabled")
    if re.search(r"navigator\.webdriver|headless|phantom|selenium", text, re.I):
        anti.append("Bot/scanner detection")
    if re.search(r"devtools|debugger;", text):
        anti.append("DevTools detection/block")
    if re.search(r"ipapi|ip-api\.com|ipinfo\.io|geoplugin|api\.ipify", text):
        anti.append("Visitor IP/country check (cloaking)")
    if re.search(r"(?i)antibot|blocker\.php|bot_check|crawlerdetect", text):
        anti.append("Anti-bot kit")
    if anti:
        rep.add(min(20, 6 * len(anti)), "Evasion", f"Analysis evasion techniques: {', '.join(anti)}")

    # Browser-in-the-Browser / AiTM hints
    if base_host and not is_official(base_host):
        off_refs = {reg_domain(urlparse(urljoin(base_url, link)).hostname or "") for link in pp.links + pp.scripts}
        off_refs = {d for d in off_refs if d in ALL_OFFICIAL}
        if re.search(r"(accounts\.google\.com|login\.microsoftonline\.com|facebook\.com/login)", plain) and pw:
            rep.add(15, "BitB", "Fake login window inside the page (shows real-looking URL) — Browser-in-the-Browser", "credential_harvest")
        if len(off_refs) >= 2 and pw:
            rep.add(10, "AiTM", f"Loads resources from official sites ({', '.join(sorted(off_refs)[:4])}) but login is on a different domain — may be a clone or reverse proxy", "aitm_proxy")

    # Download links
    for a in pp.anchors:
        href = a["href"]
        ext = os.path.splitext(urlparse(href).path.lower())[1]
        if ext in {".apk", ".exe", ".msi", ".scr", ".zip", ".rar", ".iso", ".js", ".hta", ".lnk", ".bat", ".vbs", ".jar", ".dmg"}:
            rep.add(20, "Download", f"Download link: {href[:100]}", "android_stealer" if ext == ".apk" else "malware_delivery")
            rep.iocs["urls"].add(urljoin(base_url or "", href))

    # Link text vs actual destination (especially in emails)
    for a in pp.anchors:
        t = a["text"].strip().lower()
        h = (urlparse(a["href"]).hostname or "").lower()
        m = re.fullmatch(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/?#]\S*)?", t)
        if m and h and reg_domain(m.group(1)) != reg_domain(h):
            rep.add(25, "Link", f"Link text shows '{m.group(1)}' but actually goes to '{h}'", "brand_impersonation")

    # Scam language
    urg = [w for w in URGENCY if w in plain]
    if urg:
        rep.add(min(12, 3 * len(urg)), "Social", f"Urgency/lure language: {', '.join(urg[:6])}")
    if re.search(r"(bkash|nagad|rocket)", plain) and re.search(r"(pin|otp|cash ?out|send money)", plain):
        rep.add(15, "Social", "Mobile banking + PIN/OTP mentioned — common scam pattern in Bangladesh", "otp_payment")
    # Phishing kit signs
    kit = re.findall(r"""(?i)["'/]((?:next|post|login|send|mail|verify|process|submit|action|result|res|rezult|antibot)\w*\.php)""", text)
    if kit:
        rep.info(sec, "Server-side scripts", sorted(set(kit))[:10])
        if pw or otp or card:
            rep.add(8, "Kit", f"PHP scripts resembling a phishing kit: {', '.join(sorted(set(kit))[:5])}")
    gen = re.search(r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)""", text, re.I)
    if gen:
        rep.info(sec, "Generator", gen.group(1))
    # Collect other suspicious URLs
    for u in extract_urls(text)[:200]:
        h = urlparse(u).hostname
        if h and not is_official(h):
            rep.iocs["domains"].add(h.lower())


def screenshot(url, outdir, rep):
    br = next((shutil.which(b) for b in ("chromium", "chromium-browser", "google-chrome") if shutil.which(b)), None)
    if not br:
        rep.info("Screenshot", "Status", "chromium not found (sudo apt install chromium)")
        return
    path = os.path.join(outdir, "screenshot.png")
    try:
        subprocess.run([br, "--headless=new", "--disable-gpu", "--no-sandbox", "--incognito",
                        "--disable-extensions", "--window-size=1366,900", f"--user-agent={UA}",
                        f"--screenshot={path}", url], capture_output=True, timeout=45)
        if os.path.exists(path):
            rep.info("Screenshot", "File", path)
        else:
            rep.info("Screenshot", "Status", f"Could not capture ({os.path.basename(br)}) — on Kali: sudo apt install chromium")
    except Exception as e:
        rep.info("Screenshot", "Error", str(e)[:100])
