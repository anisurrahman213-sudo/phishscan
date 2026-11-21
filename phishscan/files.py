"""File analysis: image/QR, PDF, Office, APK, ZIP, HTML, script"""
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
import zlib
from urllib.parse import urlparse
from .data import APK_DANGER_PERMS, DANGER_EXT
from .reputation import vt_hash
from .urlcheck import analyze_url_static
from .util import extract_urls, hashes, is_official
from .web import analyze_html
from . import mail, scanner  # circular dependency: use module.function at call time


def magic_type(d, name):
    n = name.lower()
    if d[:4] == b"%PDF" or b"%PDF" in d[:1024]:
        return "pdf"
    if d[:2] == b"MZ":
        return "pe"
    if d[:4] == b"\x7fELF":
        return "elf"
    if d[:4] == b"\xd0\xcf\x11\xe0":
        return "ole"
    if d[:4] == b"PK\x03\x04":
        return "zip"
    if d[:8] == b"\x89PNG\r\n\x1a\n" or d[:3] == b"\xff\xd8\xff" or d[:4] in (b"GIF8", b"RIFF") or d[:2] == b"BM":
        return "image"
    if d[:4] == b"L\x00\x00\x00":
        return "lnk"
    if len(d) > 0x8006 and d[0x8001:0x8006] == b"CD001":
        return "iso"
    if d[:5] == b"{\\rtf":
        return "rtf"
    if d[:4] in (b"Rar!", b"7z\xbc\xaf") or d[:2] == b"\x1f\x8b":
        return "archive"
    head = d[:4096].lower()
    if n.endswith(".eml") or re.match(rb"^(received|from|return-path|delivered-to|x-[\w-]+|mime-version|message-id|date|subject|to|arc-[\w-]+|dkim-signature|authentication-results)\s*:", head):
        if b"\nfrom:" in head or head.startswith(b"from:") or n.endswith(".eml"):
            return "eml"
    if b"<svg" in head:
        return "svg"
    if b"<html" in head or b"<!doctype html" in head or b"<script" in head or n.endswith((".htm", ".html", ".shtml")):
        return "html"
    if n.endswith((".js", ".vbs", ".ps1", ".hta", ".bat", ".cmd", ".wsf", ".sh")):
        return "script"
    return "unknown"


def decode_qr(path):
    out = []
    try:
        from pyzbar.pyzbar import decode
        from PIL import Image
        for r in decode(Image.open(path)):
            out.append(r.data.decode("utf-8", "replace"))
    except Exception:
        pass
    if not out and shutil.which("zbarimg"):
        try:
            res = subprocess.run(["zbarimg", "--raw", "-q", path], capture_output=True, text=True, timeout=30)
            out = [line for line in res.stdout.splitlines() if line.strip()]
        except Exception:
            pass
    if not out:
        try:
            import cv2
            val, *_ = cv2.QRCodeDetector().detectAndDecode(cv2.imread(path))
            if val:
                out = [val]
        except Exception:
            pass
    return out


def exif_data(path):
    if shutil.which("exiftool"):
        try:
            r = subprocess.run(["exiftool", "-j", "-n", path], capture_output=True, text=True, timeout=30)
            d = json.loads(r.stdout)[0]
            keep = ("FileType", "ImageSize", "Make", "Model", "Software", "CreateDate", "DateTimeOriginal",
                    "ModifyDate", "GPSLatitude", "GPSLongitude", "Artist", "Author", "Creator", "Producer",
                    "XPAuthor", "OwnerName", "SerialNumber", "LensModel", "Comment", "UserComment", "HostComputer")
            return {k: d[k] for k in keep if k in d}
        except Exception:
            pass
    try:
        from PIL import Image, ExifTags
        ex = Image.open(path).getexif()
        return {ExifTags.TAGS.get(k, str(k)): str(v)[:100] for k, v in ex.items()}
    except Exception:
        return {}


def analyze_pdf(d, rep, args, depth):
    sec = "PDF analysis"
    blobs = [d]
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", d, re.S):
        try:
            blobs.append(zlib.decompress(m.group(1)))
        except Exception:
            pass
    allb = b"\n".join(blobs)
    flags = {}
    for k in (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch", b"/EmbeddedFile", b"/SubmitForm", b"/AcroForm", b"/URI", b"/RichMedia", b"/XFA", b"/ObjStm"):
        c = len(re.findall(re.escape(k) + rb"(?![A-Za-z])", allb))
        if c:
            flags[k.decode()] = c
    rep.info(sec, "Keywords", flags or "None found")
    if flags.get("/JavaScript") or flags.get("/JS"):
        rep.add(25, "PDF", "JavaScript found inside the PDF", "malware_delivery")
    if flags.get("/Launch"):
        rep.add(35, "PDF", "PDF can launch another program (/Launch)", "malware_delivery")
    if flags.get("/EmbeddedFile"):
        rep.add(20, "PDF", "Hidden file embedded inside the PDF", "malware_delivery")
    if flags.get("/OpenAction") and (flags.get("/JavaScript") or flags.get("/URI")):
        rep.add(10, "PDF", "Auto-action on open (/OpenAction)")
    if flags.get("/SubmitForm"):
        rep.add(15, "PDF", "PDF sends form data externally (/SubmitForm)", "credential_harvest")
    uris = list(dict.fromkeys(u.decode("latin-1") for u in re.findall(rb"/URI\s*\(([^)]+)\)", allb)))
    uris += [u for u in extract_urls(allb.decode("latin-1")) if u not in uris]
    uris = [u for u in uris if not re.search(r"(adobe\.com|w3\.org|purl\.org|iptc\.org|ns\.adobe|aiim\.org|npes\.org|color\.org)", u)]
    rep.info(sec, "Links", uris[:20])
    for i, u in enumerate(uris[:args.max_links]):
        if u.startswith("http"):
            if i < 2 and not args.no_fetch and depth < 2:
                scanner.scan_url(u, rep, args, depth + 1, f"PDF link {i + 1}")
            else:
                analyze_url_static(u, rep, f"PDF link {i + 1}")
    if uris and len(re.findall(rb"/Type\s*/Page[^s]", d)) <= 2:
        rep.add(8, "PDF", "Small PDF whose main purpose is to get you to click a link — common phishing PDF pattern")


def analyze_zip(d, name, rep, args, depth):
    sec = f"Archive: {name}"
    try:
        z = zipfile.ZipFile(io.BytesIO(d))
        names = z.namelist()
    except Exception as e:
        rep.info(sec, "Error", str(e)[:100])
        return
    rep.info(sec, "File count", len(names))
    rep.info(sec, "File list", names[:30])
    if any(i.flag_bits & 0x1 for i in z.infolist()):
        rep.add(15, "Archive", "Password-protected archive — antivirus evasion technique", "malware_delivery")
    # APK
    if "AndroidManifest.xml" in names and "classes.dex" in names:
        rep.add(15, "APK", "This is an Android app (APK) — apps from outside Play Store are dangerous", "android_stealer")
        analyze_apk(z, d, rep)
        return
    # Office OOXML
    if "[Content_Types].xml" in names:
        if any(n.lower().endswith("vbaproject.bin") for n in names):
            rep.add(30, "Office", "Office file contains macros (VBA)", "malware_delivery")
            analyze_ole_macros(d, rep)
        for n in names:
            if n.endswith(".rels"):
                rel = z.read(n).decode("utf-8", "replace")
                for t in re.findall(r'Target="([^"]+)"[^>]*TargetMode="External"', rel):
                    if re.search(r"(?i)attachedTemplate|oleObject|\.dotm|\.rtf|\.html?|frame", rel) and t.startswith("http"):
                        rep.add(30, "Office", f"Loads remote template/object (template injection): {t[:100]}", "malware_delivery")
                    if t.startswith("http"):
                        rep.iocs["urls"].add(t)
        if any(n.lower().endswith(".bin") and "embeddings" in n.lower() for n in names):
            rep.add(12, "Office", "Contains embedded OLE object")
        return
    # Regular archive
    for n in names[:100]:
        ln = n.lower()
        base, ext = os.path.splitext(ln)
        if ext in DANGER_EXT:
            rep.add(25, "Archive", f"Dangerous file in archive: {n}", "malware_delivery")
        if re.search(r"\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|lnk|hta|bat|cmd)$", ln):
            rep.add(30, "Archive", f"Double extension trick: {n}", "malware_delivery")
    if depth < 3:
        for n in names[:10]:
            info = z.getinfo(n)
            if info.file_size < 20 * 1024 * 1024 and not (info.flag_bits & 0x1) and not n.endswith("/"):
                try:
                    analyze_bytes(n, z.read(n), rep, args, depth + 1)
                except Exception:
                    pass


def analyze_apk(z, d, rep):
    sec = "APK analysis"
    perms = set()
    # Method 1: androguard (if available) — package name, app name, permissions
    try:
        try:
            from loguru import logger as _lg
            _lg.remove()
        except Exception:
            pass
        try:
            from androguard.core.apk import APK          # androguard >= 4
        except ImportError:
            from androguard.core.bytecodes.apk import APK  # androguard 3.x
        a = APK(d, raw=True)
        rep.info(sec, "Package", a.get_package())
        rep.info(sec, "App name", a.get_app_name())
        perms |= set(a.get_permissions() or [])
    except Exception:
        pass
    # Method 2: search binary manifest directly — works even on broken/obfuscated APKs
    try:
        man = z.read("AndroidManifest.xml")
        for p in APK_DANGER_PERMS:
            full = "android.permission." + p
            if full.encode() in man or full.encode("utf-16le") in man or p.encode("utf-16le") in man:
                perms.add(full)
    except Exception:
        pass
    perms = sorted(perms)
    hits = [(p, APK_DANGER_PERMS[p.split(".")[-1]]) for p in perms if p.split(".")[-1] in APK_DANGER_PERMS]
    for p, why in hits:
        rep.info(sec, p.split(".")[-1], why)
    if any(p.split(".")[-1] in ("RECEIVE_SMS", "READ_SMS", "BIND_NOTIFICATION_LISTENER_SERVICE") for p, _ in hits):
        rep.add(30, "APK", "App can read SMS/notifications — may be built for OTP theft", "android_stealer")
    if any(p.endswith("BIND_ACCESSIBILITY_SERVICE") for p, _ in hits):
        rep.add(25, "APK", "Accessibility permission — primary weapon of banking trojans", "android_stealer")
    if len(hits) >= 5:
        rep.add(15, "APK", f"{len(hits)} dangerous permissions")
    # Search dex for servers/bots
    try:
        dex = b"".join(z.read(n) for n in z.namelist() if n.endswith(".dex"))[:40 * 1024 * 1024]
        txt = dex.decode("latin-1")
        bots = set(re.findall(r"api\.telegram\.org/bot(\d{6,12}:[A-Za-z0-9_-]{30,})", txt)) | set(re.findall(r"\b(\d{8,11}:AA[A-Za-z0-9_-]{33})\b", txt))
        for b in bots:
            rep.add(30, "APK", f"App sends stolen SMS to Telegram bot (bot {b.split(':')[0]})", "android_stealer")
            rep.iocs["telegram_bots"].add(b)
            rep.abuse["abuse@telegram.org"] = f"Telegram bot {b.split(':')[0]} used by malicious app"
        servers = sorted({u for u in extract_urls(txt) if not is_official(urlparse(u).hostname or "") and not re.search(r"(android|schemas|w3\.org|apache\.org|googleapis|github\.com/square|kotlinlang|jetbrains|xmlpull|json\.org)", u)})
        if servers:
            rep.info(sec, "Servers/URLs in code", servers[:20])
            for s in servers[:20]:
                rep.iocs["urls"].add(s)
    except Exception:
        pass


def analyze_ole_macros(d, rep):
    try:
        from oletools.olevba import VBA_Parser
        vp = VBA_Parser("file", data=d)
        if vp.detect_vba_macros():
            res = vp.analyze_macros()
            auto = [k for t, k, _ in res if t == "AutoExec"]
            susp = [k for t, k, _ in res if t == "Suspicious"]
            iocs = [k for t, k, _ in res if t == "IOC"]
            rep.info("Macro (olevba)", "AutoExec", auto)
            rep.info("Macro (olevba)", "Suspicious", susp[:15])
            rep.info("Macro (olevba)", "IOC", iocs[:15])
            if auto:
                rep.add(20, "Macro", f"Macro runs automatically on open ({', '.join(auto[:3])})", "malware_delivery")
            if susp:
                rep.add(min(25, 5 * len(susp)), "Macro", f"Suspicious macro actions: {', '.join(susp[:5])}", "malware_delivery")
            for i in iocs:
                if i.startswith("http"):
                    rep.iocs["urls"].add(i)
        vp.close()
    except ImportError:
        if re.search(rb"Attribute VB_|VBA|AutoOpen|Document_Open|Workbook_Open", d):
            rep.add(25, "Macro", "File shows signs of VBA macros (for details: pip install oletools)", "malware_delivery")
    except Exception:
        pass


def analyze_bytes(name, d, rep, args, depth=0):
    if depth > 3 or not d:
        return
    h = hashes(d)
    rep.iocs["hashes"].add(h["sha256"])
    t = magic_type(d, name)
    sec = f"File: {name}"
    rep.info(sec, "Size", f"{len(d)} bytes")
    rep.info(sec, "Actual type", t)
    rep.info(sec, "SHA256", h["sha256"])
    rep.info(sec, "MD5", h["md5"])
    ext = os.path.splitext(name.lower())[1]
    if re.search(r"\.(pdf|docx?|xlsx?|jpe?g|png|txt|mp4)\s*\.(exe|scr|js|vbs|lnk|hta|bat|cmd|html?|svg|iso|zip)$", name.lower()):
        rep.add(30, "File", f"Double extension trick: '{name}'", "malware_delivery")
    if "‮" in name:
        rep.add(35, "File", "RTLO character in filename — extension appears reversed", "malware_delivery")
    mismatch = {"pdf": ".pdf", "image": (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp")}
    if t == "pe" and ext not in (".exe", ".dll", ".scr", ".sys", ".com"):
        rep.add(35, "File", f"Actually a Windows program (EXE) but named '{ext}'", "malware_delivery")
    elif t in mismatch and ext and not ext.endswith(mismatch[t]) and ext not in (".bin", ".dat", ""):
        rep.add(10, "File", f"Extension ({ext}) does not match actual type ({t})")
    if not args.offline:
        vt_hash(h["sha256"], rep)

    tmpdir = tempfile.mkdtemp(prefix="phishscan_")
    path = os.path.join(tmpdir, "sample" + (ext if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".pdf") else ".bin"))
    with open(path, "wb") as f:
        f.write(d)
    try:
        if t == "eml":
            mail.scan_email(d, rep, args)
        elif t == "image":
            ex = exif_data(path)
            if ex:
                for k, v in ex.items():
                    rep.info(f"Image metadata (EXIF): {name}", k, v)
                if "GPSLatitude" in ex and "GPSLongitude" in ex:
                    rep.info(f"Image metadata (EXIF): {name}", "Map", f"https://maps.google.com/?q={ex['GPSLatitude']},{ex['GPSLongitude']}")
            qrs = decode_qr(path)
            for q in qrs:
                rep.info(f"QR code: {name}", "Decoded", q)
                rep.add(10, "QR", "QR code found in image — can hide links to bypass scanners", "quishing")
                if re.match(r"(?i)^(https?://|www\.)", q):
                    scanner.scan_url(q, rep, args, depth + 1, "QR link")
                elif q.lower().startswith(("upi:", "bitcoin:", "ethereum:")):
                    rep.add(15, "QR", f"Payment/wallet address in QR: {q[:80]}", "otp_payment")
        elif t == "pdf":
            analyze_pdf(d, rep, args, depth)
        elif t == "zip":
            analyze_zip(d, name, rep, args, depth)
        elif t == "ole" and (ext == ".msg" or b"_\x00_\x00s\x00u\x00b\x00s\x00t\x00g" in d[:200000]):
            mail.scan_msg(d, rep, args)
        elif t == "ole":
            rep.info(sec, "Note", "Old Office format (doc/xls) — checking for macros")
            analyze_ole_macros(d, rep)
        elif t in ("html", "svg"):
            txt = d.decode("utf-8", "replace")
            if ext in (".html", ".htm", ".shtml", ".svg") and depth >= 1:
                rep.add(15, "File", f"{ext} file as attachment — common method for local phishing page or smuggling", "credential_harvest")
            if t == "svg" and re.search(r"<script|onload=|javascript:|<foreignObject", txt, re.I):
                rep.add(25, "SVG", "Script/HTML inside image (SVG) file — SVG phishing", "malware_delivery")
            analyze_html(txt, "", rep, f"{name}")
            for i, u in enumerate([u for u in extract_urls(txt) if not is_official(urlparse(u).hostname or "")][:args.max_links]):
                analyze_url_static(u, rep, f"{name} link {i + 1}")
        elif t in ("pe", "elf"):
            rep.add(35, "File", f"Executable program ({t.upper()}) — never run this", "malware_delivery")
            strs = re.findall(rb"[ -~]{6,}", d[:8 * 1024 * 1024])
            urls = sorted({u for s in strs for u in extract_urls(s.decode())})[:20]
            rep.info(sec, "Embedded URLs", urls)
        elif t in ("lnk", "iso", "rtf"):
            w = {"lnk": 35, "iso": 25, "rtf": 15}[t]
            rep.add(w, "File", f"{t.upper()} file — commonly used to spread malware", "malware_delivery")
            txt = d.decode("latin-1")
            for pat in (r"powershell[^\x00]{0,200}", r"cmd(\.exe)?\s*/c[^\x00]{0,200}", r"mshta[^\x00]{0,150}"):
                for m in re.findall(pat, txt, re.I)[:3]:
                    rep.info(sec, "Command", m[:200])
        elif t == "script":
            txt = d.decode("utf-8", "replace")
            rep.add(30, "File", f"Script file ({ext}) — runs on double-click", "malware_delivery")
            rep.info(sec, "Embedded URLs", extract_urls(txt)[:15])
            if re.search(r"(?i)frombase64string|-enc\w*\s+[A-Za-z0-9+/=]{40,}|iex|downloadstring|invoke-webrequest|wscript\.shell|activexobject", txt):
                rep.add(15, "Script", "Code for downloading/running encoded commands")
        elif t == "archive":
            rep.info(sec, "Note", "RAR/7z/GZ — extract and scan inner files separately (7z x file -oout)")
        else:
            txt = d.decode("utf-8", "replace")
            us = extract_urls(txt)
            if us:
                rep.info(sec, "Embedded URLs", us[:15])
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
