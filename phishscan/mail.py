"""Email (.eml / .msg) analysis"""
import email
import email.message
import os
import re
import shutil
import tempfile
from email import policy
from urllib.parse import urlparse
from .data import BRANDS, URGENCY
from .infra import ip_intel
from .urlcheck import analyze_url_static
from .util import brand_in, extract_urls, is_official, is_public_ip, reg_domain, skeleton
from .web import analyze_html
from . import files, scanner  # circular dependency: use module.function at call time


def scan_email(raw, rep, args):
    msg = email.message_from_bytes(raw, policy=policy.default)
    sec = "Email headers"
    for h in ("From", "To", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID", "X-Mailer", "User-Agent", "X-Originating-IP", "X-Sender-IP"):
        if msg.get(h):
            rep.info(sec, h, str(msg.get(h))[:200])

    def addr_domain(v):
        m = re.search(r"@([\w.-]+)", v or "")
        return m.group(1).lower().rstrip(">") if m else ""

    frm = str(msg.get("From", ""))
    fdom = addr_domain(frm)
    disp = frm.split("<")[0].strip().strip('"').lower()
    for e in re.findall(r"[\w.+-]+@[\w-]+\.[\w.-]+", frm + " " + str(msg.get("Reply-To", "")) + " " + str(msg.get("Return-Path", ""))):
        rep.iocs["emails"].add(e.strip("<>").lower())
    rt = addr_domain(str(msg.get("Reply-To", "")))
    rp = addr_domain(str(msg.get("Return-Path", "")))
    if rt and fdom and reg_domain(rt) != reg_domain(fdom):
        rep.add(20, "Email", f"Reply-To ({rt}) and From ({fdom}) are different — replies go to the scammer", "email_spoof")
    if rp and fdom and reg_domain(rp) != reg_domain(fdom):
        rep.add(6, "Email", f"Return-Path ({rp}) and From ({fdom}) are different")
    for brand, offs in BRANDS.items():
        if brand_in(brand, skeleton(disp)) and fdom and reg_domain(fdom) not in offs:
            rep.add(25, "Email", f"Display name shows '{brand}' but sent from '{fdom}'", "email_spoof")
            break
    if fdom in ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com") and any(b in disp for b in ("bank", "support", "security", "team", "service", "admin")):
        rep.add(15, "Email", f"Sent from free email ({fdom}) using an organization's name", "email_spoof")
    if fdom:
        analyze_url_static("https://" + fdom, rep, "Sender domain")

    # SPF / DKIM / DMARC
    auth = " ".join(str(v) for v in (msg.get_all("Authentication-Results") or []) + (msg.get_all("ARC-Authentication-Results") or []))
    rspf = " ".join(str(v) for v in (msg.get_all("Received-SPF") or []))
    sec2 = "Authentication (SPF/DKIM/DMARC)"
    for mech in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{mech}=(\w+)", auth, re.I)
        val = m.group(1).lower() if m else None
        if mech == "spf" and not val and rspf:
            val = rspf.split()[0].lower()
        rep.info(sec2, mech.upper(), val or "Not found in headers")
        if val in ("fail", "softfail", "permerror"):
            rep.add(20 if mech != "spf" or val == "fail" else 10, "Email", f"{mech.upper()} = {val} — sender not verified (may be forged)", "email_spoof")
        elif val == "none" and mech == "dmarc":
            rep.add(5, "Email", "No DMARC — domain can be easily spoofed")

    # Received chain -> origin
    recs = msg.get_all("Received") or []
    hops = []
    for r in recs:
        r = " ".join(str(r).split())
        ips = [ip for ip in re.findall(r"\[?(\d{1,3}(?:\.\d{1,3}){3})\]?", r) if is_public_ip(ip)]
        ips += [ip for ip in re.findall(r"\[(?:IPv6:)?([0-9a-fA-F:]{6,})\]", r) if is_public_ip(ip)]
        fm = re.search(r"from\s+(\S+)", r)
        hops.append({"from": fm.group(1) if fm else "?", "ips": ips, "raw": r[:220]})
    for i, hop in enumerate(reversed(hops)):
        rep.info("Email route (first -> last)", f"Hop {i + 1}", f"{hop['from']}  {', '.join(hop['ips'])}")
    origin = None
    for v in ("X-Originating-IP", "X-Sender-IP"):
        if msg.get(v):
            m = re.search(r"[\d.]{7,15}", str(msg.get(v)))
            if m and is_public_ip(m.group(0)):
                origin = m.group(0)
    if not origin:
        for hop in reversed(hops):
            if hop["ips"]:
                origin = hop["ips"][0]
                break
    if origin:
        rep.info("Email origin", "Probable first IP", origin)
        rep.iocs["ips"].add(origin)
        if not args.offline:
            info = ip_intel(origin, rep)
            rep.infra.append({"host": "Email sending server", "ips": [info]})
            if fdom.endswith(("gmail.com", "outlook.com", "hotmail.com", "yahoo.com")):
                rep.info("Email origin", "Note", "Free email services hide the sender's real IP — this is the service's server. The real person's IP can only be obtained by law enforcement via legal request")

    # Body
    subj = str(msg.get("Subject", "")).lower()
    urg = [w for w in URGENCY if w in subj]
    if urg:
        rep.add(min(10, 4 * len(urg)), "Social", f"Urgency/lure in subject: {', '.join(urg)}")
    html_body, text_body = "", ""
    for part in msg.walk():
        ctype = part.get_content_type()
        fname = part.get_filename()
        if part.is_multipart():
            continue
        if fname or (part.get_content_disposition() == "attachment"):
            data = part.get_payload(decode=True) or b""
            rep.info("Attachment", fname or "(unnamed)", f"{ctype}, {len(data)} bytes")
            files.analyze_bytes(fname or "attachment.bin", data, rep, args, depth=1)
            continue
        try:
            content = part.get_content()
        except Exception:
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
        if ctype == "text/html":
            html_body += content
        elif ctype == "text/plain":
            text_body += content
        elif ctype.startswith("image/"):
            files.analyze_bytes(fname or "inline_image", part.get_payload(decode=True) or b"", rep, args, depth=1)
    if html_body:
        analyze_html(html_body, "", rep, "Email body")
    elif text_body:
        plain = text_body.lower()
        urg = [w for w in URGENCY if w in plain]
        if urg:
            rep.add(min(12, 3 * len(urg)), "Social", f"Urgency/lure language: {', '.join(urg[:6])}")
    urls = extract_urls(html_body + " " + text_body)
    urls += [u for u in re.findall(r"""href=["']([^"']+)""", html_body, re.I) if u.startswith("http") and u not in urls]
    rep.info("Email links", "Total", len(urls))
    sus = [u for u in urls if not is_official(urlparse(u).hostname or "")]
    for i, u in enumerate(sus[:args.max_links]):
        if i < 3 and not args.no_fetch:
            scanner.scan_url(u, rep, args, depth=1, label=f"Email link {i + 1}")
        else:
            analyze_url_static(u, rep, f"Email link {i + 1}")


def scan_msg(d, rep, args):
    """Outlook .msg -> convert to .eml and run the same analysis (pip install extract-msg)"""
    try:
        import extract_msg
    except ImportError:
        rep.info("Outlook .msg", "Note", "extract-msg not found: pip install extract-msg — or save as .eml from Outlook")
        return
    tmp = tempfile.mkdtemp(prefix="phishscan_msg_")
    try:
        path = os.path.join(tmp, "m.msg")
        with open(path, "wb") as f:
            f.write(d)
        m = extract_msg.Message(path)
        em = email.message.EmailMessage()
        hdr = m.header
        def clean(v):
            return " ".join(str(v).split())
        # Single-value headers (joined with comma if multiple), rest can appear multiple times
        for k in ("From", "To", "Cc", "Reply-To", "Return-Path", "Subject", "Date", "Message-ID",
                  "X-Mailer", "X-Originating-IP"):
            vals = (hdr.get_all(k) or []) if hdr else []
            if vals:
                try:
                    em[k] = ", ".join(clean(v) for v in vals) if k in ("To", "Cc") else clean(vals[0])
                except Exception:
                    pass
        for k in ("Received", "Authentication-Results", "Received-SPF", "ARC-Authentication-Results"):
            for v in (hdr.get_all(k) or []) if hdr else []:
                try:
                    em[k] = clean(v)
                except Exception:
                    pass
        if not em["From"] and m.sender:
            em["From"] = m.sender
        if not em["Subject"] and m.subject:
            em["Subject"] = m.subject
        em.set_content(m.body or "")
        hb = m.htmlBody
        if hb:
            em.add_alternative(hb.decode("utf-8", "replace") if isinstance(hb, bytes) else hb, subtype="html")
        for a in m.attachments:
            data = getattr(a, "data", None)
            if isinstance(data, bytes):
                em.add_attachment(data, maintype="application", subtype="octet-stream",
                                  filename=getattr(a, "longFilename", None) or getattr(a, "shortFilename", None) or "attachment.bin")
        m.close()
        scan_email(bytes(em), rep, args)
    except Exception as e:
        rep.info("Outlook .msg", "Error", str(e)[:150])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
