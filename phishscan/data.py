"""Brands, domain lists, attack types — all static data (extendable via brands.json)"""


UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/131.0 Safari/537.36")
TIMEOUT = 12
MAX_BODY = 3 * 1024 * 1024


BRANDS = {
    "paypal": ["paypal.com", "paypal.me", "paypalobjects.com", "paypal-community.com"],
    "facebook": ["facebook.com", "fb.com", "fb.me", "facebook.net", "messenger.com", "meta.com", "fbcdn.net", "facebookmail.com", "fb.watch"],
    "instagram": ["instagram.com", "cdninstagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net", "wa.me"],
    "google": ["google.com", "gmail.com", "youtube.com", "goo.gl", "googleusercontent.com", "gstatic.com", "google.com.bd", "googleapis.com", "forms.gle", "googlemail.com", "youtu.be", "withgoogle.com", "google.co.in", "google.co.uk"],
    "gmail": ["gmail.com", "google.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "office365.com", "sharepoint.com", "onedrive.com", "msn.com", "azure.com", "windows.net", "msauth.net", "msftauth.net"],
    "outlook": ["outlook.com", "live.com", "office.com", "microsoft.com", "microsoftonline.com"],
    "office365": ["office.com", "office365.com", "microsoft.com", "microsoftonline.com"],
    "onedrive": ["onedrive.com", "live.com", "microsoft.com", "sharepoint.com"],
    "apple": ["apple.com", "icloud.com", "mzstatic.com", "apple.news"],
    "icloud": ["icloud.com", "apple.com"],
    "amazon": ["amazon.com", "amazon.in", "amazonaws.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.co.jp", "media-amazon.com", "aws.amazon.com", "amazon.ae"],
    "netflix": ["netflix.com", "nflxext.com"],
    "linkedin": ["linkedin.com", "lnkd.in", "licdn.com"],
    "telegram": ["telegram.org", "t.me", "telegram.me"],
    "yahoo": ["yahoo.com"],
    "dropbox": ["dropbox.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "adobe": ["adobe.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"],
    "binance": ["binance.com"],
    "metamask": ["metamask.io"],
    "coinbase": ["coinbase.com"],
    "trustwallet": ["trustwallet.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    # Bangladesh
    "bkash": ["bkash.com"],
    "nagad": ["nagad.com.bd"],
    "dbbl": ["dutchbanglabank.com"],
    "bracbank": ["bracbank.com"],
    "citybank": ["thecitybank.com"],
    "upay": ["upaybd.com"],
    "daraz": ["daraz.com.bd", "daraz.com"],
    "pathao": ["pathao.com"],
    "foodpanda": ["foodpanda.com.bd", "foodpanda.com"],
    "grameenphone": ["grameenphone.com"],
    "banglalink": ["banglalink.net"],
    "sonalibank": ["sonalibank.com.bd"],
    "islamibank": ["islamibankbd.com"],
}
ALL_OFFICIAL = {d for v in BRANDS.values() for d in v}
# For typosquat comparison — exclude common English words (office/apple/live etc. match other real sites)
_GENERIC = {"office", "outlook", "apple", "steam", "live", "adobe", "msn", "meta", "azure", "windows", "fb",
            "t", "wa", "lnkd", "goo", "forms", "messenger", "pathao", "upay", "robi"}
TYPO_TARGETS = sorted({d for d in ALL_OFFICIAL if d.split(".")[0] not in _GENERIC and len(d.split(".")[0]) >= 5})  # list — updated in-place by add_brands()

MULTI_SUFFIX = {"com.bd", "net.bd", "org.bd", "gov.bd", "edu.bd", "ac.bd", "co.uk", "org.uk",
                "ac.uk", "com.au", "co.in", "co.jp", "com.br", "com.pk", "co.id", "com.my",
                "com.sg", "co.za", "com.tr", "com.cn", "com.ng", "com.vn", "com.ph"}
# Free hosting / platforms — frequently used by phishers
PLATFORMS = {"pages.dev", "workers.dev", "netlify.app", "vercel.app", "github.io", "web.app",
             "firebaseapp.com", "glitch.me", "weebly.com", "wixsite.com", "000webhostapp.com",
             "ngrok.io", "ngrok-free.app", "trycloudflare.com", "blogspot.com", "herokuapp.com",
             "onrender.com", "repl.co", "replit.app", "framer.app", "webflow.io", "square.site",
             "godaddysites.com", "azurewebsites.net", "r2.dev", "surge.sh", "ipfs.io",
             "dweb.link", "fleek.co", "carrd.co", "mystrikingly.com", "glide.page", "jimdosite.com"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy", "shorturl.at",
              "goo.gl", "ow.ly", "s.id", "t.ly", "tiny.cc", "rebrand.ly", "bl.ink", "shorte.st",
              "v.gd", "qrco.de", "short.gy", "lnkd.in", "buff.ly"}
BAD_TLDS = {"zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "icu", "cyou", "buzz",
            "rest", "click", "link", "quest", "sbs", "cfd", "lol", "monster", "cam", "beauty",
            "bond", "skin", "hair", "makeup", "autos", "boats", "mom", "win", "loan", "work",
            "support", "help", "live", "online", "site", "website", "store", "fun", "pw", "cc"}
URL_KEYWORDS = ["login", "signin", "sign-in", "logon", "verify", "verification", "secure",
                "account", "update", "confirm", "wallet", "otp", "bonus", "gift", "claim",
                "password", "suspend", "unlock", "recover", "billing", "invoice", "payment",
                "reward", "prize", "airdrop", "kyc", "validate", "authenticate", "webscr", "cmd=_login"]
URGENCY = ["urgent", "immediately", "suspended", "within 24 hours", "verify now", "final notice",
           "account will be", "unusual activity", "locked", "action required", "winner",
           "congratulations", "you have won", "limited time",
           "জরুরি", "বন্ধ হয়ে যাবে", "ব্লক", "২৪ ঘণ্টা", "অভিনন্দন", "জিতেছেন", "পুরস্কার",
           "লটারি", "এখনই", "ভেরিফাই", "পিন", "ওটিপি", "বোনাস", "ক্যাশব্যাক", "ফ্রি"]
DANGER_EXT = {".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe",
              ".wsf", ".hta", ".ps1", ".lnk", ".msi", ".iso", ".img", ".vhd", ".vhdx", ".jar",
              ".apk", ".dll", ".cpl", ".reg", ".chm", ".xll", ".one", ".url", ".svg", ".html",
              ".htm", ".shtml", ".appx", ".msix", ".dmg", ".pkg", ".sh", ".elf", ".bin"}
APK_DANGER_PERMS = {
    "RECEIVE_SMS": "Reads incoming SMS (OTP theft)", "READ_SMS": "Reads all SMS (OTP theft)",
    "SEND_SMS": "Sends SMS from your number", "BIND_ACCESSIBILITY_SERVICE": "Sees and controls the screen (banking trojan)",
    "SYSTEM_ALERT_WINDOW": "Draws fake screens over other apps", "READ_CONTACTS": "Steals contacts",
    "READ_CALL_LOG": "Steals call log", "CALL_PHONE": "Makes calls by itself", "REQUEST_INSTALL_PACKAGES": "Installs other apps",
    "BIND_NOTIFICATION_LISTENER_SERVICE": "Reads all notifications (OTP theft)", "RECORD_AUDIO": "Records microphone",
    "CAMERA": "Uses camera", "ACCESS_FINE_LOCATION": "Tracks location", "BIND_DEVICE_ADMIN": "Becomes device admin, blocks uninstall",
    "QUERY_ALL_PACKAGES": "Scans for banking/wallet apps", "READ_PHONE_STATE": "Reads phone/SIM info",
}

# Attack types: name, purpose (why), impact (what it can do)
ATTACK_TYPES = {
    "credential_harvest": ("Credential theft (password phishing)",
                           "Steal your username/email and password",
                           "Account takeover, requesting money from friends using your ID, stealing personal photos/data and blackmail"),
    "otp_payment": ("OTP / Payment / Card fraud",
                    "Obtain OTP, PIN, card number or mobile banking info",
                    "Direct money withdrawal from bKash/Nagad/bank account"),
    "malware_delivery": ("Malware delivery",
                         "Trick you into downloading and running a malicious file",
                         "Password/cookie theft (infostealer), remote control, ransomware"),
    "clickfix": ("ClickFix / Fake CAPTCHA",
                 "Trick you into running a malicious command yourself (paste into Win+R / Terminal)",
                 "Install infostealer or remote access trojan on the computer"),
    "html_smuggling": ("HTML smuggling",
                       "Bypass email filters by building malware inside the browser",
                       "Unknowingly download and install malware"),
    "crypto_drainer": ("Crypto drainer",
                       "Trick you into connecting/approving your wallet",
                       "Drain all tokens/NFTs from the wallet"),
    "quishing": ("Quishing (QR code phishing)",
                 "Hide links in QR codes to bypass email/link scanners",
                 "Open fake site on mobile to steal info"),
    "brand_impersonation": ("Brand impersonation",
                            "Gain trust using a known organization's name/logo",
                            "Tricked into giving away info or money"),
    "email_spoof": ("Email spoofing / BEC",
                    "Send email pretending to be a known person or organization",
                    "Send money to fake invoices, give away confidential info"),
    "android_stealer": ("Malicious Android app (APK)",
                        "Take control of phone by installing a fake app",
                        "Steal SMS/OTP to empty mobile banking, steal contacts"),
    "oauth_consent": ("OAuth / Consent phishing",
                      "Gain app permission to your account without a password",
                      "Read email, files, and send mail in your name; access persists even after password change"),
    "aitm_proxy": ("AiTM / Reverse-proxy phishing (suspected)",
                   "Proxy the real site to steal password + 2FA session cookie",
                   "Account takeover despite having 2FA enabled"),
}


# ───────────────────────── User config (brands.json) ─────────────────────────
def add_brands(extra):
    """
    Add new brands: {"mybank": ["mybank.com.bd"], ...}
    Modifies in-place, so names imported by other modules are also updated.
    """
    for brand, domains in (extra or {}).items():
        if str(brand).startswith("_"):            # comment/instruction
            continue
        if isinstance(domains, str):
            domains = [domains]
        if not isinstance(domains, (list, tuple)):
            continue
        brand = str(brand).lower().strip()
        doms = [str(d).lower().strip().lstrip(".") for d in (domains or []) if str(d).strip()]
        if not brand or not doms:
            continue
        BRANDS.setdefault(brand, [])
        for d in doms:
            if d not in BRANDS[brand]:
                BRANDS[brand].append(d)
            ALL_OFFICIAL.add(d)
    TYPO_TARGETS[:] = sorted({d for d in ALL_OFFICIAL
                              if d.split(".")[0] not in _GENERIC and len(d.split(".")[0]) >= 5})


def config_paths():
    """Search order: $PHISHSCAN_BRANDS -> ~/.config/phishscan/brands.json"""
    import os
    paths = []
    if os.environ.get("PHISHSCAN_BRANDS"):
        paths.append(os.environ["PHISHSCAN_BRANDS"])
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    paths.append(os.path.join(base, "phishscan", "brands.json"))
    return paths


def load_brand_file(path, strict=False):
    import json
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("JSON outer level must be {} (object)")
        add_brands(data)
        return True
    except FileNotFoundError:
        if strict:
            raise
        return False
    except Exception as e:
        if strict:
            raise
        import sys
        print(f"[!] Cannot read {path}: {e}", file=sys.stderr)
        return False


for _p in config_paths():
    load_brand_file(_p)
