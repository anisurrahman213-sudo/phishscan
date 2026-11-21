"""phishscan --doctor — verify setup is correct."""
import importlib
import os
import shutil
import sys

from . import VERSION
from .console import C


def _ok(b):
    return f"{C.G}✓{C.X}" if b else f"{C.R}✗{C.X}"


def run_doctor():
    print(f"{C.BO}PhishScan {VERSION} — Setup Check (--doctor){C.X}\n")
    problems = 0

    # 1) Python version
    v = sys.version_info
    py_ok = v >= (3, 9)
    print(f"{_ok(py_ok)} Python {v.major}.{v.minor}.{v.micro}" + ("" if py_ok else f"  {C.R}<- 3.9+ required{C.X}"))
    problems += not py_ok

    # 2) Required package
    req_ok = importlib.util.find_spec("requests") is not None
    print(f"{_ok(req_ok)} requests (required)" + ("" if req_ok else f"  {C.R}<- pip install requests{C.X}"))
    problems += not req_ok

    # 3) Optional packages
    print(f"\n{C.BO}Optional packages (not required, some features reduced):{C.X}")
    opt = {
        "PIL": ("pillow", "Image/QR reading"),
        "pyzbar": ("pyzbar", "QR code decode"),
        "oletools": ("oletools", "Office macro details"),
        "extract_msg": ("extract-msg", "Outlook .msg files"),
        "androguard": ("androguard", "APK package info"),
    }
    for mod, (pkg, why) in opt.items():
        has = importlib.util.find_spec(mod) is not None
        print(f"  {_ok(has)} {pkg:14} — {why}" + ("" if has else f"  {C.D}(pip install {pkg}){C.X}"))

    # 4) System tools
    print(f"\n{C.BO}System tools:{C.X}")
    tools = {"whois": "Domain info (.bd included)", "exiftool": "Image metadata",
             "zbarimg": "QR code (fallback)", "chromium": "--screenshot"}
    for tool, why in tools.items():
        has = shutil.which(tool) is not None or (tool == "chromium" and any(shutil.which(b) for b in ("chromium-browser", "google-chrome")))
        print(f"  {_ok(has)} {tool:10} — {why}" + ("" if has else f"  {C.D}(sudo apt install){C.X}"))

    # 5) API keys
    print(f"\n{C.BO}API keys (optional, free — stronger reports with them):{C.X}")
    for env, name in (("VT_API_KEY", "VirusTotal"), ("URLSCAN_API_KEY", "urlscan.io")):
        has = bool(os.environ.get(env))
        print(f"  {_ok(has)} {name:12} ({env})" + ("" if has else f"  {C.D}not set — see README{C.X}"))

    # 6) Run an offline test scan
    print(f"\n{C.BO}Functionality test (offline scan):{C.X}")
    try:
        from .api import scan
        r = scan("hxxps://bkash-verify[.]top/pin", offline=True)
        works = r["score"] >= 25 and any(t["id"] == "brand_impersonation" for t in r["attack_types"])
        print(f"  {_ok(works)} Fake bkash link detected (score {r['score']}/100)")
        problems += not works
    except Exception as e:
        print(f"  {C.R}✗ Scan failed: {str(e)[:120]}{C.X}")
        problems += 1

    print()
    if problems == 0:
        print(f"{C.G}{C.BO}✓ All good — PhishScan is ready to use.{C.X}")
        print(f"  Run:  {C.BO}phishscan{C.X}  (interactive)  or  phishscan <link/file>")
    else:
        print(f"{C.R}{C.BO}✗ {problems} critical issue(s) — fix the red items above.{C.X}")
    return 0 if problems == 0 else 1
