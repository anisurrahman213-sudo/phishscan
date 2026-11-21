"""Command-line interface"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from . import VERSION
from .console import C
from .data import ATTACK_TYPES, load_brand_file
from .report import Report, html_report, print_report
from .reputation import VT_CALLS, VT_LIMIT
from .util import refang
from . import files, scanner
from .util import requests


def _mode_label(args):
    return "offline" if args.offline else "passive (no site visit)" if args.no_fetch else "active"


def scan_one(target, args, out_json=None, out_html=None):
    """Analyze a single target (URL or file), return Report, save files."""
    target = target.strip().strip('"').strip("'").strip()
    if not os.path.isfile(target) and "\\ " in target and os.path.isfile(target.replace("\\ ", " ")):
        target = target.replace("\\ ", " ")

    stamp = dt.datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + hashlib.sha1(target.encode()).hexdigest()[:6]
    args.evidence_dir = os.path.join(args.evidence, stamp)
    os.makedirs(args.evidence_dir, exist_ok=True)

    if not os.path.isfile(target) and "://" not in target and \
       re.search(r"(?i)\.(eml|pdf|docx?|xlsx?|pptx?|csv|apk|zip|rar|7z|png|jpe?g|gif|webp|bmp|html?|svg|exe|iso|lnk|js|txt|msg)$", target):
        print(f"{C.R}[!] File not found: {target}{C.X}")
        return None

    VT_CALLS.clear()
    rep = Report(target)
    print(f"{C.D}[*] Analyzing ({_mode_label(args)})...{C.X}", file=sys.stderr)
    try:
        if os.path.isfile(target):
            with open(target, "rb") as f:
                data = f.read()
            if target.lower().endswith((".txt", ".csv")):
                lines = [refang(x) for x in data.decode("utf-8", "replace").splitlines() if x.strip() and not x.strip().startswith("#")]
                urls = [u for u in lines if re.match(r"(?i)^(https?://|www\.|[a-z0-9-]+\.[a-z]{2,})", u)]
                if not urls:
                    print(f"{C.Y}[!] No links found in file (put one link per line){C.X}")
                for i, u in enumerate(urls[:args.max_links]):
                    scanner.scan_url(u, rep, args, label=f"Link {i + 1}")
            else:
                files.analyze_bytes(os.path.basename(target), data, rep, args)
        else:
            scanner.scan_url(refang(target), rep, args)
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled")

    if args.quiet:
        v, col = rep.verdict()
        print(f"{col}{rep.score()}/100 — {v}{C.X}  " + ", ".join(ATTACK_TYPES[t][0] for t in sorted(rep.types)))
    else:
        print_report(rep)
    jpath = out_json or os.path.join(args.evidence_dir, "report.json")
    hpath = out_html or os.path.join(args.evidence_dir, "report.html")
    with open(jpath, "w", encoding="utf-8") as f:
        json.dump(rep.to_dict(), f, ensure_ascii=False, indent=2, default=str)
    html_report(rep, hpath)
    print(f"[+] JSON report : {jpath}\n[+] HTML report : {hpath}\n[+] Evidence dir : {args.evidence_dir}")
    return rep


BANNER = f"""{C.BO}{C.B}
  ╔═══════════════════════════════════════════════════╗
  ║   PhishScan {VERSION} — Interactive Mode                ║
  ╚═══════════════════════════════════════════════════╝{C.X}
  Paste anything suspicious, press Enter — analysis starts.
    • Links:  https://... or hxxps://bad[.]top  (defanged OK)
    • Files:  give path — .eml .msg .pdf .docx .xlsx .csv .txt .apk .zip .png .jpg .html ...
             (drag & drop file into terminal to paste path)
  To quit:  quit  or  Ctrl+C
{C.D}  Note: active mode visits sites — run in a VM if possible.{C.X}
"""


def interactive(args):
    print(BANNER)
    if not args.offline and not args.no_fetch:
        try:
            ans = input(f"{C.BO}Visit links directly for full info? [Y = full (use VM), n = safe/passive]: {C.X}").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return 0
        if ans in ("n", "no"):
            args.no_fetch = True
    print(f"{C.D}  Mode: {_mode_label(args)}{C.X}\n")

    count = 0
    while True:
        try:
            line = input(f"{C.BO}{C.G}phishscan>{C.X} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break
        if not line:
            continue
        if line.lower() in ("quit", "exit", "q", "bye"):
            print("Goodbye.")
            break
        if line.lower() in ("help", "?"):
            print(BANNER)
            continue
        try:
            scan_one(line, args)
        except Exception as e:
            print(f"{C.R}[!] Error on this input: {str(e)[:150]}{C.X}")
        count += 1
        print(f"{C.D}{'─' * 55}\nPaste another, or type 'quit' to exit.{C.X}\n")
    return count


def main():
    ap = argparse.ArgumentParser(
        prog="phishscan",
        description="PhishScan — Phishing link/email/file analyzer. Run without arguments for interactive mode.")
    ap.add_argument("target", nargs="?", help="URL or file (.eml .pdf .docx .xlsx .csv .apk .zip .png ...). Omit for interactive mode")
    ap.add_argument("--no-fetch", action="store_true", help="No connection to suspicious sites (passive mode)")
    ap.add_argument("--offline", action="store_true", help="No internet at all (local analysis only)")
    ap.add_argument("--screenshot", action="store_true", help="Headless chromium screenshot (VM only)")
    ap.add_argument("--json", help="JSON report file path (single scan)")
    ap.add_argument("--html", help="HTML report file path (single scan)")
    ap.add_argument("--evidence", default="phishscan_evidence", help="Evidence folder (default: phishscan_evidence)")
    ap.add_argument("--max-links", type=int, default=10, help="Max links to analyze from email/PDF/txt")
    ap.add_argument("--vt-max", type=int, default=8, help="Max VirusTotal calls per scan (free: 4/min)")
    ap.add_argument("--no-related", action="store_true", help="Skip crt.sh related domain lookup")
    ap.add_argument("--quiet", action="store_true", help="Show only score and type in terminal")
    ap.add_argument("--brands", metavar="FILE", help="Extra brand/official domain JSON file (see README)")
    ap.add_argument("--doctor", action="store_true", help="Verify setup is correct")
    ap.add_argument("--version", action="version", version=f"PhishScan {VERSION}")
    args = ap.parse_args()

    if args.doctor:
        from .doctor import run_doctor
        sys.exit(run_doctor())

    if args.brands:
        try:
            load_brand_file(args.brands, strict=True)
        except Exception as e:
            print(f"[!] --brands file error: {e}")
            sys.exit(1)
    VT_LIMIT["max"] = max(0, args.vt_max)
    args.related = not args.no_related
    if args.offline:
        args.no_fetch = True
    if requests is None and not args.offline:
        print("Warning: requests not installed: pip install requests  (or use --offline)")
        args.offline = args.no_fetch = True

    if not args.target:
        if not sys.stdin.isatty():
            any_scan = False
            for line in sys.stdin:
                s = line.strip()
                if not s or s.startswith("#") or s.lower() in ("quit", "exit", "q", "bye"):
                    continue
                scan_one(s, args)
                any_scan = True
            if not any_scan:
                ap.print_help()
            sys.exit(0)
        interactive(args)
        sys.exit(0)

    rep = scan_one(args.target, args, out_json=args.json, out_html=args.html)
    if rep is None:
        sys.exit(1)
    sys.exit(2 if rep.score() >= 70 else 1 if rep.score() >= 15 else 0)


def run():
    """console-script entry point (pip/pipx installed `phishscan` command)"""
    try:
        main()
    except BrokenPipeError:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0)
