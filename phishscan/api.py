"""Simple Python API for use from other programs"""
import os
import tempfile
from types import SimpleNamespace

from . import files, scanner
from .reputation import VT_CALLS, VT_LIMIT
from .report import Report
from .util import refang


def scan(target, *, offline=False, no_fetch=False, max_links=10, vt_max=8, evidence_dir=None, related=None):
    """
    Analyze a URL or file path and return a report dict (same as CLI JSON output).

    >>> r = scan("hxxp://bkash-verify[.]top/pin", offline=True)
    >>> r["score"] >= 25
    True
    """
    args = SimpleNamespace(no_fetch=no_fetch or offline, offline=offline, screenshot=False,
                           related=(not offline) if related is None else related,
                           max_links=max_links, evidence_dir=evidence_dir or tempfile.mkdtemp(prefix="phishscan_"))
    VT_LIMIT["max"] = vt_max
    VT_CALLS.clear()
    rep = Report(target)
    if os.path.isfile(target):
        with open(target, "rb") as f:
            files.analyze_bytes(os.path.basename(target), f.read(), rep, args)
    else:
        scanner.scan_url(refang(target), rep, args)
    return rep.to_dict()
