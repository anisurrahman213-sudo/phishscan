"""
PhishScan — Phishing link / email / file analyzer (defensive use only)

Command line:   phishscan <URL | file> [options]      (details: phishscan --help)
As a library:
    from phishscan import scan
    report = scan("https://suspicious.example/login", offline=True)
    print(report["score"], report["verdict"])

Security: never executes files, never submits forms.
License: MIT
"""
VERSION = "3.1.0"
__version__ = VERSION

from .api import scan  # noqa: E402
from .report import Report  # noqa: E402
from .urlcheck import analyze_url_static  # noqa: E402
from .util import brand_in, defang, is_official, refang, reg_domain  # noqa: E402
from .web import analyze_html  # noqa: E402

__all__ = ["VERSION", "__version__", "scan", "Report", "analyze_url_static", "analyze_html",
           "brand_in", "defang", "is_official", "refang", "reg_domain"]
