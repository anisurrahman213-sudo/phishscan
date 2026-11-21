"""General helpers: domain, IP, HTTP, URL and hash utilities"""
import hashlib
import ipaddress
import math
import re
from .data import ALL_OFFICIAL, MULTI_SUFFIX, PLATFORMS, TIMEOUT, UA
try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:  # --offline works without requests
    requests = None


def is_public_ip(s):
    try:
        ip = ipaddress.ip_address(s)
        return ip.is_global
    except ValueError:
        return False


def reg_domain(host):
    host = (host or "").lower().strip(".")
    if is_public_ip(host) or not host:
        return host
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])
    if last2 in MULTI_SUFFIX or last2 in PLATFORMS:
        return last3 if len(parts) >= 3 else host
    if last3 in PLATFORMS:
        return ".".join(parts[-4:]) if len(parts) >= 4 else host
    return last2


def is_official(host):
    rd = reg_domain(host)
    return rd in ALL_OFFICIAL


CONFUSABLE = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
              "ј": "j", "ԁ": "d", "ɡ": "g", "ӏ": "l", "ս": "u", "ⅼ": "l", "ο": "o", "ν": "v",
              "α": "a", "ı": "i", "ɑ": "a", "ѕ": "s", "һ": "h", "ԛ": "q", "ԝ": "w"}
LEET = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "@": "a"}


def skeleton(s):
    s = "".join(CONFUSABLE.get(ch, ch) for ch in s.lower())
    s = "".join(LEET.get(ch, ch) for ch in s)
    return s.replace("rn", "m").replace("vv", "w").replace("-", "")


def brand_in(brand, text, tokens=None):
    """Short brand names (<=4 chars, e.g. dhl/upay) only match as whole words -- to reduce false positives"""
    if len(brand) <= 4:
        toks = tokens if tokens is not None else set(re.split(r"[^a-z0-9]+", text))
        return brand in toks
    return brand in text


def levenshtein(a, b):
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def entropy(s):
    if not s:
        return 0
    freq = {c: s.count(c) for c in set(s)}
    return -sum(v / len(s) * math.log2(v / len(s)) for v in freq.values())


def http_get(url, **kw):
    if requests is None:
        raise RuntimeError("requests library missing (pip install requests)")
    headers = kw.pop("headers", {})
    headers.setdefault("User-Agent", UA)
    return requests.get(url, headers=headers, timeout=kw.pop("timeout", TIMEOUT), **kw)


API_STATUS = {}


def api_json(url, headers=None):
    try:
        r = http_get(url, headers=headers or {"Accept": "application/json"})
        API_STATUS[url] = r.status_code
        if r.status_code == 200:
            return r.json()
    except Exception as e:
        API_STATUS[url] = f"ERROR {str(e)[:60]}"
    return None


def api_problem(url, service):
    st = API_STATUS.get(url)
    if st in (401, 403):
        return f"{service} key invalid or unauthorized (HTTP {st}) -- re-copy the key, check if email is verified"
    if st == 429:
        return f"{service} free limit reached (HTTP 429) -- try again in one minute"
    if isinstance(st, str):
        return f"Could not connect to {service}: {st}"
    return None


URL_RE = re.compile(r"""(?:https?://|hxxps?://|www\.)[^\s"'<>()\[\]{}\\^`|]+""", re.I)


def refang(s):
    """hxxp://bad[.]com -> http://bad.com (convert defanged link back to normal)"""
    s = s.strip().strip("<>\"'")
    s = re.sub(r"(?i)^hxxp", "http", s)
    for a, b in (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("[:]", ":"), ("[://]", "://")):
        s = s.replace(a, b)
    return s


def defang(s):
    return re.sub(r"(?i)^http", "hxxp", s).replace(".", "[.]")


def extract_urls(text):
    out = []
    for u in URL_RE.findall(text or ""):
        u = u.rstrip(".,;:!?'\"")
        u = re.sub(r"^hxxp", "http", u, flags=re.I).replace("[.]", ".")
        if u.lower().startswith("www."):
            u = "http://" + u
        if u not in out:
            out.append(u)
    return out


def hashes(data):
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}
