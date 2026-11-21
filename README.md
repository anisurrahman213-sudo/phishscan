<p align="center"><a href="README.bn.md"><b>🇧🇩 বাংলা</b></a> · <b>🇬🇧 English (you are here)</b></p>

# 🛡️ PhishScan — Phishing Analyzer

[![CI](https://github.com/anisurrahman213-sudo/phishscan/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR-USERNAME/phishscan/actions/workflows/ci.yml)
[![CodeQL](https://github.com/anisurrahman213-sudo/phishscan/actions/workflows/codeql.yml/badge.svg)](https://github.com/YOUR-USERNAME/phishscan/actions/workflows/codeql.yml)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![tests](https://img.shields.io/badge/tests-86%20passed-brightgreen)
![coverage](https://img.shields.io/badge/coverage-82%25-green)
![license](https://img.shields.io/badge/license-MIT-green)

Give PhishScan a suspicious **link, email, image/QR code, PDF, Word/Excel, APK, ZIP, HTML or SVG** and it tells you:

| Question | What PhishScan shows |
|---|---|
| **What** kind of attack? | Credential theft, OTP/mobile-banking fraud, malware, ClickFix, quishing, crypto drainer and 12 types in all |
| **Why** are they doing it? | The goal of each attack type |
| **How** does it work? | Every signal and piece of evidence: fake domains, forms, hidden code, redirects |
| **Where** is it running? | IP, country, city, hosting company, when the domain was registered, which server sent the email |
| Where does the stolen data **go**? | Form destination, Telegram bot, Discord webhook, etc. |
| What **damage** can it do? | The likely consequence of each attack |
| **Which other sites** belong to the same scammer? | Hidden subdomains and other lookalike domains via crt.sh |
| **Same gang?** | A campaign fingerprint that links multiple phishing samples to one source |
| **Who** do you report to? | Abuse emails for the hosting & registrar, plus Bangladesh agencies |

Reports are written in **Bengali** and tuned for the Bangladesh context (bKash, Nagad, banks, OTP scams). This README is the English guide; the tool's own output is Bengali.

> ⚠️ **For defence, research and awareness only.** The tool never runs a file, never submits a form, never enters anyone's system.

---

## 📑 Table of contents
1. [Honest limitations (read first)](#️-honest-limitations-read-first)
2. [Install](#-install)
3. [API keys (optional, free)](#-api-keys-optional-free)
4. [Usage](#-usage)
5. [Add your own bank/brand (config)](#-add-your-own-bankbrand-config)
6. [Use as a Python library](#-use-as-a-python-library)
7. [Find the scammer's other sites (crt.sh)](#-find-the-scammers-other-sites-crtsh)
8. [Campaign fingerprint](#-campaign-fingerprint--is-it-the-same-gang)
9. [How to collect the suspicious item](#-how-to-collect-the-suspicious-item)
10. [How to read the report](#-how-to-read-the-report)
11. [Safety rules](#-safety-rules)
12. [Reporting & complaints](#-reporting--complaints)
13. [Troubleshooting](#-troubleshooting)
14. [Tests & development](#-tests--development)

<!-- TOC anchors follow GitHub's emoji-stripped leading-hyphen style. -->

---

## ⚖️ Honest limitations (read first)

No phishing detector can be **100% accurate**, and neither is this one. New tricks appear every day.

- **A low score does not prove something is safe.** Brand-new phishing is often in no database yet.
- **A high score is not a 100% guarantee of phishing.** Occasionally a real site can look suspicious. Read the evidence and decide for yourself.
- **The location is the server's, not the scammer's home.** Scammers use VPNs, Cloudflare and hacked sites.
- **Only law enforcement** can reveal the real person, by legally requesting records from hosting, telecom or bKash/Nagad. This tool's report is useful **as evidence** there.
- Phone calls (vishing) and deepfakes cannot be caught with this tool.

What PhishScan **can** do very well: expose the scam infrastructure, find the gang's *other* sites, and hand you a clean, timestamped evidence package.

---

## 📦 Install

> 🆕 New here? Follow the step-by-step **[SETUP.md](SETUP.md)** (clone → install → verify → run).

Four ways — pick one.

### A) Installer script (Kali / Ubuntu / Debian), recommended for beginners
```bash
git clone https://github.com/YOUR-USERNAME/phishscan.git
cd phishscan
chmod +x install.sh
./install.sh            # do NOT run with sudo; it will ask for a password if needed
phishscan --version     # "PhishScan 3.1.0" means success
```
Installs the system tools (whois, exiftool, zbar) and all optional packages itself. To remove: `./install.sh --uninstall`

### B) pipx (any Linux/macOS, cleanest)
```bash
sudo apt install pipx && pipx ensurepath        # macOS: brew install pipx
pipx install "git+https://github.com/YOUR-USERNAME/phishscan.git"
pipx inject phishscan pillow pyzbar oletools extract-msg androguard   # optional
```

### C) pip (Python 3.9+)
```bash
pip install "phishscan[full] @ git+https://github.com/YOUR-USERNAME/phishscan.git"
```
> On Kali, if pip gives an "externally-managed-environment" error, use method A or B.

### D) Docker (safest — runs in an isolated container)
```bash
git clone https://github.com/anisurrahman213-sudo/phishscan.git && cd phishscan
docker build -t phishscan .
docker run --rm phishscan "hxxps://bad-site[.]top/login"
docker run --rm -v "$PWD:/data" phishscan mail.eml                  # a file in the current folder
docker run --rm -e VT_API_KEY -e URLSCAN_API_KEY phishscan "URL"    # with API keys
```
Runs as a non-root user inside the container. Add `-v "$PWD:/data"` to get reports written into your folder (`phishscan_evidence/`).

### What each package is for

| Package | If missing |
|---|---|
| `requests` (required) | Nothing online works (`--offline` still runs) |
| `pillow` + `pyzbar` + `zbar-tools` | QR codes in images are not decoded |
| `exiftool` | Less image metadata |
| `oletools` | No macro detail (only "a macro exists") |
| `androguard` | No APK package name (permissions still shown) |
| `extract-msg` | Outlook `.msg` not read (save it as `.eml` instead) |
| `whois` | Less data for some domains, including `.bd` |
| `chromium` | `--screenshot` won't work |

---

## 🔑 API keys (optional, free)

The tool runs fully without keys. Keys add what the world's security researchers have already seen.

| Service | What it adds | Get the key |
|---|---|---|
| VirusTotal | How many antivirus engines flag it, the malware name | https://www.virustotal.com/gui/my-apikey |
| urlscan.io | Past scans, screenshot link, whether flagged malicious | https://urlscan.io/user/profile/ |

> If urlscan.io says "Your account is too new", try again in a few days. That's normal for new accounts.

**Set them (zsh, Kali default):**
```bash
echo 'export VT_API_KEY="your_key"' >> ~/.zshrc
echo 'export URLSCAN_API_KEY="your_key"' >> ~/.zshrc
source ~/.zshrc
```
If you use bash, replace `~/.zshrc` with `~/.bashrc`.

> 🔒 **Never commit a key to GitHub** and never share it. The code holds no keys — it only reads them from environment variables.
> VirusTotal free limit: 4/min, 500/day. The tool waits automatically to respect it.

---

## 🚀 Usage

### Interactive mode (easiest — paste and go)
Run it with **no arguments** and keep pasting things to scan — no need to retype the command each time:
```bash
phishscan                 # if installed
./phishscan.sh            # from the repo without installing
```
```
phishscan> hxxps://bkash-verify[.]top/pin      ← paste a link (defanged is fine)
phishscan> /home/kali/Downloads/invoice.pdf    ← or a file path (drag & drop works in most terminals)
phishscan> quit
```
It accepts any link or file — `.eml .msg .pdf .docx .xlsx .csv .txt .apk .zip .png .jpg .html ...` — and gathers information on each. On the first link it asks once whether to visit sites fully (VM-recommended) or stay in safe/passive mode. Files are always analysed safely.

You can also pipe:
```bash
echo "hxxps://bad[.]top/login" | phishscan
cat links.txt | phishscan                      # one link per line
```

### Single scan

```bash
phishscan "<link or file>" [options]
```

| Task | Command |
|---|---|
| Check a link | `phishscan "https://bkash-verify.top/login"` |
| Defanged link (safe to share) | `phishscan "hxxps://bkash-verify[.]top/login"` |
| Without visiting the site (passive) | `phishscan "URL" --no-fetch` |
| Email | `phishscan mail.eml` |
| Outlook email | `phishscan mail.msg` |
| QR-code image / screenshot | `phishscan qr.jpg` |
| PDF / Word / Excel | `phishscan invoice.pdf` |
| Android app | `phishscan update.apk` |
| ZIP / HTML / SVG attachment | `phishscan file.zip` |
| Many links at once | `phishscan links.txt` (one per line, `#` for comments) |
| With a screenshot (VM only!) | `phishscan "URL" --screenshot` |
| No internet | `phishscan file.pdf --offline` |
| Short result only | `phishscan "URL" --quiet` |

### All options

| Option | What it does |
|---|---|
| `--no-fetch` | Don't connect to the phishing site. Only DNS, WHOIS, location and reputation |
| `--offline` | No internet at all — only the file's or link's own analysis |
| `--screenshot` | Capture the page with headless Chromium (the page's JS runs, so **VM only**) |
| `--json FILE` / `--html FILE` | Save the report to a specific place |
| `--evidence DIR` | Evidence folder (default `phishscan_evidence/`) |
| `--max-links N` | Max links to analyse from an email/PDF (default 10) |
| `--vt-max N` | Max VirusTotal calls per scan (default 8) |
| `--brands FILE` | Extra brands JSON file (see below) |
| `--no-related` | Turn off crt.sh related-domain discovery |
| `--quiet` | Only the score and types |
| `--doctor` | Self-check: verify the setup is correct |
| `--version` | Version |

### The three modes

| Mode | Connects to site | Internet | When |
|---|---|---|---|
| normal | yes | yes | Most detail — run inside a VM |
| `--no-fetch` | no (DNS only) | yes | To check without tipping off the scammer |
| `--offline` | no | no | File analysis, or no internet |

---

## 🏦 Add your own bank/brand (config)

bKash, Nagad, major banks, Facebook, Google etc. are built in. To add your own bank, university or company you **don't need to touch the code**:

```bash
mkdir -p ~/.config/phishscan
cp config/brands.example.json ~/.config/phishscan/brands.json
nano ~/.config/phishscan/brands.json
```
```json
{
  "shapnobank": ["shapnobank.com.bd"],
  "mycompany": ["mycompany.com", "mycompany-mail.com"]
}
```
- Left side: the brand name (lowercase, as it appears in phishing links). Right side: the list of **real** domains.
- After that, a fake domain like `shapnobank-login.top` is caught, and `shapnobank.com.bd` is treated as safe.
- For a single scan: `phishscan URL --brands myfile.json`
- To keep it elsewhere: `export PHISHSCAN_BRANDS=/path/to/brands.json`

---

## 🐍 Use as a Python library

To use it in your own program, bot or website:
```python
from phishscan import scan

r = scan("hxxps://bkash-verify[.]top/pin", offline=True)
print(r["score"], r["verdict"])               # 44 ...
for t in r["attack_types"]:
    print(t["name"], "—", t["impact"])
for f in r["findings"]:
    print(f["severity"], f["message"])

r = scan("/path/to/mail.eml")                 # a file works too
```
The returned dict has the same shape as the CLI's `report.json`.

---

## 🔍 Find the scammer's other sites (crt.sh)

You can't find the scammer's **real identity** (only police can), but you *can* find their **other traps**. PhishScan automatically checks Certificate Transparency (crt.sh) — no API key, no cost:

- **Hidden subdomains:** every page on the domain, such as `login.`, `admin.`, `panel.`, `otp.`
- **Other lookalike domains:** find one bKash-impersonating site, and crt.sh surfaces **more** domains abusing the bKash name

This helps two ways: it exposes hidden login pages, and it lets you report **all** of the gang's sites together to get them taken down. Disable with `--no-related`.

## 🧬 Campaign fingerprint — is it the same gang?

By combining **where the stolen data goes** (Telegram bot, exfil server, wallet) with **who hosts it**, PhishScan builds a short ID. **Same ID = likely the same gang or the same phishing kit.** Scan several phishing samples separately and match the IDs to see whether they share one source — useful for tying many incidents into a single police case. (Works offline too; the Telegram token is never leaked, only the bot ID.)

---

## 📥 How to collect the suspicious item

| Source | What to do |
|---|---|
| **Gmail** | Open the email → ⋮ → **Download message** → `.eml` file |
| **Outlook (web)** | Open the email → ⋯ → **Save** / **Download** → `.eml` |
| **Outlook (desktop)** | File → Save As → `.msg` |
| **Yahoo** | ⋯ → **View raw message** → copy and save as `mail.eml` |
| **SMS / WhatsApp / Messenger** | Do **not** tap the link. Long-press → **Copy link**, then `phishscan "link"` |
| **QR code** | Do **not** scan it. Take a photo/screenshot, then `phishscan qr.jpg` |
| **APK file** | Do **not** install. Move it to a computer and `phishscan app.apk` |
| **Facebook post link** | Copy the link. Even `l.facebook.com/l.php?u=...` is fine — the tool extracts the real link inside |

---

## 📊 How to read the report

### Score

| Score | Meaning | exit code |
|---|---|---|
| 70–100 | 🔴 Severe phishing / malicious | 2 |
| 40–69 | 🔴 Highly suspicious | 1 |
| 15–39 | 🟡 Suspicious, be careful | 1 |
| 0–14 | 🟢 Low risk (not proven safe) | 0 |

### Report sections

| Section | What it tells you |
|---|---|
| **What kind of attack** | The type, its goal (why), and the likely damage |
| **Evidence / signals** | Each signal, its severity (HIGH/MED/LOW) and points |
| **Where it runs** | Domain age, registrar, IP, country/city, hosting/ASN, abuse email |
| **Redirect chain** | Where the link bounces you, step by step |
| **Site response** | On 403 or cloaking, what desktop vs mobile sees |
| **Email journey** | Which servers it passed through, first IP, SPF/DKIM/DMARC |
| **Content** | Forms, where data goes, hidden code, brands |
| **Related subdomains** | Hidden pages of the domain from crt.sh (login., admin., otp....) |
| **Other lookalike domains** | The gang's likely other phishing sites, to report together |
| **Campaign fingerprint** | Same ID = likely the same gang/kit |
| **IOCs** | Domains, IPs, hashes, emails, bots to block or report |
| **Where to report** | Automatically discovered abuse addresses |

Each signal's meaning and points are documented in [docs/DETECTIONS.md](docs/DETECTIONS.md).

### Saved files
Every scan is stored under `phishscan_evidence/<date_time_id>/`:
- `report.html` — a clean report you can open in a browser (print or save as PDF)
- `report.json` — machine-readable, with defanged IOCs
- `page.html` — a copy of the phishing page (evidence even after the site goes down)
- `screenshot.png` — if `--screenshot` was used

Times are in UTC (Bangladesh = UTC+6), ideal for legal evidence.

### Example (fake test email)
```
  Risk score: 100/100 — Severe phishing / malicious

▶ What kind of attack, why, what damage
  • OTP / payment / card fraud
      Goal   : take OTP, PIN, card number or mobile-banking details
      Damage : drain money directly from bKash/Nagad/bank account

▶ Evidence / signals
  [HIGH] +30 (Brand) uses the name 'bkash' but the domain is not official (real: bkash.com)
  [HIGH] +30 (Exfil) stolen data is sent to a Telegram bot (bot id 1234567890)
  ...
```
Run the demo yourself:
```bash
python3 tests/make_samples.py examples/     # safe fake samples (from inside the repo)
phishscan examples/phish_email.eml --offline
```

---

## 🧯 Safety rules

1. **Run normal mode and `--screenshot` in a separate VM only** (Kali in VirtualBox/VMware). Revert to a snapshot afterwards.
2. **Never run a suspicious file.** The tool never does either.
3. **Never enter real credentials** on a phishing page, not even to test.
4. Try `--no-fetch` first, then normal mode if needed.
5. In active mode the phishing server sees your IP. Use a VPN inside the VM for privacy. Some sites block VPNs (cloaking) — the report will note it.
6. `phishscan_evidence/` holds real phishing links and private emails, so **do not push it to GitHub** (it's excluded in `.gitignore`).

---

## 🚨 Reporting & complaints

| Where | For what |
|---|---|
| The **hosting abuse** email in the report | To take the site down (usually fastest) |
| The **registrar abuse** email in the report | To suspend the domain |
| https://abuse.cloudflare.com | If the site is behind Cloudflare |
| https://safebrowsing.google.com/safebrowsing/report_phish/ | To warn Chrome, Android and Gmail |
| https://report.netcraft.com/report | Fast takedown |
| reportphishing@apwg.org | Forward the phishing email |
| abuse@telegram.org | If the report found a Telegram bot |
| **BGD e-GOV CIRT** (cirt.gov.bd) | Bangladesh national cyber-incident report |
| **DMP Cyber Crime Unit (CTTC)** / nearest police station | GD or case, to pursue the scammer's identity |
| bKash / Nagad / bank **official helpline** | If their name is being abused |

**What to put in an abuse email:** the phishing URL (defanged), which brand it impersonates, the scan time (UTC), and attach `report.html`.

### If you already gave information or money — immediately
1. **Call the bank or bKash/Nagad helpline** and freeze the account
2. **Change your password** (everywhere you reused it)
3. **Log out of all devices**, turn on **2FA** (an authenticator app is better than SMS)
4. If you installed an APK, **disconnect the phone** from the internet, uninstall it, factory-reset if needed
5. Take the report and screenshots to the **police or cyber-crime unit**

---

## 🔧 Troubleshooting

| Problem | Cause & fix |
|---|---|
| `command not found: phishscan` | Run `./install.sh`, or use `python3 -m phishscan ...` from inside the repo. For pipx, run `pipx ensurepath` and restart the terminal |
| `[403]` in the redirect chain | The site blocks scanners (cloaking). The tool retries as mobile automatically. If it still fails, turn off VPN, or use `--screenshot` |
| "Cloudflare bot check" | The page body couldn't be read. Check urlscan.io's past scan, or use `--screenshot` in a VM |
| "VirusTotal key wrong (HTTP 401/403)" | Re-copy the key, check with `echo $VT_API_KEY` |
| "limit reached (HTTP 429)" | Wait a minute, or lower `--vt-max` |
| urlscan "account is too new" | Create the key in a few days. It works without a key until then |
| `--brands file problem` | The JSON outer layer must be `{ }`, each value a `["domain"]` list. Validate with `python3 -m json.tool file.json` |
| QR code not read | `sudo apt install zbar-tools libzbar0 && pip install pyzbar pillow` |
| `could not resolve` | The site is down, or DNS blocked. Domain data may still appear |

---

## 🧪 Tests & development

```bash
pip install -e ".[dev,full]"
ruff check .                        # code quality + security rules
pytest -q --cov=phishscan           # 86 tests, 82% coverage, no internet needed
```

**What's tested:**
- **Detection:** phishing email, PDF, APK, ClickFix, macro, ZIP, SVG, crypto, homoglyph, typosquat, Facebook redirect links
- **No false alarms:** Google, bKash, Wikipedia, GitHub, ample.com, officer.com, real emails, ordinary images/PDFs/HTML
- **Online parts (mocked):** redirects, meta-refresh, cloaking, downloads on a local server; and mocked RDAP, IP geolocation, VirusTotal (wrong key, quota, rate limit), urlscan.io, crt.sh related domains, campaign fingerprint
- **Structure:** config file, Python API, version consistency, HTML-report injection blocking

**What GitHub runs automatically on every push:**
| Job | What it checks |
|---|---|
| CI → lint | ruff security & quality rules |
| CI → test | All tests on Python 3.9, 3.11, 3.12, 3.13; fails if coverage drops below 75% |
| CI → package | Builds a wheel and installs it in a clean environment |
| CI → docker | Builds and runs the Docker image |
| CodeQL | GitHub's security scan (weekly) |
| Dependabot | Dependency security updates (weekly) |
| Release | A tag like `v3.1.1` creates an automatic release |

### Project structure
```
phishscan/
├── phishscan/                 # main package
│   ├── cli.py                 #   command line
│   ├── api.py                 #   Python API: scan()
│   ├── scanner.py             #   URL scan flow
│   ├── urlcheck.py            #   URL offline analysis
│   ├── web.py                 #   page fetch, redirects, HTML
│   ├── infra.py               #   DNS, RDAP/WHOIS, IP geolocation, SSL
│   ├── reputation.py          #   VirusTotal, urlscan.io
│   ├── intel.py               #   crt.sh related domains & campaign
│   ├── mail.py                #   email (.eml/.msg)
│   ├── files.py               #   image/QR, PDF, Office, APK, ZIP...
│   ├── report.py              #   report (terminal/JSON/HTML)
│   ├── doctor.py              #   self-check (--doctor)
│   ├── data.py                #   brands, lists, config loading
│   └── util.py, console.py    #   helpers
├── tests/                     # 86 tests + safe fake-sample generator
├── config/brands.example.json # config example
├── docs/DETECTIONS.md         # what each signal means, and points
├── .github/                   # CI, CodeQL, Dependabot, release, issue templates
├── phishscan.sh                 # run without installing
├── pyproject.toml · Dockerfile · install.sh
└── README · README.bn · SETUP · CHANGELOG · CONTRIBUTING · SECURITY · LICENSE
```

To contribute, see [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 📜 License & responsible use
MIT License, see [LICENSE](LICENSE). Use it only on suspicious messages you received yourself, or for authorised work in your organisation. Responsible-use and bug-report rules are in [SECURITY.md](SECURITY.md).
