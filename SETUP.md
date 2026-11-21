<p align="center"><b>🇧🇩 বাংলা</b> · <a href="#english-setup-guide"><b>🇬🇧 English</b></a></p>

# 🚀 PhishScan — সম্পূর্ণ সেটআপ গাইড

GitHub থেকে clone করা থেকে শুরু করে প্রথম স্ক্যান পর্যন্ত — সব কমান্ড এক জায়গায়। Kali Linux / Ubuntu / Debian ধরে লেখা।

---

## ধাপ ০ — আগে যা লাগবে
- Linux (Kali সবচেয়ে ভালো, VM-এ)। Python 3.9 বা তার বেশি
- ইন্টারনেট সংযোগ
- পরীক্ষা করুন:
```bash
python3 --version        # 3.9+ হতে হবে
git --version            # না থাকলে: sudo apt install git
```

---

## ধাপ ১ — GitHub থেকে clone করুন
`আপনার-ইউজারনেম` জায়গায় আপনার আসল GitHub ইউজারনেম দিন:
```bash
git clone https://github.com/আপনার-ইউজারনেম/phishscan.git
cd phishscan
```

---

## ধাপ ২ — ইনস্টল করুন (যেকোনো একটি উপায়)

### উপায় A — ইনস্টলার স্ক্রিপ্ট (নতুনদের জন্য সবচেয়ে সহজ) ✅
```bash
chmod +x install.sh phishscan.sh
./install.sh
```
> ⚠️ `sudo ./install.sh` **নয়** — শুধু `./install.sh`। দরকার হলে এটা নিজেই পাসওয়ার্ড চাইবে।

এটা নিজে থেকে বসায়: সিস্টেম টুল (whois, exiftool, zbar, chromium), একটা আলাদা Python environment, আর সব ঐচ্ছিক প্যাকেজ। শেষে `phishscan` কমান্ড তৈরি করে।

### উপায় B — pipx (পরিষ্কার, যেকোনো Linux/macOS)
```bash
sudo apt install -y pipx && pipx ensurepath
# টার্মিনাল বন্ধ করে আবার খুলুন, তারপর:
pipx install .
pipx inject phishscan pillow pyzbar oletools extract-msg androguard
```

### উপায় C — ইনস্টল ছাড়াই (শুধু রিপো থেকে চালাবেন)
```bash
pip install requests --break-system-packages
chmod +x phishscan.sh
# চালানোর সময়:  ./phishscan.sh  বদলে  phishscan
```

### উপায় D — Docker (সবচেয়ে নিরাপদ)
```bash
docker build -t phishscan .
docker run --rm -v "$PWD:/data" phishscan --doctor
```

---

## ধাপ ৩ — সব ঠিকমতো বসেছে কিনা যাচাই করুন ✅
```bash
phishscan --doctor
```
(উপায় C হলে: `./phishscan.sh --doctor`)

এটা দেখাবে Python, প্যাকেজ, সিস্টেম টুল আর API key ঠিক আছে কিনা, আর শেষে নিজে একটা নকল লিংক স্ক্যান করে দেখবে কাজ করছে কিনা। **সব সবুজ ✓ আর "সব ঠিক আছে" দেখালে** আপনি প্রস্তুত। লাল ✗ থাকলে পাশে কী করতে হবে লেখা থাকবে (API key-র ✗ সমস্যা নয়, ওগুলো ঐচ্ছিক)।

---

## ধাপ ৪ — (ঐচ্ছিক) ফ্রি API key বসান
রিপোর্ট আরও শক্তিশালী করে। না দিলেও টুল চলে।
```bash
# VirusTotal: https://www.virustotal.com/gui/my-apikey
# urlscan.io: https://urlscan.io/user/profile/
echo 'export VT_API_KEY="আপনার_key"' >> ~/.zshrc
echo 'export URLSCAN_API_KEY="আপনার_key"' >> ~/.zshrc
source ~/.zshrc
```
> bash ব্যবহার করলে `~/.zshrc`-এর বদলে `~/.bashrc`। key কখনো GitHub-এ দেবেন না।

---

## ধাপ ৫ — চালান 🎉

**ইন্টার‍্যাক্টিভ মোড (সবচেয়ে সহজ):**
```bash
phishscan
```
```
phishscan> hxxps://bkash-verify[.]top/pin      ← লিংক পেস্ট করুন
phishscan> /home/kali/Downloads/invoice.pdf    ← অথবা ফাইলের পাথ
phishscan> quit
```

**একটা জিনিস স্ক্যান:**
```bash
phishscan "https://সন্দেহজনক-লিংক.top/login"
phishscan suspicious.eml
phishscan photo_with_qr.jpg
phishscan update.apk
```

**নিরাপদে পরীক্ষা করে দেখুন (নকল স্যাম্পল দিয়ে):**
```bash
python3 tests/make_samples.py examples/
phishscan examples/phish_email.eml --offline
```

রিপোর্ট টার্মিনালে আসবে, আর `phishscan_evidence/` ফোল্ডারে HTML + JSON সেভ হবে।

---

## সমস্যা হলে
| সমস্যা | সমাধান |
|---|---|
| `command not found: phishscan` | উপায় A (`./install.sh`) চালান, অথবা `./phishscan.sh` ব্যবহার করুন |
| `externally-managed-environment` | উপায় A বা B ব্যবহার করুন |
| `Permission denied: ./install.sh` | আগে `chmod +x install.sh` |
| অন্য কিছু | `phishscan --doctor` চালিয়ে লাল ✗ দেখুন, অথবা README.bn.md-এর "সমস্যা সমাধান" |

পূর্ণ ব্যবহারবিধি: **[README.bn.md](README.bn.md)**

---
---

<a id="english-setup-guide"></a>
# 🚀 PhishScan — Full Setup Guide (English)

Every command from `git clone` to your first scan. Written for Kali Linux / Ubuntu / Debian.

## Step 0 — Prerequisites
```bash
python3 --version        # must be 3.9+
git --version            # if missing: sudo apt install git
```

## Step 1 — Clone from GitHub
Replace `YOUR-USERNAME` with your real GitHub username:
```bash
git clone https://github.com/YOUR-USERNAME/phishscan.git
cd phishscan
```

## Step 2 — Install (pick one)

**A — Installer script (easiest)** ✅
```bash
chmod +x install.sh phishscan.sh
./install.sh             # NOT sudo; it asks for a password itself if needed
```

**B — pipx**
```bash
sudo apt install -y pipx && pipx ensurepath   # then reopen the terminal
pipx install .
pipx inject phishscan pillow pyzbar oletools extract-msg androguard
```

**C — No install (run from the repo)**
```bash
pip install requests --break-system-packages
chmod +x phishscan.sh                          # then use ./phishscan.sh instead of phishscan
```

**D — Docker (safest)**
```bash
docker build -t phishscan .
docker run --rm -v "$PWD:/data" phishscan --doctor
```

## Step 3 — Verify the setup ✅
```bash
phishscan --doctor        # or ./phishscan.sh --doctor
```
Checks Python, packages, system tools and API keys, then runs a test scan. **All green ✓ and "everything is OK"** means you're ready. (API-key ✗ marks are fine — they're optional.)

## Step 4 — (Optional) free API keys
```bash
echo 'export VT_API_KEY="your_key"' >> ~/.zshrc        # virustotal.com/gui/my-apikey
echo 'export URLSCAN_API_KEY="your_key"' >> ~/.zshrc   # urlscan.io/user/profile/
source ~/.zshrc                                        # use ~/.bashrc if you use bash
```

## Step 5 — Run 🎉
```bash
phishscan                                  # interactive: paste link/file, repeat, 'quit' to exit
phishscan "https://suspicious.top/login"   # single scan
phishscan suspicious.eml                   # a file

# safe self-test with fake samples:
python3 tests/make_samples.py examples/
phishscan examples/phish_email.eml --offline
```

Reports print to the terminal and are saved as HTML + JSON under `phishscan_evidence/`.

Full usage: **[README.md](README.md)**
