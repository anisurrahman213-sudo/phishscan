#!/usr/bin/env bash
# PhishScan ইনস্টলার — Kali / Debian / Ubuntu
# ব্যবহার:  ./install.sh          (sudo দিয়ে চালাবেন না, প্রয়োজনে নিজেই পাসওয়ার্ড চাইবে)
# আনইনস্টল: ./install.sh --uninstall
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$HOME/.phishscan-venv"
OPTIONAL="pillow pyzbar oletools extract-msg androguard opencv-python-headless"

if [ "${1:-}" = "--uninstall" ]; then
  rm -rf "$VENV"
  sudo rm -f /usr/local/bin/phishscan
  echo "[+] PhishScan সরানো হয়েছে (প্রমাণ ফোল্ডার phishscan_evidence/ রেখে দেওয়া হয়েছে)"
  exit 0
fi

if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
  echo "[!] sudo ছাড়া চালান:  ./install.sh"
  exit 1
fi

echo "[1/4] সিস্টেম টুল ইনস্টল হচ্ছে..."
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -qq
  sudo apt-get install -y python3 python3-venv python3-pip whois libimage-exiftool-perl zbar-tools libzbar0 p7zip-full
  sudo apt-get install -y chromium 2>/dev/null || echo "    (chromium পাওয়া যায়নি — শুধু --screenshot কাজ করবে না)"
else
  echo "    apt নেই — python3 (3.9+), whois, exiftool, zbar নিজে ইনস্টল করুন"
fi

echo "[2/4] Python virtual environment: $VENV"
python3 -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q "$DIR"

echo "[3/4] ঐচ্ছিক প্যাকেজ (কোনোটা ব্যর্থ হলেও টুল চলবে)..."
for pkg in $OPTIONAL; do
  if "$VENV/bin/pip" install -q "$pkg"; then echo "    ✓ $pkg"; else echo "    ✗ $pkg (বাদ দেওয়া হলো)"; fi
done

echo "[4/4] 'phishscan' কমান্ড তৈরি হচ্ছে..."
sudo ln -sf "$VENV/bin/phishscan" /usr/local/bin/phishscan

echo
"$VENV/bin/phishscan" --version
echo "[+] সম্পন্ন!"
echo "    শুধু  phishscan  লিখলে ইন্টার‍্যাক্টিভ মোড — বারবার লিংক/ফাইল পেস্ট করুন"
echo "    অথবা  phishscan <লিংক বা ফাইল>"
echo "    API key ও কনফিগ: README.md দেখুন"
