# পরিবর্তনের তালিকা (Changelog)

এই প্রজেক্ট [Semantic Versioning](https://semver.org/) মেনে চলে: `MAJOR.MINOR.PATCH`।

## [3.1.0] — 2026-11-21
### নতুন ফিচার
- **ইন্টার‍্যাক্টিভ মোড:** আর্গুমেন্ট ছাড়া `phishscan` (বা `./phishscan.sh`) চালালে বারবার লিংক/ফাইল পেস্ট করে স্ক্যান করা যায়; পাইপও চলে (`cat urls.txt | phishscan`)। `.csv` ফাইল থেকেও লিংক পড়ে
- **crt.sh (Certificate Transparency):** একই প্রতারকের লুকানো সাবডোমেইন ও একই ব্র্যান্ড নকল করা অন্য ডোমেইন খুঁজে বের করে — কোনো API key ছাড়াই। `--no-related` দিয়ে বন্ধ করা যায়
- **ক্যাম্পেইন ফিঙ্গারপ্রিন্ট:** exfil চ্যানেল (Telegram বট/সার্ভার/ওয়ালেট) + হোস্টিং মিলিয়ে একটা আইডি — একাধিক ফিশিং একই দল থেকে কিনা চেনায় (অফলাইনেও কাজ করে, টোকেন ফাঁস হয় না)
- **`--doctor` সেল্ফ-চেক:** সেটআপ (Python, প্যাকেজ, টুল, API key) ঠিক আছে কিনা নিজে যাচাই করে + একটা টেস্ট স্ক্যান চালায়
- **`SETUP.md`:** clone থেকে প্রথম স্ক্যান পর্যন্ত পূর্ণ সেটআপ গাইড (বাংলা+ইংরেজি)
- **দ্বিভাষিক README:** `README.md` (English) ও `README.bn.md` (বাংলা), উপরে ক্লিক করে ভাষা পাল্টানোর লিংক
### উন্নতি
- টেস্ট ৬৭ → ৭৭, কভারেজ ৮২%; crt.sh ও ফিঙ্গারপ্রিন্ট নকল সার্ভার উত্তর দিয়ে টেস্ট
- নতুন মডিউল `phishscan/intel.py`

## [3.0.0] — 2026-11-21
### প্রফেশনাল কাঠামো
- এক ফাইলের কোড ১৫টি মডিউলে ভাগ (`phishscan/` প্যাকেজ)
- `pip install` / `pipx install` / Docker দিয়ে ইনস্টল; `phishscan` ও `python -m phishscan` কমান্ড
- Python API: `from phishscan import scan`
- **কনফিগ ফাইল** `brands.json` — কোড না ছুঁয়ে নতুন ব্যাংক/প্রতিষ্ঠান যোগ (`--brands` বা `~/.config/phishscan/brands.json`)
- `install.sh --uninstall`
### মান ও নিরাপত্তা
- ৬৬টি টেস্ট, ৮১% কোড কভারেজ; VirusTotal/urlscan/RDAP/IP লোকেশন নকল সার্ভার উত্তর দিয়ে টেস্ট
- ruff (নিরাপত্তা নিয়ম সহ), CodeQL, Dependabot
- CI: ৪টি Python ভার্সন, wheel বিল্ড ও ইনস্টল, Docker বিল্ড
- ট্যাগ দিলে স্বয়ংক্রিয় GitHub Release
- Issue/PR টেমপ্লেট, CONTRIBUTING গাইড

## [2.0] — 2026-11-20
- পূর্ণ অডিট: ৭টি বাগ ঠিক (false positive, `.msg` ক্র্যাশ, APK অনুমতি মিস, broken pipe ইত্যাদি)
- Outlook `.msg`, ডিফ্যাং লিংক, Facebook/Google রিডাইরেক্ট লিংক খোলা, VirusTotal রেট-লিমিট, exit code, `--quiet`
- ৪৭টি টেস্ট, GitHub Actions

## [1.1] — 2026-11-20
- 403/cloaking শনাক্ত, মোবাইল ব্রাউজার হিসেবে পুনরায় চেষ্টা, API key ত্রুটির পরিষ্কার বার্তা

## [1.0] — 2026-11-20
- প্রথম সংস্করণ: URL, ইমেইল, ছবি/QR, PDF, Office, APK, ZIP, HTML বিশ্লেষণ; বাংলা রিপোর্ট
