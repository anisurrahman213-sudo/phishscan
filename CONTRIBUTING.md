# অবদান রাখার গাইড

PhishScan-কে আরও ভালো করতে আপনাকে স্বাগতম! 🙏

## ডেভেলপমেন্ট পরিবেশ
```bash
git clone https://github.com/YOUR-USERNAME/phishscan.git
cd phishscan
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,full]"
```

## কাজের আগে ও পরে
```bash
ruff check .                 # কোডের মান ও নিরাপত্তা নিয়ম
pytest -q --cov=phishscan    # সব টেস্ট (ইন্টারনেট লাগে না)
```
দুটোই পাস না করলে PR গ্রহণ করা হবে না। কভারেজ ৭৫%-এর নিচে নামলে CI ব্যর্থ হবে।

## কোড কোথায়
| ফাইল | কাজ |
|---|---|
| `phishscan/data.py` | ব্র্যান্ড, TLD, কীওয়ার্ড, আক্রমণের ধরন |
| `phishscan/urlcheck.py` | URL-এর অফলাইন বিশ্লেষণ |
| `phishscan/web.py` | পেজ ফেচ, রিডাইরেক্ট, HTML বিশ্লেষণ |
| `phishscan/infra.py` | DNS, RDAP/WHOIS, IP লোকেশন, SSL |
| `phishscan/reputation.py` | VirusTotal, urlscan.io |
| `phishscan/mail.py` | ইমেইল |
| `phishscan/files.py` | ছবি/QR, PDF, Office, APK, ZIP... |
| `phishscan/scanner.py` | URL স্ক্যানের প্রবাহ |
| `phishscan/report.py` | রিপোর্ট ও আউটপুট |
| `phishscan/cli.py` | কমান্ড লাইন |

## নতুন শনাক্তকরণ যোগ করার নিয়ম
1. লক্ষণ যোগ করুন: `rep.add(পয়েন্ট, "বিভাগ", "বাংলা বার্তা", "attack_type")`
2. **দুটো টেস্ট আবশ্যক:** একটা যেটা ধরা পড়বে, আর একটা আসল জিনিস যেটা ভুল করে ধরা পড়বে **না**
3. `docs/DETECTIONS.md`-এ পয়েন্ট ও কারণ লিখুন
4. `CHANGELOG.md` আপডেট করুন

পয়েন্ট নির্ধারণ: একা নিশ্চিত প্রমাণ হলে ২৫–৪৫, শক্ত সন্দেহ হলে ১০–২০, দুর্বল ইঙ্গিত হলে ৩–৮।

## কঠোর নিয়ম
- আসল ফিশিং লিংক, ম্যালওয়্যার, ব্যক্তিগত ইমেইল বা API key **কখনো কমিট করবেন না**
- টেস্ট স্যাম্পল `tests/make_samples.py`-এ কোড দিয়ে তৈরি করুন, কাল্পনিক ডোমেইন ব্যবহার করে
- টুল কখনো কোনো ফাইল **রান** বা ফর্ম **সাবমিট** করবে না, এমন কোনো পরিবর্তন গ্রহণযোগ্য নয়

## রিলিজ (মেইনটেইনার)
```bash
# pyproject.toml ও phishscan/__init__.py-তে ভার্সন বদলান, CHANGELOG আপডেট করুন
git tag v3.0.1 && git push --tags     # GitHub Release স্বয়ংক্রিয়ভাবে তৈরি হবে
```
