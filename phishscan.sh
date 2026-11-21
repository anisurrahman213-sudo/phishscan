#!/usr/bin/env bash
# PhishScan লঞ্চার — ইনস্টল ছাড়াই রিপো থেকে চালানোর জন্য:  ./phishscan  বা  ./phishscan <লিংক/ফাইল>
# (install.sh চালালে system-wide `phishscan` কমান্ডও পাবেন)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$(command -v python3 || command -v python)"
if [ -z "$PY" ]; then echo "python3 পাওয়া যায়নি — আগে Python 3.9+ ইনস্টল করুন"; exit 1; fi
exec env PYTHONPATH="$DIR${PYTHONPATH:+:$PYTHONPATH}" "$PY" -m phishscan "$@"
