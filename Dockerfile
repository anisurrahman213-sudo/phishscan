# PhishScan — আলাদা কন্টেইনারে নিরাপদ বিশ্লেষণ
#
#   docker build -t phishscan .
#   docker run --rm -v "$PWD:/data" phishscan suspicious.eml
#   docker run --rm -e VT_API_KEY phishscan "hxxps://bad[.]top/login"
#
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends whois libimage-exiftool-perl libzbar0 zbar-tools p7zip-full ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY pyproject.toml README.md LICENSE ./
COPY phishscan ./phishscan
RUN pip install --no-cache-dir ".[full]" && rm -rf /src

# root হিসেবে না চালানো — ক্ষতিকর ফাইল বিশ্লেষণে বাড়তি নিরাপত্তা
RUN useradd --create-home --uid 1000 scanner
USER scanner
WORKDIR /data
ENV PYTHONUNBUFFERED=1

ENTRYPOINT ["phishscan"]
CMD ["--help"]
