#!/usr/bin/env python3
"""TBH-PhishDetector v3 - Heuristic phishing URL scorer (defensive, local-only)."""
import argparse, csv, json, math, re, sys
from urllib.parse import urlparse

VERSION = "3.0"
REPO = "https://github.com/TulungagungBlackHat/TBH-PhishDetector"

def banner():
    import os
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[91m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-PhishDetector v3\033[91m - 12 Signals  ║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[91m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

SUSPICIOUS_TLD = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work", ".click", ".link", ".rest"}
BRANDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook", "instagram",
          "whatsapp", "bank", "bni", "bca", "mandiri", "bri", "tokopedia", "shopee", "gojek", "dana"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "s.id", "v.gd"}
PATH_KEYWORDS = ["login", "signin", "verify", "secure", "account", "update", "confirm", "password", "banking", "wallet"]
HEURISTICS = [
    "ip-host", "long-url", "at-sign", "suspicious-tld", "punycode", "non-ascii",
    "no-https", "brand-in-host", "subdomain-depth", "shortener", "path-keyword", "high-entropy-host",
]

def entropy(s):
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())

def analyze(url):
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    domain = (parsed.hostname or "").lower()
    path = parsed.path.lower()
    score, reasons = 0, []

    def add(pts, why):
        nonlocal score
        score += pts
        reasons.append(why)

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        add(3, "ip-host")
    if len(raw) > 75:
        add(1, f"long-url:{len(raw)}")
    if "@" in raw:
        add(2, "at-sign")
    if any(domain.endswith(t) for t in SUSPICIOUS_TLD):
        add(2, "suspicious-tld")
    if "xn--" in domain:
        add(3, "punycode")
    try:
        domain.encode("ascii")
    except UnicodeEncodeError:
        add(3, "non-ascii")
    if not raw.lower().startswith("https"):
        add(1, "no-https")
    for b in BRANDS:
        if b in domain and not domain.endswith(b + ".com") and domain != b + ".com":
            add(2, f"brand-in-host:{b}")
            break
    labels = domain.split(".")
    if len(labels) >= 4:
        add(1, f"subdomain-depth:{len(labels)}")
    if domain in SHORTENERS or any(domain.endswith("." + s) for s in SHORTENERS):
        add(1, "shortener")
    if any(k in path for k in PATH_KEYWORDS):
        add(1, "path-keyword")
    core = domain.split(".")[0]
    if len(core) >= 12 and entropy(core) > 3.8:
        add(1, "high-entropy-host")

    score = min(score, 10)
    verdict = "PHISHING" if score >= 5 else "SUSPICIOUS" if score >= 3 else "SAFE"
    return {"url": raw, "score": score, "verdict": verdict, "reasons": reasons}

def main():
    import os
    parser = argparse.ArgumentParser(description=f"TBH-PhishDetector v{VERSION}")
    parser.add_argument("-u", "--url", help="single URL")
    parser.add_argument("-b", "--bulk", help="file with one URL per line")
    parser.add_argument("--min-score", type=int, default=0, help="only print/save results >= score")
    parser.add_argument("--csv", help="save CSV")
    parser.add_argument("--json", help="save JSON")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-PhishDetector {VERSION}")
    args = parser.parse_args()
    print(banner())

    use_color = not args.no_color and not os.environ.get("NO_COLOR")
    urls = []
    if args.bulk:
        try:
            with open(args.bulk) as fh:
                urls = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            print(color("91", f"[!] cannot read bulk file: {e}", use_color), file=sys.stderr)
            sys.exit(2)
    elif args.url:
        urls = [args.url]
    else:
        parser.error("need -u or -b")

    results = [analyze(u) for u in urls]
    if args.min_score:
        results = [r for r in results if r["score"] >= args.min_score]

    for r in results:
        vcolor = {"PHISHING": "91", "SUSPICIOUS": "93", "SAFE": "92"}[r["verdict"]]
        print(color(vcolor, f"[*] {r['url']} -> {r['score']}/10 {r['verdict']} {r['reasons']}", use_color))

    phish = sum(1 for r in results if r["verdict"] == "PHISHING")
    susp = sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
    print(f"\n[✓] {len(results)} URLs | phishing: {phish} | suspicious: {susp}")

    if args.csv:
        try:
            with open(args.csv, "w", newline="") as fh:
                w = csv.DictWriter(fh, fieldnames=["url", "score", "verdict", "reasons"])
                w.writeheader()
                for r in results:
                    w.writerow({**r, "reasons": "|".join(r["reasons"])})
            print(f"[✓] CSV: {args.csv}")
        except OSError as e:
            print(color("91", f"[!] cannot write CSV: {e}", use_color), file=sys.stderr)
            sys.exit(2)
    if args.json:
        report = {"tool": "TBH-PhishDetector", "version": VERSION,
                  "summary": {"total": len(results), "phishing": phish, "suspicious": susp},
                  "heuristics": HEURISTICS, "findings": results}
        try:
            with open(args.json, "w") as fh:
                json.dump(report, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    sys.exit(1 if phish else 0)

if __name__ == "__main__":
    main()
