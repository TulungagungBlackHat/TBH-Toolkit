#!/usr/bin/env python3
"""TBH-PassStrength v3 - Password strength checker + generator (defensive)."""
import argparse, json, math, re, secrets, string, sys

VERSION = "3.0"
REPO = "https://github.com/TulungagungBlackHat/TBH-PassStrength"

def banner():
    import os
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[92m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-PassStrength v3\033[92m - Score+Passphrase║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[92m║\n"
            "╚════════════════════════════════════╝\033[0m")

def color(code, text, enabled=True):
    return f"\033[{code}m{text}\033[0m" if enabled else text

COMMON = [
    "123456", "password", "qwerty", "admin", "12345678", "iloveyou", "123123",
    "abc123", "letmein", "monkey", "dragon", "football", "baseball", "master",
    "welcome", "login", "princess", "solo", "passw0rd", "starwars", "whatever",
    "trustno1", "superman", "shadow", "michael", "jennifer", "hunter", "ranger",
    "summer2026", "winter2026", "password1", "qwerty123", "1q2w3e4r", "1qaz2wsx",
]
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

def has_year(pwd):
    return bool(re.search(r"(19|20)\d{2}", pwd))

def keyboard_walk(pwd):
    low = pwd.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - 3):
            seq = row[i:i + 4]
            if seq in low or seq[::-1] in low:
                return True
    return False

def entropy_bits(pwd):
    pool = 0
    if re.search(r"[a-z]", pwd):
        pool += 26
    if re.search(r"[A-Z]", pwd):
        pool += 26
    if re.search(r"\d", pwd):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", pwd):
        pool += 33
    if not pwd:
        return 0.0
    return len(pwd) * math.log2(pool) if pool else 0.0

def check(pwd):
    score, adv = 0, []
    if len(pwd) >= 16:
        score += 2
    elif len(pwd) >= 12:
        score += 1
    else:
        adv.append("min 12 chars")
    if re.search(r"[A-Z]", pwd):
        score += 1
    else:
        adv.append("uppercase letter")
    if re.search(r"[a-z]", pwd):
        score += 1
    else:
        adv.append("lowercase letter")
    if re.search(r"\d", pwd):
        score += 1
    else:
        adv.append("digit")
    if re.search(r"[^A-Za-z0-9]", pwd):
        score += 2
    else:
        adv.append("symbol")

    if pwd.lower() in COMMON:
        score, adv = 0, ["common password"]
    if len(set(pwd)) <= 3:
        score = min(score, 1)
        adv.append("too few unique chars")
    if keyboard_walk(pwd):
        score = max(0, score - 2)
        adv.append("keyboard walk (qwerty/1qaz...)")
    if has_year(pwd):
        score = max(0, score - 1)
        adv.append("contains year")
    if pwd.lower().rstrip("0123456789!") in COMMON:
        score = max(0, score - 2)
        adv.append("common base + decoration")

    score = max(0, min(7, score))
    bits = round(entropy_bits(pwd), 1)
    verdict = ("VERY STRONG" if score >= 6 else "STRONG" if score >= 4
               else "WEAK" if score >= 2 else "VERY WEAK")
    return score, bits, verdict, adv

PASSPHRASE_WORDS = [
    "correct", "horse", "battery", "staple", "hunter", "orange", "planet",
    "river", "copper", "forest", "guitar", "harbor", "igloo", "jungle",
    "kettle", "lemon", "marble", "nectar", "orbit", "pebble", "quartz",
    "raven", "silver", "tunnel", "velvet", "willow", "yonder", "zenith",
    "anchor", "blossom", "canyon", "drifter", "ember", "falcon", "glacier",
]

def generate_password(length=16):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    pwd = [secrets.choice(string.ascii_uppercase), secrets.choice(string.ascii_lowercase),
           secrets.choice(string.digits), secrets.choice("!@#$%^&*")]
    pwd += [secrets.choice(chars) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd)

def generate_passphrase(words=4):
    rng = secrets.SystemRandom()
    picked = [rng.choice(PASSPHRASE_WORDS) for _ in range(words)]
    return "-".join(picked) + "-" + str(rng.randint(10, 99))

def main():
    import os
    parser = argparse.ArgumentParser(description=f"TBH-PassStrength v{VERSION}")
    parser.add_argument("-p", "--password", help="password to check")
    parser.add_argument("-g", "--generate", action="store_true", help="generate random password")
    parser.add_argument("--passphrase", action="store_true", help="generate memorable passphrase")
    parser.add_argument("-l", "--length", type=int, default=16, help="password length (default 16)")
    parser.add_argument("-w", "--words", type=int, default=4, help="passphrase words (default 4)")
    parser.add_argument("--json", help="save JSON")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-PassStrength {VERSION}")
    args = parser.parse_args()
    print(banner())
    use_color = not args.no_color and not os.environ.get("NO_COLOR")

    if args.generate:
        pwd = generate_password(args.length)
    elif args.passphrase:
        pwd = generate_passphrase(args.words)
    else:
        pwd = args.password or input("Password: ")

    score, bits, verdict, adv = check(pwd)
    vcolor = "92" if score >= 4 else "93" if score >= 2 else "91"
    display = pwd if (args.generate or args.passphrase) else "*" * len(pwd)
    print(color(vcolor, f"[+] {display} | {score}/7 {verdict} | ~{bits} bits entropy", use_color))
    if adv:
        print(f"    Advice: {', '.join(adv)}")

    if args.json:
        result = {"tool": "TBH-PassStrength", "version": VERSION,
                  "password": pwd if (args.generate or args.passphrase) else None,
                  "score": score, "entropy_bits": bits, "verdict": verdict, "advice": adv}
        try:
            with open(args.json, "w") as fh:
                json.dump(result, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(color("91", f"[!] cannot write JSON: {e}", use_color), file=sys.stderr)
            sys.exit(2)

    sys.exit(0 if score >= 4 else 1)

if __name__ == "__main__":
    main()
