#!/usr/bin/env python3
"""TBH-Utils v3 - Everyday encoders, hashes, and JWT inspection (local only)."""
import argparse, base64, hashlib, hmac, json, sys, urllib.parse

VERSION = "3.0"
REPO = "https://github.com/TulungagungBlackHat/TBH-Utils"

def banner():
    import os
    if os.environ.get("NO_COLOR"):
        return ""
    return ("\033[96m╔════════════════════════════════════╗\n"
            "║ \033[97mTBH-Utils v3\033[96m - Codecs + JWT        \033[96m║\n"
            "║ \033[90mTulungagung Black Hat | uchil404 \033[96m║\n"
            "╚════════════════════════════════════╝\033[0m")

def rot13(s):
    out = []
    for c in s:
        if "a" <= c <= "z":
            out.append(chr((ord(c) - 97 + 13) % 26 + 97))
        elif "A" <= c <= "Z":
            out.append(chr((ord(c) - 65 + 13) % 26 + 65))
        else:
            out.append(c)
    return "".join(out)

def b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

def jwt_inspect(token):
    parts = token.split(".")
    if len(parts) != 3:
        return {"error": "not a JWT (expected 3 dot-separated parts)"}
    try:
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
    except Exception as e:
        return {"error": f"decode failed: {e}"}
    import time
    now = time.time()
    exp = payload.get("exp")
    expired = (exp < now) if isinstance(exp, (int, float)) else None
    alg = header.get("alg", "")
    return {"header": header, "payload": payload, "alg": alg,
            "none_vulnerable": alg.lower() == "none",
            "expired": expired,
            "note": "signature NOT verified - inspect claims only"}

def main():
    import os
    parser = argparse.ArgumentParser(description=f"TBH-Utils v{VERSION}")
    parser.add_argument("action", choices=["qr", "b64e", "b64d", "urle", "urld", "hash",
                                           "hmac", "count", "hexe", "hexd", "rot13", "jwt"])
    parser.add_argument("-t", "--text", required=True, help="input text ('-' = read stdin)")
    parser.add_argument("-k", "--key", help="HMAC key (for hmac action)")
    parser.add_argument("--json", help="save JSON")
    parser.add_argument("--no-color", action="store_true")
    parser.add_argument("--version", action="version", version=f"TBH-Utils {VERSION}")
    args = parser.parse_args()
    print(banner())
    use_color = not args.no_color and not os.environ.get("NO_COLOR")

    text = sys.stdin.read() if args.text == "-" else args.text
    result = {"tool": "TBH-Utils", "version": VERSION, "action": args.action}

    try:
        if args.action == "b64e":
            result["output"] = base64.b64encode(text.encode()).decode()
        elif args.action == "b64d":
            result["output"] = base64.b64decode(text).decode("utf-8", "replace")
        elif args.action == "urle":
            result["output"] = urllib.parse.quote(text, safe="")
        elif args.action == "urld":
            result["output"] = urllib.parse.unquote(text)
        elif args.action == "hexe":
            result["output"] = text.encode().hex()
        elif args.action == "hexd":
            result["output"] = bytes.fromhex(text.strip()).decode("utf-8", "replace")
        elif args.action == "rot13":
            result["output"] = rot13(text)
        elif args.action == "hash":
            result["md5"] = hashlib.md5(text.encode()).hexdigest()
            result["sha1"] = hashlib.sha1(text.encode()).hexdigest()
            result["sha256"] = hashlib.sha256(text.encode()).hexdigest()
        elif args.action == "hmac":
            if not args.key:
                print("[!] hmac needs -k KEY", file=sys.stderr)
                sys.exit(2)
            result["hmac_sha256"] = hmac.new(args.key.encode(), text.encode(), hashlib.sha256).hexdigest()
        elif args.action == "count":
            result["chars"] = len(text)
            result["words"] = len(text.split())
            result["lines"] = text.count("\n") + 1
        elif args.action == "jwt":
            result.update(jwt_inspect(text.strip()))
        elif args.action == "qr":
            try:
                import qrcode
            except ImportError:
                print("[!] pip install qrcode[pil]", file=sys.stderr)
                sys.exit(2)
            qrcode.make(text).save("qrcode.png")
            result["output"] = "qrcode.png"
    except ValueError as e:
        print(color("91" if use_color else "", f"[!] decode error: {e}", use_color), file=sys.stderr)
        sys.exit(2)

    for k, v in result.items():
        if k in ("tool", "version", "action"):
            continue
        print(f"{k}: {v}")

    if args.json:
        try:
            with open(args.json, "w") as fh:
                json.dump(result, fh, indent=2)
            print(f"[✓] JSON: {args.json}")
        except OSError as e:
            print(f"[!] cannot write JSON: {e}", file=sys.stderr)
            sys.exit(2)
    sys.exit(0)

if __name__ == "__main__":
    main()
