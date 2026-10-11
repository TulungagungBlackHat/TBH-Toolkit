#!/usr/bin/env python3
"""tbh scan - run a bunch of tools against one target, one report.

quick mode = recon + the cheap detectors. --deep also hits subdomains,
dirs, js secrets, ports, phish check. logs land in ~/.tbh/logs/.
"""
import argparse
import datetime
import html as html_mod
import json
import os
import subprocess
import sys

VERSION = "1.0"
TBH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tbh"))
HOME = os.path.expanduser("~/.tbh")

CORE = ["recon", "cors", "xss", "sqli", "lfi", "ssrf", "ssti", "redirect", "idor"]
DEEP_ONLY = ["subfinder", "dirfinder", "jsleak", "portscan", "phish"]
# most tools want -u, these want -t
TARGET_FLAG = {"portscan": "-t", "subfinder": "-t"}
# flags a tool actually understands (see dispatcher SUPPORT matrix)
HAS = {
    "subfinder": {"--proxy", "--timeout"},
    "portscan": {"--timeout"},
    "phish": set(), "utils": set(), "passstrength": set(),
}
DEFAULT_HAS = {"--proxy", "--cookie", "--timeout", "-H"}

def color(code, text, enabled=True):
    if not enabled or os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return text
    return f"\033[{code}m{text}\033[0m"

def build_parser():
    p = argparse.ArgumentParser(
        prog="tbh scan",
        description="multi-tool scan against one target, combined json/html report")
    p.add_argument("-u", "--url", required=True, help="target url")
    p.add_argument("--only", help="comma list of tools (overrides mode)")
    p.add_argument("--skip", help="comma list of tools to skip")
    p.add_argument("--deep", action="store_true",
                   help="core + subfinder, dirfinder, jsleak, portscan, phish")
    p.add_argument("--proxy", help="proxy url forwarded to tools that support it")
    p.add_argument("--cookie", help="cookie forwarded to web tools")
    p.add_argument("-H", "--header", action="append", default=[],
                   help="extra header, repeatable")
    p.add_argument("--timeout", type=int, help="per-request timeout forwarded")
    p.add_argument("--json", help="write combined json here")
    p.add_argument("--html", help="write combined html report here")
    p.add_argument("--verbose", action="store_true", help="stream tool output live")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"tbh-scan {VERSION}")
    return p

def pick_tools(args):
    if args.only:
        tools = [t.strip() for t in args.only.split(",") if t.strip()]
    else:
        tools = list(CORE)
        if args.deep:
            tools += DEEP_ONLY
    if args.skip:
        skip = {t.strip() for t in args.skip.split(",")}
        tools = [t for t in tools if t not in skip]
    return tools

def passthrough(tool, args):
    allowed = HAS.get(tool, DEFAULT_HAS)
    out = []
    if args.proxy and "--proxy" in allowed:
        out += ["--proxy", args.proxy]
    if args.cookie and "--cookie" in allowed:
        out += ["--cookie", args.cookie]
    if args.timeout and "--timeout" in allowed:
        out += ["--timeout", str(args.timeout)]
    if args.header and "-H" in allowed:
        for h in args.header:
            out += ["-H", h]
    return out

def load_child_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}

def write_html(path, combined):
    esc = html_mod.escape
    sev = combined["summary"]["by_severity"]
    rows = "".join(
        f"<tr><td>{esc(str(f.get('severity','info')))}</td>"
        f"<td>{esc(str(f.get('tool','')))}</td>"
        f"<td>{esc(str(f.get('url', f.get('target',''))))}</td>"
        f"<td>{esc(str(f.get('detail', f.get('evidence',''))))[:200]}</td></tr>"
        for f in combined["findings"])
    tools_rows = "".join(
        f"<tr><td>{esc(name)}</td><td>{esc(str(st.get('status','')))}</td>"
        f"<td>{st.get('findings',0)}</td><td>{esc(st.get('log',''))}</td></tr>"
        for name, st in combined["modules"].items())
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<title>tbh scan - {esc(combined['target'])}</title>
<style>
body{{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#222}}
h1{{color:#b00}} .cards span{{display:inline-block;background:#f4f4f4;padding:.5rem 1rem;margin-right:.5rem;border-radius:6px}}
table{{border-collapse:collapse;margin:1rem 0}} td,th{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left}}
th{{background:#fafafa}} .c{{color:#060}} .h{{color:#b00}} .m{{color:#a60}} .i{{color:#555}}
</style></head><body>
<h1>tbh scan</h1>
<p><b>{esc(combined['target'])}</b> — {esc(combined['started'])} — toolset v{esc(str(VERSION))}</p>
<div class="cards">
<span class="h">high: {sev.get('high',0)}</span>
<span class="m">medium: {sev.get('medium',0)}</span>
<span class="i">info/low: {sev.get('info',0)+sev.get('low',0)}</span>
<span>tools: {len(combined['modules'])}</span>
</div>
<h2>findings</h2>
<table><tr><th>sev</th><th>tool</th><th>url</th><th>detail</th></tr>{rows or '<tr><td colspan=4><i>none</i></td></tr>'}</table>
<h2>tools</h2>
<table><tr><th>tool</th><th>status</th><th>findings</th><th>log</th></tr>{tools_rows}</table>
<p><i>generated by tbh - authorized testing only</i></p>
</body></html>"""
    with open(path, "w") as f:
        f.write(doc)

def main():
    args = build_parser().parse_args()
    nc = args.no_color
    tools = pick_tools(args)
    if not tools:
        print(color("91", "[!] nothing to run (check --only/--skip)", not nc), file=sys.stderr)
        return 2

    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    logdir = os.path.join(HOME, "logs", f"scan-{ts}")
    os.makedirs(logdir, exist_ok=True)

    started = datetime.datetime.now().isoformat(timespec="seconds")
    print(color("91", f"[scan] {args.url}", not nc) +
          color("90", f"  {len(tools)} tools -> {logdir}", not nc), flush=True)

    modules, flat = {}, []
    worst = 0
    for i, tool in enumerate(tools, 1):
        jp = os.path.join(logdir, f"{tool}.json")
        lp = os.path.join(logdir, f"{tool}.log")
        flag = TARGET_FLAG.get(tool, "-u")
        cmd = [sys.executable, TBH, tool, flag, args.url, "--json", jp]
        cmd += passthrough(tool, args)
        print(f"[{i}/{len(tools)}] {tool:<12}", end="", flush=True)
        try:
            with open(lp, "w") as logf:
                if args.verbose:
                    rc = subprocess.call(cmd, stdout=None, stderr=subprocess.STDOUT)
                else:
                    rc = subprocess.call(cmd, stdout=logf, stderr=subprocess.STDOUT)
        except OSError:
            rc = 127
        child = load_child_json(jp)
        findings = child.get("findings") or []
        if isinstance(findings, dict):
            findings = list(findings.values())
        for f in findings:
            if isinstance(f, dict):
                f.setdefault("tool", tool)
                flat.append(f)
        status = "ok" if rc == 0 else ("findings" if rc == 1 else f"error({rc})")
        if rc not in (0, 1):
            worst = 2
        elif rc == 1 and worst != 2:
            worst = 1
        mark = color("92", " ok ", not nc) if rc == 0 else (
            color("93", " hit " if rc == 1 else " err ", not nc))
        print(f"{mark}{color('90', status if rc else f'{len(findings)} findings', not nc)}", flush=True)
        modules[tool] = {"status": status, "exit": rc, "findings": len(findings),
                         "log": lp if not args.verbose else "(live)"}

    by_sev = {}
    for f in flat:
        s = str(f.get("severity", "info")).lower()
        by_sev[s] = by_sev.get(s, 0) + 1
    combined = {
        "tool": "scan", "version": VERSION, "target": args.url, "started": started,
        "modules": modules, "findings": flat,
        "summary": {"findings": len(flat), "by_severity": by_sev,
                    "tools": len(modules),
                    "clean": sum(1 for m in modules.values() if m["exit"] == 0),
                    "failed": sum(1 for m in modules.values() if m["exit"] not in (0, 1))},
    }

    if flat:
        try:
            os.makedirs(HOME, exist_ok=True)
            with open(os.path.join(HOME, "findings.jsonl"), "a") as jf:
                for f in flat:
                    rec = {"when": started, "via": "scan", "target": args.url}
                    rec.update(f)
                    jf.write(json.dumps(rec) + "\n")
        except OSError:
            pass

    if args.json:
        with open(args.json, "w") as f:
            json.dump(combined, f, indent=2)
        print(color("90", f"[+] json -> {args.json}", not nc))
    if args.html:
        write_html(args.html, combined)
        print(color("90", f"[+] html -> {args.html}", not nc))

    tot = len(flat)
    print(color("90", f"[*] done: {len(modules)} tools, {tot} findings "
                      f"(high={by_sev.get('high', 0)} med={by_sev.get('medium', 0)})", not nc))
    return worst

if __name__ == "__main__":
    sys.exit(main() or 0)
