"""Professional CLI: toolkit <command> with safety, JSON/human output, exit codes."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from toolkit import __version__
from toolkit.core.config import DEFAULT_TOML, ToolkitConfig
from toolkit.core.logging_setup import get_logger, setup_logging
from toolkit.core.models import ScanResult
from toolkit.core.safety import SafetyError, validate_target

log = get_logger("cli")

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_SAFETY = 3
EXIT_FINDINGS = 10


def _add_global(p: argparse.ArgumentParser) -> None:
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    p.add_argument("--timeout", type=float, default=None)
    p.add_argument("--config", default=None)
    p.add_argument("--allow-external", action="store_true")
    p.add_argument("--confirm-external", action="store_true")
    p.add_argument("--format", choices=["json", "html", "md", "csv"], default=None)
    p.add_argument("-o", "--output", default=None)


def _ctx(args) -> ToolkitConfig:
    cfg = ToolkitConfig.load(args.config)
    if args.timeout:
        cfg.timeout = args.timeout
    lvl = "DEBUG" if args.verbose else ("ERROR" if args.quiet else cfg.log_level)
    setup_logging(lvl)
    return cfg


def _emit(obj: dict, as_json: bool, quiet: bool = False) -> None:
    if as_json or quiet and False:
        print(json.dumps(obj, indent=2))
    elif as_json:
        print(json.dumps(obj, indent=2))


def _print_findings(results: list[ScanResult], as_json: bool, quiet: bool) -> None:
    if as_json:
        print(json.dumps([r.to_dict() for r in results], indent=2))
        return
    for r in results:
        if not quiet:
            print(f"[*] {r.module} :: {r.target} ({r.duration_s}s, {len(r.findings)} findings, highest={r.highest_severity()})")
        for f in r.findings:
            mark = {"CRITICAL": "[!!]", "HIGH": "[!]", "MEDIUM": "[~]", "LOW": "[-]", "INFO": "[*]"}[f.severity]
            print(f"  {mark} {f.severity:8} {f.title}")
            if f.endpoint:
                print(f"      endpoint: {f.endpoint[:120]}")
            if f.evidence and f.severity in ("HIGH", "CRITICAL", "MEDIUM"):
                print(f"      evidence: {f.evidence[:200]}")
            if f.remediation and f.severity != "INFO":
                print(f"      fix: {f.remediation[:160]}")


def cmd_info(args) -> int:
    info = {"name": "tbh-security-toolkit", "version": __version__,
            "modules": ["web", "recon", "network.ports", "vuln(xss/sqli/lfi/ssrf/redirect/ssti/idor/dirs/jsleak/cors)",
                        "osint.phish", "lab.auth", "analyzer.integrity", "network.loadtest", "reporting"],
            "policy": "authorized lab-only by default; external needs --allow-external --confirm-external"}
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print(f"TBH Security Toolkit v{__version__} - authorized defensive testing")
        print("Modules: " + ", ".join(info["modules"]))
        print("Policy: " + info["policy"])
    return EXIT_OK


def cmd_doctor(args) -> int:
    import socket
    cfg = _ctx(args)
    checks = []
    checks.append({"name": "python", "ok": sys.version_info >= (3, 11), "detail": sys.version.split()[0]})
    try:
        import requests  # noqa
        checks.append({"name": "requests", "ok": True, "detail": "installed"})
    except ImportError:
        checks.append({"name": "requests", "ok": False, "detail": "missing: pip install requests"})
    try:
        socket.gethostbyname("localhost")
        checks.append({"name": "dns-local", "ok": True, "detail": "localhost resolves"})
    except OSError as e:
        checks.append({"name": "dns-local", "ok": False, "detail": str(e)})
    checks.append({"name": "config", "ok": True, "detail": str(ToolkitConfig.default_path())})
    ok = all(c["ok"] for c in checks)
    if args.json:
        print(json.dumps({"ok": ok, "checks": checks, "config": cfg.to_dict()}, indent=2))
    else:
        for c in checks:
            print(f"[{'OK' if c['ok'] else 'FAIL'}] {c['name']}: {c['detail']}")
    return EXIT_OK if ok else EXIT_USAGE


def _guarded_host(target: str, args) -> str:
    try:
        return validate_target(target, allow_external=args.allow_external or ToolkitConfig.load(args.config).allow_external,
                               confirm_external=args.confirm_external)
    except SafetyError as e:
        print(f"[!] Safety blocked: {e}", file=sys.stderr)
        raise SystemExit(EXIT_SAFETY)


def cmd_web(args) -> int:
    from toolkit.scanners.web import scan_web
    cfg = _ctx(args)
    host = _guarded_host(args.target, args)
    r = scan_web(args.target, timeout=cfg.timeout, user_agent=cfg.user_agent)
    results = [r]
    _maybe_write_report(results, args)
    _print_findings(results, args.json, args.quiet)
    return _exit_for(results, args)


def cmd_headers(args) -> int:
    from toolkit.core.http import build_session
    from toolkit.scanners.web import check_security_headers
    from toolkit.core.models import Finding
    cfg = _ctx(args)
    _guarded_host(args.target, args)
    base = args.target if args.target.startswith("http") else "http://" + args.target
    s = build_session(timeout=cfg.timeout, user_agent=cfg.user_agent)
    try:
        resp = s.get(base, timeout=cfg.timeout)
        findings = check_security_headers(resp, resp.url)
        r = ScanResult(target=resp.url, module="web.headers",
                       started_at=datetime.now(timezone.utc).isoformat(), findings=findings)
    except Exception as e:
        r = ScanResult(target=args.target, module="web.headers",
                       started_at=datetime.now(timezone.utc).isoformat(),
                       findings=[Finding(id="http-error", title="fetch failed", severity="MEDIUM",
                                         endpoint=base, evidence=str(e)[:200], explanation="unreachable",
                                         remediation="check target", module="web.headers")])
    _maybe_write_report([r], args)
    _print_findings([r], args.json, args.quiet)
    return _exit_for([r], args)


def cmd_dns(args) -> int:
    from toolkit.recon.recon import dns_info
    _ctx(args)
    domain = args.domain
    try:
        _guarded_host(domain, args)
    except SystemExit as e:
        return int(str(e.code)) if str(e.code).isdigit() else EXIT_SAFETY
    info = dns_info(domain)
    print(json.dumps(info, indent=2) if args.json else f"{domain} -> {info.get('ip', info)}")
    return EXIT_OK if "ip" in info else EXIT_USAGE


def cmd_ports(args) -> int:
    from toolkit.network.diagnostics import scan_ports
    cfg = _ctx(args)
    host = _guarded_host(args.target, args)
    ports = _parse_ports(args.ports)
    r = scan_ports(host, ports, timeout=cfg.timeout, threads=min(args.threads, cfg.max_concurrency), rate_rps=cfg.rate_rps)
    _maybe_write_report([r], args)
    _print_findings([r], args.json, args.quiet)
    return _exit_for([r], args)


def cmd_ssl(args) -> int:
    from toolkit.scanners.web import check_tls
    _ctx(args)
    host = _guarded_host(args.target, args)
    findings = check_tls(host)
    r = ScanResult(target=host, module="web.tls", started_at=datetime.now(timezone.utc).isoformat(), findings=findings)
    _maybe_write_report([r], args)
    _print_findings([r], args.json, args.quiet)
    return _exit_for([r], args)


def cmd_recon(args) -> int:
    from toolkit.recon.recon import scan_recon
    cfg = _ctx(args)
    _guarded_host(args.target, args)
    r = scan_recon(args.target, timeout=cfg.timeout, user_agent=cfg.user_agent,
                   active=args.active, include_subs=args.subs)
    _maybe_write_report([r], args)
    _print_findings([r], args.json, args.quiet)
    return _exit_for([r], args)


def cmd_scan(args) -> int:
    from toolkit.recon.recon import scan_recon
    from toolkit.scanners.web import scan_web
    from toolkit.scanners.vuln import scan_vuln
    cfg = _ctx(args)
    _guarded_host(args.target, args)
    results = [
        scan_recon(args.target, timeout=cfg.timeout, user_agent=cfg.user_agent),
        scan_web(args.target, timeout=cfg.timeout, user_agent=cfg.user_agent),
        scan_vuln(args.target, checks=["xss", "sqli", "cors"], timeout=cfg.timeout, user_agent=cfg.user_agent),
    ]
    _maybe_write_report(results, args)
    _print_findings(results, args.json, args.quiet)
    return _exit_for(results, args)


def cmd_osint(args) -> int:
    _ctx(args)
    if args.mode == "url":
        from toolkit.osint.phish import analyze_url
        res = analyze_url(args.value)
        print(json.dumps(res, indent=2) if args.json else f"{res['verdict']} ({res['score']}): {res['reasons']}")
    else:
        from toolkit.lab.auth import password_audit
        res = password_audit(args.value)
        masked = {"score": res["score"], "max": res["max"], "verdict": res["verdict"],
                  "advice": res["advice"], "length": res["length"]}
        print(json.dumps(masked, indent=2) if args.json else f"{res['verdict']} {res['score']}/{res['max']}: {res['advice']}")
    return EXIT_OK


def cmd_loadtest(args) -> int:
    from toolkit.network.loadtest import run_loadtest
    cfg = _ctx(args)
    _guarded_host(args.target, args)
    stats = run_loadtest(args.target, requests_n=args.requests, concurrency=min(args.concurrency, cfg.max_concurrency),
                         rate=args.rate, timeout=cfg.timeout, path=args.path)
    s = stats.summary()
    if args.json:
        print(json.dumps(s, indent=2))
    else:
        print(f"[loadtest] {s['target']}: {s['requests']} req in {s['duration_s']}s = {s['rps']} rps, errors={s['errors']} ({s['error_rate']*100:.1f}%)")
        print(f"  latency ms: {s['latency_ms']}")
        print(f"  status: {s['status_distribution']}")
    if args.output:
        Path(args.output).write_text(json.dumps(s, indent=2))
        print(f"[wrote] {args.output}")
    return EXIT_OK


def cmd_integrity(args) -> int:
    from toolkit.analyzer.integrity import build_baseline, check_against_baseline
    _ctx(args)
    if args.mode == "baseline":
        base = build_baseline(args.path)
        Path(args.baseline).write_text(json.dumps(base, indent=2))
        print(f"[wrote baseline] {args.baseline} ({len(base['files'])} files)")
    else:
        base = json.loads(Path(args.baseline).read_text())
        rep = check_against_baseline(args.path, base)
        print(json.dumps(rep, indent=2) if args.json else
              f"NEW={rep['counts']['new']} MODIFIED={rep['counts']['modified']} DELETED={rep['counts']['deleted']} SUSPICIOUS={rep['counts']['suspicious']}")
        for k in ("NEW", "MODIFIED", "DELETED", "SUSPICIOUS"):
            for p in rep[k][:20]:
                print(f"  [{k}] {p}")
    return EXIT_OK


def cmd_lab(args) -> int:
    _ctx(args)
    if args.mode == "auth-audit":
        from toolkit.lab.auth import LockoutSimulator, password_audit
        pw = password_audit(args.password or "Password123!")
        sim = LockoutSimulator()
        demo = [sim.attempt(False) for _ in range(6)]
        out = {"password": {"score": pw["score"], "verdict": pw["verdict"], "advice": pw["advice"]},
               "lockout_demo": demo, "lesson": "Real apps: Argon2/bcrypt, rate-limit, lockout, MFA, audit log."}
        print(json.dumps(out, indent=2) if args.json else
              f"password: {pw['verdict']} {pw['advice']}\nlockout demo: {demo[-1]}")
    elif args.mode == "serve":
        from http.server import BaseHTTPRequestHandler, HTTPServer
        from toolkit.lab.auth import demo_app_html
        html = demo_app_html()

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
                self.wfile.write(html.encode())
            def do_POST(self):
                self.send_response(200); self.send_header("Content-Type", "text/plain"); self.end_headers()
                self.wfile.write(b"demo only: credentials NOT stored, NOT forwarded. See lesson in HTML.")
            def log_message(self, *a):
                pass
        srv = HTTPServer(("127.0.0.1", args.port), H)
        print(f"[lab] vulnerable demo app on http://127.0.0.1:{args.port} (Ctrl+C to stop)")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\n[lab] stopped")
    return EXIT_OK


def cmd_report(args) -> int:
    from toolkit.reporting.engine import write_report
    data = json.loads(Path(args.input).read_text())
    items = data.get("results", data if isinstance(data, list) else [data])
    results = []
    for it in items:
        from toolkit.core.models import Finding
        results.append(ScanResult(target=it.get("target", "?"), module=it.get("module", "?"),
                                 started_at=it.get("started_at", ""), duration_s=it.get("duration_s", 0.0),
                                 findings=[Finding(**f) for f in it.get("findings", [])], meta=it.get("meta", {})))
    fmt = args.format or "html"
    out = args.output or f"report.{fmt}"
    write_report(results, fmt, out)
    print(f"[wrote] {out}")
    return EXIT_OK


def cmd_config(args) -> int:
    if args.mode == "show":
        cfg = ToolkitConfig.load(args.config)
        print(json.dumps(cfg.to_dict(), indent=2) if args.json else str(cfg.to_dict()))
    elif args.mode == "init":
        p = Path(args.config) if args.config else ToolkitConfig.default_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists() and not args.force:
            print(f"[exists] {p} (use --force to overwrite)", file=sys.stderr)
            return EXIT_USAGE
        p.write_text(DEFAULT_TOML)
        print(f"[wrote] {p}")
    return EXIT_OK


def _parse_ports(spec: str) -> list[int]:
    spec = spec.strip()
    if spec == "top":
        return [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 6379, 8080, 8443]
    if "-" in spec:
        a, b = spec.split("-", 1)
        return list(range(int(a), int(b) + 1))
    return [int(x) for x in spec.split(",") if x.strip()]


def _maybe_write_report(results: list[ScanResult], args) -> None:
    if args.format and args.output:
        from toolkit.reporting.engine import write_report
        write_report(results, args.format, args.output)
        if not args.quiet:
            print(f"[wrote] {args.output}")


def _exit_for(results: list[ScanResult], args) -> int:
    if getattr(args, "fail_on", None):
        rank = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        thresh = rank.get(args.fail_on, 4)
        for r in results:
            for f in r.findings:
                if rank.get(f.severity, 0) >= thresh:
                    return EXIT_FINDINGS
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="toolkit", description="TBH Security Toolkit - authorized defensive testing")
    p.add_argument("--version", action="store_true")
    _add_global(p)
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("info"); _add_global(s); s.set_defaults(fn=cmd_info)
    s = sub.add_parser("doctor"); _add_global(s); s.set_defaults(fn=cmd_doctor)

    s = sub.add_parser("scan"); _add_global(s)
    s.add_argument("--target", required=True); s.add_argument("--fail-on", default=None)
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("web"); _add_global(s)
    wsub = s.add_subparsers(dest="webcmd")
    w = wsub.add_parser("scan"); _add_global(w); w.add_argument("--target", required=True)
    w.add_argument("--fail-on", default=None); w.set_defaults(fn=cmd_web)
    s.set_defaults(fn=cmd_web)  # `toolkit web --target X` also works
    s.add_argument("--target", required=False, default=None)

    s = sub.add_parser("headers"); _add_global(s); s.add_argument("--target", required=True); s.set_defaults(fn=cmd_headers)
    s = sub.add_parser("dns"); _add_global(s); s.add_argument("--domain", required=True); s.set_defaults(fn=cmd_dns)
    s = sub.add_parser("ports"); _add_global(s); s.add_argument("--target", required=True)
    s.add_argument("--ports", default="top"); s.add_argument("--threads", type=int, default=10); s.set_defaults(fn=cmd_ports)
    s = sub.add_parser("ssl"); _add_global(s); s.add_argument("--target", required=True); s.set_defaults(fn=cmd_ssl)

    s = sub.add_parser("recon"); _add_global(s); s.add_argument("--target", required=True)
    s.add_argument("--active", action="store_true"); s.add_argument("--subs", action="store_true")
    s.add_argument("--passive", action="store_true"); s.set_defaults(fn=cmd_recon)

    s = sub.add_parser("osint"); _add_global(s); s.add_argument("mode", choices=["url", "pass"])
    s.add_argument("--value", required=True); s.set_defaults(fn=cmd_osint)

    s = sub.add_parser("loadtest"); _add_global(s); s.add_argument("--target", required=True)
    s.add_argument("--requests", type=int, default=100); s.add_argument("--concurrency", type=int, default=5)
    s.add_argument("--rate", type=float, default=2.0); s.add_argument("--path", default="/"); s.set_defaults(fn=cmd_loadtest)

    s = sub.add_parser("integrity"); _add_global(s); s.add_argument("mode", choices=["baseline", "check"])
    s.add_argument("path"); s.add_argument("--baseline", default="baseline.json"); s.set_defaults(fn=cmd_integrity)

    s = sub.add_parser("lab"); _add_global(s); s.add_argument("mode", choices=["auth-audit", "serve"])
    s.add_argument("--password", default=None); s.add_argument("--port", type=int, default=8901); s.set_defaults(fn=cmd_lab)

    s = sub.add_parser("report"); _add_global(s); s.add_argument("--input", required=True); s.set_defaults(fn=cmd_report)

    s = sub.add_parser("config"); _add_global(s); s.add_argument("mode", choices=["show", "init"])
    s.add_argument("--force", action="store_true"); s.set_defaults(fn=cmd_config)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "version", False):
        print(__version__)
        return EXIT_OK
    if not getattr(args, "cmd", None):
        parser.print_help()
        return EXIT_USAGE
    # `toolkit web --target X` without subcommand:
    if args.cmd == "web" and getattr(args, "webcmd", None) is None and not getattr(args, "target", None):
        print("usage: toolkit web scan --target URL  (or: toolkit web --target URL)", file=sys.stderr)
        return EXIT_USAGE
    try:
        return int(args.fn(args))
    except SystemExit as e:
        code = e.code
        return int(code) if isinstance(code, int) else EXIT_SAFETY
    except SafetyError as e:
        print(f"[!] Safety blocked: {e}", file=sys.stderr)
        return EXIT_SAFETY
    except KeyboardInterrupt:
        print("\n[cancelled]", file=sys.stderr)
        return 130
    except Exception as e:  # never dump long tracebacks for user errors
        if getattr(args, "verbose", False):
            raise
        print(f"[!] error: {type(e).__name__}: {str(e)[:300]}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
