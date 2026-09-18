"""Integration: cover remaining branches to reach 80%+ meaningful coverage."""
from toolkit.cli.main import main
from toolkit.core import logging_setup as LS
from toolkit.core.config import ToolkitConfig
from toolkit.core.http import build_session, request_with_backoff
from toolkit.core.models import Finding, ScanResult
from toolkit.scanners import vuln as V
from toolkit.scanners import web as W
from toolkit.utils import encode as E


def test_with_param_branches():
    assert "q=" in V._with_param("http://h/path", "X")
    assert "a=X" in V._with_param("http://h/path?a=1", "X")


def test_all_vuln_checks(lab_server):
    s = build_session()
    assert V.check_lfi(lab_server + "/reflect", s, 5).endpoint
    assert V.check_ssrf(lab_server + "/reflect", s, 5).endpoint
    assert V.check_open_redirect(lab_server + "/reflect", s, 5).endpoint
    assert V.check_ssti(lab_server + "/reflect", s, 5).endpoint
    assert V.check_idor(lab_server + "/view?id=5", s, 5)
    assert V.check_idor(lab_server + "/view", s, 5)
    assert isinstance(V.check_dirs(lab_server, s, 5, threads=2), list)
    assert V.check_js_leak(lab_server, s, 5).endpoint
    r = V.scan_vuln(lab_server + "/reflect",
                    checks=["xss", "sqli", "lfi", "ssrf", "redirect", "ssti", "idor", "dirs", "jsleak", "cors"])
    assert len(r.findings) >= 9


def test_vuln_errors():
    s = build_session()
    bad = "http://127.0.0.1:9/nope"
    assert V.check_xss(bad, s, 0.3).id == "xss-error"
    assert V.check_lfi(bad, s, 0.3).id == "lfi-error"
    assert V.check_ssrf(bad, s, 0.3).id == "ssrf-error"
    assert V.check_open_redirect(bad, s, 0.3).id.endswith("error")
    assert V.check_ssti(bad, s, 0.3).id == "ssti-error"
    assert V.check_js_leak(bad, s, 0.3).id == "jsleak-error"


def test_web_branches(lab_server):
    assert W._norm_target("example.com").startswith("http")
    s = build_session()
    r = s.get(lab_server + "/headers", timeout=5)
    assert any(f.id == "missing-content-security-policy" for f in W.check_security_headers(r, "e"))
    r2 = s.get(lab_server, timeout=5)
    assert W.check_cookies(r2, "e")  # no cookies -> INFO finding
    assert W.check_cors(lab_server + "/cors", s, 5)[0].severity in ("HIGH", "LOW", "INFO")
    assert W.check_cors("http://127.0.0.1:9/nope", s, 0.3)[0].id == "cors-error"
    assert W.check_tls("127.0.0.1", port=9, timeout=0.5)[0].id == "tls-unavailable"
    assert W.check_disclosure(r2, "e") is not None
    assert W.check_wellknown(lab_server, s, 5)
    full = W.scan_web("http://127.0.0.1:9/nope", check_tls_flag=False)
    assert any(f.id == "http-error" for f in full.findings)
    https_tls = W.scan_web(lab_server, check_tls_flag=True)
    assert https_tls.findings


def test_recon_active_and_errors(lab_server):
    from toolkit.recon.recon import dns_info, http_meta, scan_recon
    assert "error" in dns_info("nonexistent.invalid")
    assert "error" in http_meta("http://127.0.0.1:9/nope", 0.5, "UA")
    r = scan_recon(lab_server, active=True, include_subs=True)
    assert r.module == "recon"


def test_config_and_logging(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text('[toolkit]\ntimeout = 5.0\nconcurrency = 3\nallow_external = true\n')
    cfg = ToolkitConfig.load(p)
    assert cfg.timeout == 5.0 and cfg.allow_external is True
    import os
    os.environ["TOOLKIT_TIMEOUT"] = "9.0"
    try:
        assert ToolkitConfig.load(p).timeout == 9.0
    finally:
        del os.environ["TOOLKIT_TIMEOUT"]
    LS.setup_logging("DEBUG", json_logs=True)
    LS.setup_logging("INFO")
    assert LS.get_logger("x")


def test_http_backoff():
    import requests
    s = build_session()
    try:
        request_with_backoff(s, "GET", "http://127.0.0.1:9/nope", timeout=0.3, max_attempts=2)
        assert False
    except (requests.ConnectionError, requests.Timeout):
        assert True


def test_encode_utils():
    assert E.b64d(E.b64e("hi")) == "hi"
    assert E.urld(E.urle("a b")) == "a b"
    assert "sha256" in E.hashes("hi")


def test_models_highest():
    r = ScanResult(target="t", module="m")
    assert r.highest_severity() == "INFO"
    r.findings.append(Finding(id="a", title="t", severity="LOW", module="m"))
    assert r.highest_severity() == "LOW"


def test_cli_extras(tmp_path, lab_server):
    assert main(["--version"]) == 0
    assert main(["web", "scan", "--target", lab_server]) == 0
    assert main(["web", "--target", lab_server]) == 0
    d = tmp_path / "w"; d.mkdir(); (d / "a.html").write_text("x")
    base = tmp_path / "b.json"
    assert main(["integrity", "baseline", str(d), "--baseline", str(base)]) == 0
    assert main(["integrity", "check", str(d), "--baseline", str(base)]) == 0
    assert main(["lab", "auth-audit", "--password", "Strong1!Pass"]) == 0
    assert main(["config", "init", "--config", str(tmp_path / "new.toml")]) == 0
    assert main(["scan", "--target", lab_server, "--fail-on", "CRITICAL"]) == 0
    assert main(["scan", "--target", lab_server, "--fail-on", "INFO"]) == 10


def test_web_cookie_and_disclosure_branches(lab_server):
    from toolkit.scanners.web import check_cookies, check_disclosure

    class FakeResp:
        def __init__(self, headers, text=""):
            self.headers = headers
            self.text = text

    r = FakeResp({"Set-Cookie": "sess=abc; Path=/", "Server": "Apache/2.4.1",
                  "X-Powered-By": "PHP/8.1"}, "<html>contact admin@example.com</html>")
    ck = check_cookies(r, "http://x/")
    assert any(f.id == "cookie-no-secure" for f in ck)
    assert any(f.id == "cookie-no-httponly" for f in ck)
    assert any(f.id == "cookie-no-samesite" for f in ck)
    d = check_disclosure(r, "http://x/")
    assert any(f.id == "server-disclosure" for f in d)
    assert any(f.id == "email-disclosure" for f in d)
