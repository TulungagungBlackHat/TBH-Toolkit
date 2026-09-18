from toolkit.network.diagnostics import diagnose, scan_ports
from toolkit.network.loadtest import run_loadtest
from toolkit.recon.recon import scan_recon
from toolkit.analyzer.integrity import build_baseline, check_against_baseline
from toolkit.lab.auth import LockoutSimulator, password_audit
from toolkit.osint.phish import analyze_url
from toolkit.reporting.engine import to_json, to_csv, to_html, to_markdown
from toolkit.core.models import ScanResult, Finding


def test_diagnose_localhost():
    r = diagnose("127.0.0.1")
    assert r.target == "127.0.0.1"
    assert any(f.id == "dns-ok" for f in r.findings)


def test_port_scan_loopback(lab_server):
    import urllib.parse
    port = int(urllib.parse.urlparse(lab_server).port)
    r = scan_ports("127.0.0.1", [port, 9], threads=2, rate_rps=20)
    assert port in r.meta["open"]


def test_loadtest_lab(lab_server):
    stats = run_loadtest(lab_server, requests_n=20, concurrency=2, rate=10.0)
    s = stats.summary()
    assert s["requests"] == 20
    assert s["latency_ms"]["p50"] >= 0
    assert sum(s["status_distribution"].values()) + s["errors"] == 20


def test_recon_passive(lab_server):
    r = scan_recon(lab_server)
    assert r.module == "recon"
    assert r.meta["dns"].get("ip") == "127.0.0.1"


def test_integrity(tmp_path):
    d = tmp_path / "site"
    d.mkdir()
    (d / "index.html").write_text("<h1>hi</h1>")
    base = build_baseline(d)
    rep = check_against_baseline(d, base)
    assert rep["counts"]["total"] == 1 and rep["counts"]["modified"] == 0
    (d / "index.html").write_text("<h1>hacked by x</h1><script src='http://evil/x.js'></script>")
    rep2 = check_against_baseline(d, base)
    assert rep2["counts"]["modified"] == 1
    assert rep2["counts"]["suspicious"] == 1
    (d / "new.html").write_text("new")
    rep3 = check_against_baseline(d, base)
    assert rep3["counts"]["new"] == 1


def test_auth_lab():
    assert password_audit("Str0ng!Passw0rd-2026")["verdict"] in ("STRONG", "OK")
    assert password_audit("123456")["verdict"] == "WEAK"
    sim = LockoutSimulator(max_attempts=3, lockout_seconds=60)
    assert sim.attempt(False)["result"] == "fail"
    assert sim.attempt(False)["result"] == "fail"
    assert sim.attempt(False)["result"] == "locked"
    assert sim.attempt(False)["result"] == "blocked"


def test_phish():
    assert analyze_url("http://192.168.0.1@evil.tk/login")["verdict"] in ("PHISHING-LIKE", "SUSPICIOUS")
    assert analyze_url("https://example.com/docs")["verdict"] == "LIKELY-BENIGN"


def test_reporting():
    r = ScanResult(target="127.0.0.1", module="web", started_at="t",
                   findings=[Finding(id="x", title="T", severity="HIGH", endpoint="e",
                                     evidence="ev", explanation="ex", remediation="fix", module="m")])
    assert "HIGH" in to_json([r])
    assert "T" in to_csv([r])
    assert "<html>" in to_html([r])
    assert "# " in to_markdown([r])
