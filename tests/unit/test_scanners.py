from toolkit.scanners.web import scan_web
from toolkit.scanners.vuln import scan_vuln, check_xss, check_sqli
from toolkit.core.http import build_session


def test_web_scan_lab(lab_server):
    r = scan_web(lab_server, check_tls_flag=False)
    assert r.target == "127.0.0.1"
    ids = {f.id for f in r.findings}
    assert "http-status" in ids
    assert any(i.startswith("missing-") for i in ids)
    assert any("cookies" in i or "cors" in i for i in ids)


def test_xss_reflected(lab_server):
    s = build_session()
    f = check_xss(lab_server + "/reflect", s, 5.0)
    assert f.severity == "HIGH"  # mock echoes payload


def test_sqli_detected(lab_server):
    s = build_session()
    f = check_sqli(lab_server + "/sql", s, 5.0)
    assert f.severity == "HIGH"


def test_vuln_pipeline(lab_server):
    r = scan_vuln(lab_server + "/reflect", checks=["xss", "sqli", "cors"])
    assert len(r.findings) >= 3
