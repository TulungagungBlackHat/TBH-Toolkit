from toolkit.cli.main import main


def test_cli_info(capsys):
    assert main(["info"]) == 0
    assert "toolkit" in capsys.readouterr().out.lower()


def test_cli_doctor():
    assert main(["doctor"]) == 0


def test_cli_dns_lab():
    assert main(["dns", "--domain", "127.0.0.1"]) == 0


def test_cli_safety_blocks_external():
    assert main(["dns", "--domain", "github.com"]) != 0


def test_cli_headers_and_scan(lab_server):
    assert main(["headers", "--target", lab_server]) == 0
    assert main(["scan", "--target", lab_server]) == 0
    assert main(["recon", "--target", lab_server]) == 0
    assert main(["ports", "--target", "127.0.0.1", "--ports", "9"]) == 0
    assert main(["ssl", "--target", "127.0.0.1"]) == 0
    assert main(["osint", "url", "--value", "https://example.com"]) == 0
    assert main(["osint", "pass", "--value", "Strong1!Pass"]) == 0
    assert main(["loadtest", "--target", lab_server, "--requests", "5", "--concurrency", "1", "--rate", "5"]) == 0


def test_cli_report_and_config(tmp_path, lab_server):
    out = tmp_path / "r.json"
    assert main(["scan", "--target", lab_server, "--format", "json", "-o", str(out)]) == 0
    assert out.is_file()
    html = tmp_path / "r.html"
    assert main(["report", "--input", str(out), "--output", str(html)]) == 0
    assert main(["config", "show"]) == 0
