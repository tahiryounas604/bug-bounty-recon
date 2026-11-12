"""Tests for Markdown + JSON report generation."""

import json

from recon.report import build_report_data, render_markdown, write_reports


def sample_data():
    return build_report_data(
        domain="example.com",
        crtsh_subdomains=["www.example.com", "api.example.com"],
        dns_found={"api.example.com": ["93.184.216.34"]},
        live_results=[
            {
                "host": "www.example.com",
                "url": "https://www.example.com/",
                "scheme": "https",
                "alive": True,
                "status": 200,
                "server": "nginx",
                "title": "Example Domain",
                "error": "",
            },
            {
                "host": "api.example.com",
                "url": "",
                "scheme": "",
                "alive": False,
                "status": None,
                "server": "",
                "title": "",
                "error": "timed out",
            },
        ],
        port_results={"www.example.com": {80: True, 443: True, 8080: False}},
        nuclei_result={
            "available": False,
            "ran": False,
            "returncode": None,
            "findings_file": "",
            "note": "nuclei not found on PATH — scan skipped.",
        },
    )


def test_summary_counts():
    data = sample_data()
    assert data["summary"] == {
        "crtsh_subdomains": 2,
        "dns_probe_found": 1,
        "total_subdomains": 2,
        "live_hosts": 1,
        "nuclei_ran": False,
        "wildcard_dns": False,
    }
    assert data["subdomains"] == ["api.example.com", "www.example.com"]


def test_markdown_warns_on_wildcard_dns():
    data = sample_data()
    data["summary"]["wildcard_dns"] = True
    md = render_markdown(data)
    assert "wildcard DNS detected" in md
    assert "cannot be trusted as real subdomains" in md


def test_markdown_contains_key_sections():
    md = render_markdown(sample_data())
    assert "# Recon report — example.com" in md
    assert "www.example.com" in md
    assert "Example Domain" in md
    assert "nginx" in md
    assert "200" in md
    assert "nuclei not found on PATH" in md
    assert "Scan only targets you are authorized to test." in md


def test_markdown_empty_results():
    data = build_report_data("example.com", [], {}, [], {}, {"ran": False, "note": "skipped"})
    md = render_markdown(data)
    assert "_None found._" in md
    assert "_No live hosts._" in md


def test_write_reports_creates_both_files(tmp_path):
    data = sample_data()
    paths = write_reports(data, str(tmp_path / "out"))
    md = (tmp_path / "out" / "report.md").read_text(encoding="utf-8")
    loaded = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert paths["markdown"].endswith("report.md")
    assert paths["json"].endswith("report.json")
    assert "Recon report" in md
    assert loaded["domain"] == "example.com"
    assert loaded["summary"]["live_hosts"] == 1
    assert loaded["live_hosts"][0]["title"] == "Example Domain"
