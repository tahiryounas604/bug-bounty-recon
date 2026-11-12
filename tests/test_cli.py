"""Tests for CLI argument parsing, port parsing and the full pipeline
(with network steps monkeypatched — the real network paths are covered
in test_crtsh / test_dnsprobe / test_liveprobe).
"""

import json

import pytest

from recon import cli


def test_parse_ports_valid():
    assert cli.parse_ports("80,443,8080") == (80, 443, 8080)
    assert cli.parse_ports("443, 80, 443") == (80, 443)


def test_parse_ports_invalid():
    with pytest.raises(ValueError):
        cli.parse_ports("0")
    with pytest.raises(ValueError):
        cli.parse_ports("70000")
    with pytest.raises(ValueError):
        cli.parse_ports("abc")
    with pytest.raises(ValueError):
        cli.parse_ports("")


def test_invalid_domain_rejected(capsys):
    assert cli.main(["notadomain"]) == 2
    assert "error" in capsys.readouterr().err


def test_full_pipeline_end_to_end(monkeypatch, tmp_path):
    """Pipeline with mocked network steps writes real md + json reports."""
    monkeypatch.setattr(cli, "fetch_subdomains", lambda domain: ["www.example.com"])
    monkeypatch.setattr(
        cli, "probe_dns", lambda domain, labels, workers: {"api.example.com": ["1.2.3.4"]}
    )
    monkeypatch.setattr(cli, "detect_wildcard", lambda domain: False)
    monkeypatch.setattr(
        cli,
        "probe_hosts",
        lambda hosts, timeout, workers: [
            {
                "host": "api.example.com",
                "url": "https://api.example.com/",
                "scheme": "https",
                "alive": True,
                "status": 200,
                "server": "nginx",
                "title": "API",
                "error": "",
            },
            {
                "host": "www.example.com",
                "url": "",
                "scheme": "",
                "alive": False,
                "status": None,
                "server": "",
                "title": "",
                "error": "refused",
            },
        ],
    )
    monkeypatch.setattr(cli, "check_ports", lambda host, ports: {80: True, 443: True})
    monkeypatch.setattr(
        cli,
        "run_nuclei",
        lambda hosts, out: {
            "available": False,
            "ran": False,
            "returncode": None,
            "findings_file": "",
            "note": "nuclei not found on PATH — scan skipped.",
        },
    )
    out = tmp_path / "recon-out"
    assert cli.main(["example.com", "--output-dir", str(out), "--no-nuclei"]) == 0

    report = json.loads((out / "report.json").read_text(encoding="utf-8"))
    assert report["domain"] == "example.com"
    assert report["subdomains"] == ["api.example.com", "www.example.com"]
    assert report["summary"]["live_hosts"] == 1
    assert report["ports"]["api.example.com"] == {"80": True, "443": True}
    md = (out / "report.md").read_text(encoding="utf-8")
    assert "Recon report — example.com" in md
    assert "api.example.com" in md
