"""Tests for nuclei integration (mocked binary / subprocess)."""

import subprocess

from recon import nuclei


def test_skips_cleanly_when_nuclei_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(nuclei.shutil, "which", lambda name: None)
    result = nuclei.run_nuclei(["example.com"], str(tmp_path))
    assert result["available"] is False
    assert result["ran"] is False
    assert "not found on PATH" in result["note"]


def test_skips_when_no_live_hosts(monkeypatch, tmp_path):
    monkeypatch.setattr(nuclei.shutil, "which", lambda name: "/usr/bin/nuclei")
    result = nuclei.run_nuclei([], str(tmp_path))
    assert result["available"] is True
    assert result["ran"] is False
    assert "no live hosts" in result["note"]


def test_runs_nuclei_and_writes_targets_file(monkeypatch, tmp_path):
    monkeypatch.setattr(nuclei.shutil, "which", lambda name: "/usr/bin/nuclei")

    calls = {}

    def fake_run(command, timeout, capture_output, text):
        calls["command"] = command
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr(nuclei.subprocess, "run", fake_run)
    result = nuclei.run_nuclei(
        ["www.example.com", "api.example.com"], str(tmp_path)
    )
    assert result["ran"] is True
    assert result["returncode"] == 0
    assert result["findings_file"].endswith("nuclei-findings.txt")
    targets = (tmp_path / "live-hosts.txt").read_text(encoding="utf-8")
    assert targets == "www.example.com\napi.example.com\n"
    assert calls["command"][:3] == ["/usr/bin/nuclei", "-l", str(tmp_path / "live-hosts.txt")]


def test_timeout_reported(monkeypatch, tmp_path):
    monkeypatch.setattr(nuclei.shutil, "which", lambda name: "/usr/bin/nuclei")

    def fake_run(command, timeout, capture_output, text):
        raise subprocess.TimeoutExpired(command, timeout)

    monkeypatch.setattr(nuclei.subprocess, "run", fake_run)
    result = nuclei.run_nuclei(["www.example.com"], str(tmp_path), timeout=5)
    assert result["ran"] is True
    assert result["returncode"] is None
    assert "timed out" in result["note"]
