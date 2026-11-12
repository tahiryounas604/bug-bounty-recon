"""Optional nuclei integration.

nuclei (https://github.com/projectdiscovery/nuclei) is an external
vulnerability scanner and is NOT bundled with this tool. If the
``nuclei`` binary is on PATH, ``run_nuclei`` feeds it the list of live
hosts and records its findings file; if it is absent, the scan is
skipped with a clear note and the rest of the recon still runs.
"""

from __future__ import annotations

import shutil
import subprocess


def nuclei_available() -> str | None:
    """Return the nuclei binary path, or None when it is not installed."""
    return shutil.which("nuclei")


def run_nuclei(
    live_hosts: list[str],
    output_dir: str,
    extra_args: list[str] | None = None,
    timeout: float = 1800.0,
) -> dict:
    """Run nuclei against ``live_hosts``; return a status dict.

    Result keys: available, ran, returncode, findings_file, note.
    ``ran`` is False when nuclei is missing or there are no live hosts.
    """
    binary = nuclei_available()
    if binary is None:
        return {
            "available": False,
            "ran": False,
            "returncode": None,
            "findings_file": "",
            "note": "nuclei not found on PATH — scan skipped. "
            "Install nuclei (https://github.com/projectdiscovery/nuclei) "
            "and re-run with --nuclei to enable vulnerability scanning.",
        }
    if not live_hosts:
        return {
            "available": True,
            "ran": False,
            "returncode": None,
            "findings_file": "",
            "note": "nuclei available but no live hosts found — scan skipped.",
        }
    targets_file = f"{output_dir}/live-hosts.txt"
    findings_file = f"{output_dir}/nuclei-findings.txt"
    with open(targets_file, "w", encoding="utf-8") as handle:
        handle.write("\n".join(live_hosts) + "\n")
    command = [
        binary,
        "-l",
        targets_file,
        "-o",
        findings_file,
        "-silent",
    ]
    if extra_args:
        command.extend(extra_args)
    try:
        completed = subprocess.run(
            command, timeout=timeout, capture_output=True, text=True
        )
        return {
            "available": True,
            "ran": True,
            "returncode": completed.returncode,
            "findings_file": findings_file,
            "note": completed.stderr.strip()[-500:] if completed.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "ran": True,
            "returncode": None,
            "findings_file": findings_file,
            "note": f"nuclei timed out after {timeout:.0f}s — partial results may be in {findings_file}.",
        }
