"""Command-line interface for bug-bounty-recon.

Usage:
    python3 recon.py example.com
    python3 recon.py example.com --output-dir ./out --no-nuclei

Pipeline: crt.sh enumeration -> DNS wordlist probe -> live-host probe
-> port checks -> optional nuclei -> Markdown + JSON report.
"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .crtsh import fetch_subdomains
from .dnsprobe import detect_wildcard, load_wordlist, probe_dns
from .liveprobe import DEFAULT_PORTS, check_ports, probe_hosts
from .nuclei import nuclei_available, run_nuclei
from .report import build_report_data, write_reports


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="recon",
        description=(
            "bug-bounty-recon: enumerate subdomains, probe live hosts, "
            "check ports, optionally run nuclei, and write a report. "
            "Scan ONLY targets you are authorized to test."
        ),
    )
    parser.add_argument("domain", help="target domain, e.g. example.com")
    parser.add_argument(
        "--output-dir",
        default=None,
        help="where to write report.md / report.json "
        "(default: ./recon-<domain>)",
    )
    parser.add_argument(
        "--wordlist",
        default=None,
        help="custom subdomain wordlist (default: bundled wordlist.txt)",
    )
    parser.add_argument(
        "--no-crtsh", action="store_true", help="skip crt.sh enumeration"
    )
    parser.add_argument(
        "--no-dns-probe", action="store_true", help="skip DNS wordlist probe"
    )
    parser.add_argument(
        "--no-nuclei",
        action="store_true",
        help="skip the nuclei scan even if nuclei is installed",
    )
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help="comma-separated TCP ports to check (default: 80,443,8080,8443)",
    )
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="HTTP probe timeout in seconds"
    )
    parser.add_argument(
        "--workers", type=int, default=20, help="concurrency for probes"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser.parse_args(argv)


def parse_ports(value: str) -> tuple[int, ...]:
    ports = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        port = int(part)
        if not 1 <= port <= 65535:
            raise ValueError(f"port out of range: {port}")
        ports.append(port)
    if not ports:
        raise ValueError("no ports given")
    return tuple(sorted(set(ports)))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    domain = args.domain.strip().lower().rstrip(".")
    if not domain or "." not in domain:
        print("error: give a domain like example.com", file=sys.stderr)
        return 2
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"error: --ports: {exc}", file=sys.stderr)
        return 2

    output_dir = args.output_dir or f"./recon-{domain}"
    print(f"[+] bug-bounty-recon v{__version__} — target: {domain}")

    # 1. crt.sh enumeration
    crtsh_subdomains: list[str] = []
    if args.no_crtsh:
        print("[*] crt.sh enumeration skipped (--no-crtsh)")
    else:
        print("[*] querying crt.sh ...")
        try:
            crtsh_subdomains = fetch_subdomains(domain)
            print(f"[+] crt.sh: {len(crtsh_subdomains)} subdomains")
        except RuntimeError as exc:
            print(f"[!] crt.sh failed ({exc}) — continuing with DNS probe only")

    # 2. DNS wordlist probe
    dns_found: dict[str, list[str]] = {}
    wildcard_dns = False
    if args.no_dns_probe:
        print("[*] DNS wordlist probe skipped (--no-dns-probe)")
    else:
        labels = load_wordlist(args.wordlist)
        print(f"[*] DNS probing {len(labels)} wordlist labels ...")
        dns_found = probe_dns(domain, labels=labels, workers=args.workers)
        print(f"[+] DNS probe: {len(dns_found)} resolving subdomains")
        wildcard_dns = detect_wildcard(domain)
        if wildcard_dns:
            print(
                "[!] WARNING: wildcard DNS detected — random labels resolve, "
                "so DNS-probe hits cannot be trusted as real subdomains. "
                "Rely on crt.sh and the live-host probe instead."
            )

    all_subdomains = sorted(set(crtsh_subdomains) | set(dns_found))
    print(f"[+] total unique subdomains: {len(all_subdomains)}")

    # 3. Live-host probe (subdomains plus the base domain itself)
    probe_targets = sorted(set(all_subdomains) | {domain})
    print(f"[*] probing {len(probe_targets)} hosts (HTTPS, fallback HTTP) ...")
    live_results = probe_hosts(probe_targets, timeout=args.timeout, workers=args.workers)
    live_hosts = [r["host"] for r in live_results if r["alive"]]
    print(f"[+] live hosts: {len(live_hosts)}")

    # 4. Port checks on live hosts
    port_results: dict[str, dict[int, bool]] = {}
    for host in live_hosts:
        port_results[host] = check_ports(host, ports)
        open_ports = [p for p, ok in port_results[host].items() if ok]
        print(f"    {host}: open ports {open_ports or 'none'}")

    # 5. Nuclei (optional, external binary)
    if args.no_nuclei:
        nuclei_result = {
            "available": nuclei_available() is not None,
            "ran": False,
            "returncode": None,
            "findings_file": "",
            "note": "Nuclei scan skipped (--no-nuclei).",
        }
        print("[*] nuclei skipped (--no-nuclei)")
    else:
        os.makedirs(output_dir, exist_ok=True)
        print("[*] nuclei: checking for binary ...")
        nuclei_result = run_nuclei(live_hosts, output_dir)
        if nuclei_result["ran"]:
            print(f"[+] nuclei finished (exit {nuclei_result['returncode']})")
        else:
            print(f"[*] nuclei: {nuclei_result['note']}")

    # 6. Reports
    data = build_report_data(
        domain,
        crtsh_subdomains,
        dns_found,
        live_results,
        port_results,
        nuclei_result,
        wildcard_dns=wildcard_dns,
    )
    paths = write_reports(data, output_dir)
    print(f"[+] report written: {paths['markdown']}")
    print(f"[+] JSON written:   {paths['json']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
