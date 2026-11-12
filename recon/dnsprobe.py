"""Concurrent DNS wordlist probing (standard library only).

For each label in the built-in wordlist, ``<label>.<domain>`` is resolved.
A label counts as "found" when the resolver returns at least one address.
Resolution runs in a thread pool so a 140-label wordlist finishes in
seconds instead of minutes.

The resolver is injectable (``resolver`` parameter) so tests can supply
a fake without touching the network. The default resolver uses
``socket.getaddrinfo``.
"""

from __future__ import annotations

import os
import socket
from concurrent.futures import ThreadPoolExecutor

DEFAULT_TIMEOUT = 5.0


def default_resolver(hostname: str) -> list[str]:
    """Resolve ``hostname`` to a list of IP addresses (empty on failure)."""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError):
        return []
    return sorted({info[4][0] for info in infos})


def load_wordlist(path: str | None = None) -> list[str]:
    """Load subdomain labels from ``path`` (default: bundled wordlist.txt).

    Blank lines and ``#`` comments are skipped; duplicates removed,
    order preserved.
    """
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "wordlist.txt")
    labels: list[str] = []
    seen: set[str] = set()
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            label = line.strip().lower()
            if not label or label.startswith("#"):
                continue
            if label not in seen:
                seen.add(label)
                labels.append(label)
    return labels


def probe_dns(
    domain: str,
    labels: list[str] | None = None,
    workers: int = 20,
    resolver=default_resolver,
) -> dict[str, list[str]]:
    """Probe ``<label>.<domain>`` for every label; return {host: [ips]}.

    Only hosts that resolve are included in the result.
    """
    domain = domain.strip().lower().rstrip(".")
    if labels is None:
        labels = load_wordlist()
    hosts = [f"{label}.{domain}" for label in labels]

    found: dict[str, list[str]] = {}

    def _check(host: str) -> tuple[str, list[str]]:
        return host, resolver(host)

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for host, ips in pool.map(_check, hosts):
            if ips:
                found[host] = sorted(ips)
    return dict(sorted(found.items()))


def detect_wildcard(domain: str, resolver=default_resolver) -> bool:
    """True when ``domain`` has wildcard DNS (or the resolver answers everything).

    Two random labels that almost certainly do not exist are resolved.
    If either resolves, every wordlist hit is suspect: a wildcard makes
    the DNS probe unable to distinguish real subdomains from noise.
    Callers should warn the user and treat probe results as unreliable.
    """
    import secrets

    domain = domain.strip().lower().rstrip(".")
    for _ in range(2):
        label = f"recon-nonexistent-{secrets.token_hex(8)}"
        if resolver(f"{label}.{domain}"):
            return True
    return False
