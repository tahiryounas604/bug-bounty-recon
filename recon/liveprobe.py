"""Live-host probing over HTTP/HTTPS and TCP port checks.

``probe_host`` tries HTTPS first and falls back to HTTP, recording the
status code, final URL (after redirects), ``Server`` header and the
``<title>`` of the page (first 200 KB only). ``check_ports`` tests
whether common TCP ports accept a connection. Standard library only.
"""

from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")

DEFAULT_PORTS = (80, 443, 8080, 8443)
MAX_BODY_BYTES = 200_000


def extract_title(html: str) -> str:
    """Return the page title with tags/whitespace cleaned, or ""."""
    match = TITLE_RE.search(html)
    if not match:
        return ""
    text = TAG_RE.sub("", match.group(1))
    return WS_RE.sub(" ", text).strip()


def probe_host(host: str, timeout: float = 10.0, port: int | None = None, path: str = "/") -> dict:
    """Probe ``host`` over HTTPS, falling back to HTTP.

    ``port``/``path`` are optional overrides (used by tests to point at
    a local fixture server); when ``port`` is None the scheme default
    ports (443/80) are used.

    Returns a dict with keys: host, url (final URL), scheme, alive,
    status (int or None), server (header or ""), title, error.
    A host counts as alive only when an HTTP response is received.
    """
    result: dict = {
        "host": host,
        "url": "",
        "scheme": "",
        "alive": False,
        "status": None,
        "server": "",
        "title": "",
        "error": "",
    }
    # A permissive SSL context: recon cares about reachability and
    # headers, not certificate validity (expired/self-signed certs on
    # recon targets are themselves a finding, not a reason to abort).
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    last_error = ""
    for scheme in ("https", "http"):
        authority = f"{host}:{port}" if port else host
        url = f"{scheme}://{authority}{path}"
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "bug-bounty-recon/0.1 (+https://tytechlabs)"},
        )
        try:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=context)
                if scheme == "https"
                else urllib.request.HTTPHandler()
            )
            with opener.open(request, timeout=timeout) as response:
                body = response.read(MAX_BODY_BYTES).decode("utf-8", "replace")
                result.update(
                    {
                        "url": response.geturl(),
                        "scheme": scheme,
                        "alive": True,
                        "status": response.status,
                        "server": response.headers.get("Server", "") or "",
                        "title": extract_title(body),
                        "error": "",
                    }
                )
                return result
        except urllib.error.HTTPError as exc:
            # An HTTP error status (404, 403, 500...) still proves the
            # host is alive and serving.
            try:
                body = exc.read(MAX_BODY_BYTES).decode("utf-8", "replace")
            except Exception:
                body = ""
            result.update(
                {
                    "url": exc.geturl(),
                    "scheme": scheme,
                    "alive": True,
                    "status": exc.code,
                    "server": (exc.headers.get("Server", "") or "") if exc.headers else "",
                    "title": extract_title(body),
                    "error": "",
                }
            )
            return result
        except (urllib.error.URLError, OSError, ssl.SSLError, ValueError) as exc:
            last_error = str(exc) or exc.__class__.__name__
            continue
    result["error"] = last_error
    return result


def probe_hosts(
    hosts: list[str], timeout: float = 10.0, workers: int = 20
) -> list[dict]:
    """Probe many hosts concurrently; results sorted by host name."""
    if not hosts:
        return []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = list(pool.map(lambda h: probe_host(h, timeout), hosts))
    return sorted(results, key=lambda r: r["host"])


def check_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """True when a TCP connection to ``host:port`` succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_ports(
    host: str, ports: tuple[int, ...] = DEFAULT_PORTS, timeout: float = 3.0
) -> dict[int, bool]:
    """Check each port on ``host`` concurrently; return {port: open}."""
    with ThreadPoolExecutor(max_workers=len(ports)) as pool:
        outcomes = list(pool.map(lambda p: check_port(host, p, timeout), ports))
    return dict(zip(ports, outcomes))
