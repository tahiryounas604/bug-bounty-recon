"""Subdomain enumeration via the crt.sh certificate-transparency API.

crt.sh publishes a public JSON endpoint:
    https://crt.sh/?q=%25<domain>&output=json
Each entry has a ``name_value`` field that may contain several hostnames
(newline separated) and may be prefixed with ``*.`` (wildcard).

Only the standard library is used. ``fetch_subdomains`` performs the
network call; ``parse_crtsh_response`` is pure and fully unit-testable.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"


def parse_crtsh_response(payload, domain: str) -> list[str]:
    """Extract unique subdomains of ``domain`` from a crt.sh JSON payload.

    ``payload`` is the already-decoded JSON value (a list of dicts).
    Rules applied, in order:
    - only the ``name_value`` field is read;
    - newline-separated values are split;
    - a leading ``*.`` wildcard prefix is stripped;
    - surrounding whitespace and a trailing dot are removed;
    - the bare domain itself is kept out (we want *sub*domains);
    - only names that are exactly ``domain`` or end with ``.<domain>``
      are kept (case-insensitive);
    - results are de-duplicated and returned sorted.
    """
    domain = domain.strip().lower().rstrip(".")
    found: set[str] = set()
    if not isinstance(payload, list):
        return []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("name_value") or ""
        for name in str(raw).splitlines():
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if not name or name == domain:
                continue
            if name.endswith("." + domain):
                found.add(name)
    return sorted(found)


def fetch_subdomains(domain: str, timeout: float = 30.0) -> list[str]:
    """Query crt.sh for ``domain`` and return sorted unique subdomains.

    Raises ``RuntimeError`` with a clear message on network/HTTP/JSON
    failure so the CLI can report it instead of crashing with a raw
    traceback. Returns an empty list only when crt.sh genuinely
    returns no matching certificates.
    """
    url = CRTSH_URL.format(domain=urllib.parse.quote(domain))
    request = urllib.request.Request(
        url, headers={"User-Agent": "bug-bounty-recon/0.1 (+https://tytechlabs)"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"crt.sh request failed: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"crt.sh request failed: {exc.reason}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"crt.sh returned unparsable JSON: {exc}") from exc
    return parse_crtsh_response(payload, domain)
