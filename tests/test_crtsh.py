"""Tests for crt.sh subdomain parsing (canned response, no network)."""

import io
import json
import urllib.request

from recon import crtsh
from recon.crtsh import parse_crtsh_response

CANNED = [
    {"name_value": "example.com"},
    {"name_value": "www.example.com"},
    {"name_value": "*.api.example.com"},
    {"name_value": "a.example.com\nb.example.com"},
    {"name_value": "WWW.EXAMPLE.COM"},  # case duplicate
    {"name_value": "api.example.com"},  # duplicate of wildcard-stripped
    {"name_value": "other.com"},
    {"name_value": "notexample.com"},
    {"name_value": "evil-example.com"},
    {"name_value": "deep.sub.example.com"},
    {"name_value": "trailing.example.com."},
    {"name_value": ""},
    {"not_name_value": "x.example.com"},
    "not-a-dict",
]


def test_parses_subdomains():
    result = parse_crtsh_response(CANNED, "example.com")
    assert result == [
        "a.example.com",
        "api.example.com",
        "b.example.com",
        "deep.sub.example.com",
        "trailing.example.com",
        "www.example.com",
    ]


def test_bare_domain_excluded():
    assert parse_crtsh_response([{"name_value": "example.com"}], "example.com") == []


def test_unrelated_domains_excluded():
    payload = [
        {"name_value": "other.com"},
        {"name_value": "notexample.com"},
        {"name_value": "example.com.evil.com"},
    ]
    assert parse_crtsh_response(payload, "example.com") == []


def test_empty_and_bad_payload():
    assert parse_crtsh_response([], "example.com") == []
    assert parse_crtsh_response(None, "example.com") == []
    assert parse_crtsh_response("garbage", "example.com") == []


def test_wildcard_and_case_normalised():
    payload = [{"name_value": "*.API.Example.COM"}]
    assert parse_crtsh_response(payload, "example.com") == ["api.example.com"]


def test_fetch_uses_correct_crtsh_url_and_parses(monkeypatch):
    """The crt.sh query must be q=%.<domain> — %25 is rejected by crt.sh."""
    seen = {}

    class FakeResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        body = json.dumps(
            [{"name_value": "www.example.com"}, {"name_value": "*.api.example.com"}]
        ).encode()
        return FakeResponse(body)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = crtsh.fetch_subdomains("example.com")
    assert result == ["api.example.com", "www.example.com"]
    assert seen["url"] == "https://crt.sh/?q=%.example.com&output=json"
