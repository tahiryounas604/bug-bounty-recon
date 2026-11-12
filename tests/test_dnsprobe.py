"""Tests for the DNS wordlist probe with a mocked resolver."""

import os

from recon.dnsprobe import detect_wildcard, load_wordlist, probe_dns

WORDLIST = os.path.join(
    os.path.dirname(__file__), "..", "recon", "wordlist.txt"
)


def fake_resolver_factory(mapping):
    def resolver(hostname):
        return mapping.get(hostname, [])

    return resolver


def test_probe_finds_only_resolving_hosts():
    mapping = {
        "www.example.com": ["93.184.216.34"],
        "api.example.com": ["93.184.216.34", "93.184.216.35"],
    }
    result = probe_dns(
        "example.com",
        labels=["www", "api", "nope"],
        workers=4,
        resolver=fake_resolver_factory(mapping),
    )
    assert result == {
        "api.example.com": ["93.184.216.34", "93.184.216.35"],
        "www.example.com": ["93.184.216.34"],
    }


def test_probe_empty_when_nothing_resolves():
    result = probe_dns(
        "example.com",
        labels=["www", "api"],
        resolver=fake_resolver_factory({}),
    )
    assert result == {}


def test_bundled_wordlist_has_enough_labels():
    labels = load_wordlist(WORDLIST)
    assert len(labels) >= 100
    assert "www" in labels
    assert "api" in labels
    assert "admin" in labels
    assert len(labels) == len(set(labels))  # no duplicates
    assert all(label.islower() and " " not in label for label in labels)


def test_load_wordlist_skips_comments_and_blanks(tmp_path):
    path = tmp_path / "wl.txt"
    path.write_text("# comment\n\nwww\napi\nwww\n\n", encoding="utf-8")
    assert load_wordlist(str(path)) == ["www", "api"]


def test_detect_wildcard_true_when_random_labels_resolve():
    assert detect_wildcard("example.com", resolver=lambda h: ["1.2.3.4"]) is True


def test_detect_wildcard_false_when_random_labels_fail():
    assert detect_wildcard("example.com", resolver=lambda h: []) is False
