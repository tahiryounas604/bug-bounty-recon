"""Tests for live-host probing and port checks against a local server.

A real ``http.server`` fixture runs on localhost — no mocks for the
HTTP path, so this exercises the actual probe code end to end.
"""

import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from recon.liveprobe import check_port, check_ports, extract_title, probe_host


class Handler(BaseHTTPRequestHandler):
    def version_string(self):
        return "TestServer/1.0"

    def do_GET(self):
        if self.path == "/missing":
            self.send_response(404)
            body = b"<html><head><title>Not Found Page</title></head></html>"
        else:
            self.send_response(200)
            body = (
                b"<html><head><title>  Test  Page </title></head>"
                b"<body>hello</body></html>"
            )
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_extract_title():
    assert extract_title("<title> Hello   World </title>") == "Hello World"
    assert extract_title("<TITLE>Upper</TITLE>") == "Upper"
    assert extract_title("<html>no title</html>") == ""
    assert extract_title("<title>A <b>B</b> C</title>") == "A B C"


def test_probe_host_live_http_server(http_server):
    """Real probe against the fixture: HTTPS fails, HTTP succeeds."""
    port = http_server.server_address[1]
    result = probe_host("127.0.0.1", timeout=5, port=port)
    assert result["alive"] is True
    assert result["status"] == 200
    assert result["scheme"] == "http"
    assert result["server"] == "TestServer/1.0"
    assert result["title"] == "Test Page"
    assert result["url"] == f"http://127.0.0.1:{port}/"


def test_probe_host_http_error_status_counts_alive(http_server):
    """A 404 response still proves the host is alive (HTTPError path)."""
    port = http_server.server_address[1]
    result = probe_host("127.0.0.1", timeout=5, port=port, path="/missing")
    assert result["alive"] is True
    assert result["status"] == 404
    assert result["title"] == "Not Found Page"


def test_probe_host_unreachable_returns_not_alive():
    result = probe_host("nonexistent.invalid", timeout=3)
    assert result["alive"] is False
    assert result["status"] is None
    assert result["error"]


def test_check_port_open_and_closed(http_server):
    port = http_server.server_address[1]
    assert check_port("127.0.0.1", port) is True
    assert check_port("127.0.0.1", _free_port()) is False


def test_check_ports_dict(http_server):
    port = http_server.server_address[1]
    closed = _free_port()
    result = check_ports("127.0.0.1", (port, closed))
    assert result == {port: True, closed: False}
