# -*- coding: utf-8 -*-
"""WebhookNotifier: Hermes generic-V2 signing (default) and legacy format."""
import hashlib
import hmac
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haap.policy import WebhookNotifier, build_request


@pytest.fixture()
def receiver():
    """A tiny HTTP receiver capturing headers + body of each POST."""
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            received.append(({k.lower(): v for k, v in self.headers.items()}, body))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}/webhooks/haap", received
    httpd.shutdown()
    httpd.server_close()


def _card():
    return build_request("HF-0123456789abcdef", "Peer", "hola", None, "guest",
                         {"speciality": "citas"})


def test_hermes_v2_signature_is_default_and_verifies(receiver):
    url, received = receiver
    WebhookNotifier(url, "s3cret").notify(_card())
    assert len(received) == 1
    headers, body = received[0]
    ts = headers["x-webhook-timestamp"]
    assert abs(int(ts) - int(time.time())) <= 5
    expected = hmac.new(b"s3cret", ts.encode() + b"." + body, hashlib.sha256).hexdigest()
    assert headers["x-webhook-signature-v2"] == expected
    assert "x-haap-signature" not in headers
    assert json.loads(body)["type"] == "haap.friend_request"


def test_legacy_format_keeps_old_header(receiver):
    url, received = receiver
    WebhookNotifier(url, "s3cret", fmt="legacy").notify(_card())
    headers, body = received[0]
    expected = hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert headers["x-haap-signature"] == f"sha256={expected}"
    assert "x-webhook-signature-v2" not in headers


def test_unknown_format_rejected():
    with pytest.raises(ValueError):
        WebhookNotifier("http://x", "s", fmt="nope")


def test_headers_for_is_deterministic_for_fixed_timestamp():
    n = WebhookNotifier("http://x", "k")
    h1 = n.headers_for(b"{}", timestamp=1700000000)
    h2 = n.headers_for(b"{}", timestamp=1700000000)
    assert h1 == h2 and h1["X-Webhook-Timestamp"] == "1700000000"


def test_failures_never_raise():
    # Unreachable port: notify must swallow the error (protocol never breaks).
    WebhookNotifier("http://127.0.0.1:9/nope", "k").notify(_card())
