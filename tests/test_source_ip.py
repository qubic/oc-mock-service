"""Self-check for _source_ip: CF and non-CF deployments both resolve a source.

Run: python tests/test_source_ip.py   (from oc_mock_service/)
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from starlette.requests import Request

from service.app import _source_ip


def req(headers=None, client=("203.0.113.7", 51234)):
    """Minimal real Starlette Request (ASGI scope), not a stand-in dict."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/ingest",
        "headers": [(k.lower().encode(), v.encode())
                    for k, v in (headers or {}).items()],
    }
    if client is not None:
        scope["client"] = client
    return Request(scope)


def demo():
    # Behind Cloudflare: the real client IP wins over the CF edge socket peer.
    assert _source_ip(req({"CF-Connecting-IP": "198.51.100.42"})) == "198.51.100.42"

    # Header lookup must be case-insensitive (CF sends mixed case).
    assert _source_ip(req({"cf-connecting-ip": "198.51.100.43"})) == "198.51.100.43"

    # Not behind Cloudflare: header absent -> socket peer.
    assert _source_ip(req()) == "203.0.113.7"

    # Present but empty/whitespace -> treated as absent, not stored as "".
    assert _source_ip(req({"CF-Connecting-IP": ""})) == "203.0.113.7"
    assert _source_ip(req({"CF-Connecting-IP": "   "})) == "203.0.113.7"

    # Distinct machines behind CF stay distinct (this is the whole point:
    # the deliveries PRIMARY KEY is (invocation_id, source)).
    a = _source_ip(req({"CF-Connecting-IP": "198.51.100.1"}))
    b = _source_ip(req({"CF-Connecting-IP": "198.51.100.2"}))
    assert a != b, "CF clients must not collapse to one source"

    # No client info at all (e.g. non-HTTP transport) -> sentinel, never crash.
    assert _source_ip(req(client=None)) == "unknown"

    print("ok")


if __name__ == "__main__":
    demo()
