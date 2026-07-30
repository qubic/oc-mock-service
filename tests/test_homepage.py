"""Homepage live-update rendering.

The table is now rendered twice: server-side on first paint, and client-side by
the poller. These checks pin the contract between the two — the hooks the
script needs, and the uint64 decode that both sides implement independently.

Run: python3 tests/test_homepage.py   (matches test_source_ip.py; not pytest)
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("OC_DB_PATH", str(Path(tempfile.gettempdir()) / "oc_test_homepage.db"))

from service.app import _render, _mock_value  # noqa: E402


def row(**kw):
    r = dict(
        invocation_id="ABC123",
        tick=66395869,
        epoch=219,
        interface_index=0,
        request_hex="2a00000000000000",
        verified_sigs=451,
        replication=3,
        last_seen=time.time() - 42,
    )
    r.update(kw)
    return r


# uint64 request values the JS must agree with. Includes values above 2^53,
# where a naive JS Number would silently lose precision.
DECODE_CASES = [
    "2a00000000000000",
    "0000000000000000",
    "ffffffffffffffff",
    "0100000000000080",
    "2a000000000000000badc0ffee",
    "abc",
    "",
]


def demo():
    html = _render([row()], 7)

    # The poller replaces the meta-refresh; if both ship, the page reloads
    # mid-animation and the effect is never seen.
    assert 'http-equiv="refresh"' not in html, "meta-refresh must be gone"

    # Hooks the script queries by id — renaming any of these silently kills
    # the live updates, since the script fails soft.
    for hook in ('id="rows"', 'id="total"', 'id="card-total"',
                 'id="shown"', 'id="fx-toggle"'):
        assert hook in html, f"missing hook {hook}"

    # Server-rendered rows must carry the dedup/age attributes, or the first
    # poll flags every already-visible row as new and sweeps the whole table.
    assert 'data-id="ABC123"' in html, "row missing data-id"
    assert 'data-seen=' in html, "row missing data-seen"

    # Effects state is per-browser (the HTML is edge-cached).
    assert "localStorage" in html and "oc_fx" in html

    assert "/api/invocations" in html, "poller endpoint missing"
    assert ">42</td>" in html, "uint64 request value not decoded"
    assert ">7</div>" in html, "total not rendered"

    # Empty state still gives the poller its mount point.
    empty = _render([], 0)
    assert 'id="rows"' in empty
    assert "No verified invocations yet" in empty

    # Escaping: a hostile invocation_id must not break out of the attribute.
    # ponytail: ids are hex from the verifier, so this is defence in depth.
    eff = _render([row(invocation_id='X"><script>bad()</script>')], 1)
    assert "<script>bad()" not in eff.split("<script>\n(function")[0], \
        "row content escaped into markup"

    _check_js_parity()
    print("ok")


def _check_js_parity():
    """The JS mockValue() must match Python _mock_value() exactly.

    Skipped when node is unavailable — the Python side is still checked above.
    """
    node = shutil.which("node")
    if not node:
        print("note: node not found, skipping JS decode parity")
        return

    js = """
    function mockValue(hex) {
      if (!hex || hex.length < 16) return hex ? hex : '-';
      let v = 0n;
      for (let i = 0; i < 8; i++) v |= BigInt(parseInt(hex.substr(i*2,2),16)) << BigInt(i*8);
      return v.toString();
    }
    console.log(JSON.stringify(JSON.parse(process.argv[1]).map(mockValue)));
    """
    out = subprocess.run(
        [node, "-e", js, json.dumps(DECODE_CASES)],
        capture_output=True, text=True, check=True,
    ).stdout
    got = json.loads(out)
    want = [_mock_value(c) for c in DECODE_CASES]
    assert got == want, f"JS/Python decode drift:\n  js={got}\n  py={want}"


if __name__ == "__main__":
    demo()
