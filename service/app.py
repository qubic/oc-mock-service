"""OC mock interface service — public collector + homepage.

Ingest: OC machines POST the RAW OcMachineInvocation bundle bytes. The service
verifies >= 451 computor signatures (via the oc_verify C++ CLI), and only then
dedups by invocationId and stores. The endpoint is public and unauthenticated
by design — signature verification is the authenticity guarantee.

Homepage: read-only table of verified invocations for community visibility.

Config via env vars:
    OC_VERIFY_BIN            path to oc_verify        (default: ../build/oc_verify)
    OC_KEYS_DIR              dir with computors_<epoch>.bin (default: ./keys)
    OC_DB_PATH               sqlite path              (default: ./data/oc_mock.db)
    OC_KEYS_NODE             Qubic node to lazily fetch missing epoch keysets
                             from, "host" or "host:port" (default port 31841).
                             Empty = no auto-fetch (manual keys only).
    OC_ARBITRATOR            60-char arbitrator identity the fetched computor
                             list must be signed by (default: mainnet arbitrator)
    OC_COMPUTORS_VERIFY_BIN  path to computors_verify (default: ../build/computors_verify)
    OC_ALLOW_UNSIGNED_COMPUTORS  "1" accepts a fetched list whose signature is
                             all-zero (test networks have no arbitrator; their
                             nodes load the list from disk unsigned).
                             NEVER enable against mainnet.
"""

import os
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from .computors import KeyFetcher
from .db import Store
from .verifier import Verifier, VerifyError

_HERE = Path(__file__).resolve().parent
_DEFAULT_BIN = str(_HERE.parent / "build" / "oc_verify")

# Mainnet arbitrator (src/public_settings.h). Override for test networks.
_DEFAULT_ARBITRATOR = "AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ"

OC_VERIFY_BIN = os.environ.get("OC_VERIFY_BIN", _DEFAULT_BIN)
OC_KEYS_DIR = os.environ.get("OC_KEYS_DIR", str(_HERE.parent / "keys"))
OC_DB_PATH = os.environ.get("OC_DB_PATH", str(_HERE.parent / "data" / "oc_mock.db"))
OC_KEYS_NODE = os.environ.get("OC_KEYS_NODE", "")
OC_ARBITRATOR = os.environ.get("OC_ARBITRATOR", _DEFAULT_ARBITRATOR)
OC_COMPUTORS_VERIFY_BIN = os.environ.get(
    "OC_COMPUTORS_VERIFY_BIN", str(_HERE.parent / "build" / "computors_verify"))

app = FastAPI(title="OC Mock Interface Service")
store = Store(OC_DB_PATH)
verifier = Verifier(OC_VERIFY_BIN, OC_KEYS_DIR)

key_fetcher = None
if OC_KEYS_NODE:
    _host, _, _port = OC_KEYS_NODE.partition(":")
    key_fetcher = KeyFetcher(
        node_host=_host,
        node_port=int(_port) if _port else 31841,
        arbitrator=OC_ARBITRATOR,
        verify_bin=OC_COMPUTORS_VERIFY_BIN,
        keys_dir=OC_KEYS_DIR,
        allow_unsigned=os.environ.get("OC_ALLOW_UNSIGNED_COMPUTORS", "") == "1",
    )

MAX_BUNDLE = 64 * 1024  # spec max ~30790 bytes; generous ceiling


@app.post("/ingest")
async def ingest(request: Request):
    """Accept a raw OcMachineInvocation bundle from an OC machine."""
    body = await request.body()
    if not body:
        raise HTTPException(400, "empty body")
    if len(body) > MAX_BUNDLE:
        raise HTTPException(413, "bundle too large")

    source = request.headers.get("X-OC-Machine-Id") or (
        request.client.host if request.client else "unknown"
    )

    # Lazily provision the epoch's computor keyset if it is missing (fetched
    # from the configured node, authenticated by the arbitrator signature).
    if key_fetcher is not None:
        try:
            epoch = verifier.peek_epoch(body)
        except VerifyError as e:
            raise HTTPException(400, f"malformed bundle: {e}")
        if not verifier.keys_path(epoch).exists():
            key_fetcher.ensure(epoch)

    try:
        verdict = verifier.verify(body)
    except VerifyError as e:
        # Missing keys / malformed = we couldn't verify -> reject.
        raise HTTPException(422, f"verification unavailable: {e}")

    if not verdict.get("valid"):
        raise HTTPException(
            400,
            {"rejected": "signature verification failed", "verdict": verdict},
        )

    is_new, replication = store.record(
        invocation_id=verdict["invocationId"],
        tick=verdict["tick"],
        epoch=verdict["epoch"],
        interface_index=verdict["interfaceIndex"],
        request_size=verdict["requestSize"],
        request_hex=Verifier.request_hex(body),
        verified_sigs=verdict["verifiedCount"],
        source=source,
    )
    return JSONResponse(
        {
            "accepted": True,
            "new": is_new,
            "invocationId": verdict["invocationId"],
            "verifiedCount": verdict["verifiedCount"],
            "replication": replication,
        }
    )


@app.get("/api/invocations")
def api_invocations(limit: int = 100):
    return {"invocations": store.recent(limit)}


@app.get("/", response_class=HTMLResponse)
def homepage():
    rows = store.recent(100)
    return _render(rows)


def _mock_value(request_hex: str) -> str:
    """Decode the Mock interface's uint64 request value for display."""
    try:
        b = bytes.fromhex(request_hex)
        if len(b) >= 8:
            return str(int.from_bytes(b[:8], "little"))
    except ValueError:
        pass
    return request_hex or "-"


def _render(rows) -> str:
    body = "\n".join(
        f"""<tr>
            <td>{r['invocation_id']}</td>
            <td>{r['tick']}</td>
            <td>{r['epoch']}</td>
            <td>{r['interface_index']}</td>
            <td>{_mock_value(r['request_hex'])}</td>
            <td>{r['verified_sigs']}</td>
            <td>{r['replication']}</td>
        </tr>"""
        for r in rows
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>Qubic OC Mock Interface Service</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; background:#0b0e14; color:#e6e6e6; }}
  h1 {{ font-weight: 600; }}
  .sub {{ color:#8a94a6; margin-bottom:1.5rem; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ padding: .5rem .75rem; text-align: right; border-bottom: 1px solid #232a36; }}
  th {{ color:#8a94a6; font-weight:600; text-align:right; }}
  th:first-child, td:first-child {{ text-align:left; }}
  tr:hover td {{ background:#141922; }}
  .ok {{ color:#4ade80; }}
</style></head>
<body>
  <h1>Qubic Outsourced Computations — Mock Interface Service</h1>
  <div class="sub">Authorized execution orders received &amp; cryptographically verified
    (&ge;451 computor signatures) from the live network. Auto-refresh 5s.</div>
  <table>
    <thead><tr>
      <th>Invocation ID</th><th>Tick</th><th>Epoch</th><th>Interface</th>
      <th>Request value</th><th class="ok">Verified sigs</th><th>OC machines</th>
    </tr></thead>
    <tbody>
      {body if rows else '<tr><td colspan="7">No verified orders yet.</td></tr>'}
    </tbody>
  </table>
</body></html>"""
