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
    OC_KEYS_NODE             Qubic node(s) to lazily fetch missing epoch keysets
                             from: comma-separated "host" or "host:port"
                             (default port 21841), tried in order until one
                             serves the epoch.
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
import time
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, Response
from fastapi.responses import HTMLResponse, JSONResponse

from .assets import FAVICON_SVG, LOGO_SVG
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

def _parse_nodes(spec: str):
    """"host, host:port, ..." -> [(host, port), ...] (default port 21841)."""
    nodes = []
    for entry in spec.split(","):
        entry = entry.strip()
        if not entry:
            continue
        host, _, port = entry.partition(":")
        nodes.append((host, int(port) if port else 21841))
    return nodes


key_fetcher = None
if OC_KEYS_NODE:
    key_fetcher = KeyFetcher(
        nodes=_parse_nodes(OC_KEYS_NODE),
        arbitrator=OC_ARBITRATOR,
        verify_bin=OC_COMPUTORS_VERIFY_BIN,
        keys_dir=OC_KEYS_DIR,
        allow_unsigned=os.environ.get("OC_ALLOW_UNSIGNED_COMPUTORS", "") == "1",
    )

MAX_BUNDLE = 64 * 1024  # spec max ~30790 bytes; generous ceiling


def _source_ip(request) -> str:
    """Reporting machine's IP, used as the delivery/replication source key.

    Behind Cloudflare the socket peer is a CF edge IP, so every machine would
    collapse into a single delivery source and the replication count would
    always read 1. CF-Connecting-IP carries the real client IP and CF strips
    any client-supplied copy, so it is trustworthy when present. It is absent
    when the service is reached directly -> fall back to the socket peer.

    ponytail: IP is not machine identity — machines behind one NAT still
    collapse, a machine on a dynamic IP still inflates. Needs an operator key
    in the bundle if replication ever becomes a trust signal rather than a
    liveness display.
    """
    cf = request.headers.get("CF-Connecting-IP")
    if cf and cf.strip():
        return cf.strip()
    return request.client.host if request.client else "unknown"


@app.post("/ingest")
async def ingest(request: Request):
    """Accept a raw OcMachineInvocation bundle from an OC machine."""
    body = await request.body()
    if not body:
        raise HTTPException(400, "empty body")
    if len(body) > MAX_BUNDLE:
        raise HTTPException(413, "bundle too large")

    source = _source_ip(request)

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
    return _render(rows, store.total())


@app.get("/favicon.svg")
def favicon():
    return Response(FAVICON_SVG, media_type="image/svg+xml")


def _mock_value(request_hex: str) -> str:
    """Decode the Mock interface's uint64 request value for display."""
    try:
        b = bytes.fromhex(request_hex)
        if len(b) >= 8:
            return str(int.from_bytes(b[:8], "little"))
    except ValueError:
        pass
    return request_hex or "-"


def _ago(ts: float) -> str:
    """Human-readable age of a unix timestamp."""
    d = int(time.time() - ts)
    if d < 60:
        return f"{d}s ago"
    if d < 3600:
        return f"{d // 60}m ago"
    if d < 86400:
        return f"{d // 3600}h ago"
    return f"{d // 86400}d ago"


def _render(rows, total: int) -> str:
    body = "\n".join(
        f"""<tr>
            <td class="mono id">{r['invocation_id']}</td>
            <td class="mono">{r['tick']}</td>
            <td class="mono">{r['epoch']}</td>
            <td class="mono">{r['interface_index']}</td>
            <td class="mono val">{_mock_value(r['request_hex'])}</td>
            <td class="mono ok">{r['verified_sigs']}</td>
            <td class="mono">&times;{r['replication']}</td>
            <td class="age">{_ago(r['last_seen'])}</td>
        </tr>"""
        for r in rows
    )
    stats = [
        ("Verified invocations", f"{total}"),
    ]
    cards = "\n".join(
        f'<div class="card"><div class="k">{k}</div><div class="v mono">{v}</div></div>'
        for k, v in stats
    )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>Qubic Outsourced Computations — Mock Interface Service</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=Fragment+Mono&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:#000; --panel:#232429; --panel2:#1f2024; --line:#ffffff14;
    --fg:#fefff5; --muted:#a6a298; --cyan:#32d9d9; --amber:#ffdea1;
    --sans:'Space Grotesk', system-ui, sans-serif;
    --mono:'Fragment Mono', ui-monospace, monospace;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin:0; background:var(--bg); color:var(--fg); font-family:var(--sans);
    -webkit-font-smoothing:antialiased;
  }}
  .mono {{ font-family:var(--mono); font-variant-numeric:tabular-nums; }}
  .wrap {{ max-width:1180px; margin:0 auto; padding:2.5rem 1.5rem 4rem; }}
  header {{ display:flex; align-items:center; gap:.9rem; margin-bottom:2.5rem; }}
  .logo {{ height:26px; width:auto; display:block; }}
  .tag {{
    font-family:var(--mono); font-size:.7rem; letter-spacing:.08em;
    text-transform:uppercase; color:var(--cyan);
    border:1px solid var(--line); border-radius:999px; padding:.3rem .6rem;
  }}
  h1 {{ font-size:clamp(1.7rem,4vw,2.6rem); line-height:1.1; font-weight:500; margin:0 0 .8rem; letter-spacing:-.02em; }}
  h1 em {{ font-style:normal; color:var(--cyan); }}
  .sub {{ color:var(--muted); max-width:60ch; line-height:1.6; margin:0 0 2.5rem; }}
  .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,max-content)); gap:1rem; margin-bottom:2.5rem; }}
  .card {{
    background:linear-gradient(139deg,var(--panel2) 0%,var(--panel) 94%);
    border:1px solid var(--line); border-radius:14px; padding:1.1rem 1.25rem;
  }}
  .card .k {{ font-size:.72rem; letter-spacing:.08em; text-transform:uppercase; color:var(--muted); margin-bottom:.5rem; }}
  .card .v {{ font-size:1.6rem; color:var(--fg); }}
  .panel {{ background:var(--panel2); border:1px solid var(--line); border-radius:16px; overflow:hidden; }}
  .panel-h {{
    display:flex; justify-content:space-between; align-items:baseline; gap:1rem;
    padding:1.1rem 1.25rem; border-bottom:1px solid var(--line);
  }}
  .panel-h h2 {{ font-size:.95rem; font-weight:500; margin:0; }}
  .muted {{ color:var(--muted); font-weight:400; }}
  .live {{ font-family:var(--mono); font-size:.72rem; color:var(--muted); display:flex; align-items:center; gap:.45rem; }}
  .dot {{ width:7px; height:7px; border-radius:50%; background:var(--cyan); box-shadow:0 0 0 0 #32d9d966; animation:p 2s infinite; }}
  @keyframes p {{ 70% {{ box-shadow:0 0 0 7px #32d9d900; }} 100% {{ box-shadow:0 0 0 0 #32d9d900; }} }}
  .scroll {{ overflow-x:auto; }}
  table {{ border-collapse:collapse; width:100%; font-size:.87rem; }}
  th, td {{ padding:.7rem 1rem; text-align:right; white-space:nowrap; }}
  th {{
    color:var(--muted); font-weight:500; font-size:.7rem; letter-spacing:.07em;
    text-transform:uppercase; border-bottom:1px solid var(--line);
  }}
  td {{ border-bottom:1px solid #ffffff0a; }}
  tbody tr:last-child td {{ border-bottom:0; }}
  th:first-child, td:first-child {{ text-align:left; }}
  tbody tr:hover td {{ background:var(--panel); }}
  .id {{ color:var(--fg); }}
  .val {{ color:var(--amber); }}
  .ok {{ color:var(--cyan); }}
  .age {{ color:var(--muted); font-size:.8rem; }}
  td.empty {{ text-align:center; color:var(--muted); padding:3rem 1rem; }}
  @media (max-width:640px) {{ .wrap {{ padding:1.5rem 1rem 3rem; }} }}
</style></head>
<body>
  <div class="wrap">
    <header>
      {LOGO_SVG}
      <span class="tag">Outsourced Computations</span>
    </header>

    <h1>Mock Interface <em>Service</em></h1>
    <p class="sub">Authorized invocations received from the live network and
      cryptographically verified against the epoch's computor set — every invocation
      shown here carries at least 451 valid computor signatures.</p>

    <div class="stats">
      {cards}
    </div>

    <div class="panel">
      <div class="panel-h">
        <h2>Verified invocations <span class="muted">· latest {len(rows)}</span></h2>
        <span class="live"><span class="dot"></span>live · refreshes every 5s</span>
      </div>
      <div class="scroll">
        <table>
          <thead><tr>
            <th>Invocation ID</th><th>Tick</th><th>Epoch</th><th>Interface</th>
            <th>Request value</th><th>Verified sigs</th><th>OC machines</th><th>Last seen</th>
          </tr></thead>
          <tbody>
            {body if rows else '<tr><td class="empty" colspan="8">No verified invocations yet — waiting for the first authorized invocation.</td></tr>'}
          </tbody>
        </table>
      </div>
    </div>
  </div>
</body></html>"""
