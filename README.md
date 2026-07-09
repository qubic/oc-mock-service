# OC Mock Interface Service

A standalone third-party service that receives **authorized Outsourced
Computation (OC) invocations** from Qubic OC machines, **cryptographically
verifies** them (≥ 451 computor signatures), deduplicates them, and displays
them on a live homepage.

It is both a proof-of-concept for the OC protocol and a public,
community-facing view of OC activity once the mock protocol is deployed to
mainnet.

## Where it sits

```
many Core nodes ──whitelisted IP──▶ OC machines ──raw bundle bytes──▶ THIS service ──▶ homepage
 (operator-run)                     (operator-run, dumb relay)         (single, public)
```

- The OC machine → service hop is **open**: any operator's OC machine may POST,
  so it cannot be IP-whitelisted. **Authenticity rests entirely on signature
  verification** — a forged bundle cannot carry 451 valid computor signatures.
- OC machines forward the **raw `OcMachineInvocation` bundle bytes** exactly as
  the Core node emitted them (no lossy JSON re-encoding in the trust path).

## Components

| Path | What |
|---|---|
| `src/oc_verify_main.cpp` | `oc_verify` — C++ CLI, the trust anchor. Reads a raw bundle + the epoch's computor keys, recomputes `paramsDigest`, reconstructs the `QUBIC_OC_AUTH` authMessage, verifies ≥ 451 **distinct** signers. |
| `src/computors_verify_main.cpp` | `computors_verify` — C++ CLI. Verifies a fetched `Computors` list against the arbitrator identity (mirrors `processBroadcastComputors`: no zeroed keys, SchnorrQ over `K12(epoch ‖ publicKeys)`). |
| `vendor/qubic_crypto/` | Vendored clang-portable FourQ + KangarooTwelve (from `core-lite`). Same crypto the network uses. |
| `service/verifier.py` | Wraps `oc_verify` as a subprocess; reads per-epoch keys. |
| `service/computors.py` | Fetches `BroadcastComputors` from a node; `KeyFetcher` = lazy verified fetch-on-miss with cooldown. |
| `service/db.py` | SQLite storage + dedup (by `invocationId`) + replication count. |
| `service/app.py` | FastAPI: `POST /ingest`, `GET /api/invocations`, `GET /` homepage. |
| `tools/fetch_computors.py` | Manual keyset fetch CLI (verifies by default). |
| `tests/make_test_bundle.cpp` | Generates real signed bundles (valid / forged / short / dup) for testing. |
| `tests/make_test_computors.cpp` | Generates an arbitrator-signed computor list matching the test bundle's keys. |

## Build the verifier

```bash
cmake -S . -B build -D CMAKE_CXX_COMPILER=clang++ -D CMAKE_BUILD_TYPE=Release
cmake --build build          # produces build/oc_verify and build/make_test_bundle
```

Requires x86-64 with AVX2 (`-mavx2 -maes`) or aarch64.

## Run the service

```bash
pip install -r requirements.txt

# Provide the computor public keys for each epoch you expect bundles from:
#   keys/computors_<epoch>.bin  =  676 * 32 raw bytes (publicKeys[] from BroadcastComputors)
mkdir -p keys
./build/make_test_bundle --keys-out keys/computors_150.bin > /tmp/bundle.bin   # demo keyset

uvicorn service.app:app --host 0.0.0.0 --port 8000
```

Then:

```bash
# An OC machine posts a raw bundle:
curl -X POST --data-binary @/tmp/bundle.bin -H "X-OC-Machine-Id: demo" \
     http://localhost:8000/ingest

open http://localhost:8000/          # live homepage
```

### Config (env vars)

| Var | Default | Meaning |
|---|---|---|
| `OC_VERIFY_BIN` | `build/oc_verify` | path to the verifier binary |
| `OC_KEYS_DIR` | `keys/` | dir of `computors_<epoch>.bin` files |
| `OC_DB_PATH` | `data/oc_mock.db` | SQLite file |
| `OC_KEYS_NODE` | *(empty = off)* | node (`host` or `host:port`) to lazily fetch missing epoch keysets from |
| `OC_ARBITRATOR` | mainnet arbitrator | identity the fetched computor list must be signed by |
| `OC_COMPUTORS_VERIFY_BIN` | `build/computors_verify` | path to the list verifier binary |
| `OC_ALLOW_UNSIGNED_COMPUTORS` | *(off)* | `1` accepts a fetched list with an **all-zero** signature (test networks have no arbitrator). A wrong non-zero signature is still rejected. Never enable against mainnet. |

With `OC_KEYS_NODE` set, the service self-heals across epoch transitions: a
bundle for an unknown epoch triggers a fetch of `BroadcastComputors` from that
node, the arbitrator signature is verified (`computors_verify`), and only then
is the keyset cached. The node is a transport, not a trust root — a
substituted list fails the signature check. Fetches are rate-limited (60 s
cooldown), so garbage bundles with fake epochs cannot hammer the node.

## Verification semantics (proven by tests)

| Bundle | Result |
|---|---|
| 451 valid signatures | **accepted**, stored, replication counted |
| same order from N OC machines | stored **once**, replication = N |
| one forged signature (450 valid) | **rejected** (below quorum) |
| < 451 signers | **rejected** |
| duplicate signer padding | **rejected** (distinct count < quorum) |
| wrong-epoch / garbage keys | **rejected** |
| truncated bundle | **rejected** |

## Not yet implemented (next steps)

- **DoS hardening** on the open ingest endpoint (rate limiting, cheap
  pre-checks before the expensive verify).
