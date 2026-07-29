#!/usr/bin/env python3
"""Fetch the epoch's computor public keys from a Qubic node, verify the
arbitrator signature on the list, and write the keyset file the mock service
verifier expects (<out_dir>/computors_<epoch>.bin).

Verification runs the computors_verify C++ CLI and mirrors the core's
processBroadcastComputors: no zeroed keys, SchnorrQ signature over
K12(epoch || publicKeys) checked against the arbitrator identity. Pass
--no-verify only if the queried node is fully trusted.

Usage: fetch_computors.py [host] [port] [--out keys/]
                          [--arbitrator <60-char id>] [--verify-bin <path>]
                          [--no-verify]
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from service.computors import (  # noqa: E402
    FetchError, fetch_computors_payload, payload_epoch,
    verify_computors_payload, write_keyset)

# Mainnet arbitrator (src/public_settings.h). Override for test networks.
DEFAULT_ARBITRATOR = "AFZPUAIYVPNUYGJRQVLUKOPPVLHAZQTGLYAAUUNBXFTVTAMSBKQBLEIEPCVJ"
DEFAULT_VERIFY_BIN = str(Path(__file__).resolve().parents[1] / "build" / "computors_verify")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("port", nargs="?", type=int, default=21841)
    parser.add_argument("--out", default="keys", help="output directory (default: keys/)")
    parser.add_argument("--arbitrator", default=DEFAULT_ARBITRATOR,
                        help="arbitrator identity the list must be signed by")
    parser.add_argument("--verify-bin", default=DEFAULT_VERIFY_BIN,
                        help="path to the computors_verify binary")
    parser.add_argument("--no-verify", action="store_true",
                        help="skip the arbitrator signature check (trusted node only)")
    parser.add_argument("--timeout", type=float, default=15.0)
    args = parser.parse_args()

    try:
        payload = fetch_computors_payload(args.host, args.port, args.timeout)
    except (OSError, FetchError) as e:
        print(f"fetch from {args.host}:{args.port} failed: {e}", file=sys.stderr)
        return 1

    if args.no_verify:
        print("WARNING: --no-verify: arbitrator signature NOT checked", file=sys.stderr)
    else:
        try:
            verdict = verify_computors_payload(args.verify_bin, args.arbitrator, payload)
        except FetchError as e:
            print(f"verification failed to run: {e}", file=sys.stderr)
            return 1
        if not verdict.get("valid"):
            print(f"REJECTED: computor list for epoch {verdict.get('epoch')} failed "
                  f"verification ({verdict.get('reason')})", file=sys.stderr)
            return 1
        print(f"arbitrator signature OK (epoch {verdict['epoch']})")

    path = write_keyset(Path(args.out), payload)
    print(f"wrote {path} (epoch {payload_epoch(payload)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
