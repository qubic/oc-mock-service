"""Fetching + verifying epoch computor keysets from a Qubic node.

Speaks just enough of the Qubic peer protocol to pull a BroadcastComputors
message, verifies the arbitrator signature on it via the computors_verify C++
CLI, and writes the keyset file the bundle verifier expects
(keys/computors_<epoch>.bin, 676 * 32 raw public-key bytes).

KeyFetcher gives the service lazy self-healing across epoch transitions: when
a bundle arrives for an epoch with no local keyset, it fetches the list from
the configured node on the spot (with a cooldown so garbage bundles with fake
epochs cannot make it hammer the node).
"""

import json
import random
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

REQUEST_COMPUTORS = 11   # NetworkMessageType::REQUEST_COMPUTORS
BROADCAST_COMPUTORS = 2  # NetworkMessageType::BROADCAST_COMPUTORS

NUMBER_OF_COMPUTORS = 676
HEADER_SIZE = 8
# Computors payload: epoch (2) + publicKeys (676*32) + signature (64)
PAYLOAD_SIZE = 2 + NUMBER_OF_COMPUTORS * 32 + 64
KEYS_OFFSET = 2
KEYS_SIZE = NUMBER_OF_COMPUTORS * 32


class FetchError(Exception):
    pass


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise FetchError("node closed the connection")
        buf += chunk
    return buf


def fetch_computors_payload(host: str, port: int, timeout: float = 15.0) -> bytes:
    """Request BroadcastComputors from a node; return the raw Computors payload."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        # Header only, no payload. Non-zero random dejavu marks a direct request.
        dejavu = random.getrandbits(32) or 1
        sock.sendall(struct.pack(
            "<BBBB I", HEADER_SIZE & 0xFF, (HEADER_SIZE >> 8) & 0xFF,
            (HEADER_SIZE >> 16) & 0xFF, REQUEST_COMPUTORS, dejavu))

        # The node multiplexes other traffic; skip frames until the answer arrives.
        while True:
            header = _recv_exact(sock, HEADER_SIZE)
            size = header[0] | (header[1] << 8) | (header[2] << 16)
            if size < HEADER_SIZE:
                raise FetchError(f"corrupt frame (size {size})")
            body = _recv_exact(sock, size - HEADER_SIZE)
            if header[3] != BROADCAST_COMPUTORS:
                continue
            # The core tolerates up to 4 padding bytes on this message; so do we.
            if not (PAYLOAD_SIZE <= len(body) <= PAYLOAD_SIZE + 4):
                raise FetchError(f"unexpected BroadcastComputors size {len(body)}")
            return body[:PAYLOAD_SIZE]


def verify_computors_payload(verify_bin: str, arbitrator: str, payload: bytes) -> dict:
    """Run computors_verify; returns the verdict dict (always has 'valid')."""
    proc = subprocess.run(
        [verify_bin, "--arbitrator", arbitrator],
        input=payload, capture_output=True, timeout=30)
    out = proc.stdout.decode("utf-8", "replace").strip()
    if proc.returncode == 2 or not out:
        raise FetchError(
            f"computors_verify usage/IO error (rc={proc.returncode}): "
            f"{proc.stderr.decode('utf-8', 'replace').strip()}")
    try:
        return json.loads(out.splitlines()[-1])
    except json.JSONDecodeError as e:
        raise FetchError(f"cannot parse computors_verify output: {out!r}") from e


def payload_epoch(payload: bytes) -> int:
    return struct.unpack_from("<H", payload, 0)[0]


def write_keyset(keys_dir: Path, payload: bytes) -> Path:
    """Extract publicKeys[] from a (verified) payload and write the keyset file."""
    epoch = payload_epoch(payload)
    keys_dir.mkdir(parents=True, exist_ok=True)
    path = keys_dir / f"computors_{epoch}.bin"
    path.write_bytes(payload[KEYS_OFFSET:KEYS_OFFSET + KEYS_SIZE])
    return path


class KeyFetcher:
    """Lazy, verified, rate-limited keyset provisioning from a trusted-transport node.

    The node is only trusted as a transport: the arbitrator signature on the
    fetched list is what authenticates it (mirroring processBroadcastComputors
    in the core), so even a compromised node cannot substitute keys.
    """

    def __init__(self, node_host: str, node_port: int, arbitrator: str,
                 verify_bin: str, keys_dir: str, cooldown: float = 60.0,
                 allow_unsigned: bool = False):
        self.node_host = node_host
        self.node_port = node_port
        self.arbitrator = arbitrator
        self.verify_bin = verify_bin
        self.keys_dir = Path(keys_dir)
        self.cooldown = cooldown
        # Test networks load their computor list from disk without an arbitrator,
        # leaving the signature all-zero. With allow_unsigned, exactly that case
        # is accepted (a non-zero-but-wrong signature is still rejected, and the
        # zeroed-key check still applies). NEVER enable against mainnet.
        self.allow_unsigned = allow_unsigned
        self._last_attempt = 0.0

    def ensure(self, epoch: int) -> bool:
        """Make sure keys/computors_<epoch>.bin exists; fetch if missing.

        Returns True if the file exists afterwards. A node only ever serves its
        CURRENT epoch's list, so a request for another epoch fetches (and
        caches) whatever the node has and then reports honestly.
        """
        path = self.keys_dir / f"computors_{epoch}.bin"
        if path.exists():
            return True

        now = time.monotonic()
        if now - self._last_attempt < self.cooldown:
            return False
        self._last_attempt = now

        try:
            payload = fetch_computors_payload(self.node_host, self.node_port)
            verdict = verify_computors_payload(self.verify_bin, self.arbitrator, payload)
        except (OSError, FetchError) as e:
            print(f"KeyFetcher: fetch from {self.node_host}:{self.node_port} failed: {e}",
                  file=sys.stderr)
            return False

        if not verdict.get("valid"):
            unsigned = payload[-64:] == bytes(64)
            if (self.allow_unsigned and unsigned
                    and verdict.get("reason") == "arbitrator signature invalid"):
                print(f"KeyFetcher: WARNING accepting UNSIGNED computor list for epoch "
                      f"{verdict.get('epoch')} (OC_ALLOW_UNSIGNED_COMPUTORS — testnet only)",
                      file=sys.stderr)
            else:
                print(f"KeyFetcher: REJECTED computor list for epoch {verdict.get('epoch')} "
                      f"({verdict.get('reason')}) — arbitrator signature check failed",
                      file=sys.stderr)
                return False

        written = write_keyset(self.keys_dir, payload)
        print(f"KeyFetcher: verified + wrote {written} (epoch {verdict['epoch']})",
              file=sys.stderr)
        return path.exists()
