"""Wraps the oc_verify C++ CLI: hand it a raw bundle + the epoch's computor
keys, get back a verdict.

Key provisioning for the PoC: computor public keys are read from a per-epoch
file `<keys_dir>/computors_<epoch>.bin` (676 * 32 raw bytes, the publicKeys[]
array from a BroadcastComputors message). Fetching that from a live Qubic node
is a later refinement; the file lets us run the whole service + demo now.
"""

import json
import struct
import subprocess
from pathlib import Path

# Header: invocationId(q) epoch(H) interfaceIndex(H) requestSize(H) signatureCount(H)
_HEADER = struct.Struct("<qHHHH")
NUMBER_OF_COMPUTORS = 676
KEYS_BYTES = NUMBER_OF_COMPUTORS * 32


class VerifyError(Exception):
    pass


class Verifier:
    def __init__(self, oc_verify_path: str, keys_dir: str):
        self.oc_verify = oc_verify_path
        self.keys_dir = Path(keys_dir)
        if not Path(oc_verify_path).exists():
            raise FileNotFoundError(f"oc_verify binary not found: {oc_verify_path}")

    def peek_epoch(self, bundle: bytes) -> int:
        """Read the epoch from the bundle header without verifying."""
        if len(bundle) < _HEADER.size:
            raise VerifyError("bundle too small for header")
        _, epoch, _, _, _ = _HEADER.unpack_from(bundle, 0)
        return epoch

    def keys_path(self, epoch: int) -> Path:
        return self.keys_dir / f"computors_{epoch}.bin"

    def cached_epochs(self) -> list:
        """Epochs we hold a keyset for, ascending. Empty if none fetched yet."""
        epochs = []
        for p in self.keys_dir.glob("computors_*.bin"):
            try:
                epochs.append(int(p.stem.split("_")[1]))
            except (IndexError, ValueError):
                continue  # not one of ours
        return sorted(epochs)

    def verify(self, bundle: bytes) -> dict:
        """Verify a raw OcMachineInvocation bundle.

        Returns the parsed verdict dict from oc_verify, always including
        'valid' (bool). Raises VerifyError if keys for the epoch are missing.
        """
        epoch = self.peek_epoch(bundle)
        keys = self.keys_path(epoch)
        if not keys.exists():
            raise VerifyError(f"no computor keys for epoch {epoch} ({keys})")

        proc = subprocess.run(
            [self.oc_verify, "--keys", str(keys)],
            input=bundle,
            capture_output=True,
            timeout=30,
        )
        # oc_verify prints one JSON verdict line on stdout for exit 0/1.
        out = proc.stdout.decode("utf-8", "replace").strip()
        if proc.returncode == 2 or not out:
            raise VerifyError(
                f"oc_verify usage/IO error (rc={proc.returncode}): "
                f"{proc.stderr.decode('utf-8', 'replace').strip()}"
            )
        try:
            verdict = json.loads(out.splitlines()[-1])
        except json.JSONDecodeError as e:
            raise VerifyError(f"cannot parse oc_verify output: {out!r}") from e
        return verdict

    @staticmethod
    def request_hex(bundle: bytes) -> str:
        """Extract the pinned request bytes as hex for display/storage."""
        _, _, _, req_size, _ = _HEADER.unpack_from(bundle, 0)
        start = _HEADER.size
        return bundle[start:start + req_size].hex()
