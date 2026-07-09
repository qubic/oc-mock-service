"""SQLite storage + dedup for verified OC invocations.

Dedup key is invocationId: every operator's OC machine forwards the SAME
authorized bundle to the single public service, so the same invocationId
arrives many times. We store each verified invocation once and count how many
distinct sources reported it (the "replication factor").
"""

import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS invocations (
    invocation_id   INTEGER PRIMARY KEY,   -- dedup key
    tick            INTEGER NOT NULL,
    epoch           INTEGER NOT NULL,
    interface_index INTEGER NOT NULL,
    request_size    INTEGER NOT NULL,
    request_hex     TEXT    NOT NULL,       -- raw pinned OcRequest bytes, hex
    verified_sigs   INTEGER NOT NULL,       -- distinct valid signatures (>= 451)
    first_seen      REAL    NOT NULL,       -- unix ts of first accepted delivery
    last_seen       REAL    NOT NULL
);

CREATE TABLE IF NOT EXISTS deliveries (
    invocation_id INTEGER NOT NULL,
    source        TEXT    NOT NULL,         -- reporting OC machine (ip or id)
    seen          REAL    NOT NULL,
    PRIMARY KEY (invocation_id, source)     -- one row per (order, source)
);
"""


class Store:
    def __init__(self, path: str):
        self.path = path
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def record(self, *, invocation_id, tick, epoch, interface_index,
               request_size, request_hex, verified_sigs, source):
        """Store a verified invocation (idempotent) and log the delivery.

        Returns (is_new, replication_factor).
        """
        now = time.time()
        with self._conn() as c:
            # Upsert the invocation; INSERT OR IGNORE keeps the first-seen row.
            cur = c.execute(
                """INSERT OR IGNORE INTO invocations
                   (invocation_id, tick, epoch, interface_index, request_size,
                    request_hex, verified_sigs, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (invocation_id, tick, epoch, interface_index, request_size,
                 request_hex, verified_sigs, now, now),
            )
            is_new = cur.rowcount == 1
            if not is_new:
                c.execute(
                    "UPDATE invocations SET last_seen=? WHERE invocation_id=?",
                    (now, invocation_id),
                )
            # Log this source's delivery (idempotent per source).
            c.execute(
                "INSERT OR IGNORE INTO deliveries (invocation_id, source, seen) VALUES (?,?,?)",
                (invocation_id, source, now),
            )
            rep = c.execute(
                "SELECT COUNT(*) AS n FROM deliveries WHERE invocation_id=?",
                (invocation_id,),
            ).fetchone()["n"]
        return is_new, rep

    def recent(self, limit: int = 100):
        with self._conn() as c:
            rows = c.execute(
                """SELECT i.*,
                          (SELECT COUNT(*) FROM deliveries d
                             WHERE d.invocation_id = i.invocation_id) AS replication
                   FROM invocations i
                   ORDER BY i.first_seen DESC
                   LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]
