"""SQLite index (Phase 4).

Derived, rebuildable query layer over trajectories + annotations + outcomes. Holds
ids, digests, scores, tiers, and area — NO authoritative content (raw + artifacts
remain the source). Deleting the index loses nothing: rebuild from the frozen
records + evaluator/evaluator_version.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS trajectories (
    trajectory_id TEXT PRIMARY KEY,
    normalized_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    session_id TEXT,
    model TEXT,
    claude_code_version TEXT
);
-- one annotation / one outcome per trajectory: re-grounding or re-evaluation
-- REPLACES the prior row (INSERT OR REPLACE on the UNIQUE trajectory_id), so a
-- stale row can never mask the current tier (reviewer finding).
CREATE TABLE IF NOT EXISTS annotations (
    annotation_id TEXT PRIMARY KEY,
    trajectory_id TEXT NOT NULL UNIQUE,
    evaluator_version TEXT NOT NULL,
    engineering_quality REAL, governance REAL, risk REAL, trajectory REAL,
    tier TEXT, candidate_for TEXT, system_area TEXT,
    FOREIGN KEY (trajectory_id) REFERENCES trajectories(trajectory_id)
);
CREATE TABLE IF NOT EXISTS outcomes (
    outcome_id TEXT PRIMARY KEY,
    trajectory_id TEXT NOT NULL UNIQUE,
    annotation_id TEXT NOT NULL,
    grounded_tier TEXT NOT NULL,
    tests_passed INTEGER, ci_status TEXT, review_decision TEXT,
    FOREIGN KEY (trajectory_id) REFERENCES trajectories(trajectory_id)
);
CREATE INDEX IF NOT EXISTS idx_ann_tier ON annotations(tier);
CREATE INDEX IF NOT EXISTS idx_ann_area ON annotations(system_area);
CREATE INDEX IF NOT EXISTS idx_out_tier ON outcomes(grounded_tier);
"""


class Index:
    def __init__(self, path: str | os.PathLike[str] = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # ---- ingest (idempotent upserts) ---------------------------------------

    def add_trajectory(self, record: dict[str, Any]) -> None:
        env = record["environment"]
        self.conn.execute(
            "INSERT OR REPLACE INTO trajectories VALUES (?,?,?,?,?,?)",
            (record["trajectory_id"], record["integrity"]["normalized_sha256"],
             record["integrity"]["status"], env.get("session_id"), env.get("model"),
             env.get("claude_code_version")),
        )
        self.conn.commit()

    def add_annotation(self, ann: dict[str, Any]) -> None:
        s = ann["scores"]
        self.conn.execute(
            "INSERT OR REPLACE INTO annotations VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ann["annotation_id"], ann["trajectory_ref"]["trajectory_id"], ann["evaluator_version"],
             s["engineering_quality"], s["governance"], s["risk"], s["trajectory"],
             ann["tier"]["assigned"], ann["tier"].get("candidate_for"), ann["system_area"]),
        )
        self.conn.commit()

    def add_outcome(self, outcome: dict[str, Any]) -> None:
        tp = outcome["tests"]["passed"]
        self.conn.execute(
            "INSERT OR REPLACE INTO outcomes VALUES (?,?,?,?,?,?,?)",
            (outcome["outcome_id"], outcome["trajectory_ref"]["trajectory_id"],
             outcome["annotation_ref"]["annotation_id"], outcome["grounded_tier"]["assigned"],
             None if tp is None else int(tp), outcome["ci"]["status"], outcome["review"]["decision"]),
        )
        self.conn.commit()

    # ---- queries -----------------------------------------------------------

    def effective_tier(self, trajectory_id: str) -> str:
        """Grounded tier if an outcome exists, else the annotation's provisional tier."""
        r = self.conn.execute("SELECT grounded_tier FROM outcomes WHERE trajectory_id=? ORDER BY outcome_id LIMIT 1",
                              (trajectory_id,)).fetchone()
        if r:
            return r["grounded_tier"]
        r = self.conn.execute("SELECT tier FROM annotations WHERE trajectory_id=? ORDER BY annotation_id LIMIT 1",
                              (trajectory_id,)).fetchone()
        return r["tier"] if r else "C"

    def by_effective_tier(self, tiers: tuple[str, ...]) -> list[str]:
        ids = [row["trajectory_id"] for row in self.conn.execute("SELECT trajectory_id FROM trajectories")]
        return sorted(tid for tid in ids if self.effective_tier(tid) in tiers)

    def by_area(self, areas: tuple[str, ...]) -> list[str]:
        q = "SELECT DISTINCT trajectory_id FROM annotations WHERE system_area IN (%s)" % ",".join("?" * len(areas))
        return sorted(row["trajectory_id"] for row in self.conn.execute(q, areas))

    def annotation_for(self, trajectory_id: str) -> dict[str, Any] | None:
        r = self.conn.execute("SELECT * FROM annotations WHERE trajectory_id=? ORDER BY annotation_id LIMIT 1",
                              (trajectory_id,)).fetchone()
        return dict(r) if r else None

    def tier_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for tid in (row["trajectory_id"] for row in self.conn.execute("SELECT trajectory_id FROM trajectories")):
            t = self.effective_tier(tid)
            counts[t] = counts.get(t, 0) + 1
        return counts
