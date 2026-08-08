"""Outcome grounding (Phase 3).

Links a trajectory + its annotation to MEASURABLE outcomes (commit, diff, tests,
CI, review, deploy) and only then confirms high tiers. Deterministic: all outcome
evidence is SUPPLIED (from git_evidence + external test/CI/review records); this
module performs no non-deterministic fetches. Never mutates the trajectory or the
annotation — emits a separate governance_outcome/v1 artifact.

Fail-closed: any required evidence missing/None → no tier promotion. Success is
never marked without evidence.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, sha256_hex

OUTCOME_VERSION = "governance_outcome/v1"


def _norm_commit(inp: dict[str, Any]) -> dict[str, Any] | None:
    c = inp.get("commit")
    if not c or not c.get("sha"):
        return None
    diff = c.get("diff_ref")
    diff_ref = None
    if diff and diff.get("uri") and diff.get("sha256"):
        diff_ref = {"uri": diff["uri"], "sha256": diff["sha256"]}
    return {"sha": c["sha"], "diff_ref": diff_ref}


def build_outcome(annotation: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
    """Build a governance_outcome/v1 artifact from an annotation + supplied evidence.

    ``inputs`` (all optional, absent → fail-closed):
      commit: {sha, diff_ref:{uri,sha256}}
      tests:  {passed: bool, command, marker_sha256}
      ci:     {status: passed|failed|pending|none}
      review: {decision: approved|changes_requested|commented|none, reviewer}
      deploy: {status: deployed|failed|none}
    """
    commit = _norm_commit(inputs)
    tests_in = inputs.get("tests") or {}
    tests = {
        "passed": tests_in.get("passed") if isinstance(tests_in.get("passed"), bool) else None,
        "command": tests_in.get("command"),
        "marker_sha256": tests_in.get("marker_sha256"),
    }
    ci = {"status": (inputs.get("ci") or {}).get("status", "none")}
    review = {
        "decision": (inputs.get("review") or {}).get("decision", "none"),
        "reviewer": (inputs.get("review") or {}).get("reviewer"),
    }
    deploy = {"status": (inputs.get("deploy") or {}).get("status", "none")}

    present: list[str] = []
    if commit:
        present.append("commit")
    if tests["passed"] is not None:
        present.append("tests")
    if ci["status"] != "none":
        present.append("ci")
    if review["decision"] != "none":
        present.append("review")
    if deploy["status"] != "none":
        present.append("deploy")

    # deploy is captured as evidence (folded into outcome_id) but is intentionally
    # NOT a promotion gate — only commit/tests (A) and +review/ci (S) gate the tier.
    grounded = ground_tier(annotation, commit, tests, ci, review)

    outcome = {
        "outcome_version": OUTCOME_VERSION,
        "outcome_id": sha256_hex(annotation["annotation_id"] + _evidence_digest(commit, tests, ci, review, deploy)),
        "trajectory_ref": dict(annotation["trajectory_ref"]),
        "annotation_ref": {
            "annotation_id": annotation["annotation_id"],
            "annotation_sha256": annotation["integrity"]["annotation_sha256"],
            "evaluator_version": annotation["evaluator_version"],
        },
        "commit": commit,
        "tests": tests,
        "ci": ci,
        "review": review,
        "deploy": deploy,
        "grounded_tier": grounded,
        "integrity": {
            "outcome_sha256": "0" * 64,
            "inputs_present": present,
            "fail_closed": True,
        },
    }
    _stamp(outcome)
    return outcome


def ground_tier(annotation, commit, tests, ci, review) -> dict[str, Any]:
    """Lift the Phase-2 provisional tier ONLY with real outcome evidence."""
    base = annotation["tier"]["assigned"]
    candidate = annotation["tier"].get("candidate_for")
    reasons: list[str] = []
    confirmed: list[str] = []

    # fail-closed: a Phase-2 annotation must be capped at B/C. Anything else is
    # out-of-contract (tampered / wrong producer) -> treat as C, never trust it up.
    if base not in ("B", "C"):
        return {"assigned": "C", "confirmed_by": [], "reasons": ["invalid_base_tier_fail_closed"]}

    # a quarantined/incomplete-derived C or a non-candidate never promotes
    if base == "C" or candidate is None:
        reasons.append("no_promotion_no_candidate_or_tier_C")
        return {"assigned": base, "confirmed_by": confirmed, "reasons": reasons}

    tests_ok = tests.get("passed") is True
    has_commit = commit is not None
    review_ok = review.get("decision") == "approved"
    ci_ok = ci.get("status") == "passed"

    # A: meaningful work + complete trajectory + verified outcome
    if candidate in ("A", "S") and tests_ok and has_commit:
        confirmed += [f"tests:{tests.get('command') or 'passed'}", f"commit:{commit['sha']}"]
        # S: also human-reviewed + CI green (merged-quality)
        if review_ok and ci_ok:
            confirmed += [f"review:{review.get('reviewer') or 'approved'}", "ci:passed"]
            reasons.append("confirmed_S_verified_outcome_reviewed_ci_green")
            return {"assigned": "S", "confirmed_by": confirmed, "reasons": reasons}
        reasons.append("confirmed_A_verified_outcome")
        return {"assigned": "A", "confirmed_by": confirmed, "reasons": reasons}

    # candidate present but outcome evidence incomplete -> stay at base (fail-closed)
    missing = []
    if not tests_ok:
        missing.append("tests_passed")
    if not has_commit:
        missing.append("commit")
    reasons.append("promotion_withheld_missing:" + ",".join(missing) if missing else "promotion_withheld")
    return {"assigned": base, "confirmed_by": confirmed, "reasons": reasons}


def _evidence_digest(commit, tests, ci, review, deploy) -> str:
    return sha256_hex(canonical_bytes([commit, tests, ci, review, deploy]))


def _stamp(outcome: dict[str, Any]) -> None:
    clone = json.loads(json.dumps(outcome))
    clone["integrity"]["outcome_sha256"] = "0" * 64
    outcome["integrity"]["outcome_sha256"] = sha256_hex(canonical_bytes(clone))


def collect_git_outcome(repo: str, commit_sha: str, parent_sha: str | None = None) -> dict[str, Any]:
    """Helper: assemble the git portion of outcome inputs from the H1 capture.
    Deterministic given the repo state; used to feed build_outcome(inputs)."""
    from .git_evidence import git_transition, subprocess_runner

    out: dict[str, Any] = {"commit": {"sha": commit_sha}}
    if parent_sha:
        block = git_transition(parent_sha, commit_sha, subprocess_runner(repo))
        out["commit"]["diff_ref"] = {
            "uri": f"git:{parent_sha}..{commit_sha}",
            "sha256": sha256_hex(canonical_bytes(block)),
        }
    return out


class OutcomeStore:
    """Content-addressed outcome artifacts + hash-chained registry (mirrors AnnotationStore)."""

    def __init__(self, root: str | os.PathLike[str]) -> None:
        self.root = Path(root)
        self.dir = self.root / "outcomes"
        self.registry_path = self.root / "outcome_registry.jsonl"
        self.dir.mkdir(parents=True, exist_ok=True)

    def put(self, outcome: dict[str, Any]) -> str:
        oid = outcome["outcome_id"]
        d = self.dir / oid[:2]
        d.mkdir(parents=True, exist_ok=True)
        path = d / f"{oid}.json"
        if not path.exists():
            path.write_text(json.dumps(outcome, sort_keys=True, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        return str(path.relative_to(self.root))

    def _last(self) -> str | None:
        if not self.registry_path.exists():
            return None
        last = None
        for line in self.registry_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                last = line
        return json.loads(last).get("entry_sha256") if last else None

    def annotate(self, outcome: dict[str, Any]) -> dict[str, Any]:
        uri = self.put(outcome)
        body = {
            "outcome_id": outcome["outcome_id"],
            "trajectory_id": outcome["trajectory_ref"]["trajectory_id"],
            "annotation_id": outcome["annotation_ref"]["annotation_id"],
            "grounded_tier": outcome["grounded_tier"]["assigned"],
            "outcome_sha256": outcome["integrity"]["outcome_sha256"],
            "uri": uri,
            "prev_entry_sha256": self._last(),
        }
        body["entry_sha256"] = sha256_hex(canonical_bytes(body))
        with self.registry_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(body, sort_keys=True, ensure_ascii=False) + "\n")
        return body

    def verify_chain(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        prev = None
        if not self.registry_path.exists():
            return True, errors
        for i, line in enumerate(self.registry_path.read_text(encoding="utf-8").splitlines()):
            if not line.strip():
                continue
            entry = json.loads(line)
            claimed = entry.get("entry_sha256")
            if entry.get("prev_entry_sha256") != prev:
                errors.append(f"entry {i}: broken prev link")
            body = {k: v for k, v in entry.items() if k != "entry_sha256"}
            if sha256_hex(canonical_bytes(body)) != claimed:
                errors.append(f"entry {i}: hash mismatch")
            prev = claimed
        return (not errors), errors
