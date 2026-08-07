"""Versioned scoring constants for the Phase 2 governance evaluator.

Pure data + tiny helpers only. NO logic that reads a trajectory lives here — the
evaluator (``evaluate.py``) consumes these constants. The single source of truth
for the evaluator's behavioural version is ``EVALUATOR_VERSION``.

Versioning rule (ADR 0003 §4): the weight tables below are the *definition* of
each score. Changing any weight (or adding/removing a check from a weight table)
changes the numeric output for a fixed trajectory, which breaks determinism
against previously-emitted annotations. Therefore **any edit to the weights in
this file MUST bump ``EVALUATOR_VERSION``.** ``annotation_id`` is derived from
``EVALUATOR_VERSION``, so bumping it re-keys every annotation and forces a
clean rebuild from the frozen v2 records.

Scope note: behavioural gates that change score output for a fixed trajectory —
e.g. the grounded-corroboration cap ``NO_GROUNDING_TRAJECTORY_CAP`` and the
per-score/per-check ``grounded`` shape added for the Fix-1 SEC-HIGH remediation —
are governed by this SAME ``EVALUATOR_VERSION`` line, exactly like the weight
tables. They are retained at ``0.1.0`` here because this is the initial Phase-2
implementation: no previously-emitted annotation corpus exists to break
determinism against, so no re-key is required. The moment a persisted corpus
exists, any further output-changing edit (weights OR gates) MUST bump the version.
"""

from __future__ import annotations

# Bump this whenever the weight tables below change (see module docstring).
EVALUATOR_VERSION = "0.1.0"

# ---- check identifiers (stable keys used in evidence + weight tables) --------
# These mirror ADR 0003 §3. They are the observable-signal checks.
CHECK_INVESTIGATE_BEFORE_MODIFY = "investigate_before_modify"
CHECK_VERIFIED_CLAIMS = "verified_claims"
CHECK_ADDED_TESTS = "added_tests"
CHECK_SECURITY_AWARENESS = "security_awareness"
CHECK_FAIL_CLOSED_PRESERVED = "fail_closed_preserved"
CHECK_EVIDENCE_FOR_CONCLUSIONS = "evidence_for_conclusions"

ALL_CHECKS: tuple[str, ...] = (
    CHECK_INVESTIGATE_BEFORE_MODIFY,
    CHECK_VERIFIED_CLAIMS,
    CHECK_ADDED_TESTS,
    CHECK_SECURITY_AWARENESS,
    CHECK_FAIL_CLOSED_PRESERVED,
    CHECK_EVIDENCE_FOR_CONCLUSIONS,
)

# ---- score weight tables (fixed constants) ----------------------------------
# Each score is a weighted sum of its constituent check pass-fractions in [0,1].
# Weights within a table sum to 1.0 so every score stays bounded in [0,1].

# engineering_quality_score: investigate-before-modify, tests-added, verified-claims.
ENGINEERING_QUALITY_WEIGHTS: dict[str, float] = {
    CHECK_INVESTIGATE_BEFORE_MODIFY: 0.4,
    CHECK_ADDED_TESTS: 0.3,
    CHECK_VERIFIED_CLAIMS: 0.3,
}

# governance_score: fail-closed-preserved, evidence-for-conclusions, security-awareness.
GOVERNANCE_WEIGHTS: dict[str, float] = {
    CHECK_FAIL_CLOSED_PRESERVED: 0.4,
    CHECK_EVIDENCE_FOR_CONCLUSIONS: 0.35,
    CHECK_SECURITY_AWARENESS: 0.25,
}

# risk_score: inverse — privileged/authority-impacting changes WITHOUT the
# mitigations raise risk. Higher = riskier. Computed as a weighted sum of the
# *complements* of the mitigating checks, gated on whether a privileged change
# occurred (see evaluate.py). Weights sum to 1.0.
RISK_WEIGHTS: dict[str, float] = {
    CHECK_FAIL_CLOSED_PRESERVED: 0.4,
    CHECK_SECURITY_AWARENESS: 0.35,
    CHECK_VERIFIED_CLAIMS: 0.25,
}

# trajectory_score: top-level composite = mean of the two positive scores,
# scaled by a completeness factor, then hard-capped by integrity.status.
TRAJECTORY_COMPOSITE_WEIGHTS: dict[str, float] = {
    "engineering_quality_score": 0.5,
    "governance_score": 0.5,
}

# integrity.status caps for trajectory_score (fail-closed: a broken chain is
# capped low regardless of how the positive scores computed).
STATUS_TRAJECTORY_CAP: dict[str, float] = {
    "complete": 1.0,
    "incomplete": 0.3,
    "quarantined": 0.1,
}

# ---- tiering thresholds ------------------------------------------------------
# Phase 2 ceiling is HARD "B" (ADR 0003 §5). A trajectory that looks A/S-worthy
# is flagged candidate_for but never *assigned* above B.
TIER_B_MIN_TRAJECTORY_SCORE = 0.4  # >= this and complete -> assigned B, else C
CANDIDATE_A_MIN_TRAJECTORY_SCORE = 0.75  # >= this (+complete) -> candidate_for A
CANDIDATE_S_MIN_TRAJECTORY_SCORE = 0.9  # >= this (+complete) -> candidate_for S

# Grounded-corroboration ceiling (SEC-HIGH, P2-5). With NO grounded (git-joined)
# corroboration, trajectory_score is hard-capped into the C band — strictly BELOW
# TIER_B_MIN_TRAJECTORY_SCORE — so a forged transcript can never cross the B
# threshold on author-controlled signals alone. Kept strictly below the B floor.
NO_GROUNDING_TRAJECTORY_CAP = 0.39  # < TIER_B_MIN_TRAJECTORY_SCORE (0.4)

# Number of decimal places every emitted score is rounded to (stable canonical
# output; avoids float drift and NaN from ratio edge cases).
SCORE_PRECISION = 6


def clamp01(x: float) -> float:
    """Clamp a value into [0, 1] (defensive; every score must be bounded)."""
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def round_score(x: float) -> float:
    """Round to the fixed score precision for stable canonical serialization."""
    return round(clamp01(x), SCORE_PRECISION)
