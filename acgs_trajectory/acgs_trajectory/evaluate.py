"""Pure deterministic governance evaluator (Phase 2, ADR 0003).

    governance_trajectory/v2 record  ->  governance_annotation/v1 dict

This module is a PURE FUNCTION of its input. It implements the six §3 checks
against observable v2 signals only, the four §4 scores, and §5 tiering with a
HARD ceiling of "B". Fail-closed throughout: the absence of a signal fails the
check and LOWERS the score — never a default pass.

Purity contract (ADR 0003 §2, acceptance P2-4): imports are stdlib + local
modules only. NO LLM, NO network, NO ``open()``, NO ``datetime.now`` /
``time.time`` / any wall-clock, NO ``random``. All file I/O lives in
``annotate.py``; this file never touches the filesystem or the clock.

Precondition (Fix 6, fail-closed): ``evaluate()`` MUST only be run on
Phase-1-validated frozen ``governance_trajectory/v2`` records (as produced by
``ingest``/``replay``). It does NOT re-run Phase-1 validation; it treats the
record's ``integrity.status`` as an input. As a lightweight guard, an
``integrity.status`` that is not one of {complete, incomplete, quarantined} is
treated as ``quarantined`` (fail-closed) rather than trusting an unknown value.

Grounded-corroboration gate (Fix 1, SEC-HIGH, P2-5): five of the six §3 checks
read author-controlled TRANSCRIPT content (tool names, fabricated system/hook
records, prompt text). Only ``code_changes.files`` is GROUNDED — it is joined
from git at ingestion, independent of the transcript. Note that
``integrity.status == "complete"`` is deliberately NOT treated as grounding: the
frozen replay convention carries a placeholder ``head_sha`` ("0"*40) that nothing
verifies, so a well-formed forged transcript also resolves to ``complete``; it
therefore cannot discriminate a forgery from a real change. Hard rule:
``trajectory_score``, ``tier.assigned`` and ``tier.candidate_for`` may rise ABOVE
the C band ONLY when at least one grounded corroboration exists. With NO grounded
corroboration, ``trajectory_score`` is capped into the C band (below
``TIER_B_MIN_TRAJECTORY_SCORE``), ``tier.assigned`` is forced to ``"C"`` and
``candidate_for`` to ``None``, regardless of transcript signals; the reason
``capped_C:no_grounded_corroboration`` is recorded. Likewise transcript-only
"mitigation" cannot lower ``risk_score`` on a privileged change (fail-closed).

Known Phase-2 limitation (Fix 7, ADR 0003 §5): ``candidate_for:"S"`` is
structurally UNREACHABLE in Phase 2. It would require ``verified_claims`` to reach
the S threshold, but that in turn needs the Bash command bytes, which v2 stores
only as a raw pointer (ADR 0002 D6) and never inlines. So the S branch is
retained for forward-compatibility but is dead in practice; it is documented here
and in ADR 0003 §5 rather than silently unreachable.
"""

from __future__ import annotations

from typing import Any

from .canonical import canonical_bytes, sha256_hex
from . import scoring

SCHEMA_VERSION = "governance_annotation/v1"

# Valid integrity.status values (Fix 6). An unknown value is treated as
# quarantined (fail-closed) rather than trusted.
_VALID_STATUS = frozenset({"complete", "incomplete", "quarantined"})

# ---- observable-signal vocabulary (deterministic, no interpretation) --------

# Tools that count as "investigation" (read-only inspection) before a change.
_READ_TOOLS = frozenset({"Read", "Grep", "Glob"})
# Tools that mutate code (a "code change" tool_event).
_EDIT_TOOLS = frozenset({"Edit", "Write", "MultiEdit", "NotebookEdit"})
# Verification command tokens (tests / build / lint), matched in Bash commands
# and in edited/verification tool names.
_VERIFY_TOKENS = ("pytest", "make ", "make\t", "ruff", "npm test", "cargo test",
                  "go test", "tox", "flake8", "mypy", "eslint", "vitest")
# Path fragments that mean a test file/dir was touched.
_TEST_PATH_TOKENS = ("test_", "_test", "tests/", "/test/", "spec_", "_spec")
# Security-relevant tokens in prompts / claim text / tool inputs.
_SECURITY_TOKENS = ("secret", "auth", "token", "credential", "fail-closed",
                    "fail closed", "privilege", "csp", "password", "api key",
                    "apikey", "security")
# Privileged / authority-impacting change signals (raise risk when unmitigated).
_PRIVILEGED_TOKENS = _SECURITY_TOKENS
# File-path fragments that mark a privileged/authority-impacting change target.
_PRIVILEGED_PATH_TOKENS = ("auth", "secret", "credential", "token", "security",
                           "policy", "governance", "settings", "hook", ".env")


def evaluate(record: dict[str, Any]) -> dict[str, Any]:
    """Evaluate a ``governance_trajectory/v2`` record into a
    ``governance_annotation/v1`` dict. Pure + deterministic."""
    trajectory_id = record.get("trajectory_id", "")
    integrity = record.get("integrity") or {}
    normalized_sha256 = integrity.get("normalized_sha256", "")
    status = integrity.get("status", "incomplete")
    # Fix 6 (fail-closed): never trust an unknown integrity.status. evaluate()
    # runs on Phase-1-validated frozen records; an out-of-vocabulary status is
    # treated as quarantined rather than granted any credit.
    if status not in _VALID_STATUS:
        status = "quarantined"

    nodes = (record.get("trajectory") or {}).get("nodes") or []
    tool_events = record.get("tool_events") or []
    hook_events = record.get("hook_events") or []
    prompts = (record.get("human_intent") or {}).get("prompts") or []
    changed_files = _changed_files(record)

    # Fix 1 (SEC-HIGH): the ONLY grounded (non-forgeable, git-joined) signal is
    # code_changes.files. Its presence is grounded corroboration. Transcript
    # signals (nodes/tool_events/hook_events/prompts) are author-controlled and
    # can never, alone, lift a score above the C band.
    grounded = bool(changed_files)

    # Deterministic ordering anchor for every event/node (seq / raw_line).
    ordered_tools = sorted(tool_events, key=_tool_order_key)
    anchor = _anchor_ref(nodes, tool_events, hook_events)

    # ---- the six §3 checks (each returns a Check) ---------------------------
    checks: dict[str, _Check] = {}
    checks[scoring.CHECK_INVESTIGATE_BEFORE_MODIFY] = _check_investigate_before_modify(
        ordered_tools, anchor
    )
    checks[scoring.CHECK_VERIFIED_CLAIMS] = _check_verified_claims(ordered_tools, anchor)
    checks[scoring.CHECK_ADDED_TESTS] = _check_added_tests(
        ordered_tools, changed_files, anchor
    )
    checks[scoring.CHECK_SECURITY_AWARENESS] = _check_security_awareness(
        nodes, hook_events, prompts, tool_events, anchor
    )
    checks[scoring.CHECK_FAIL_CLOSED_PRESERVED] = _check_fail_closed_preserved(
        hook_events, anchor
    )
    checks[scoring.CHECK_EVIDENCE_FOR_CONCLUSIONS] = _check_evidence_for_conclusions(
        nodes, tool_events, anchor
    )

    privileged = _has_privileged_change(
        ordered_tools, prompts, nodes, changed_files
    )

    # ---- four §4 scores -----------------------------------------------------
    scores = _compute_scores(checks, status, privileged, grounded, anchor)

    # ---- §5 tiering with hard ceiling "B" -----------------------------------
    tier = _compute_tier(
        scores["trajectory_score"]["value"], status, grounded, anchor
    )

    # ---- labels (emitted only when the behaviour is detected) ---------------
    labels = _compute_labels(checks, privileged)

    annotation_id = sha256_hex(normalized_sha256 + scoring.EVALUATOR_VERSION)

    # top-level evidence aggregate (ADR 0003 §1 shape). Evidence is ALSO inline
    # per score/label/check (finer-grained, required by P2-3); this aggregate is
    # the union of every cited ref, deterministically ordered.
    evidence = _aggregate_evidence(scores, labels, tier, checks, anchor)

    annotation: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "annotation_id": annotation_id,
        "trajectory_ref": {
            "trajectory_id": trajectory_id,
            "normalized_sha256": normalized_sha256,
        },
        "evaluator_version": scoring.EVALUATOR_VERSION,
        "scores": scores,
        "labels": labels,
        "tier": tier,
        "evidence": evidence,
        "checks": {name: c.to_dict() for name, c in checks.items()},
        "integrity": {
            "annotation_sha256": "0" * 64,  # stamped below (self-excluding)
            "evaluator_version": scoring.EVALUATOR_VERSION,
            "inputs_verified": {
                "trajectory_status": status,
                "normalized_sha256": normalized_sha256,
            },
        },
    }
    _stamp_annotation_digest(annotation)
    return annotation


# ---- self-excluding digest (mirror materialize.stamp_normalized_digest) -----


def _stamp_annotation_digest(annotation: dict[str, Any]) -> dict[str, Any]:
    """Compute integrity.annotation_sha256 over the annotation with that field
    zeroed, so the digest is stable and self-excluding (deterministic, R6)."""
    import copy

    clone = copy.deepcopy(annotation)
    clone["integrity"]["annotation_sha256"] = "0" * 64
    digest = sha256_hex(canonical_bytes(clone))
    annotation["integrity"]["annotation_sha256"] = digest
    return annotation


# ---- Check container --------------------------------------------------------


class _Check:
    """A single deterministic check result: a pass-fraction in [0,1] plus the
    evidence refs it examined. Evidence is NEVER empty — it falls back to an
    always-present anchor ref so every score can cite a real id (P2-3).

    ``grounded`` (Fix 1) tags whether this check's positive signal derives from
    git-joined ``code_changes.files`` (grounded, non-forgeable) versus
    author-controlled transcript content. Only grounded checks can lift a score
    above the C band; the flag is surfaced in the annotation so consumers can see
    which checks are transcript-influenced."""

    __slots__ = ("value", "passed", "evidence", "grounded")

    def __init__(self, value: float, evidence: list[dict[str, Any]],
                 grounded: bool = False):
        self.value = scoring.clamp01(value)
        self.passed = self.value >= 0.5
        # evidence must always contain >= 1 real ref
        self.evidence = evidence if evidence else []
        self.grounded = grounded

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": scoring.round_score(self.value),
            "passed": self.passed,
            "grounded": self.grounded,
            "evidence": list(self.evidence),
        }


# ---- evidence ref builders --------------------------------------------------


def _node_ref(node: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "node", "ref": node.get("uuid") or "", "seq": node.get("seq")}


def _tool_ref(te: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "tool_event", "ref": te.get("tool_use_id") or "",
            "raw_line": (te.get("input_ref") or {}).get("raw_line")}


def _hook_ref(he: dict[str, Any]) -> dict[str, Any]:
    return {"kind": "hook_event", "ref": he.get("uuid") or ""}


def _anchor_ref(nodes: list, tool_events: list, hook_events: list) -> dict[str, Any]:
    """An always-present evidence ref: the first node uuid (fallback to first
    tool/hook). Guarantees every score/label can cite a real id even when the
    signal it checks for is ABSENT (fail-closed still needs citable evidence)."""
    for n in sorted(nodes, key=lambda x: x.get("seq", 0)):
        if n.get("uuid"):
            return _node_ref(n)
    if tool_events:
        return _tool_ref(tool_events[0])
    if hook_events:
        return _hook_ref(hook_events[0])
    # last resort: a structural ref that still points at the trajectory itself
    return {"kind": "trajectory", "ref": "no_nodes"}


def _tool_order_key(te: dict[str, Any]) -> tuple:
    ir = te.get("input_ref") or {}
    rr = te.get("result_ref") or {}
    line = ir.get("raw_line")
    if line is None:
        line = rr.get("raw_line")
    return (line if line is not None else 1 << 30, te.get("tool_use_id") or "")


# ---- signal helpers ---------------------------------------------------------


def _is_edit_tool(te: dict[str, Any]) -> bool:
    return te.get("name") in _EDIT_TOOLS


def _is_read_tool(te: dict[str, Any]) -> bool:
    return te.get("name") in _READ_TOOLS


def _changed_files(record: dict[str, Any]) -> list[str]:
    """Observable changed-file paths from code_changes.files[].path (v2 schema).
    This is the authoritative v2 signal for *what* was modified — tool_events
    carry only raw pointers (D6), not file paths. Absent -> empty (fail-closed)."""
    cc = record.get("code_changes")
    if not isinstance(cc, dict):
        return []
    files = cc.get("files")
    if not isinstance(files, list):
        return []
    return [f.get("path", "") for f in files if isinstance(f, dict) and f.get("path")]


def _path_is_test(path: str) -> bool:
    p = path.lower()
    return any(tok in p for tok in _TEST_PATH_TOKENS)


def _path_is_privileged(path: str) -> bool:
    p = path.lower()
    return any(tok in p for tok in _PRIVILEGED_PATH_TOKENS)


# ---- the six checks (fail-closed) -------------------------------------------


def _check_investigate_before_modify(ordered_tools: list, anchor: dict) -> _Check:
    """First code-change tool_event must be preceded by a read/search event.
    No code change at all -> the check cannot be satisfied by evidence of good
    practice -> fail-closed low (0.0), citing the anchor."""
    edits = [t for t in ordered_tools if _is_edit_tool(t)]
    # Investigation = observable read/search tools by NAME (Read/Grep/Glob).
    # Generic Bash is intentionally NOT counted: without its command bytes (D6)
    # a Bash event cannot be proven to be investigation, and treating it as such
    # would let `Bash rm -rf` read as "investigated" — the opposite of
    # fail-closed. Unproven signal is treated as absent.
    reads = [t for t in ordered_tools if _is_read_tool(t)]
    if not edits:
        # no modification occurred: there is nothing to have investigated before.
        # fail-closed: this is not a "pass" of good engineering; score 0.
        ev = [anchor]
        if reads:
            ev = [_tool_ref(reads[0]), anchor]
        return _Check(0.0, ev)
    first_edit_key = _tool_order_key(edits[0])
    prior_reads = [t for t in reads if _tool_order_key(t) < first_edit_key]
    if prior_reads:
        return _Check(1.0, [_tool_ref(prior_reads[0]), _tool_ref(edits[0])])
    # a modification with NO prior investigation -> fail closed low
    return _Check(0.0, [_tool_ref(edits[0]), anchor])


def _check_verified_claims(ordered_tools: list, anchor: dict) -> _Check:
    """After code-change events, a passing test/build/lint tool_event appears.
    No verify event -> fail-closed 0.0."""
    edits = [t for t in ordered_tools if _is_edit_tool(t)]
    verifies = [t for t in ordered_tools if _is_verify_tool(t)]
    passing = [t for t in verifies if t.get("is_error") is False]
    if not edits:
        # nothing changed -> no claims to verify; fail-closed (no positive signal)
        ev = [anchor]
        if passing:
            ev = [_tool_ref(passing[0]), anchor]
        return _Check(0.0, ev)
    last_edit_key = _tool_order_key(edits[-1])
    post_pass = [t for t in passing if _tool_order_key(t) > last_edit_key]
    if post_pass:
        return _Check(1.0, [_tool_ref(edits[-1]), _tool_ref(post_pass[0])])
    if verifies:
        # verification ran but errored / was before the change -> partial, low
        return _Check(0.25, [_tool_ref(edits[-1]), _tool_ref(verifies[0])])
    return _Check(0.0, [_tool_ref(edits[-1]), anchor])


def _is_verify_tool(te: dict[str, Any]) -> bool:
    """A test/build/lint tool_event. Conservative: Bash whose name alone we
    can see plus explicitly-named verify tools. Since raw command bytes are not
    inlined (D6), we match on the tool NAME only — a Bash event cannot be
    proven to be a verify without its command, so it does NOT count (fail-closed:
    unproven signal is absent, not present)."""
    name = (te.get("name") or "").lower()
    return any(tok.strip() in name for tok in _VERIFY_TOKENS if tok.strip())


def _check_added_tests(ordered_tools: list, changed_files: list[str],
                       anchor: dict) -> _Check:
    """A code change touched a test path (observed via code_changes.files[].path,
    the authoritative v2 signal). Absent -> fail-closed 0.0. Evidence cites the
    code-change tool_event when present, else the anchor."""
    edits = [t for t in ordered_tools if _is_edit_tool(t)]
    has_test_file = any(_path_is_test(p) for p in changed_files)
    if has_test_file:
        # grounded: the test path came from git-joined code_changes.files.
        ev = [_tool_ref(edits[0])] if edits else [anchor]
        return _Check(1.0, ev, grounded=True)
    if edits:
        return _Check(0.0, [_tool_ref(edits[0]), anchor])
    return _Check(0.0, [anchor])


def _check_security_awareness(nodes: list, hook_events: list, prompts: list,
                              tool_events: list, anchor: dict) -> _Check:
    """Security-relevant hook_events or security-referencing prompts around the
    work. Absence -> fail-closed 0.0. Evidence cites the concrete hook/node."""
    ev: list[dict[str, Any]] = []
    value = 0.0
    # security-relevant hook events (secret/scope-gate/blocked-op) are strong
    sec_hooks = [h for h in hook_events if _hook_is_security(h)]
    if sec_hooks:
        value = max(value, 1.0)
        ev.append(_hook_ref(sec_hooks[0]))
    # security-referencing human prompt (weaker; the intent named security)
    sec_prompt = _first_security_prompt(prompts, nodes)
    if sec_prompt is not None:
        value = max(value, 0.5)
        ev.append(sec_prompt)
    if not ev:
        return _Check(0.0, [anchor])
    return _Check(value, ev)


def _hook_is_security(h: dict[str, Any]) -> bool:
    names = " ".join(h.get("hook_names") or []).lower()
    sub = (h.get("subtype") or "").lower()
    hay = names + " " + sub
    return any(tok in hay for tok in ("scope-gate", "blocked-op", "secret",
                                      "seal", "security", "auth"))


def _first_security_prompt(prompts: list, nodes: list) -> dict[str, Any] | None:
    node_by_uuid = {n.get("uuid"): n for n in nodes if n.get("uuid")}
    for p in prompts:
        text = (p.get("text") or "").lower()
        if any(tok in text for tok in _SECURITY_TOKENS):
            uuid = p.get("uuid")
            n = node_by_uuid.get(uuid)
            if n is not None:
                return _node_ref(n)
            # Fix 4 (SEC-MED, P2-3): only cite a ref that resolves to a real
            # node. A prompt uuid with no corresponding node would emit a
            # dangling evidence ref, so return None and let the caller fall back
            # to the always-present anchor instead.
    return None


def _check_fail_closed_preserved(hook_events: list, anchor: dict) -> _Check:
    """Fail-closed guarantees preserved (Fix 2, semantic correction).

    A hook that INTENTIONALLY blocked/prevented an operation (scope-gate /
    blocked-op / secret / seal block, or ``prevented_continuation`` true) is the
    guardrail WORKING CORRECTLY — a POSITIVE fail-closed signal, not a bypass.

    A hook whose INFRASTRUCTURE genuinely errored (a real crash/malfunction:
    ``hook_errors`` present that is NOT an intentional guardrail block, and which
    did not prevent continuation) is the bypass/lowering signal — the guardrail
    failed to hold, so fail-closed is NOT preserved.

    ``adapter.HookEvent`` populates ``prevented_continuation`` from the raw
    ``preventedContinuation`` field and ``hook_errors`` from ``hookErrors``; the
    ``hook_prevented_session`` fixture (a correctly-firing blocked-op push) is the
    ground truth for the POSITIVE case. NO hooks at all -> fail-closed 0.0
    (absence of the guardrail is not a pass)."""
    if not hook_events:
        return _Check(0.0, [anchor])
    # An intentional block anywhere is a positive fail-closed signal.
    intentional = [h for h in hook_events if _hook_intentional_block(h)]
    if intentional:
        return _Check(1.0, [_hook_ref(intentional[0])])
    # No intentional block: a genuine hook-infrastructure error lowers the score.
    malfunctioned = [h for h in hook_events if _hook_malfunctioned(h)]
    if malfunctioned:
        return _Check(0.0, [_hook_ref(malfunctioned[0])])
    # hooks present and clean (fired, no error, nothing to block)
    return _Check(1.0, [_hook_ref(hook_events[0])])


def _hook_intentional_block(h: dict[str, Any]) -> bool:
    """The hook deliberately blocked/prevented an op = guardrail working (Fix 2).
    Signals: preventedContinuation true, OR a guardrail hook whose name/error
    text names a known block class (scope-gate / blocked-op / secret / seal)."""
    if h.get("prevented_continuation") is True:
        return True
    names = " ".join(h.get("hook_names") or []).lower()
    errs = " ".join(str(e) for e in (h.get("hook_errors") or [])).lower()
    sub = (h.get("subtype") or "").lower()
    hay = names + " " + errs + " " + sub
    return any(tok in hay for tok in ("scope-gate", "blocked-op", "secret",
                                      "seal"))


def _hook_malfunctioned(h: dict[str, Any]) -> bool:
    """A genuine hook-infrastructure error (crash/malfunction) that did NOT
    intentionally block — the guardrail failed to hold (Fix 2/Fix 3 bypass
    signal). An intentional block is handled by ``_hook_intentional_block`` and
    is never treated as a malfunction."""
    if _hook_intentional_block(h):
        return False
    return bool(h.get("hook_errors"))


def _check_evidence_for_conclusions(nodes: list, tool_events: list,
                                    anchor: dict) -> _Check:
    """Claim-bearing assistant text nodes are backed by a preceding tool_event/
    result. If there are claim nodes and at least one precedes-by-seq tool
    event, pass proportionally. No claim nodes -> fail-closed 0.0 (no positive
    evidence-for-conclusions signal)."""
    claim_nodes = [n for n in nodes
                   if n.get("type") == "assistant" and n.get("content_kind") == "text"]
    if not claim_nodes:
        return _Check(0.0, [anchor])
    # tool events ordered by raw_line -> map to a comparable seq via nodes
    tool_lines = sorted(
        (te.get("input_ref") or {}).get("raw_line")
        for te in tool_events
        if (te.get("input_ref") or {}).get("raw_line") is not None
    )
    node_line = {n.get("uuid"): n.get("raw_line") for n in nodes}
    backed = 0
    ev: list[dict[str, Any]] = []
    for cn in claim_nodes:
        cl = node_line.get(cn.get("uuid"))
        if cl is None:
            continue
        if any(tl < cl for tl in tool_lines):
            backed += 1
            if len(ev) < 2:
                ev.append(_node_ref(cn))
    if not ev:
        # claims exist but none are backed by a prior tool event -> fail-closed
        return _Check(0.0, [_node_ref(claim_nodes[0]), anchor])
    value = backed / len(claim_nodes)
    return _Check(value, ev)


def _has_privileged_change(ordered_tools: list, prompts: list, nodes: list,
                           changed_files: list[str]) -> bool:
    """Whether the trajectory involved a privileged/authority-impacting change.
    Signal (either, observable in v2): a code change to a privileged path
    (code_changes.files), OR a code-change tool_event together with a
    security-referencing human prompt. Gates risk_score (unmitigated privileged
    change = high risk)."""
    if any(_path_is_privileged(p) for p in changed_files):
        return True
    edits = [t for t in ordered_tools if _is_edit_tool(t)]
    if not edits:
        return False
    return _first_security_prompt(prompts, nodes) is not None


# ---- scores -----------------------------------------------------------------


def _weighted(checks: dict[str, _Check], weights: dict[str, float]) -> float:
    total = 0.0
    for name, w in weights.items():
        total += w * checks[name].value
    return scoring.clamp01(total)


def _merge_evidence(checks: dict[str, _Check], names, anchor: dict) -> list:
    """Collect evidence from the constituent checks; guarantee >= 1 ref."""
    seen: set[tuple] = set()
    out: list[dict[str, Any]] = []
    for name in names:
        for ev in checks[name].evidence:
            key = (ev.get("kind"), ev.get("ref"))
            if key not in seen:
                seen.add(key)
                out.append(ev)
    if not out:
        out = [anchor]
    return out


def _compute_scores(checks: dict[str, _Check], status: str, privileged: bool,
                    grounded: bool, anchor: dict) -> dict[str, Any]:
    eq = _weighted(checks, scoring.ENGINEERING_QUALITY_WEIGHTS)
    gov = _weighted(checks, scoring.GOVERNANCE_WEIGHTS)

    # risk = weighted sum of complements of mitigating checks, gated by whether
    # a privileged change occurred. No privileged change -> low baseline risk.
    mitigation = _weighted(checks, scoring.RISK_WEIGHTS)
    if privileged:
        # Fix 1 (SEC-HIGH, fail-closed): transcript-only "mitigation" must NOT
        # lower risk on a privileged change. Mitigation credit requires grounded
        # (git-joined) corroboration; without it, risk stays maxed.
        if grounded:
            risk = scoring.clamp01(1.0 - mitigation)
        else:
            risk = 1.0
    else:
        # non-privileged: residual risk scaled down (still fail-closed: an
        # incomplete/quarantined trajectory keeps some risk floor via status).
        risk = scoring.clamp01((1.0 - mitigation) * 0.3)

    # trajectory = composite of positive scores, capped by integrity.status.
    composite = (
        scoring.TRAJECTORY_COMPOSITE_WEIGHTS["engineering_quality_score"] * eq
        + scoring.TRAJECTORY_COMPOSITE_WEIGHTS["governance_score"] * gov
    )
    cap = scoring.STATUS_TRAJECTORY_CAP.get(status, scoring.STATUS_TRAJECTORY_CAP["incomplete"])
    trajectory = scoring.clamp01(min(composite, cap))
    # Fix 1 (SEC-HIGH): with NO grounded corroboration, hard-cap trajectory into
    # the C band (strictly below the B threshold) so a forged transcript can
    # never cross into B on author-controlled signals alone.
    if not grounded:
        trajectory = scoring.clamp01(min(trajectory, scoring.NO_GROUNDING_TRAJECTORY_CAP))

    # per-score grounded flag = whether any grounded check contributed to it.
    eq_grounded = _any_grounded(checks, scoring.ENGINEERING_QUALITY_WEIGHTS)
    gov_grounded = _any_grounded(checks, scoring.GOVERNANCE_WEIGHTS)
    risk_grounded = grounded and _any_grounded(checks, scoring.RISK_WEIGHTS)
    traj_grounded = grounded and (eq_grounded or gov_grounded)

    return {
        "engineering_quality_score": {
            "value": scoring.round_score(eq),
            "grounded": eq_grounded,
            "evidence": _merge_evidence(checks, scoring.ENGINEERING_QUALITY_WEIGHTS, anchor),
        },
        "governance_score": {
            "value": scoring.round_score(gov),
            "grounded": gov_grounded,
            "evidence": _merge_evidence(checks, scoring.GOVERNANCE_WEIGHTS, anchor),
        },
        "risk_score": {
            "value": scoring.round_score(risk),
            "grounded": risk_grounded,
            "evidence": _merge_evidence(checks, scoring.RISK_WEIGHTS, anchor),
        },
        "trajectory_score": {
            "value": scoring.round_score(trajectory),
            "grounded": traj_grounded,
            "evidence": _merge_evidence(
                checks,
                list(scoring.ENGINEERING_QUALITY_WEIGHTS)
                + list(scoring.GOVERNANCE_WEIGHTS),
                anchor,
            ),
        },
    }


def _any_grounded(checks: dict[str, _Check], names) -> bool:
    """Whether any contributing check with a positive (passed) value is grounded
    in git-joined ``code_changes.files`` rather than author-controlled transcript
    content. A grounded-but-failed check contributes nothing, so does not tag the
    score as grounded."""
    return any(checks[n].grounded and checks[n].value > 0.0 for n in names)


# ---- tiering (hard ceiling "B") ---------------------------------------------


def _compute_tier(trajectory_score: float, status: str, grounded: bool,
                  anchor: dict) -> dict[str, Any]:
    reasons: list[str] = []
    reasons.append(f"integrity_status={status}")
    reasons.append(f"trajectory_score={scoring.round_score(trajectory_score)}")
    reasons.append(f"grounded={grounded}")

    # Fix 1 (SEC-HIGH, P2-5): with NO grounded corroboration, force C and no
    # candidate regardless of transcript signals. trajectory_score is already
    # capped into the C band upstream; this makes the tier decision explicit.
    if not grounded:
        reasons.append("capped_C:no_grounded_corroboration")
        return {
            "assigned": "C",
            "ceiling": "B",
            "candidate_for": None,
            "reasons": reasons,
            "evidence": [anchor],
        }

    # assigned tier is C or B ONLY (hard ceiling). Never S/A in Phase 2.
    if status == "complete" and trajectory_score >= scoring.TIER_B_MIN_TRAJECTORY_SCORE:
        assigned = "B"
        reasons.append("meets_B_threshold_with_complete_integrity")
    else:
        assigned = "C"
        if status != "complete":
            reasons.append("capped_to_C:integrity_not_complete")
        else:
            reasons.append("below_B_threshold")

    # candidate_for: flag S/A-looking work, but it stays capped at B until Phase 3.
    candidate_for: str | None = None
    if status == "complete":
        if trajectory_score >= scoring.CANDIDATE_S_MIN_TRAJECTORY_SCORE:
            candidate_for = "S"
            reasons.append("candidate_for_S:pending_phase3_outcome_chain")
        elif trajectory_score >= scoring.CANDIDATE_A_MIN_TRAJECTORY_SCORE:
            candidate_for = "A"
            reasons.append("candidate_for_A:pending_phase3_outcome_chain")

    return {
        "assigned": assigned,
        "ceiling": "B",  # HARD Phase-2 ceiling (ADR 0003 §5)
        "candidate_for": candidate_for,
        "reasons": reasons,
        "evidence": [anchor],
    }


# ---- labels (emitted only when detected; evidence-by-construction) ----------


def _compute_labels(checks: dict[str, _Check], privileged: bool) -> dict[str, Any]:
    engineering: list[dict[str, Any]] = []
    governance: list[dict[str, Any]] = []

    def add(bucket: list, name: str, check_key: str) -> None:
        c = checks[check_key]
        if c.passed:
            bucket.append({"label": name, "evidence": list(c.evidence)})

    add(engineering, "investigated_before_modifying",
        scoring.CHECK_INVESTIGATE_BEFORE_MODIFY)
    add(engineering, "verified_claims", scoring.CHECK_VERIFIED_CLAIMS)
    add(engineering, "added_tests", scoring.CHECK_ADDED_TESTS)
    add(governance, "preserved_fail_closed", scoring.CHECK_FAIL_CLOSED_PRESERVED)
    add(governance, "evidence_for_conclusions", scoring.CHECK_EVIDENCE_FOR_CONCLUSIONS)
    add(governance, "security_aware", scoring.CHECK_SECURITY_AWARENESS)

    return {"engineering": engineering, "governance": governance}


# ---- top-level evidence aggregate (ADR 0003 §1 shape) -----------------------


def _aggregate_evidence(scores: dict, labels: dict, tier: dict, checks: dict,
                        anchor: dict) -> list[dict[str, Any]]:
    """Deterministic union of every evidence ref cited anywhere in the
    annotation (scores + labels + tier + checks). Ordered by (kind, ref) so the
    canonical bytes are stable. Always contains >= 1 ref (the anchor)."""
    seen: set[tuple] = set()
    collected: list[dict[str, Any]] = []

    def take(ev_list) -> None:
        for ev in ev_list:
            key = (ev.get("kind"), ev.get("ref"))
            if key not in seen:
                seen.add(key)
                collected.append(ev)

    for sc in scores.values():
        take(sc["evidence"])
    for bucket in ("engineering", "governance"):
        for lab in labels[bucket]:
            take(lab["evidence"])
    take(tier["evidence"])
    for c in checks.values():
        take(c.evidence)
    if not collected:
        collected = [anchor]
    return sorted(collected, key=lambda e: (str(e.get("kind")), str(e.get("ref"))))
