"""CI enforcement for claim-sensitive ACGS design invariants.

The RFC (``docs/design/acgs-physical-execution-profile.md``) declares five
decisions frozen before P0 implementation. Until this file existed, that freeze
was enforced by human review only — a reviewer had to notice that an edit
quietly relaxed one. These tests make the freeze mechanical.

Design note on brittleness: these assertions deliberately match **structure and
distinctive tokens**, never long prose sentences. A gate that asserts a full
paragraph turns every editorial commit red and trains people to edit the gate
instead of restoring the invariant — which is exactly backwards. Prose may be
rewritten freely here; the invariants may not.

Scope is limited to the physical execution profile and the two reviewed
questionnaire/site-copy contracts named below. Other design files belong to
different work streams and are not governed by this file.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RFC = "docs/design/acgs-physical-execution-profile.md"
QUESTIONNAIRE_SPEC = "docs/superpowers/specs/2026-07-25-agent-run-ai-questionnaire-pack-design.md"
SITE_DECK = "docs/SITE-COPY-DECK-0.md"

# Responses that must never be reachable from a fault or a geometric violation.
PATH_FOLLOWING_RESPONSE = "ramp_stop"

# A violation of any of these means the commanded path itself is untrustworthy,
# so continuing along it is never an acceptable response.
NO_PATH_FOLLOWING_TRIGGERS = (
    "TorqueSensorMismatch",
    "ActuatorIntegrityFailure",
    "SDF / forbidden zone",
    "Non-finite setpoint",
    "Calibration epoch change",
    "Lease revoked",
)

# Every field the execution binding must commit to. Dropping any one of these
# re-opens a replay path: the same trajectory bytes becoming valid in a
# different physical context.
EXECUTION_ROOT_BINDINGS = (
    "merkle_root",
    "receipt_id",
    "robot_id",
    "calibration_digest",
    "contract_digest",
    "lease_id",
    "calibration_epoch",
    "boot_id",
)

# The loader verifies and refuses. It never decides.
LOADER_PROHIBITIONS = (
    "modify or re-derive constraints",
    "resolve conflicts",
    "upgrade, widen",
    "substitute a default",
    "recompute a digest",
)

# Claim boundaries. These must stay absent regardless of how the RFC evolves.
#
# Each entry must be a phrase that can ONLY appear as a claim. Loose terms are
# actively harmful here: "certified safe" also matches the disclaimer "requires
# a certified safety function", so banning it would flag the RFC for correctly
# disclaiming certification. A gate that fires on its own disclaimers teaches
# people to delete disclaimers.
FORBIDDEN_CLAIMS = (
    "production-certified",
    "compliance-certified",
    "safety-certified",
    "regulator-approved",
    "formal verification complete",
    "guaranteed safe",
    "production-ready",
)


def _rfc() -> str:
    path = ROOT / RFC
    assert path.is_file(), f"missing design RFC: {RFC}"
    return path.read_text(encoding="utf-8")


def _read(relative: str) -> str:
    path = ROOT / relative
    assert path.is_file(), f"missing required design document: {relative}"
    return path.read_text(encoding="utf-8")


def _python_symbols(relative: str) -> set[str]:
    tree = ast.parse(_read(relative))
    symbols: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            symbols.add(node.name)
    return symbols


def _table_rows(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.lstrip().startswith("|")]


def _prose(text: str) -> str:
    """Lowercase text with markdown emphasis and line breaks flattened.

    Claim-boundary sentences carry bold/italic markers that move around during
    ordinary editing (``is **not** a functional-safety system``). Matching the
    normalized form keeps the gate anchored to the claim rather than to its
    current formatting.
    """
    return re.sub(r"\s+", " ", text.replace("*", "").replace("`", "")).lower()


def test_rfc_declares_its_frozen_decisions() -> None:
    """The freeze section must exist and still carry five numbered decisions."""
    text = _rfc()
    assert "Frozen before P0" in text, "RFC lost its frozen-decision section"

    _, _, tail = text.partition("### Frozen before P0")
    section, _, _ = tail.partition("### Open questions")
    numbered = re.findall(r"^\d+\.\s+\*\*", section, flags=re.MULTILINE)
    assert len(numbered) == 5, (
        f"expected 5 frozen decisions, found {len(numbered)}. "
        "Adding or removing one is an RFC amendment, not an edit."
    )


def test_fault_and_geometric_violations_never_follow_the_path() -> None:
    """A fault or geometric violation must not resolve to ``ramp_stop``.

    ``ramp_stop`` decelerates *along the authorized path*. Applying it to an SDF
    or forbidden-zone violation drives the robot into the obstacle that
    triggered the stop; applying it to a fault keeps following a trajectory
    planned against dynamics that no longer describe the machine.
    """
    rows = _table_rows(_rfc())
    for trigger in NO_PATH_FOLLOWING_TRIGGERS:
        matching = [r for r in rows if trigger in r]
        assert matching, f"violation class disappeared from the RFC: {trigger}"
        for row in matching:
            assert PATH_FOLLOWING_RESPONSE not in row, (
                f"{trigger!r} maps to {PATH_FOLLOWING_RESPONSE!r}; a fault or "
                "geometric violation must never continue along the path"
            )


def test_torque_taxonomy_separates_envelope_breach_from_fault() -> None:
    """A limit breach and a fault must remain distinct classes."""
    text = _rfc()
    for token in (
        "TorqueEnvelopeViolation",
        "TorqueSensorMismatch",
        "ActuatorIntegrityFailure",
    ):
        assert token in text, f"torque taxonomy lost its {token} class"

    envelope_rows = [r for r in _table_rows(text) if "TorqueEnvelopeViolation" in r]
    assert envelope_rows, "TorqueEnvelopeViolation left the response table"
    assert any(PATH_FOLLOWING_RESPONSE in r for r in envelope_rows), (
        "TorqueEnvelopeViolation no longer maps to ramp_stop — an envelope "
        "breach leaves the model intact and the path valid"
    )


def test_execution_root_binds_the_full_physical_context() -> None:
    """The enforced root must commit to context, not just trajectory bytes."""
    text = _rfc()
    assert "execution_root" in text, "execution_root binding removed"
    _, _, tail = text.partition("execution_root = H(")
    formula, _, _ = tail.partition(")")
    assert formula, "execution_root derivation formula removed"
    for field in EXECUTION_ROOT_BINDINGS:
        assert field in formula, (
            f"execution_root no longer binds {field!r}; dropping it re-opens "
            "replay of the same trajectory in a different physical context"
        )


def test_loader_cannot_become_a_second_authority() -> None:
    """The compiler decides; the loader only verifies and refuses."""
    text = _rfc()
    assert "Compiler / Loader authority boundary" in text
    for prohibition in LOADER_PROHIBITIONS:
        assert prohibition in text, (
            f"loader prohibition removed: {prohibition!r}. A loader that can "
            "decide is a second authority with no receipt recording which won."
        )


def test_constraint_compilation_is_monotonic() -> None:
    """Narrowing is allowed; relaxation must fail compilation."""
    text = _rfc()
    assert "operator_override  ⊆  cell_policy  ⊆  robot_capability" in text, (
        "constraint monotonicity lattice removed or reordered"
    )
    assert "CompilationRejected" in text or "FAILS COMPILATION" in text, (
        "relaxation no longer produces a compile-time failure"
    )


def test_calibration_drift_is_checked_live() -> None:
    """T-13 must stay a per-tick check, not an activation-time snapshot."""
    text = _rfc()
    assert "T-13" in text, "calibration drift threat removed"
    assert "calibration_epoch" in text, "calibration epoch guard removed"


def test_threat_ids_are_contiguous() -> None:
    """No threat may be silently dropped from the middle of the table."""
    found = sorted({int(m) for m in re.findall(r"\|\s*T-(\d{2})\s*\|", _rfc())})
    assert found, "threat table has no entries"
    assert found == list(range(1, len(found) + 1)), f"threat ids are not contiguous: {found}"


def test_rfc_makes_no_certification_or_safety_claim() -> None:
    """Authority is not safety, and this RFC must never imply otherwise."""
    prose = _prose(_rfc())
    for phrase in FORBIDDEN_CLAIMS:
        assert phrase not in prose, f"RFC makes a forbidden claim: {phrase!r}"

    for required in (
        "not a functional-safety system",
        "signature is not a safety case",
        "design budgets, not measurements",
    ):
        assert required in prose, f"RFC lost its claim boundary: {required!r}"


def test_mar_issuance_uses_full_append_metadata_and_profile_expiry() -> None:
    text = _rfc()
    issuance = text.partition("### Issuance flow")[2].partition("---")[0]
    assert "Kernel.evaluate_and_append(call)" in issuance
    assert 'audited.append_result["previous_hash"]' in issuance
    assert "`Kernel.evaluate_and_record` (or" not in issuance
    for token in (
        "nonempty, timezone-aware `expires_at`",
        "maximum MAR TTL",
        "trusted clock",
        "require_expiry=True",
        "GovernanceProfile.production_strict",
        "require_expiry=False",
        "missing/malformed `previous_hash`",
    ):
        assert token in issuance
    assert "Receipt persisted to the audit chain" not in issuance
    assert "persists the `DecisionRecord`" in issuance
    assert "constructs the receipt in memory" in issuance


def test_physical_transform_requires_fresh_allow_and_never_runs_original_args() -> None:
    issuance = _rfc().partition("### Issuance flow")[2].partition("---")[0]
    issuance = re.sub(r"\s+", " ", issuance)
    for token in (
        "recompiled",
        "rebound",
        "rehashed",
        "fresh evaluation",
        "original arguments are discarded",
        "final `ALLOW`",
    ):
        assert token in issuance


def test_physical_replay_authority_is_not_attributed_to_execution_root() -> None:
    text = _rfc()
    assert "derived lease-context identity" in text
    assert "not from `execution_root`" in text
    for authority in (
        "signed receipt bindings",
        "bounded expiry",
        "consumed receipt/nonce state",
        "pinned boot state",
        "shared nonce authority",
    ):
        assert authority in text


def test_physical_drive_and_replay_authorities_are_in_the_tcb() -> None:
    text = _rfc()
    diagram = text.partition("```mermaid")[2].partition("```")[0]
    trust = text.partition("### TCB enumeration")[2].partition("## 4.")[0]
    normalized = re.sub(r"\s+", " ", trust)
    for token in (
        "drive command boundary",
        "pinned bus/interface configuration",
        "command-channel credentials or physical isolation",
        "Drives accept commands only from the RT kernel",
        "ROS, DDS, and other processes receive neither the bus mapping nor command credential",
        "hardware command subset",
        "Compromise can command arbitrary motion",
        "`ReceiptConsumptionLedger`",
        "durable JSONL store",
        "OS lock/permissions",
        "integrity sidecars",
        "roll back burns and reopen receipts",
        "shared nonce/receipt-burn authority",
        "durable transactional or consensus store",
        "redundant controllers remain unsupported and must fail closed",
        "direct ROS publisher or untrusted process attempting drive actuation",
        "rejected at the bus/arbiter boundary without actuator motion",
    ):
        assert token in normalized
    diagram = re.sub(r"\s+", " ", diagram)
    for token in (
        'RCL["ReceiptConsumptionLedger<br/>durable JSONL + OS lock/permissions + '
        'integrity sidecars"]',
        'BURN["Shared transactional burn/nonce authority<br/>UNIMPLEMENTED — required '
        'for redundant controllers"]',
        'LA -- "single-controller receipt-anchor consume" --> RCL',
        'LA -. "redundant consume required;<br/>fail closed if absent" .-> BURN',
        "class ACGS,LOAD,RTSK,SHM,LA,RCL,BURN tcb",
    ):
        assert token in diagram


def test_physical_tcb_and_atomic_state_publication_are_explicit() -> None:
    text = _rfc()
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "Lease Authority binary",
        "pinned configuration",
        "bootstrap write path for the authority page",
        "typed `EMPTY -> ARMED` request to the STM",
        "OS identity, permissions, and process isolation",
        "policy bundle and policy-decision path",
        "receipt issuer, signer, verification-key custody",
        "non-RT loader executable",
        "exclusive ownership of the verified setpoint buffer",
        "exclusive capability to release-store `blocks_verified`",
        "RT subset",
        "can cause unauthorized motion",
        "class ACGS,LOAD,RTSK,SHM,LA,RCL,BURN tcb",
        "atomic release-store",
        "acquire-load",
        "_Atomic uint32_t blocks_verified",
        "fresh-block `EMPTY -> ARMED`",
        "ARMED -> ACTIVE",
        "ACTIVE -> CONSUMED",
        "ARMED|ACTIVE -> REVOKED",
        "ARMED|ACTIVE -> EXPIRED",
        "cannot be overwritten",
        "revocation is dominant",
        "never clear/rebind an old request page or reuse a terminal block",
        "STM.transition_inline(ARMED->ACTIVE) must succeed",
        "final_state = acquire-load immediately before emit",
        "bounded next-tick revocation contract",
        "at most the current command",
        "No subsequent tick may emit",
        "inline validated STM state path",
        "category_1_stop` (never path-following ramp stop)",
        "loader_watermark_page",
        "rt_sequence_page",
        "lease_state_page",
        "verified setpoint buffer is a fifth region",
        "page alignment ensures no writable mapping exposes",
        "Negative capability tests attempt every external cross-field write",
        "no writable lease-state, identity, or acknowledgement mapping",
        "sole RW capability is the safe-direction `revoke_publish_page`",
        "REVOKED -> ACTIVE|ARMED",
        "CONSUMED|EXPIRED -> ACTIVE|ARMED",
    ):
        assert token in normalized

    state_section = text.partition("/* Page D: trusted RT component RW only")[2]
    state_section = state_section.partition("### Per-tick RT check")[0]
    assert "Trusted RT component (Safety Kernel + inline STM)" in state_section
    assert "revoke request adapter | `revoke_publish_page` only" in state_section
    assert "revoker writable state" not in state_section


def test_physical_final_tick_completes_without_out_of_range_tick() -> None:
    hot_path = _rfc().partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    normalized = re.sub(r"\s+", " ", hot_path)
    for token in (
        "if seq == seq_hi",
        "STM.transition_inline(ACTIVE->CONSUMED)",
        "if observed state is REVOKED/EXPIRED: preserve it",
        "success returns without scheduling a next out-of-range tick",
        "after the final command is committed",
        "no extra command is emitted",
        "steady ACTIVE branch performs one sequence CAS",
        "first tick may also make one inline STM `ARMED -> ACTIVE` transition",
        "final tick may also make one inline STM `ACTIVE -> CONSUMED` transition",
        "WCET characterization must measure each branch separately",
    ):
        assert token in normalized
    assert "integer compares, one CAS" not in normalized


def test_physical_revoke_is_a_mediated_request_without_write_mapping() -> None:
    text = _rfc()
    trust = text.partition("## 3. Trust boundaries")[2].partition("## 4.")[0]
    control = text.partition("### Control block")[2].partition("### Per-tick RT check")[0]
    interfaces = text.partition("### Interfaces")[2].partition("### Why ROS 2")[0]
    trust = re.sub(r"\s+", " ", trust)
    control = re.sub(r"\s+", " ", control)
    interfaces = re.sub(r"\s+", " ", interfaces)
    for token in (
        'REV["revoke request adapter"]',
        'REV -- "lease-bound monotonic revoke generation" --> RTSK',
        'RTSK -- "inline validated STM state path" --> SHM',
        "state page's only RW mapping",
    ):
        assert token in trust
    for token in (
        "no writable lease-state, identity, or acknowledgement mapping",
        "revoke request adapter | `revoke_publish_page` only",
        "invalid predecessors are refused",
        "trusted RT source mutates state only through STM",
    ):
        assert token in control
    assert "atomically increment `published_generation`" in interfaces
    assert "sole RW capability is the safe-direction publish page" in interfaces


def test_physical_stm_is_rt_inline_bounded_and_nonblocking() -> None:
    text = _rfc()
    trust = text.partition("### TCB enumeration")[2].partition("## 4.")[0]
    control = text.partition("### Control block")[2].partition("### Per-tick RT check")[0]
    hot_path = text.partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    trust = re.sub(r"\s+", " ", trust + control)
    hot_path = re.sub(r"\s+", " ", hot_path)
    for token in (
        "same trusted RT component that owns the state RW mapping",
        "Items 1--4, including item 1's inline STM path, are the **RT software subset**",
        "fixed-size requests through per-principal SPSC mailboxes",
            "allocation-bound monotonic revoke generation",
        "No synchronous IPC or blocking operation exists on the servo path",
        "not a service process or a protection boundary",
        "executes at most one CAS",
    ):
        assert token in trust
    assert "No IPC, wait, timeout, hash, lock, or allocation occurs in the hot path" in hot_path


def test_physical_hot_path_failures_latch_terminal_before_stop() -> None:
    text = _rfc()
    hot_path = text.partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    normalized = re.sub(r"\s+", " ", hot_path)
    for failure in (
        "BOOT_MISMATCH",
        "SEQUENCE",
        "WATERMARK",
        "NONFINITE",
        "INADMISSIBLE",
        "STALE_PERCEPTION",
        "CALIBRATION",
    ):
        assert f"fail_terminal({failure})" in normalized
    for token in (
        "inline safe-terminal transition",
        "preserve any first terminal winner",
        "execute `category_1_stop`",
        "return without emitting",
        "no subsequent tick can emit",
    ):
        assert token in normalized


def test_physical_completion_and_cleanup_never_reuse_terminal_lease() -> None:
    text = _rfc()
    hot_path = text.partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    lifecycle = text.partition("### State transitions")[2].partition("### Interfaces")[0]
    hot_path = re.sub(r"\s+", " ", hot_path)
    lifecycle = re.sub(r"\s+", " ", lifecycle)
    for token in (
        "outcome == SUCCESS: report normal CONSUMED completion",
        "observed state is REVOKED/EXPIRED",
        "at most one additional conditional CAS to `REVOKED`",
        "never report normal completion while ACTIVE",
    ):
        assert token in hot_path
    for token in (
        "retire/destroy without zero/reset/reuse",
        "state remains terminal for the allocation's entire observable lifetime",
        "never writes `EMPTY`, zeroes state, or reuses identity",
    ):
        assert token in lifecycle


def test_physical_never_published_empty_allocation_retires_without_revoke_ack() -> None:
    lifecycle = _rfc().partition("### State transitions")[2].partition("### Interfaces")[0]
    normalized = re.sub(r"\s+", " ", lifecycle)
    for token in (
        "fails before the `EMPTY -> ARMED` CAS",
        "never published as a lease",
        "proves no RT tick ever started",
        "RT quiescence holds",
        "never-published `EMPTY` allocation directly",
        "without waiting for revoke acknowledgement",
        "never exposed, reset, or reused",
        "distinct from cleanup of an observable lease",
    ):
        assert token in normalized


def test_physical_rt_and_stm_share_one_trust_domain() -> None:
    text = _rfc()
    control = text.partition("### Control block")[2].partition("### Per-tick RT check")[0]
    threat = text.partition("| T-09 |")[2].partition("| T-10 |")[0]
    control = re.sub(r"\s+", " ", control)
    for token in (
        "logical STM API by code invariant",
        "not a service process or a protection boundary",
        "compromised RT component can bypass it",
        "Structural review and unit tests—not OS mapping claims",
        "external attempt must fault or be refused",
    ):
        assert token in control
    assert "STM is the reviewed state-mutation path, not isolation from RT compromise" in threat


def test_physical_revoke_generation_is_lease_bound_monotonic_and_stale_safe() -> None:
    text = _rfc()
    control = text.partition("struct revoke_identity_page")[2]
    control = control.partition("### Per-tick RT check")[0]
    hot_path = text.partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    lifecycle = text.partition("### State transitions")[2].partition("### Interfaces")[0]
    normalized = re.sub(r"\s+", " ", control + hot_path + lifecycle)
    for token in (
        "lease_identity[32]",
        "revoke_publish_page",
        "revoke_ack_page",
        "published_generation",
        "acknowledged_generation",
        "no writable lease-state, identity, or acknowledgement mapping",
        "monotonically advances `acknowledged_generation`",
        "publish after either per-tick snapshot is observed no later than the next tick",
        "stale handle therefore targets only the retired allocation",
        "fresh generation namespace",
        "never clear/rebind an old request page",
    ):
        assert token in normalized


def test_physical_revoke_pages_are_disjoint_page_level_capabilities() -> None:
    text = _rfc()
    control = text.partition("### Control block")[2]
    control = control.partition("### Per-tick RT check")[0]
    normalized = re.sub(r"\s+", " ", control)
    for token in (
        "Three separate page-aligned request mappings",
        "adapter RW; contains ONLY this field",
        "trusted RT component RW only",
        "Identity, publish, and acknowledgement never share a writable page",
        "protection is page-level",
        "revoke request adapter | `revoke_publish_page` only",
        "identity RO; ack and every lease region unmapped or RO",
    ):
        assert token in normalized


def test_physical_revoke_processing_orders_latch_ack_stop_and_end_tick() -> None:
    text = _rfc()
    hot_path = text.partition("process_revoke_snapshot(revoke):")[2]
    hot_path = hot_path.partition("1. revoke =")[0]
    normalized = re.sub(r"\s+", " ", hot_path)
    ordered = (
        "STM.transition_inline(ARMED|ACTIVE -> REVOKED)",
        "if observed in {REVOKED, EXPIRED, CONSUMED}",
        "release-store acknowledged_generation = revoke.published",
        "emit revoke evidence",
        "category_1_stop",
        "return END_TICK",
    )
    positions = [normalized.index(token) for token in ordered]
    assert positions == sorted(positions)
    assert "pending request remains unacknowledged" in normalized
    assert "Next tick retries the same generation before any command can emit" in normalized


def test_physical_revoke_cas_loss_retries_once_and_never_acks_nonterminal() -> None:
    text = _rfc()
    hot_path = text.partition("process_revoke_snapshot(revoke):")[2]
    hot_path = hot_path.partition("1. revoke =")[0]
    contract = text.partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    lifecycle = text.partition("### State transitions")[2].partition("### Why ROS 2")[0]
    normalized = re.sub(r"\s+", " ", hot_path + contract + lifecycle)
    for token in (
        "result == CAS_LOST and observed == ACTIVE",
        "ARMED -> ACTIVE won",
        "STM.transition_inline(ACTIVE -> REVOKED)",
        "one bounded retry",
        "leaves the generation pending and unacknowledged",
        "retries before emission on the next tick",
        "only the servo thread calls STM for a revoke",
        "every non-servo, adapter, and lifecycle caller can only publish a request",
        "only after tick scheduling has stopped and RT quiescence is proven",
    ):
        assert token in normalized
    assert normalized.index("if observed in {REVOKED, EXPIRED, CONSUMED}") < normalized.index(
        "release-store acknowledged_generation"
    )


def test_physical_cleanup_waits_before_unmapping() -> None:
    text = _rfc()
    lifecycle = text.partition("### State transitions")[2].partition("### Interfaces")[0]
    normalized = re.sub(r"\s+", " ", lifecycle)
    for token in (
        "stop scheduling new RT ticks",
        "wait for RT quiescence",
        "only after acknowledgement/terminal observation revoke mappings, unmap",
        "No mapping is revoked or unmapped before both RT quiescence",
    ):
        assert token in normalized
    assert "remains terminal `CONSUMED`" in re.sub(r"\s+", " ", text)
    assert "acknowledges the revoke generation as terminal/non-executable" in re.sub(
        r"\s+", " ", text
    )


def test_physical_final_failure_branch_has_finite_cas_bound() -> None:
    hot_path = _rfc().partition("### Per-tick RT check")[2].partition("### 6.3")[0]
    normalized = re.sub(r"\s+", " ", hot_path)
    for token in (
        "exactly one CAS",
        "at most one additional conditional",
        "category_1_stop and emit failure evidence regardless of its result",
        "never loop",
        "at most two state CAS operations, with no loop",
    ):
        assert token in normalized


def test_physical_receipt_hash_uses_internal_canonical_payload() -> None:
    text = _rfc()
    assert "`_hash_payload()`" in text
    assert "inside `to_dict()`, which is what `compute_hash` canonicalizes" not in text


def test_physical_live_bindings_and_negative_requirements_are_frozen() -> None:
    text = _rfc()
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "complete `constraints.physical`",
        "live compiled contract",
        "source_hash",
        "immutable source repository revision",
        "missing/mismatched predecessor metadata",
        "empty/naive/expired/overlong expiry",
        "unavailable shared nonce authority",
    ):
        assert token in normalized


def test_questionnaire_refuted_and_insufficient_states_never_support_delivery() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    assert "QA output is citation-level data" in text
    assert "stable `question_id`" in text
    for state, verdict in (("QA_REFUTED", "REFUTED"), ("QA_INSUFFICIENT", "INSUFFICIENT")):
        assert state in text
        assert f"QA-`{verdict}`" in text
    section = text.partition("### 8.3.2b Refuted and insufficient QA never support delivery")[2]
    section = section.partition("### ")[0]
    assert "fail the assembly support predicate" in section
    assert "cannot reach delivery" in section


def test_questionnaire_citation_qa_is_per_citation_and_reduced() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "### 2.3.1 CitationQARecord",
        "citation_qa_record_id",
        "deterministic_check_passed",
        "qa_outcome_hash",
        "response_version",
        "answer_hash",
        "assertion_id",
        "assertion_hash",
        "evidence_binding_hash",
        "source_evidence_hash",
        "receipt `argument_hash`",
        "QA `OutcomeEvent.result_hash`",
        "Evidence.verified_by_receipt_id == CitationQARecord.qa_receipt_id",
        "Evidence.verified_by_outcome_hash == CitationQARecord.qa_outcome_hash",
        "Evidence.citation_qa_record_id == CitationQARecord.citation_qa_record_id",
        "substituted otherwise-valid pointer",
        "stale response version or swapped assertion/evidence record fails",
        "response reducer",
        "complete record set",
        "cannot contribute to `SUPPORTED`",
        "distinct QA executions",
        "distinct receipt ids and outcome hashes",
    ):
        assert token in normalized
    response_section = text.partition("### 2.4 Response")[2].partition("### 2.5 Gap")[0]
    response_table = response_section.partition("**`verification_state`")[0]
    assert "| `qa_verdict` |" not in response_table
    assert "| `qa_rationale` |" not in response_table
    assert "| `verified_by_receipt_id` |" not in response_table
    assert "| `verified_by_outcome_hash` |" not in response_table


def test_questionnaire_source_fidelity_is_not_semantic_support() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "Check 0 proves source fidelity only",
        "cannot decide whether those bytes support an assertion",
        "An LLM `PASS` alone is insufficient",
        "Independent semantic-relevance gate",
        "CANDIDATE_EVIDENCE",
        "check-0-valid but irrelevant citation",
        "stubbed QA model returns `PASS`",
        "non-deliverable as `SUPPORTED`",
    ):
        assert token in normalized
    assert "Every path that adds support terminates in a deterministic check" not in text


def test_questionnaire_trust_summary_requires_all_three_support_gates() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    trust = text.partition("### 6.1 Threat model — what is trusted")[2]
    trust = trust.partition("### 6.2 Prompt injection")[0]
    trust = re.sub(r"\s+", " ", trust)
    for token in (
        "deterministic check 0",
        "valid assertion/evidence-bound `CitationQARecord`",
        "valid independently signed and bound `SemanticAdjudicationRecord`",
        "QA alone is never sufficient",
        "non-deliverable `CANDIDATE_EVIDENCE`",
    ):
        assert token in trust


def test_questionnaire_semantic_adjudication_is_signed_and_cross_bound() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    schema = text.partition("### 2.3.2 SemanticAdjudicationRecord")[2]
    schema = schema.partition("### 2.3.3 MiningOutcomeEnvelope")[0]
    schema = re.sub(r"\s+", " ", schema)
    for token in (
        "immutable signed event",
        "response_version` / `answer_hash",
        "assertion_id` / `assertion_hash",
        "evidence_id` / `producer_lineage_hash",
        "semantic_evidence_binding_hash",
        "adjudicator_id` / `adjudicator_kind",
        "rule_id` / `rule_version",
        "semantic_adjudication_event_hash",
        "signature",
        "allowlisted key",
        "recomputes the rule inputs and verdict",
        "unknown/revoked adjudicator or key",
        "both a valid QA record and a valid confirming semantic record",
    ):
        assert token in schema

    lineage_test = text.partition("### 8.3.10 Immutable assertion-level QA lineage")[2]
    lineage_test = lineage_test.partition("### 8.3.11")[0]
    lineage_test = re.sub(r"\s+", " ", lineage_test)
    for token in (
        "signed `SemanticAdjudicationRecord`",
        "tampered record/hash/signature",
        "unknown or revoked adjudicator/key",
        "differs from recomputation",
        "QA alone, including `PASS`, cannot produce `SUPPORTED`",
    ):
        assert token in lineage_test


def test_questionnaire_mining_envelope_binds_producer_lineage_without_cycle() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    schema = text.partition("### 2.3.3 MiningOutcomeEnvelope")[2]
    schema = schema.partition("### 2.4 Response")[0]
    schema = re.sub(r"\s+", " ", schema)
    for token in (
        "MiningOutcomePreimage",
        "mining agent returns only",
        "outcome_event_id, produced_by_receipt_id",
        "evidence_records[] sorted by evidence_id",
        "MUST NOT contain `produced_by_outcome_hash`",
        "OutcomeEvent.result_hash",
        "OutcomeEvent.outcome_hash",
        "mining_result_hash",
        "mining_envelope_hash",
        "producer_lineage_hash",
        "Response.response_lineage_hash",
        "receipt's `argument_hash`",
        "substituted producer pointer",
        "wrong envelope",
        "without asking either hash to contain itself",
    ):
        assert token in schema

    regression = text.partition("### 8.3.12 Mining envelope and producer lineage")[2]
    regression = regression.partition("### 8.4")[0]
    regression = re.sub(r"\s+", " ", regression)
    for token in (
        "agent returns that preimage only",
        "reserves a unique append slot",
        "atomically finalizes the pending record",
        "verifies the bound `ATTESTED` `AppendAcceptance`",
        "only afterward constructs `MiningOutcomeEnvelope`",
        "producer receipt",
        "outcome-event id",
        "outcome hash",
        "remove or swap an evidence record",
        "wrong envelope",
        "not self-referential",
    ):
        assert token in regression


def test_questionnaire_outcome_payment_and_spend_fail_closed_contracts() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "product-owned canonical `OutcomeEvent`",
        "product-owned outcome wrapper",
        "Pinned canonical-event schema",
        "raw value returned by `execute_with_receipt`",
        "outcome_hash",
        "result_hash",
        "receipt_id",
        "DecisionReceipt.audit_event_hash",
        "OutcomePayloadPreimage",
        "KMS.Sign(\"acgs-outcome-v1\" || outcome_hash)",
        "allowlisted outcome-signing key",
        "actor/action/argument bindings",
        "blocks every dependent delivery",
        "provider-signed event",
        "quote id and quote version",
        "exact amount",
        "currency",
        "settled status",
        "operation-wide worst-case maximum",
        "all bounded attempts",
        "capped input tokens",
        "capped output tokens",
        "maximum attempt count",
        "zero Gemini calls",
        "reconcile total actual provider usage once",
        "nonempty, timezone-aware `expires_at`",
        "explicitly selects `require_expiry=True`",
        "plain `execute_with_receipt` default is `require_expiry=False`",
        "shared atomic burn-before-execute authority",
        "receipt_consumptions/{receipt_anchor}",
        "exactly one tool call occurs",
        "Cross-worker receipt replay",
        "Shared receipt-anchor burn",
        "not implied by the plain runtime default",
    ):
        assert token in normalized
    assert "Receipt.result_hash" not in text
    assert "only a dispatched" not in text


def test_questionnaire_ambiguous_dispatch_never_reopens_spend_ceiling() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regression = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    normalized = re.sub(r"\s+", " ", spend + regression).replace("`", "").replace("**", "")
    for token in (
        "only a failure proven to occur before the durable dispatch-intent commit",
        "PROVABLY_UNDISPATCHED",
        "DISPATCH_AMBIGUOUS",
        "timeout after send but before response",
        "transport error, a lost response, or missing usage metadata",
        "may have been accepted and charged",
        "charges the operation-wide capped reserved maximum",
        "retains an equivalent quarantine hold",
        "MUST NOT reopen that budget",
        "Authoritative usage may reconcile downward idempotently",
        "never below already known spend",
        "cannot exceed the job ceiling",
        "timeout after the provider path records dispatch",
        "refuses a later operation that would exceed the job ceiling",
        "real provider-adapter and shared-ledger path",
        "capped hold must remain visible to the other worker",
    ):
        assert token in normalized


def test_questionnaire_dispatch_and_usage_are_durably_exactly_bound() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regression = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    normalized = re.sub(r"\s+", " ", spend + regression).replace("`", "").replace("**", "")

    for token in (
        "durable write-ahead CAS",
        "RESERVED -> DISPATCH_AMBIGUOUS",
        "DispatchIntent",
        "job_id",
        "reservation_id",
        "attempt_id",
        "provider_request_id",
        "idempotency_key",
        "provider_account_id",
        "model_id",
        "model_version",
        "capped_attempt_max_minor_units",
        "dispatch_sequence",
        "Only after a successful and certain commit",
        "uncertain commit status makes zero provider calls",
        "crash after the CAS but before send retains the full hold",
        "UsageRecord",
        "usage_record_id",
        "input_tokens",
        "output_tokens",
        "cost",
        "currency",
        "issued_at",
        "exact typed equality—including billing rule/version, minor-unit cap, ISO currency, and "
        "exponent—with the stored",
        "consumes usage_record_id atomically",
        "wrong, stale, mismatched, unauthenticated, or replayed record",
        "no valid UsageRecord exists, the capped maximum remains held",
        "Crash after CAS-before-send and after send-before-response",
        "Exactly one durable monotonic DispatchIntent CAS",
    ):
        assert token in normalized


def test_questionnaire_retry_authority_and_usage_attestor_fail_closed() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regressions = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    normalized = re.sub(r"\s+", " ", spend + regressions).replace("`", "").replace("**", "")

    for token in (
        "reservation immutably pins max_attempts",
        "expected next and unused attempt_id set",
        "price schedule and version",
        "sum of all authorized attempt caps",
        "Over-limit or duplicate attempts",
        "validation failure, store failure, or uncertain transaction outcome",
        "zero provider calls",
        "ProviderUsageAttestor",
        "pinned/allowlisted provider account",
        "read-only usage-API credential",
        "both provider_request_id and idempotency_key",
        "issuer_id",
        "issuer_version",
        "signing_key_id",
        "expires_at",
        "dedicated KMS attestation key",
        "no direct spend-ledger write, hold-release, reconciliation, or provider dispatch grant",
        "key rotation/revocation",
        "unknown/revoked issuer or key",
        "forged/wrong-key signature",
        "no authoritative provider record exists",
        "attempt beyond max_attempts",
        "cumulative authorized cap above the operation maximum",
        "Each must fail before DispatchIntent commit and make zero provider calls",
        "attestor principal has no direct ledger-write/release grant and no provider "
        "dispatch grant",
    ):
        assert token in normalized


def test_questionnaire_dispatch_digest_and_usage_signature_are_canonical() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regressions = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    trust = text.partition("### 6.1 Threat model — what is trusted")[2]
    trust = trust.partition("| Untrusted | Consequence |")[0]
    normalized = re.sub(r"\s+", " ", spend + regressions + trust)
    normalized = normalized.replace("`", "").replace("**", "")

    for token in (
        "input_token_cap",
        "output_token_cap",
        "price_schedule_id",
        "price_schedule_version",
        "input_unit_price",
        "output_unit_price",
        "provider_request_config_hash",
        "ACGS-PROVIDER-REQUEST-CONFIG-V1\\0 || JCS(config)",
        "every provider request option that can alter cost or limits",
        "constructs the network request only from the committed DispatchIntent values",
        "Immediately before TLS handoff",
        "same-dollar-cap request with different token limits",
        "signature-excluded preimage",
        'signature_algorithm = "EC_SIGN_P256_SHA256"',
        "ACGS-PROVIDER-USAGE-ATTESTATION-V1\\0",
        "RFC 8785 JCS",
        "usage_record_hash = hex(SHA256",
        "signature is the base64-encoded Cloud KMS",
        "recomputes and exactly compares usage_record_hash",
        "unknown algorithms",
        "valid low-usage signature is nevertheless mediated co-authorization",
        "Compromise of the attestor or attestation key can therefore falsely lower a hold",
        "Tamper each signed-envelope field",
        "retain the full hold on every failure",
    ):
        assert token in normalized


def test_questionnaire_transport_bytes_and_usage_values_are_closed() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regressions = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    normalized = re.sub(r"\s+", " ", spend + regressions)
    normalized = normalized.replace("`", "").replace("**", "")

    for token in (
        "ProviderTransportEnvelope",
        'fixed scheme = "https"',
        "allowlisted host",
        "allowlisted path",
        "normalized_query",
        "RFC 3986 percent-encoded",
        "semantic_headers",
        "semantic_options",
        "body_sha256",
        "body_b64",
        "exact emitted body bytes",
        "ACGS-PROVIDER-TRANSPORT-V1\\0",
        "sends those exact bytes without JSON parsing or reserialization",
        "Immediately before TLS handoff",
        "alternate body encoding",
        "unknown field or option injection",
        "post-hash body mutation",
        "The status/value contract is closed",
        "FINAL_SUCCEEDED",
        "FINAL_FAILED_CHARGED",
        "FINAL_NOT_CHARGED",
        "cost_minor_units",
        "currency_minor_unit_exponent",
        "billing_rule_id",
        "billing_rule_version",
        "exact pinned ISO 4217 currency",
        "JSON integers only",
        "Unknown, pending, provider-error, unrecognized",
        "nonzero fields on FINAL_NOT_CHARGED",
        "Only a complete valid terminal record",
        "Every case must retain the full hold",
    ):
        assert token in normalized


def test_questionnaire_money_and_transport_maps_are_canonical_and_closed() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regressions = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    normalized = re.sub(r"\s+", " ", spend + regressions)
    normalized = normalized.replace("`", "").replace("**", "")

    for token in (
        "capped_attempt_max_minor_units",
        "operation_wide_max_minor_units",
        "currency_minor_unit_exponent",
        "base-10 JSON integers",
        "exact minor units",
        "bounded to 0..2^63-1",
        "sole monetary-string exemption",
        r"0|[1-9][0-9]*(\.[0-9]*[1-9])?",
        "never strings, floats, or exponent notation",
        "string-encoded cost/cap values",
        "major-unit values placed in minor-unit fields",
        "comparison performed under mismatched units",
        "closed semantic_headers map",
        "closed semantic_options map",
        "all emitted fields that can alter provider interpretation",
        "Content-Encoding",
        "API version",
        "vendor feature flags",
        "routing flags",
        "Authorization credential value",
        "Content-Length derived exactly from the committed body bytes",
        "trace id only when",
        "Any other emitted header or option must be present in the closed map or absent",
        "three enumerated runtime-derived exclusions",
        "must make zero provider calls",
    ):
        assert token in normalized


def test_questionnaire_credential_account_and_billing_rules_are_bound() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    spend = text.partition("### 3.3.1 Spend control")[2].partition("### 3.3.2")[0]
    regressions = text.partition("### 8.3.4 Spend ceiling")[2].partition("### 8.3.8")[0]
    trust = text.partition("### 6.1 Threat model — what is trusted")[2]
    trust = trust.partition("| Untrusted | Consequence |")[0]
    normalized = re.sub(r"\s+", " ", spend + regressions + trust)
    normalized = normalized.replace("`", "").replace("**", "")

    for token in (
        "provider_credential_binding_id",
        "workload_identity_principal",
        "workload_identity_issuer",
        "workload_identity_audience",
        "credential_mapping_version",
        "credential_min_valid_until",
        "exact provider_account_id",
        "billing_rule_id",
        "billing_rule_version",
        "ProviderCredentialInjector",
        "only component allowed to read the workload credential store",
        "short-lived credential",
        "Authorization secret is excluded from hashes and logs",
        "binding id, mapping version, exact provider_account_id",
        "re-resolves and validates credential binding/mapping version",
        "revocation state, and sufficient credential expiry",
        "wrong, rotated, revoked, expired",
        "makes zero provider calls",
        "read-only usage role of the same provider_credential_binding_id",
        "signature-excluded preimage contains every field listed above",
        "wrong billing rule/version",
        "usage attestor must query the same committed account/binding namespace",
        "retains the full hold",
        "compromise can substitute credentials/accounts and dispatch paid calls",
    ):
        assert token in normalized


def test_questionnaire_outcome_chain_is_signed_and_offline_verifiable() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    outcome = text.partition("product-owned canonical `OutcomeEvent` schema")[2]
    outcome = outcome.partition("### 2.6.1")[0]
    trust = text.partition("The product outcome chain has two authentication boundaries")[2]
    trust = trust.partition("### 6.3")[0]
    offline = text.partition("### 8.6 Receipt chain verification")[2]
    offline = offline.partition("### 8.7")[0]
    signing_test = text.partition("### 8.7 Signing-mode assertion")[2]
    signing_test = signing_test.partition("## 9.")[0]
    normalized = re.sub(r"\s+", " ", outcome + trust + offline + signing_test)
    for token in (
        "OutcomePayloadPreimage",
        "CAS-reserves the current head before any event signature is issued",
        "OutcomeReservation",
        "payload_hash",
        "OutcomeEventUnsignedPreimage",
        "previous_outcome_hash",
        "signature_algorithm` / `signing_key_id",
        "KMS signature",
        "ordering avoids self-reference",
        "AppendAcceptanceUnsignedPreimage",
        "matching finalizer-signed, `ATTESTED` `AppendAcceptance`",
        "orphan and remains unacceptable",
        "without both the event-signing and append-acceptance keys",
        "cannot rewrite or rechain events that the verifier will accept",
        "tamper status, result hash, or error hash",
        "unknown/revoked/wrong key",
        "no two accepted events share a predecessor",
        "single genesis",
        "unique predecessor per accepted event",
        "two product wrappers concurrently against one head",
        "rejected contender receives no signature",
        "orphan signature is rejected online and offline",
        "COMMITTED_PENDING_SIGNATURE",
        "current head's row is not `ATTESTED`",
        "finalizer never signs a precommit or aborted reservation",
        "crash before the finalize transaction advances no head",
        "crash after finalize but before signing",
        "crash after KMS signing but before signature storage",
        "No event is exposed to consumers or accepted offline before `ATTESTED`",
    ):
        assert token in normalized


def test_questionnaire_failed_outcome_is_redacted_hashed_and_exclusive() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    schema = text.partition("product-owned canonical `OutcomeEvent` schema")[2]
    schema = schema.partition("### 2.6.1")[0]
    regression = text.partition("### 8.7 Signing-mode assertion")[2].partition("## 9.")[0]
    normalized = re.sub(r"\s+", " ", schema + regression)
    for token in (
        "`error_hash`",
        "nonnull iff `FAILED`",
        "Exactly one outcome hash is populated",
        "null `error_hash`/`error_envelope`",
        "null `result_hash`",
        "stable redacted envelope",
        "{schema_version, error_class, error_code, safe_message_hash, retryable}",
        "error_hash = SHA256(canonical(ErrorEnvelope))",
        "no raw exception text, stack, request payload, credential, or secret",
        "event signature covers the failure binding",
        "Tamper the error class, code, safe-message hash, retryability",
        "status/result/error exclusivity",
    ):
        assert token in normalized


def test_questionnaire_trust_tcb_names_every_security_authority() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    trust = text.partition("### 6.1 Threat model — what is trusted")[2]
    trust = trust.partition("| Untrusted | Consequence |")[0]
    normalized = re.sub(r"\s+", " ", trust)
    for token in (
        "policy kernel and receipt verifier",
        "Receipt signer and receipt-key custody",
        "Shared receipt-burn authority and Firestore consumption store",
        "Spend ledger and Firestore transaction authority",
        "`ProviderCredentialInjector` principal, workload credential mapping store",
        "short-lived credential issuer",
        "compromise can substitute credentials/accounts",
        "`ProviderUsageAttestor`, pinned provider account/API endpoint",
        "read-only usage credential, and KMS attestation key custody",
        "has no direct ledger-write/release grant",
        "signature co-authorizes downward reconciliation",
        "compromise can falsely release holds",
        "Payment webhook signature verifier and event store",
        "Provider-approval signature verifier, allowlisted approval keys",
        "single-use approval event store",
        "Product executor and side-effect credential boundary",
        "Outcome canonicalizer, event signer, and outcome-signing key custody",
        "`OutcomeAppendAuthority` identity and reservation/finalization store",
        "Dedicated acceptance-finalizer identity and append-acceptance key custody",
        "narrowly scoped reservation/finalize transaction grants",
        "Ordinary sink/store writers have neither event-signing nor acceptance-signing authority",
        "Semantic adjudicator, allowlisted rules, identities, and keys",
        "authority-completeness set",
        "Missing or ambiguous ownership is release-blocking",
        "necessarily in the TCB",
        "least-privilege short-lived credentials",
        "compromise can bypass the receipt gate",
    ):
        assert token in normalized


def test_questionnaire_escalation_and_transform_authority_fail_closed() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    normalized = re.sub(r"\s+", " ", text)
    for token in (
        "provider-authenticated approval event",
        "fresh proposal and fresh policy evaluation",
        "non-executable escalation receipt is never reused or upgraded",
        "original arguments never execute",
        "wrong-proposal",
        "new exact rewritten `TRANSFORM`",
    ):
        assert token in normalized


def test_questionnaire_uses_stable_shipped_symbols_not_line_citations() -> None:
    text = _read(QUESTIONNAIRE_SPEC)
    assert not re.search(r"(?:receipt|kernel|signing)\.py:\d", text)
    assert "f4a700824f597ecf77ff581f6301dfec6db252fd" in text

    expected = {
        "packages/gove-zone/src/gove_zone/kernel.py": {"evaluate_and_append", "simulate"},
        "packages/gove-zone/src/gove_zone/receipt.py": {"DecisionReceipt", "from_record"},
        "packages/gove-zone/src/gove_zone/executor.py": {
            "execute_with_receipt",
            "GovernedExecutor",
        },
        "packages/gove-zone/src/gove_zone/proofpack.py": {"generate_proof_pack", "verify_pack"},
    }
    for relative, names in expected.items():
        symbols = _python_symbols(relative)
        assert names <= symbols, f"missing documented symbols in {relative}: {names - symbols}"


def test_questionnaire_legal_boundary_is_counsel_pending_not_a_legal_conclusion() -> None:
    prose = _prose(_read(QUESTIONNAIRE_SPEC))
    assert "chosen boundary pending counsel" in prose
    assert "primary sources reviewed on 2026-07-25" in prose
    assert "not a definitive legal conclusion" in prose
    assert "only lawful shape available" not in prose
    assert "is legal to print" not in prose
    assert "there is no third-party assessment role to sell into" not in prose


def test_site_copy_preserves_the_four_verdict_execution_invariant() -> None:
    text = _read(SITE_DECK)
    for verdict in ("ALLOW", "DENY", "TRANSFORM", "ESCALATE"):
        assert verdict in text
    assert "Only ALLOW and TRANSFORM can authorize a side effect" in text
    assert "Sends only the approved" in text
    assert "Fail closed. No tool call." in text
