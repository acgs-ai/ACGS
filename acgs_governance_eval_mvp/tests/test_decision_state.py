from __future__ import annotations

from governance.adapters.tools import GovernedToolAdapter
from governance.audit import ChainHashAuditStore
from governance.models import DECISION_SCHEMA_VERSION, ActionRequest, Principal, sha256_json
from governance.replay import replay_event


def _allowed_payload(**overrides):
    base = {
        "actor": {"id": "agent-legal-1", "role": "LegalOps"},
        "intent": "Redline supplier agreement",
        "action_type": "contract.redline",
        "resource": "contracts/supplier-123",
        "metadata": {"policy_citations": ["CONTRACT-AUTHORITY-001"]},
        "tool_input": {"path": "contracts/supplier-123.txt", "redactions": []},
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# decision_state field
# ---------------------------------------------------------------------------

def test_decision_state_is_allow_when_all_checks_allow(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)

    decision = adapter.validate(_allowed_payload())

    assert decision.allow is True
    assert decision.decision_state == "allow"


def test_decision_state_is_deny_when_any_check_denies(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)

    # MarketingOps cannot do contract.approve → denial.
    decision = adapter.validate(
        _allowed_payload(
            actor={"id": "agent-mkt-1", "role": "MarketingOps"},
            action_type="contract.approve",
            metadata={},
        )
    )

    assert decision.allow is False
    assert decision.decision_state == "deny"


# ---------------------------------------------------------------------------
# schema version + bundle hashes
# ---------------------------------------------------------------------------

def test_decision_record_has_schema_version_v1(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)

    decision = adapter.validate(_allowed_payload())

    assert decision.decision_schema_version == DECISION_SCHEMA_VERSION
    assert decision.decision_schema_version == "v1"


def test_decision_record_carries_policy_bundle_hash(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)
    expected = sha256_json(policy_bundle)

    decision = adapter.validate(_allowed_payload())

    assert decision.policy_bundle_hash == expected
    assert len(decision.policy_bundle_hash) == 64  # sha256 hex


def test_decision_record_carries_role_bundle_hash(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)
    expected = sha256_json(roles_bundle)

    decision = adapter.validate(_allowed_payload())

    assert decision.role_bundle_hash == expected


# ---------------------------------------------------------------------------
# effective_tool_input
# ---------------------------------------------------------------------------

def test_effective_tool_input_set_on_allow(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)
    payload = _allowed_payload(tool_input={"path": "contracts/supplier-123.txt", "limit": 10})

    decision = adapter.validate(payload)

    assert decision.allow is True
    assert decision.effective_tool_input == {"path": "contracts/supplier-123.txt", "limit": 10}


def test_effective_tool_input_none_on_deny(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)

    decision = adapter.validate(
        _allowed_payload(
            actor={"id": "agent-mkt-1", "role": "MarketingOps"},
            action_type="contract.approve",
            metadata={},
        )
    )

    assert decision.allow is False
    assert decision.effective_tool_input is None


def test_action_request_from_dict_derives_inputs_hash_from_tool_input():
    tool_input = {"path": "contracts/x.txt", "redactions": []}
    request = ActionRequest.from_dict(
        {
            "actor": {"id": "a", "role": "LegalOps"},
            "intent": "Redline",
            "action_type": "contract.redline",
            "resource": "contracts/x",
            "tool_input": tool_input,
        }
    )

    # When inputs_hash is not provided, from_dict derives it from tool_input.
    assert request.inputs_hash == sha256_json(tool_input)
    assert request.tool_input == tool_input


# ---------------------------------------------------------------------------
# guard() TOCTOU defense
# ---------------------------------------------------------------------------

def test_guard_calls_fn_with_effective_tool_input(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)
    received: list[dict] = []

    def executor(tool_input):
        received.append(tool_input)
        return "ok"

    payload = _allowed_payload(tool_input={"path": "contracts/supplier-123.txt"})
    result = adapter.guard(payload, executor)

    assert result == "ok"
    assert received == [{"path": "contracts/supplier-123.txt"}]


def test_guard_refuses_when_request_has_no_tool_input(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)
    fn_called = False

    def executor(_tool_input):
        nonlocal fn_called
        fn_called = True

    payload = _allowed_payload()
    payload.pop("tool_input", None)

    raised: RuntimeError | None = None
    try:
        adapter.guard(payload, executor)
    except RuntimeError as exc:
        raised = exc

    assert raised is not None
    assert "tool_input" in str(raised)
    assert fn_called is False


def test_guard_does_not_execute_fn_when_decision_denies(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)
    fn_called = False

    def executor(_tool_input):
        nonlocal fn_called
        fn_called = True

    payload = _allowed_payload(
        actor={"id": "agent-mkt-1", "role": "MarketingOps"},
        action_type="contract.approve",
        metadata={},
        tool_input={"path": "contracts/x"},
    )

    raised: PermissionError | None = None
    try:
        adapter.guard(payload, executor)
    except PermissionError as exc:
        raised = exc

    assert raised is not None
    assert fn_called is False


# ---------------------------------------------------------------------------
# replay drift detection
# ---------------------------------------------------------------------------

def test_replay_no_drift_when_bundle_unchanged(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)

    decision = adapter.validate(_allowed_payload())
    stored = store.query(event_id=decision.event_id, limit=1)[0]

    result = replay_event(stored, roles_bundle=roles_bundle, policy_bundle=policy_bundle)

    assert result["policy_drift"] is False
    assert result["role_drift"] is False
    assert result["same_allow"] is True


def test_replay_detects_policy_drift_via_bundle_hash(tmp_path, roles_bundle, policy_bundle):
    store = ChainHashAuditStore(tmp_path / "audit.jsonl")
    adapter = GovernedToolAdapter(roles_bundle=roles_bundle, policy_bundle=policy_bundle, audit_store=store)

    decision = adapter.validate(_allowed_payload())
    stored = store.query(event_id=decision.event_id, limit=1)[0]

    drifted_policy = dict(policy_bundle)
    drifted_policy["version"] = "drifted-version"

    result = replay_event(stored, roles_bundle=roles_bundle, policy_bundle=drifted_policy)

    assert result["policy_drift"] is True
    assert result["original_policy_bundle_hash"] != result["replay_policy_bundle_hash"]
    assert result["role_drift"] is False


def test_replay_old_event_without_bundle_hash_passes_gracefully(roles_bundle, policy_bundle):
    # Simulate an event written by a pre-refactor version: no bundle_hash fields.
    legacy_event = {
        "event_id": "legacy-1",
        "request": {
            "actor": {"id": "agent-legal-1", "role": "LegalOps"},
            "intent": "Redline",
            "action_type": "contract.redline",
            "resource": "contracts/supplier-123",
            "inputs_hash": "sha256:legacy",
            "metadata": {"policy_citations": ["CONTRACT-AUTHORITY-001"]},
        },
        "allow": True,
        "reason_codes": ["AUTH_ALLOWED", "POLICY_CITATION_MATCHED", "GOVERNANCE_RECALL_OK"],
        "policy_version": "legacy",
        "role_version": "legacy",
    }

    result = replay_event(legacy_event, roles_bundle=roles_bundle, policy_bundle=policy_bundle)

    # Drift fields are False (cannot evaluate without an anchor); replay still runs.
    assert result["policy_drift"] is False
    assert result["role_drift"] is False
    assert result["original_policy_bundle_hash"] == ""
