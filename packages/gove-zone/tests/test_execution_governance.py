"""Execution Governance Layer (ADR-0010 / P11) — classification and verdicts.

Two properties are load-bearing here and are tested as such:

1. **Classification is structural, never substring.** The mechanism this layer
   replaces matched substrings of command text and produced observable false
   positives. Those exact commands are regression cases below.
2. **Every tool a hook matcher can deliver has a tier assignment.** An
   unassigned tool falls to the fail-closed default tier (DENY). That is correct
   behavior and a self-lockout at the same time, so the matcher set is asserted
   against the tier bundle rather than left to inspection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest

from gove_zone.errors import ProductionProfileError
from gove_zone.execution import (
    ACTION_GIT_MUTATE,
    ACTION_PACKAGE_INSTALL,
    ACTION_PACKAGE_INVOKE,
    ACTION_RELEASE_PUBLISH,
    ACTION_SHELL_EXEC,
    EXECUTION_ACTIONS,
    EXECUTION_BOUNDARY,
    EXECUTION_TIER_BUNDLE,
    EXECUTION_VALIDATOR_ID,
    TIER_DEPENDENCY,
    TIER_SOURCE,
    TIER_UNCLASSIFIED,
    UNATTRIBUTED_ACTOR,
    build_execution_gateway,
    build_execution_policy,
    classify_command,
    declared_package_manager,
    execution_tool_calls_from_hook_payload,
    make_execution_call_factory,
    resolve_execution_actor,
    verify_execution_chain,
)
from gove_zone.gateway import UniversalGateway
from gove_zone.policy import RiskTierPolicy
from gove_zone.profile import GovernanceProfile
from gove_zone.receipt import Validator
from gove_zone.tool import ToolCall

REPO_ROOT = Path(__file__).resolve().parents[3]


class FakeSigner:
    """Deterministic HMAC signer implementing the ReceiptSigner protocol."""

    algorithm = "test-hmac-sha256"

    def __init__(self, key: bytes = b"exec-key", key_id: str = "exec-key-1") -> None:
        self._key = key
        self.key_id = key_id

    def sign(self, payload: bytes) -> str:
        return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


def make_execution_gateway(tmp_path: Path, **kwargs: Any) -> UniversalGateway:
    signer = FakeSigner()
    return UniversalGateway(
        tenant_id="tenant-exec",
        execution_boundary=EXECUTION_BOUNDARY,
        policy=build_execution_policy(),
        profile=GovernanceProfile.production(signer=signer, verifier=signer),
        validator=Validator(validator_id="validator-exec"),
        authority="execution-governance",
        audit_path=tmp_path / "audit.jsonl",
        ledger_path=tmp_path / "ledger.jsonl",
        **kwargs,
    )


def bash_payload(command: str) -> dict[str, Any]:
    return {"tool_name": "Bash", "tool_input": {"command": command}}


def audit_events(tmp_path: Path) -> list[dict[str, Any]]:
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def decide(gateway: UniversalGateway, command: str, *, canonical: str = "pnpm") -> dict[str, Any]:
    return gateway.handle_claude_hook(
        bash_payload(command),
        actor="operator-a",
        call_factory=make_execution_call_factory(canonical),
    )


def permission(response: dict[str, Any]) -> str:
    return str(response["hookSpecificOutput"]["permissionDecision"])


# -- 1. structural classification -------------------------------------------- #


def test_quoted_argument_never_promotes_a_command() -> None:
    """The retired classifier read ``" team "`` out of a commit message.

    This is that exact command. It is a git mutation and nothing else.
    """
    event = classify_command('git commit -m "fix team dashboard"')

    assert event.action == ACTION_GIT_MUTATE
    assert event.argv_prefix == ("git", "commit")
    assert event.facts["subcommand"] == "commit"


def test_grep_pattern_containing_a_keyword_is_not_an_orchestration_event() -> None:
    """Live false positive ``ev_de6629e1f60f41ea``: a read-only grep whose
    *pattern* contained ``autopilot`` was audited as an autopilot event."""
    event = classify_command('grep -rn "autopilot" .claude/hooks/')

    assert event.action == ACTION_SHELL_EXEC
    assert event.binary == "grep"
    assert event.tier_hint == TIER_UNCLASSIFIED


def test_ralph_in_a_file_path_is_not_an_orchestration_event() -> None:
    event = classify_command("cat docs/ralph-notes.md")

    assert event.action == ACTION_SHELL_EXEC
    assert event.binary == "cat"


@pytest.mark.parametrize(
    ("command", "action"),
    [
        ("npm install", ACTION_PACKAGE_INSTALL),
        ("pnpm add left-pad", ACTION_PACKAGE_INSTALL),
        ("npm run build", ACTION_PACKAGE_INVOKE),
        ("uv sync", ACTION_PACKAGE_INSTALL),
        ("pip install requests", ACTION_PACKAGE_INSTALL),
        ("git rebase -i main", ACTION_GIT_MUTATE),
        ("git status", ACTION_SHELL_EXEC),
        ("npm publish", ACTION_RELEASE_PUBLISH),
        ("twine upload dist/*", ACTION_RELEASE_PUBLISH),
        ("ls -la", ACTION_SHELL_EXEC),
    ],
)
def test_argv_prefix_routes_to_the_declared_surface(command: str, action: str) -> None:
    assert classify_command(command).action == action


def test_wrappers_and_absolute_paths_do_not_hide_the_binary() -> None:
    event = classify_command("sudo /usr/local/bin/npm install left-pad")

    assert event.action == ACTION_PACKAGE_INSTALL
    assert event.binary == "npm"
    assert event.facts["wrapped"] is True
    assert event.facts["invoked_by_absolute_path"] is True


@pytest.mark.parametrize(
    ("command", "wrapper", "option_value"),
    [
        ("sudo -u root npm install left-pad", "sudo", "root"),
        ("env -i npm install left-pad", "env", None),
        ("command -- npm install left-pad", "command", None),
        ("nice -n 5 npm install left-pad", "nice", "5"),
        ("doas -u root npm install left-pad", "doas", "root"),
    ],
)
def test_option_bearing_wrappers_are_undecidable_without_parsing_values(
    command: str,
    wrapper: str,
    option_value: str | None,
) -> None:
    event = classify_command(command)

    assert event.action == ACTION_SHELL_EXEC
    assert event.decidable is False
    assert event.undecidable_reasons == ("unsupported-wrapper-options",)
    assert event.facts["wrapped"] is True
    assert event.facts["wrapper_options_supported"] is False
    assert event.binary == wrapper
    serialized_args = json.dumps(event.to_args(), sort_keys=True)
    if option_value is not None:
        assert option_value not in serialized_args


def test_env_assignment_prefix_does_not_hide_the_binary() -> None:
    event = classify_command("FOO=bar NODE_ENV=production npm ci")

    assert event.action == ACTION_PACKAGE_INSTALL
    assert event.binary == "npm"


def test_option_before_subcommand_does_not_hide_package_install() -> None:
    event = classify_command("npm --silent install")

    assert event.action == ACTION_PACKAGE_INSTALL
    assert event.facts["subcommand"] == "install"


def test_package_manager_with_only_options_has_no_subcommand() -> None:
    event = classify_command("npm --silent --color")

    assert event.action == ACTION_PACKAGE_INVOKE
    assert event.facts["subcommand"] == ""


# -- 2. what the classifier refuses to decide -------------------------------- #


@pytest.mark.parametrize(
    "command",
    [
        "echo hi > tracked.txt",
        "cat a.txt | tee tracked.txt",
        "ls; npm install",
        "npm install && npm publish",
        "cp $(which npm) /tmp/npm",
    ],
)
def test_shell_operators_make_the_effect_undecidable(command: str) -> None:
    """A redirect or a second command is not recoverable from an argv prefix.

    The honest result is a recorded, attributed, *unclassified* event — not a
    verdict about a surface the gate did not actually resolve.
    """
    event = classify_command(command)

    assert event.action == ACTION_SHELL_EXEC
    assert event.decidable is False
    assert event.undecidable_reasons
    assert event.tier_hint == TIER_UNCLASSIFIED


def test_unbalanced_quotes_are_undecidable_not_guessed() -> None:
    event = classify_command('git commit -m "unterminated')

    assert event.decidable is False
    assert event.undecidable_reasons == ("unparseable-command",)


def test_operator_detection_ignores_quoted_operators() -> None:
    """``|`` inside a quoted grep pattern is data, not a pipe."""
    event = classify_command('grep -rn "autopilot\\|ralph" .')

    assert event.decidable is True
    assert event.facts["operator_present"] is False


def test_backtick_command_substitution_is_undecidable() -> None:
    event = classify_command("echo `whoami`")

    assert event.action == ACTION_SHELL_EXEC
    assert event.decidable is False
    assert "command-substitution" in event.undecidable_reasons


def test_operator_only_command_is_undecidable() -> None:
    event = classify_command("&&")

    assert event.action == ACTION_SHELL_EXEC
    assert event.binary == ""
    assert event.decidable is False
    assert event.undecidable_reasons == ("shell-operator",)


# -- 3. classification is bound into the receipt, and matched by policy ------- #


def test_classification_appears_in_both_args_and_state() -> None:
    """``args`` is hashed into the receipt; ``state`` is what PolicyRule reads.

    Publishing to only one of the two would either decide without attesting or
    attest without deciding.
    """
    (call,) = execution_tool_calls_from_hook_payload(
        bash_payload("npm install"),
        action_kind="PreToolUse",
        actor="operator-a",
        canonical_package_manager="pnpm",
    )

    assert call.name == ACTION_PACKAGE_INSTALL
    assert call.args["facts"]["manager"] == "npm"
    assert call.state["manager_is_canonical"] is False
    assert call.state["execution_surface"] == ACTION_PACKAGE_INSTALL
    # The argument hash is what the receipt binds.
    assert call.argument_hash()


def test_raw_command_text_is_not_carried_into_the_receipt() -> None:
    """A command line may contain a secret; the receipt must not become an
    exfiltration channel. Only the argv prefix is bound."""
    (call,) = execution_tool_calls_from_hook_payload(
        bash_payload("curl -H 'Authorization: Bearer s3cr3t' https://example.test"),
        action_kind="PreToolUse",
        actor="operator-a",
    )

    assert "s3cr3t" not in json.dumps(call.args)
    assert "s3cr3t" not in json.dumps(dict(call.state))


def test_non_bash_calls_keep_their_existing_runtime_shape() -> None:
    calls = execution_tool_calls_from_hook_payload(
        {"tool_name": "Edit", "tool_input": {"file_path": "a.py", "new_string": "x"}},
        action_kind="PreToolUse",
        actor="operator-a",
    )

    assert [c.name for c in calls] == ["runtime.Edit"]


def test_command_extraction_failure_uses_the_malformed_batch_surface() -> None:
    class OneUseToolName:
        def __init__(self) -> None:
            self._reads = 0

        def __bool__(self) -> bool:
            return True

        def __str__(self) -> str:
            self._reads += 1
            if self._reads > 1:
                raise RuntimeError("tool name became unreadable")
            return "Bash"

    payload = {"tool_name": OneUseToolName(), "tool_input": {"command": "npm install"}}

    (call,) = execution_tool_calls_from_hook_payload(
        payload,
        action_kind="PreToolUse",
        actor="operator-a",
    )

    assert call.name == "runtime.malformed_batch"
    assert "execution_surface" not in call.state


# -- 4. policy verdicts ------------------------------------------------------ #


def test_non_canonical_package_manager_is_denied(tmp_path: Path) -> None:
    """The 2026-08-09 incident, replayed. ``npm`` in a pnpm workspace is denied
    at the gate — before any fetch, before any lifecycle script."""
    gateway = make_execution_gateway(tmp_path)

    response = decide(gateway, "npm install")

    assert permission(response) == "deny"
    event = audit_events(tmp_path)[-1]
    assert event["tool"] == ACTION_PACKAGE_INSTALL
    assert event["decision"] == "deny"
    assert "deny-non-canonical-package-manager" in event["matched_rules"]


def test_option_bearing_wrapper_is_denied_before_receipt_minting(tmp_path: Path) -> None:
    gateway = make_execution_gateway(tmp_path)

    response = decide(gateway, "sudo -u root npm install left-pad")

    assert permission(response) == "deny"
    assert "gove_zone" not in response
    events = audit_events(tmp_path)
    assert len(events) == 1
    assert events[0]["actor"] == "operator-a"
    assert events[0]["decision"] == "deny"
    assert "deny-unsupported-wrapper-options" in events[0]["matched_rules"]


def test_canonical_manager_escalates_rather_than_denying(tmp_path: Path) -> None:
    """Positive control. The canonical manager is not denied — but a dependency
    mutation still requires a human, which is the ``dependency`` tier baseline.
    """
    gateway = make_execution_gateway(tmp_path)

    response = decide(gateway, "pnpm install --ignore-scripts")

    assert permission(response) == "ask"
    event = audit_events(tmp_path)[-1]
    assert event["decision"] == "escalate"
    assert f"RISK_TIER:{TIER_DEPENDENCY}" in event["matched_rules"]


def test_install_with_lifecycle_scripts_enabled_names_its_own_rule(tmp_path: Path) -> None:
    """``matched_rules`` must say *why*: the generic tier escalation and the
    lifecycle-script escalation are different findings."""
    gateway = make_execution_gateway(tmp_path)

    response = decide(gateway, "pnpm install")

    assert permission(response) == "ask"
    event = audit_events(tmp_path)[-1]
    assert "escalate-install-with-lifecycle-scripts-enabled" in event["matched_rules"]


def test_unclassified_shell_command_is_allowed_and_receipted(tmp_path: Path) -> None:
    gateway = make_execution_gateway(tmp_path)

    response = decide(gateway, "ls -la")

    assert permission(response) == "allow"
    anchors = response["gove_zone"]["receipts"]
    assert len(anchors) == 1
    assert anchors[0]["receipt_hash"]
    assert anchors[0]["audit_hash"]
    assert anchors[0]["policy_hash"]


def test_git_control_surface_escalates(tmp_path: Path) -> None:
    gateway = make_execution_gateway(tmp_path)

    assert permission(decide(gateway, "git push origin main")) == "ask"
    assert permission(decide(gateway, "git commit -m 'ordinary work'")) == "allow"


def test_release_publication_escalates(tmp_path: Path) -> None:
    gateway = make_execution_gateway(tmp_path)

    assert permission(decide(gateway, "npm publish")) == "ask"


def test_batch_wrapped_install_is_still_classified(tmp_path: Path) -> None:
    """Wrapping the call in a batch must not evade the classifier — the reason
    the raw per-call payload is expanded before classification."""
    gateway = make_execution_gateway(tmp_path)

    response = gateway.handle_claude_hook(
        {
            "tool_calls": [
                {"name": "Bash", "args": {"command": "ls -la"}},
                {"name": "Bash", "args": {"command": "npm install"}},
            ]
        },
        actor="operator-a",
        call_factory=make_execution_call_factory("pnpm"),
    )

    assert permission(response) == "deny"
    tools = [e["tool"] for e in audit_events(tmp_path)]
    assert ACTION_PACKAGE_INSTALL in tools


def test_non_string_bash_command_requires_review_without_authorization(tmp_path: Path) -> None:
    gateway = make_execution_gateway(tmp_path)

    response = gateway.handle_claude_hook(
        {"tool_name": "Bash", "tool_input": {"command": None}},
        actor="operator-a",
        call_factory=make_execution_call_factory("pnpm"),
    )

    assert permission(response) == "ask"
    assert audit_events(tmp_path)[-1]["tool"] == "runtime.malformed_batch"
    assert "gove_zone" not in response


def test_call_factory_cannot_spoof_the_gateway_actor(tmp_path: Path) -> None:
    gateway = make_execution_gateway(tmp_path)

    def spoofing_factory(
        payload: dict[str, Any],
        *,
        action_kind: str,
        actor: str,
    ) -> tuple[ToolCall, ...]:
        assert payload["tool_name"] == "Bash"
        assert action_kind == "PreToolUse"
        assert actor == "operator-a"
        return (
            ToolCall(
                name=ACTION_SHELL_EXEC,
                args={"argv_prefix": ["ls"]},
                actor="spoofed-actor",
            ),
        )

    response = gateway.handle_claude_hook(
        bash_payload("ls"),
        actor="operator-a",
        call_factory=spoofing_factory,
    )

    assert permission(response) == "deny"
    assert "gove_zone" not in response
    assert "spoofed-actor" not in json.dumps(response)
    assert audit_events(tmp_path) == []


# -- 5. fail-closed wiring --------------------------------------------------- #


def test_unassigned_tool_falls_to_the_deny_default() -> None:
    policy = RiskTierPolicy.from_dict(EXECUTION_TIER_BUNDLE)

    assert policy.default_tier == "trust-root"
    assert policy.tier_for("tool.nobody.classified").enforcement.value == "deny"


def test_every_hook_matcher_tool_has_a_tier_assignment() -> None:
    """Lockout guard. ``.claude/settings.json`` decides which tools reach this
    gate; an unassigned one is denied by the fail-closed default, which for
    ``Edit``/``Write`` would block the operator from repairing the policy."""
    settings_path = REPO_ROOT / ".claude" / "settings.json"
    if not settings_path.exists():
        pytest.skip("workspace .claude/settings.json not present (standalone checkout)")

    settings = json.loads(settings_path.read_text(encoding="utf-8"))
    hook_script = "acgs-emit-receipt.py"
    matched_tools: set[str] = set()
    for entry in settings.get("hooks", {}).get("PreToolUse", []):
        commands = " ".join(str(h.get("command", "")) for h in entry.get("hooks", []))
        if hook_script not in commands:
            continue
        matched_tools.update(m for m in str(entry.get("matcher", "")).split("|") if m)

    assert matched_tools, "hook is wired to no matcher — the wiring assumption is stale"

    policy = RiskTierPolicy.from_dict(EXECUTION_TIER_BUNDLE)
    for tool in sorted(matched_tools):
        tier = policy.tier_for(f"runtime.{tool}")
        assert tier.enforcement.value != "deny", (
            f"runtime.{tool} resolves to the fail-closed default tier "
            f"{tier.name!r}; the operator would be locked out"
        )


def test_every_declared_surface_has_a_tier_assignment() -> None:
    tools = EXECUTION_TIER_BUNDLE["tools"]
    for action in EXECUTION_ACTIONS:
        assert action in tools, f"{action} has no tier assignment"


def test_production_profile_without_a_signer_refuses_to_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """ADV10 anti-downgrade. A production posture with no signer would mint
    receipts carrying ``signature_algorithm="none"`` — a silent downgrade to the
    unsigned dev contract. This regression was introduced during cutover and
    caught by ``test_integration_gaps.py::test_hook_end_to_end_production_without_signer_blocks``.
    """
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setenv("GOVE_ZONE_PROFILE", "production")

    with pytest.raises(ProductionProfileError, match="signer"):
        build_execution_gateway()


def test_malformed_batch_escalates_rather_than_denying() -> None:
    policy = RiskTierPolicy.from_dict(EXECUTION_TIER_BUNDLE)

    assert policy.tier_for("runtime.malformed_batch").enforcement.value == "escalate"


def test_policy_is_content_addressed_and_sealed() -> None:
    """ADV-D: a rewritten policy is a different policy. Receipts minted under the
    old one carry the old hash and are refused by a gate holding the new one."""
    first = build_execution_policy()
    second = build_execution_policy()
    assert first.version == second.version

    mutated = dict(EXECUTION_TIER_BUNDLE)
    mutated["tools"] = {**mutated["tools"], ACTION_PACKAGE_INSTALL: TIER_SOURCE}
    assert build_execution_policy(tier_bundle=mutated).version != first.version

    with pytest.raises(AttributeError):
        first._policies = ()  # type: ignore[attr-defined]


def test_declared_package_manager_reads_the_workspace_contract() -> None:
    if not (REPO_ROOT / "package.json").exists():
        pytest.skip("workspace package.json not present (standalone checkout)")

    assert declared_package_manager(REPO_ROOT) == "pnpm"


def test_declared_package_manager_absent_disables_the_contract(tmp_path: Path) -> None:
    """No declaration means no contract to violate — this control cannot invent
    a canonical manager the repository never named."""
    assert declared_package_manager(tmp_path) == ""

    event = classify_command("npm install", canonical_package_manager="")
    assert event.facts["manager_contract_applies"] is False
    assert event.facts["manager_is_canonical"] is True


@pytest.mark.parametrize(
    "package_json",
    [
        "{not-json",
        "[]",
        "{}",
        '{"packageManager": 7}',
        '{"packageManager": "   "}',
    ],
)
def test_invalid_package_manager_declarations_disable_the_contract(
    tmp_path: Path, package_json: str
) -> None:
    (tmp_path / "package.json").write_text(package_json, encoding="utf-8")

    assert declared_package_manager(tmp_path) == ""


def test_python_manager_is_not_bound_by_a_javascript_contract() -> None:
    event = classify_command("pip install requests", canonical_package_manager="pnpm")

    assert event.facts["manager_contract_applies"] is False


# -- 5b. deployment wiring --------------------------------------------------- #


def test_actor_resolution_states_its_own_source() -> None:
    """Attribution precedence is explicit, and the *basis* is recorded. None of
    these is an authenticated identity; the source string is what keeps that
    auditable instead of hidden behind a constant."""
    assert resolve_execution_actor({"GOVE_ZONE_ACTOR": "ci", "USER": "x"}) == ("ci", "explicit")
    assert resolve_execution_actor({"PAPERCLIP_AGENT_ID": "agent-7"}) == ("agent-7", "agent-id")
    assert resolve_execution_actor({"USER": "martin"}) == ("local:martin", "posix-user")
    assert resolve_execution_actor({}) == (UNATTRIBUTED_ACTOR, "none")


def test_unattributed_actor_is_not_a_plausible_principal() -> None:
    """A0/A1 residual: the fallback must not read like a real identity, or an
    audit record gets mistaken for an authorization."""
    assert UNATTRIBUTED_ACTOR == "unattributed"
    assert UNATTRIBUTED_ACTOR != EXECUTION_VALIDATOR_ID


def test_gateway_factory_writes_to_the_existing_audit_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cutover must not fork the chain. ``UniversalGateway`` defaults to
    ``gateway-audit.jsonl``; taking that default would leave the pre-cutover
    history in one file and everything after it in another."""
    monkeypatch.setenv("CLAUDE_PROJECT_DIR", str(tmp_path))
    monkeypatch.setenv("GOVE_ZONE_PROFILE", "dev")

    gateway = build_execution_gateway()
    gateway.handle_claude_hook(
        bash_payload("ls -la"),
        actor="operator-a",
        call_factory=make_execution_call_factory("pnpm"),
    )

    chain = tmp_path / ".gove-zone" / "audit.jsonl"
    assert chain.exists(), "the gateway wrote somewhere other than the canonical chain"
    assert not (tmp_path / ".gove-zone" / "gateway-audit.jsonl").exists()


def test_run_context_is_threaded_into_the_receipt_binding() -> None:
    """``run_id`` was accepted by the prior path and dropped before the receipt
    was built, leaving decisions correlated to nothing. It is bound now."""
    (call,) = execution_tool_calls_from_hook_payload(
        bash_payload("ls -la"),
        action_kind="PreToolUse",
        actor="operator-a",
        run_context={"run_id": "run-42", "attribution_source": "posix-user"},
    )

    assert call.args["run_id"] == "run-42"
    assert call.state["attribution_source"] == "posix-user"


def test_run_context_reaches_non_shell_calls_too() -> None:
    (call,) = execution_tool_calls_from_hook_payload(
        {"tool_name": "Edit", "tool_input": {"file_path": "a.py"}},
        action_kind="PreToolUse",
        actor="operator-a",
        run_context={"run_id": "run-42"},
    )

    assert call.name == "runtime.Edit"
    assert call.args["run_id"] == "run-42"


def test_a_payload_cannot_choose_its_own_canonical_manager() -> None:
    """The canonical manager is deployment configuration. If a payload could
    name it, any install could exempt itself in one field."""
    factory = make_execution_call_factory("pnpm")
    (call,) = factory(
        {
            "tool_name": "Bash",
            "tool_input": {"command": "npm install"},
            "canonical_package_manager": "npm",
        },
        action_kind="PreToolUse",
        actor="operator-a",
    )

    assert call.state["manager_is_canonical"] is False


# -- 6. independent verification --------------------------------------------- #


def test_verifier_flags_fallback_actor_and_legacy_observer_path() -> None:
    report = verify_execution_chain(
        [
            {
                "event_id": "ev_1",
                "tool": "runtime.Bash",
                "actor": "govern-zone-hook",
                "decision": "allow",
                "matched_rules": ["action_kind:autopilot"],
            }
        ]
    )

    assert report["ok"] is False
    assert report["counts"]["unattributed"] == 1
    assert report["counts"]["legacy_observer_path"] == 1


def test_verifier_always_flags_the_canonical_unattributed_actor() -> None:
    report = verify_execution_chain(
        [
            {
                "event_id": "ev_unattributed",
                "tool": ACTION_SHELL_EXEC,
                "actor": UNATTRIBUTED_ACTOR,
                "decision": "allow",
                "matched_rules": [f"RISK_TIER:{TIER_UNCLASSIFIED}"],
            }
        ],
        fallback_actors=(),
    )

    assert report["ok"] is False
    assert report["counts"]["unattributed"] == 1
    assert report["findings"]["unattributed"][0]["actor"] == UNATTRIBUTED_ACTOR
    assert report["counts"]["unassigned_tier"] == 0
    assert report["counts"]["unconditional_allow"] == 0
    assert report["counts"]["legacy_observer_path"] == 0


def test_verifier_flags_unassigned_tier() -> None:
    report = verify_execution_chain(
        [
            {
                "event_id": "ev_2",
                "tool": "env.unknown",
                "actor": "operator-a",
                "decision": "deny",
                "matched_rules": ["RISK_TIER:trust-root", "RISK_TIER:default"],
            }
        ]
    )

    assert report["counts"]["unassigned_tier"] == 1


def test_verifier_accepts_a_governed_chain(tmp_path: Path) -> None:
    gateway = make_execution_gateway(tmp_path)
    decide(gateway, "ls -la")
    decide(gateway, "npm install")

    report = verify_execution_chain(audit_events(tmp_path))

    assert report["ok"] is True, report["findings"]
    assert report["execution_records"] == 2


def test_verifier_reports_the_pre_cutover_boundary(tmp_path: Path) -> None:
    """The count of substring-classified records is the migration boundary: it
    can only be historical, and it must never grow after cutover."""
    gateway = make_execution_gateway(tmp_path)
    decide(gateway, "grep -rn 'autopilot' .")

    report = verify_execution_chain(audit_events(tmp_path))

    assert report["counts"]["legacy_observer_path"] == 0


def test_verifier_tolerates_malformed_events() -> None:
    report = verify_execution_chain([{"tool": "env.shell.exec"}, "not-a-mapping"])  # type: ignore[list-item]

    assert report["checked"] == 1
