import json
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evidence_writer import ChainEvidenceWriter
from hermes_acgs_middleware import (
    DEFAULT_CONSTITUTION,
    DENY,
    REDACT,
    REQUIRE_HUMAN,
    SOFT_BLOCK_WITH_EXPLANATION,
    HermesACGSMiddleware,
)


def build_middleware(tmp_path: Path) -> HermesACGSMiddleware:
    return HermesACGSMiddleware(
        constitution_path=ROOT / "constitution.min.yaml",
        evidence_path=tmp_path / "session.jsonl",
        session_id="pytest-session",
        agent_id="hermes-test-agent",
    )


def test_non_allowlisted_tool_is_denied_and_audited(tmp_path):
    acgs = build_middleware(tmp_path)

    decision = acgs.check_pre_tool("shell", {"cmd": "rm -rf /"}, user_msg="run this")

    assert decision.action == DENY
    assert "TOOL_ALLOWLIST" in decision.policy_ids
    assert "tool_not_allowed" in decision.tags

    ok, errors = ChainEvidenceWriter.verify_chain(tmp_path / "session.jsonl")
    assert ok, errors


def test_tool_output_with_api_key_is_redacted(tmp_path):
    acgs = build_middleware(tmp_path)
    raw = "request succeeded with api_key=sk_test_1234567890ABCDEF"

    decision = acgs.check_post_tool("web_search", {}, raw)
    result = acgs.apply_post_action(raw, decision)

    assert decision.action == REDACT
    assert "[REDACTED:" in result
    assert "sk_test_1234567890ABCDEF" not in result


def test_tool_output_with_bare_hyphenated_openai_key_is_redacted(tmp_path):
    acgs = build_middleware(tmp_path)
    raw = "request succeeded with sk-proj-1234567890abcdef"

    decision = acgs.check_post_tool("web_search", {}, raw)
    result = acgs.apply_post_action(raw, decision)

    assert decision.action == REDACT
    assert "OUTPUT_REDACT_OPENAI_STYLE_KEY" in decision.policy_ids
    assert "sk-proj-1234567890abcdef" not in result


def test_tool_output_with_embedded_hyphenated_openai_key_is_redacted(tmp_path):
    acgs = build_middleware(tmp_path)
    raw = {"stdout": "token=sk-proj-abc_def-1234567890; ok=true"}

    decision = acgs.check_post_tool("web_search", {}, raw)
    result = acgs.apply_post_action(raw, decision)

    assert decision.action == REDACT
    assert "OUTPUT_REDACT_OPENAI_STYLE_KEY" in decision.policy_ids
    assert "sk-proj-abc_def-1234567890" not in result


def test_tool_output_with_hyphenated_assignment_key_is_redacted(tmp_path):
    acgs = build_middleware(tmp_path)
    raw = "request succeeded with api_key=sk-proj-1234567890abcdef"

    decision = acgs.check_post_tool("web_search", {}, raw)
    result = acgs.apply_post_action(raw, decision)

    assert decision.action == REDACT
    assert "sk-proj-1234567890abcdef" not in result


def test_final_answer_with_hyphenated_openai_key_is_soft_blocked(tmp_path):
    acgs = build_middleware(tmp_path)
    draft = "Use sk-proj-1234567890abcdef for the next request."

    decision = acgs.check_final(draft)
    final = acgs.apply_final_action(draft, decision)

    assert decision.action == SOFT_BLOCK_WITH_EXPLANATION
    assert "OUTPUT_REDACT_OPENAI_STYLE_KEY" in decision.policy_ids
    assert "sk-proj-1234567890abcdef" not in final


def test_default_and_bundled_constitution_openai_key_regex_stay_in_sync():
    bundled = json.loads((ROOT / "constitution.min.yaml").read_text(encoding="utf-8"))

    def openai_key_regex(constitution):
        return next(
            item["regex"]
            for item in constitution["redaction_patterns"]
            if item["id"] == "OUTPUT_REDACT_OPENAI_STYLE_KEY"
        )

    assert openai_key_regex(DEFAULT_CONSTITUTION) == openai_key_regex(bundled)


def test_finance_final_answer_requires_human_review_and_disclaimer(tmp_path):
    acgs = build_middleware(tmp_path)
    draft = "Based on the portfolio, move 80% into a single volatile asset."

    decision = acgs.check_final(draft, context={"domain": "finance"})
    final = acgs.apply_final_action(draft, decision)

    assert decision.action == REQUIRE_HUMAN
    assert decision.add_disclaimer is True
    assert "HIGH_RISK_DOMAIN" in decision.policy_ids
    assert "Human review required" in final
    assert "not a substitute" in final
    # Draft must NOT be returned to the caller before human review
    assert "80%" not in final
    assert "volatile asset" not in final


def test_require_human_does_not_leak_draft_to_caller(tmp_path):
    """REQUIRE_HUMAN must never return draft content to the normal call path."""
    acgs = build_middleware(tmp_path)
    draft = "Sensitive legal advice: sign document X to transfer ownership."

    for domain in ("legal", "medical", "finance"):
        decision = acgs.check_final(draft, context={"domain": domain})
        final = acgs.apply_final_action(draft, decision)

        assert decision.action == REQUIRE_HUMAN, f"Expected REQUIRE_HUMAN for domain={domain}"
        # Hold message must be present
        assert "Human review required" in final
        # Draft content must not appear anywhere in the user-visible output
        assert "Sensitive legal advice" not in final, f"Draft leaked for domain={domain}"
        assert "sign document" not in final, f"Draft leaked for domain={domain}"


def test_concurrent_evidence_writers_maintain_valid_chain(tmp_path):
    """Two ChainEvidenceWriter instances targeting the same file must produce a valid chain."""
    evidence_path = tmp_path / "concurrent.jsonl"
    writer_a = ChainEvidenceWriter(evidence_path, session_id="session-a")
    writer_b = ChainEvidenceWriter(evidence_path, session_id="session-b")

    errors_seen: list[str] = []

    def write_events(writer: ChainEvidenceWriter, count: int) -> None:
        for i in range(count):
            try:
                writer.append_event(
                    hook="test",
                    subject=f"event-{i}",
                    input_payload={"i": i},
                    decision="ALLOW",
                    reasons=[],
                    policy_ids=["TEST"],
                )
            except Exception as exc:
                errors_seen.append(str(exc))

    thread_a = threading.Thread(target=write_events, args=(writer_a, 10))
    thread_b = threading.Thread(target=write_events, args=(writer_b, 10))
    thread_a.start()
    thread_b.start()
    thread_a.join()
    thread_b.join()

    assert not errors_seen, f"Writer threads raised errors: {errors_seen}"

    ok, chain_errors = ChainEvidenceWriter.verify_chain(evidence_path)
    assert ok, f"Chain verification failed after concurrent writes: {chain_errors}"

    events = ChainEvidenceWriter.read_events(evidence_path)
    assert len(events) == 20
