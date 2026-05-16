import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evidence_writer import (
    ChainEvidenceWriter,
)
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
