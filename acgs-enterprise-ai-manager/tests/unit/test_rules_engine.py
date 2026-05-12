"""
Unit tests for RulesEngine
Tests pattern matching, validation logic, and rule enforcement.
"""

import pytest
from pathlib import Path
from backend.governance.rules_engine import RulesEngine


@pytest.mark.unit
@pytest.mark.governance
class TestRulesEngine:
    """Test suite for RulesEngine class."""

    def test_initialization_with_valid_constitution(self, sample_governance_rules):
        """Test RulesEngine initializes correctly with valid constitution file."""
        engine = RulesEngine(str(sample_governance_rules))

        assert engine is not None
        assert len(engine.rules) == 3
        assert engine.enforcement_config["fail_mode"] == "CLOSED"
        assert engine.audit_config["enabled"] is True

    def test_initialization_with_missing_file(self, temp_dir):
        """Test RulesEngine handles missing constitution file gracefully."""
        missing_file = temp_dir / "nonexistent.yaml"
        engine = RulesEngine(str(missing_file))

        assert engine.rules == []

    def test_validate_blocking_operation(self, sample_governance_rules, sample_context):
        """Test validation blocks operations matching BLOCK rules."""
        engine = RulesEngine(str(sample_governance_rules))

        result = engine.validate("This is a dangerous operation", sample_context)

        assert result["valid"] is False
        assert len(result["violations"]) > 0
        assert result["violations"][0]["action"] == "BLOCK"
        assert result["violations"][0]["rule_id"] == "test-block-rule"

    def test_validate_approval_required_operation(
        self, sample_governance_rules, sample_context
    ):
        """Test validation requires approval for REQUIRE_APPROVAL rules."""
        engine = RulesEngine(str(sample_governance_rules))

        result = engine.validate("Delete user data", sample_context)

        assert result["requires_approval"] is True
        assert len(result["violations"]) > 0
        assert result["violations"][0]["action"] == "REQUIRE_APPROVAL"
        assert result["violations"][0]["rule_id"] == "test-approval-rule"

    def test_validate_with_confidence_threshold(self, sample_governance_rules):
        """Test validation enforces confidence thresholds."""
        engine = RulesEngine(str(sample_governance_rules))

        # Low confidence - should fail validation
        low_confidence_context = {"confidence": 0.5}
        result = engine.validate("I recommend this action", low_confidence_context)

        assert result["valid"] is False
        assert any(
            "confidence" in v["description"].lower() for v in result["violations"]
        )

    def test_validate_with_high_confidence(self, sample_governance_rules):
        """Test validation passes with sufficient confidence."""
        engine = RulesEngine(str(sample_governance_rules))

        # High confidence - should pass validation
        high_confidence_context = {"confidence": 0.85}
        result = engine.validate("I recommend this action", high_confidence_context)

        assert result["valid"] is True
        assert "test-validate-rule" in result["matched_rules"]

    def test_validate_safe_operation(self, sample_governance_rules, sample_context):
        """Test validation allows safe operations."""
        engine = RulesEngine(str(sample_governance_rules))

        result = engine.validate("List all users", sample_context)

        assert result["valid"] is True
        assert len(result["violations"]) == 0
        assert result["requires_approval"] is False

    def test_get_rule_by_id(self, sample_governance_rules):
        """Test retrieving rule by ID."""
        engine = RulesEngine(str(sample_governance_rules))

        rule = engine.get_rule("test-block-rule")

        assert rule is not None
        assert rule["id"] == "test-block-rule"
        assert rule["severity"] == "CRITICAL"

    def test_get_rule_by_id_not_found(self, sample_governance_rules):
        """Test retrieving non-existent rule returns None."""
        engine = RulesEngine(str(sample_governance_rules))

        rule = engine.get_rule("nonexistent-rule")

        assert rule is None

    def test_get_rules_by_severity(self, sample_governance_rules):
        """Test filtering rules by severity level."""
        engine = RulesEngine(str(sample_governance_rules))

        critical_rules = engine.get_rules_by_severity("CRITICAL")

        assert len(critical_rules) == 1
        assert critical_rules[0]["id"] == "test-block-rule"

    def test_pattern_matching_case_insensitive(
        self, sample_governance_rules, sample_context
    ):
        """Test pattern matching is case-insensitive."""
        engine = RulesEngine(str(sample_governance_rules))

        result_lower = engine.validate("dangerous operation", sample_context)
        result_upper = engine.validate("DANGEROUS OPERATION", sample_context)
        result_mixed = engine.validate("DaNgErOuS OpErAtIoN", sample_context)

        assert result_lower["valid"] is False
        assert result_upper["valid"] is False
        assert result_mixed["valid"] is False

    def test_reload_constitution(self, sample_governance_rules):
        """Test reloading constitution updates rules."""
        engine = RulesEngine(str(sample_governance_rules))
        initial_count = len(engine.rules)

        engine.reload_constitution()

        assert len(engine.rules) == initial_count
