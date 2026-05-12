"""
Unit tests for ACGSIntegration
Tests the main governance integration layer and MACI pattern implementation.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from backend.governance.acgs_integration import (
    ACGSIntegration,
    get_governance,
    initialize_governance,
)


@pytest.mark.unit
@pytest.mark.governance
class TestACGSIntegration:
    """Test suite for ACGSIntegration class."""

    def test_initialization(self, sample_governance_rules):
        """Test ACGSIntegration initializes correctly."""
        integration = ACGSIntegration(
            constitution_path=str(sample_governance_rules),
            fail_closed=True,
            audit_enabled=True,
        )

        assert integration is not None
        assert integration.fail_closed is True
        assert integration.audit_enabled is True
        assert integration.rules_engine is not None
        assert integration.audit_logger is not None

    def test_initialization_without_audit(self, sample_governance_rules):
        """Test initialization with audit disabled."""
        integration = ACGSIntegration(
            constitution_path=str(sample_governance_rules), audit_enabled=False
        )

        assert integration.audit_logger is None

    def test_validate_operation_allow(
        self, sample_governance_rules, sample_context, mock_agent_id
    ):
        """Test validate_operation allows safe operations."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        result = integration.validate_operation(
            operation="List all users", context=sample_context, agent_id=mock_agent_id
        )

        assert result["valid"] is True
        assert result["action"] == "ALLOW"
        assert len(result["violations"]) == 0

    def test_validate_operation_block(
        self, sample_governance_rules, sample_context, mock_agent_id
    ):
        """Test validate_operation blocks dangerous operations."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        result = integration.validate_operation(
            operation="Execute dangerous command",
            context=sample_context,
            agent_id=mock_agent_id,
        )

        assert result["valid"] is False
        assert result["action"] == "BLOCK"
        assert len(result["violations"]) > 0

    def test_validate_operation_require_approval(
        self, sample_governance_rules, sample_context, mock_agent_id
    ):
        """Test validate_operation requires approval for sensitive operations."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        result = integration.validate_operation(
            operation="Delete user account",
            context=sample_context,
            agent_id=mock_agent_id,
        )

        assert result["action"] == "REQUIRE_APPROVAL"
        assert result.get("requires_approval") is True

    def test_validate_operation_fail_closed_on_error(
        self, sample_governance_rules, sample_context, mock_agent_id
    ):
        """Test fail-closed behavior when validation encounters error."""
        integration = ACGSIntegration(
            constitution_path=str(sample_governance_rules), fail_closed=True
        )

        # Mock rules_engine to raise exception
        integration.rules_engine.validate = Mock(side_effect=Exception("Test error"))

        # Should fail closed (block operation)
        with pytest.raises(Exception):
            integration.validate_operation(
                operation="Test operation",
                context=sample_context,
                agent_id=mock_agent_id,
            )

    def test_request_approval(
        self, sample_governance_rules, sample_context, mock_agent_id
    ):
        """Test requesting approval for an operation."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        approval_request = integration.request_approval(
            operation="Delete sensitive data",
            context=sample_context,
            agent_id=mock_agent_id,
            timeout_seconds=3600,
        )

        assert approval_request["request_id"] is not None
        assert approval_request["operation"] == "Delete sensitive data"
        assert approval_request["agent_id"] == mock_agent_id
        assert approval_request["status"] == "PENDING"
        assert approval_request["timeout_seconds"] == 3600

    def test_enforce_decision_allow(self, sample_governance_rules):
        """Test enforce_decision allows operations with ALLOW action."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        validation_result = {"action": "ALLOW", "valid": True}
        allowed = integration.enforce_decision(validation_result, "Test operation")

        assert allowed is True

    def test_enforce_decision_block(self, sample_governance_rules):
        """Test enforce_decision blocks operations with BLOCK action."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        validation_result = {
            "action": "BLOCK",
            "valid": False,
            "violations": [{"rule_id": "test-rule", "severity": "HIGH"}],
        }
        allowed = integration.enforce_decision(validation_result, "Dangerous operation")

        assert allowed is False

    def test_enforce_decision_require_approval(self, sample_governance_rules):
        """Test enforce_decision blocks operations requiring approval."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        validation_result = {"action": "REQUIRE_APPROVAL", "requires_approval": True}
        allowed = integration.enforce_decision(validation_result, "Sensitive operation")

        assert allowed is False

    def test_enforce_decision_unknown_action_fails_closed(
        self, sample_governance_rules
    ):
        """Test enforce_decision fails closed on unknown action."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        validation_result = {"action": "UNKNOWN_ACTION"}
        allowed = integration.enforce_decision(validation_result, "Test operation")

        assert allowed is False

    def test_inspect_audit_trail(
        self, sample_governance_rules, sample_context, mock_agent_id
    ):
        """Test inspecting audit trail."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        # Generate some audit entries
        integration.validate_operation("Op 1", sample_context, mock_agent_id)
        integration.validate_operation("Op 2", sample_context, mock_agent_id)

        audit_entries = integration.inspect_audit_trail(
            agent_id=mock_agent_id, limit=10
        )

        assert len(audit_entries) == 2

    def test_inspect_audit_trail_without_audit_enabled(self, sample_governance_rules):
        """Test inspect_audit_trail returns empty list when audit disabled."""
        integration = ACGSIntegration(
            constitution_path=str(sample_governance_rules), audit_enabled=False
        )

        audit_entries = integration.inspect_audit_trail()

        assert audit_entries == []

    def test_get_governance_status(self, sample_governance_rules):
        """Test getting governance framework status."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        status = integration.get_governance_status()

        assert "acgs_available" in status
        assert "fail_closed" in status
        assert "audit_enabled" in status
        assert "constitution_path" in status
        assert "rules_count" in status
        assert status["fail_closed"] is True
        assert status["audit_enabled"] is True

    def test_singleton_get_governance(self):
        """Test get_governance returns singleton instance."""
        instance1 = get_governance()
        instance2 = get_governance()

        assert instance1 is instance2

    def test_initialize_governance(self, sample_governance_rules):
        """Test initialize_governance creates new instance."""
        instance = initialize_governance(
            constitution_path=str(sample_governance_rules),
            fail_closed=True,
            audit_enabled=True,
        )

        assert instance is not None
        assert instance.fail_closed is True
        assert instance.audit_enabled is True
