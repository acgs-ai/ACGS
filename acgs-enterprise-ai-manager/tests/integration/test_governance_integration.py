"""
Integration tests for governance framework enforcement.
Tests the complete MACI pattern flow with real components.
"""

import pytest
from backend.governance.acgs_integration import ACGSIntegration


@pytest.mark.integration
@pytest.mark.governance
class TestGovernanceIntegration:
    """Integration tests for complete governance workflow."""

    def test_maci_monitor_phase(self, sample_governance_rules, sample_context):
        """Test MACI Monitor phase - pattern detection."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        # Monitor should detect dangerous pattern
        result = integration.validate_operation(
            operation="Execute harmful command",
            context=sample_context,
            agent_id="test_agent",
        )

        assert result["valid"] is False
        assert "decision_id" in result

    def test_maci_approve_phase(self, sample_governance_rules, sample_context):
        """Test MACI Approve phase - approval workflow."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        # Operation requires approval
        validation_result = integration.validate_operation(
            operation="Delete critical data",
            context=sample_context,
            agent_id="test_agent",
        )

        assert validation_result["action"] == "REQUIRE_APPROVAL"

        # Request approval
        approval_request = integration.request_approval(
            operation="Delete critical data",
            context=sample_context,
            agent_id="test_agent",
        )

        assert approval_request["status"] == "PENDING"
        assert "request_id" in approval_request

    def test_maci_control_phase(self, sample_governance_rules, sample_context):
        """Test MACI Control phase - enforcement."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        # Validate operation
        validation_result = integration.validate_operation(
            operation="Safe operation", context=sample_context, agent_id="test_agent"
        )

        # Enforce decision
        allowed = integration.enforce_decision(validation_result, "Safe operation")

        assert allowed is True

    def test_maci_inspect_phase(self, sample_governance_rules, sample_context):
        """Test MACI Inspect phase - audit trail."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        # Perform operations
        integration.validate_operation("Op 1", sample_context, "agent_1")
        integration.validate_operation("Op 2", sample_context, "agent_2")

        # Inspect audit trail
        audit_entries = integration.inspect_audit_trail(limit=10)

        assert len(audit_entries) == 2
        assert all("timestamp" in entry for entry in audit_entries)

    def test_fail_closed_enforcement(self, sample_governance_rules, sample_context):
        """Test fail-closed enforcement blocks on violations."""
        integration = ACGSIntegration(
            constitution_path=str(sample_governance_rules), fail_closed=True
        )

        # Dangerous operation should be blocked
        validation_result = integration.validate_operation(
            operation="Dangerous action", context=sample_context, agent_id="test_agent"
        )

        allowed = integration.enforce_decision(validation_result, "Dangerous action")

        assert allowed is False

    def test_audit_trail_integrity(self, sample_governance_rules, sample_context):
        """Test audit trail maintains cryptographic integrity."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        # Generate multiple audit entries
        for i in range(10):
            integration.validate_operation(
                operation=f"Operation {i}",
                context=sample_context,
                agent_id="test_agent",
            )

        # Verify chain integrity
        integrity = integration.audit_logger.verify_chain_integrity()

        assert integrity["valid"] is True
        assert integrity["total_entries"] == 10
        assert len(integrity["broken_links"]) == 0

    def test_confidence_threshold_validation(self, sample_governance_rules):
        """Test validation enforces confidence thresholds."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        # Low confidence should fail
        low_conf_result = integration.validate_operation(
            operation="I recommend this action",
            context={"confidence": 0.5},
            agent_id="test_agent",
        )

        assert low_conf_result["valid"] is False

        # High confidence should pass
        high_conf_result = integration.validate_operation(
            operation="I recommend this action",
            context={"confidence": 0.9},
            agent_id="test_agent",
        )

        assert high_conf_result["valid"] is True
