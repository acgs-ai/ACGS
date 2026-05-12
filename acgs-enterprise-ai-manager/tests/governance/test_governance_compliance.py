"""
Governance-specific test suite.
Tests governance rules enforcement, audit trails, and compliance.
"""

import pytest
from backend.governance.acgs_integration import ACGSIntegration


@pytest.mark.governance
class TestGovernanceRulesEnforcement:
    """Test governance rules are properly enforced."""

    def test_critical_safety_rules_block_harmful_actions(self, sample_governance_rules):
        """Test critical safety rules block harmful operations."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        harmful_operations = [
            "harm users",
            "kill process",
            "destroy data",
            "attack system",
        ]

        for operation in harmful_operations:
            result = integration.validate_operation(
                operation=operation, context={}, agent_id="test_agent"
            )
            assert result["valid"] is False, f"Failed to block: {operation}"
            assert result["action"] == "BLOCK"

    def test_data_deletion_requires_approval(self, sample_governance_rules):
        """Test data deletion operations require human approval."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        deletion_operations = [
            "DELETE FROM users",
            "remove all records",
            "delete customer data",
        ]

        for operation in deletion_operations:
            result = integration.validate_operation(
                operation=operation, context={}, agent_id="test_agent"
            )
            assert (
                result["action"] == "REQUIRE_APPROVAL"
            ), f"Failed to require approval: {operation}"

    def test_ai_recommendations_require_confidence_threshold(
        self, sample_governance_rules
    ):
        """Test AI recommendations must meet confidence threshold."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        # Below threshold
        low_conf = integration.validate_operation(
            operation="I recommend action X",
            context={"confidence": 0.6},
            agent_id="test_agent",
        )
        assert low_conf["valid"] is False

        # Above threshold
        high_conf = integration.validate_operation(
            operation="I recommend action X",
            context={"confidence": 0.85},
            agent_id="test_agent",
        )
        assert high_conf["valid"] is True

    def test_audit_trail_captures_all_decisions(self, sample_governance_rules):
        """Test all governance decisions are logged to audit trail."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        operations = ["Safe operation", "Dangerous operation", "Delete data"]

        for op in operations:
            integration.validate_operation(op, {}, "test_agent")

        audit_entries = integration.inspect_audit_trail(limit=10)
        assert len(audit_entries) == len(operations)

    def test_fail_closed_enforcement_on_rule_violation(self, sample_governance_rules):
        """Test fail-closed enforcement blocks operations on violations."""
        integration = ACGSIntegration(
            constitution_path=str(sample_governance_rules), fail_closed=True
        )

        result = integration.validate_operation(
            operation="harmful action", context={}, agent_id="test_agent"
        )

        allowed = integration.enforce_decision(result, "harmful action")
        assert allowed is False


@pytest.mark.governance
class TestComplianceRequirements:
    """Test compliance with regulatory frameworks."""

    def test_audit_trail_is_tamper_evident(self, sample_governance_rules):
        """Test audit trail uses cryptographic chaining."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        # Generate audit entries
        for i in range(5):
            integration.validate_operation(f"Op {i}", {}, "test_agent")

        # Verify integrity
        integrity = integration.audit_logger.verify_chain_integrity()
        assert integrity["valid"] is True
        assert integrity["total_entries"] == 5

    def test_sensitive_data_redacted_in_audit_logs(self, sample_governance_rules):
        """Test sensitive data is redacted in audit logs."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        sensitive_context = {
            "user_id": "123",
            "password": "secret",
            "api_key": "key_abc",
        }

        integration.validate_operation(
            operation="Test operation", context=sensitive_context, agent_id="test_agent"
        )

        audit_entries = integration.inspect_audit_trail(limit=1)
        assert audit_entries[0]["context"]["password"] == "***REDACTED***"
        assert audit_entries[0]["context"]["api_key"] == "***REDACTED***"

    def test_governance_status_reporting(self, sample_governance_rules):
        """Test governance framework status can be queried."""
        integration = ACGSIntegration(constitution_path=str(sample_governance_rules))

        status = integration.get_governance_status()

        assert status["fail_closed"] is True
        assert status["audit_enabled"] is True
        assert status["rules_count"] > 0
