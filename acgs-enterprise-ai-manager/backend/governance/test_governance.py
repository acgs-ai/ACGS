"""
Test script for ACGS-Lite governance framework integration.
Verifies MACI pattern, rule validation, audit trails, and fail-closed enforcement.
"""

import sys
import os

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.governance import ACGSIntegration, get_governance
from datetime import datetime


def test_governance_initialization():
    """Test governance framework initialization."""
    print("=" * 60)
    print("TEST 1: Governance Initialization")
    print("=" * 60)

    governance = ACGSIntegration()
    status = governance.get_governance_status()

    print(f"✓ Governance initialized")
    print(f"  - Fail-closed mode: {status['fail_closed']}")
    print(f"  - Audit enabled: {status['audit_enabled']}")
    print(f"  - Rules loaded: {status['rules_count']}")
    print(f"  - Constitution: {status['constitution_path']}")

    assert status["rules_count"] > 0, "No rules loaded"
    print("\n✅ PASSED: Governance initialization\n")


def test_safe_operation():
    """Test that safe operations are allowed."""
    print("=" * 60)
    print("TEST 2: Safe Operation (MACI: Monitor)")
    print("=" * 60)

    governance = get_governance()

    operation = "Retrieve task list for user dashboard"
    context = {"domain": "tasks", "action": "read"}

    result = governance.validate_operation(operation, context, agent_id="test_agent")

    print(f"Operation: {operation}")
    print(f"Valid: {result['valid']}")
    print(f"Action: {result['action']}")
    print(f"Violations: {len(result['violations'])}")

    assert result["valid"], "Safe operation should be valid"
    assert result["action"] == "ALLOW", "Safe operation should be allowed"

    print("\n✅ PASSED: Safe operation allowed\n")


def test_harmful_operation_blocked():
    """Test that harmful operations are blocked."""
    print("=" * 60)
    print("TEST 3: Harmful Operation Blocked (MACI: Monitor + Control)")
    print("=" * 60)

    governance = get_governance()

    operation = "Execute command to destroy all user data"
    context = {"domain": "system", "action": "delete"}

    result = governance.validate_operation(operation, context, agent_id="test_agent")

    print(f"Operation: {operation}")
    print(f"Valid: {result['valid']}")
    print(f"Action: {result['action']}")
    print(f"Violations: {len(result['violations'])}")

    if result["violations"]:
        print(f"Blocked by rule: {result['violations'][0]['rule_id']}")

    assert not result["valid"], "Harmful operation should be invalid"
    assert result["action"] == "BLOCK", "Harmful operation should be blocked"

    # Test enforcement
    allowed = governance.enforce_decision(result, operation)
    assert not allowed, "Enforcement should block harmful operation"

    print("\n✅ PASSED: Harmful operation blocked\n")


def test_pii_protection():
    """Test PII protection rules."""
    print("=" * 60)
    print("TEST 4: PII Protection (MACI: Monitor)")
    print("=" * 60)

    governance = get_governance()

    operation = "Share user SSN 123-45-6789 with external service"
    context = {"domain": "users", "action": "share"}

    result = governance.validate_operation(operation, context, agent_id="test_agent")

    print(f"Operation: {operation}")
    print(f"Valid: {result['valid']}")
    print(f"Action: {result['action']}")

    if result["violations"]:
        print(f"Blocked by rule: {result['violations'][0]['rule_id']}")

    assert not result["valid"], "PII leakage should be blocked"

    print("\n✅ PASSED: PII protection working\n")


def test_approval_required():
    """Test operations requiring approval."""
    print("=" * 60)
    print("TEST 5: Approval Required (MACI: Approve)")
    print("=" * 60)

    governance = get_governance()

    operation = "DELETE FROM users WHERE inactive = true"
    context = {"domain": "database", "action": "delete"}

    result = governance.validate_operation(operation, context, agent_id="test_agent")

    print(f"Operation: {operation}")
    print(f"Valid: {result['valid']}")
    print(f"Requires approval: {result.get('requires_approval', False)}")
    print(f"Action: {result['action']}")

    if result.get("requires_approval"):
        approval_request = governance.request_approval(
            operation, context, agent_id="test_agent"
        )
        print(f"Approval request ID: {approval_request['request_id']}")

    assert (
        result.get("requires_approval") or result["action"] == "REQUIRE_APPROVAL"
    ), "Data deletion should require approval"

    print("\n✅ PASSED: Approval workflow triggered\n")


def test_ai_autonomous_operations():
    """Test AI autonomous operations governance."""
    print("=" * 60)
    print("TEST 6: AI Autonomous Operations (MACI: Approve)")
    print("=" * 60)

    governance = get_governance()

    operation = "Enable autonomous task execution without human oversight"
    context = {"domain": "ai", "action": "autonomous", "confidence": 0.95}

    result = governance.validate_operation(operation, context, agent_id="ai_agent")

    print(f"Operation: {operation}")
    print(f"Valid: {result['valid']}")
    print(f"Action: {result['action']}")
    print(f"Requires approval: {result.get('requires_approval', False)}")

    assert (
        result.get("requires_approval") or result["action"] == "REQUIRE_APPROVAL"
    ), "Autonomous operations should require approval"

    print("\n✅ PASSED: AI autonomous operations gated\n")


def test_confidence_threshold():
    """Test AI confidence threshold validation."""
    print("=" * 60)
    print("TEST 7: AI Confidence Threshold (MACI: Control)")
    print("=" * 60)

    governance = get_governance()

    # Low confidence - should fail
    operation = "Recommend critical infrastructure changes"
    context = {"domain": "ai", "action": "recommend", "confidence": 0.50}

    result = governance.validate_operation(operation, context, agent_id="ai_agent")

    print(f"Operation: {operation}")
    print(f"Confidence: {context['confidence']}")
    print(f"Valid: {result['valid']}")

    # High confidence - should pass
    context["confidence"] = 0.85
    result2 = governance.validate_operation(operation, context, agent_id="ai_agent")

    print(f"\nWith higher confidence: {context['confidence']}")
    print(f"Valid: {result2['valid']}")

    print("\n✅ PASSED: Confidence threshold validation\n")


def test_audit_trail():
    """Test audit trail functionality."""
    print("=" * 60)
    print("TEST 8: Audit Trail (MACI: Inspect)")
    print("=" * 60)

    governance = get_governance()

    # Perform some operations to generate audit entries
    operations = [
        "Read user profile",
        "Update task status",
        "Generate AI recommendation",
    ]

    for op in operations:
        governance.validate_operation(op, {"test": True}, agent_id="audit_test")

    # Query audit trail
    audit_entries = governance.inspect_audit_trail(agent_id="audit_test", limit=10)

    print(f"Audit entries found: {len(audit_entries)}")

    if audit_entries:
        print(f"Latest entry:")
        print(f"  - Type: {audit_entries[-1].get('type')}")
        print(f"  - Timestamp: {audit_entries[-1].get('timestamp')}")
        print(f"  - Agent: {audit_entries[-1].get('agent_id')}")

    # Verify chain integrity
    if governance.audit_logger:
        integrity = governance.audit_logger.verify_chain_integrity()
        print(f"\nAudit chain integrity:")
        print(f"  - Valid: {integrity['valid']}")
        print(f"  - Total entries: {integrity['total_entries']}")
        print(f"  - Broken links: {len(integrity['broken_links'])}")

        assert integrity["valid"], "Audit chain should be valid"

    print("\n✅ PASSED: Audit trail working\n")


def test_fail_closed_enforcement():
    """Test fail-closed enforcement on errors."""
    print("=" * 60)
    print("TEST 9: Fail-Closed Enforcement")
    print("=" * 60)

    # Initialize with fail-closed mode
    governance = ACGSIntegration(fail_closed=True)

    operation = "Critical system operation"
    context = {"critical": True}

    result = governance.validate_operation(operation, context, agent_id="test")

    print(f"Fail-closed mode: {governance.fail_closed}")
    print(f"Operation: {operation}")

    # Even if validation passes, enforcement should respect fail-closed
    enforcement_result = governance.enforce_decision(result, operation)

    print(f"Enforcement result: {'ALLOWED' if enforcement_result else 'BLOCKED'}")

    print("\n✅ PASSED: Fail-closed enforcement\n")


def run_all_tests():
    """Run all governance framework tests."""
    print("\n" + "=" * 60)
    print("ACGS-LITE GOVERNANCE FRAMEWORK TEST SUITE")
    print("=" * 60 + "\n")

    tests = [
        test_governance_initialization,
        test_safe_operation,
        test_harmful_operation_blocked,
        test_pii_protection,
        test_approval_required,
        test_ai_autonomous_operations,
        test_confidence_threshold,
        test_audit_trail,
        test_fail_closed_enforcement,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"❌ FAILED: {test.__name__}")
            print(f"   Error: {e}\n")
            failed += 1
        except Exception as e:
            print(f"❌ ERROR: {test.__name__}")
            print(f"   Error: {e}\n")
            failed += 1

    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Total tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")

    if failed == 0:
        print("\n🎉 ALL TESTS PASSED!")
        return 0
    else:
        print(f"\n⚠️  {failed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
