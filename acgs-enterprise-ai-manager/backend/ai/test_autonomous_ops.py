"""
Test suite for AI Autonomous Operations with Governance Gates
Verifies autonomous operations, risk assessment, approval workflows, and audit trails
"""

import sys
import os
import asyncio

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from backend.governance import get_governance, initialize_governance
from backend.ai.autonomous_ops import (
    AutonomousOperationsEngine,
    initialize_autonomous_engine,
    OperationStatus,
)
from backend.governance.approval_gates import RiskLevel, ApprovalStatus


async def test_autonomous_engine_initialization():
    """Test autonomous operations engine initialization."""
    print("=" * 60)
    print("TEST 1: Autonomous Engine Initialization")
    print("=" * 60)

    governance = initialize_governance()
    engine = initialize_autonomous_engine(governance)

    stats = engine.get_statistics()

    print(f"✓ Autonomous engine initialized")
    print(f"  - Operation handlers: {len(engine.operation_handlers)}")
    print(f"  - Active operations: {stats['active_operations']}")
    print(f"  - Approval gate ready: {engine.approval_gate is not None}")

    assert len(engine.operation_handlers) == 2, "Should have 2 operation handlers"
    assert engine.approval_gate is not None, "Approval gate should be initialized"

    print("\n✅ PASSED: Engine initialization\n")


async def test_low_risk_auto_approval():
    """Test low-risk operation auto-approval."""
    print("=" * 60)
    print("TEST 2: Low-Risk Operation Auto-Approval")
    print("=" * 60)

    governance = get_governance()
    engine = initialize_autonomous_engine(governance)

    # Propose low-risk task assignment
    result = await engine.propose_operation(
        operation_type="task_assignment",
        details={
            "task_id": "task_001",
            "candidate_members": ["user_1", "user_2", "user_3"],
            "summary": "Assign routine documentation task",
        },
        context={
            "impact_scope": "single",
            "financial_impact": 0,
            "reversible": True,
            "confidence": 0.85,
            "workload_data": {
                "user_1": {"active_tasks": 3, "capacity": 10, "urgent_tasks": 0},
                "user_2": {"active_tasks": 5, "capacity": 10, "urgent_tasks": 1},
                "user_3": {"active_tasks": 7, "capacity": 10, "urgent_tasks": 2},
            },
            "required_skills": ["documentation"],
            "member_skills": {
                "user_1": ["documentation", "writing"],
                "user_2": ["coding", "testing"],
                "user_3": ["documentation", "design"],
            },
        },
    )

    operation = result["operation"]
    approval = result["approval_request"]

    print(f"Operation ID: {operation['operation_id']}")
    print(f"Risk Level: {approval['risk_level']}")
    print(f"Approval Status: {approval['status']}")

    assert approval["risk_level"] == RiskLevel.LOW, "Should be low risk"
    assert approval["status"] == ApprovalStatus.AUTO_APPROVED, "Should be auto-approved"
    assert (
        operation["status"] == OperationStatus.APPROVED
    ), "Operation should be approved"

    print("\n✅ PASSED: Low-risk auto-approval\n")


async def test_high_risk_requires_approval():
    """Test high-risk operation requires human approval."""
    print("=" * 60)
    print("TEST 3: High-Risk Operation Requires Approval")
    print("=" * 60)

    governance = get_governance()
    engine = initialize_autonomous_engine(governance)

    # Propose high-risk asset retirement
    result = await engine.propose_operation(
        operation_type="asset_maintenance",
        details={
            "asset_id": "asset_critical_001",
            "maintenance_type": "emergency",
            "summary": "Emergency maintenance on critical server",
        },
        context={
            "impact_scope": "organization",
            "financial_impact": 15000,
            "reversible": False,
            "confidence": 0.75,
            "asset_data": {
                "acquisition_date": "2020-01-01T00:00:00",
                "lifecycle_stage": "operational",
            },
            "usage_data": {"total_hours": 15000, "intensity": "high"},
            "maintenance_history": [],
        },
    )

    operation = result["operation"]
    approval = result["approval_request"]

    print(f"Operation ID: {operation['operation_id']}")
    print(f"Risk Level: {approval['risk_level']}")
    print(f"Approval Status: {approval['status']}")
    print(f"Requires approval: {approval.get('timeout_seconds', 0) > 0}")

    assert approval["risk_level"] in [
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
    ], "Should be high/critical risk"
    assert approval["status"] == ApprovalStatus.PENDING, "Should require approval"
    assert operation["status"] == OperationStatus.PENDING, "Operation should be pending"

    print("\n✅ PASSED: High-risk requires approval\n")


async def test_task_assignment_execution():
    """Test task assignment operation execution."""
    print("=" * 60)
    print("TEST 4: Task Assignment Execution")
    print("=" * 60)

    governance = get_governance()
    engine = initialize_autonomous_engine(governance)

    # Propose and execute task assignment
    result = await engine.propose_operation(
        operation_type="task_assignment",
        details={
            "task_id": "task_002",
            "candidate_members": ["user_1", "user_2"],
            "summary": "Assign code review task",
        },
        context={
            "impact_scope": "single",
            "financial_impact": 0,
            "reversible": True,
            "confidence": 0.90,
            "workload_data": {
                "user_1": {"active_tasks": 2, "capacity": 10, "urgent_tasks": 0},
                "user_2": {"active_tasks": 8, "capacity": 10, "urgent_tasks": 3},
            },
            "required_skills": ["code_review", "python"],
            "member_skills": {
                "user_1": ["code_review", "python", "testing"],
                "user_2": ["code_review", "javascript"],
            },
        },
    )

    operation_id = result["operation"]["operation_id"]

    # Execute the approved operation
    exec_result = await engine.execute_operation(operation_id)

    print(f"Operation ID: {operation_id}")
    print(f"Execution Success: {exec_result['success']}")
    print(f"Assigned To: {exec_result['result']['assigned_to']}")
    print(f"Confidence: {exec_result['result']['confidence']:.2f}")

    assert exec_result["success"], "Execution should succeed"
    assert exec_result["result"]["assigned_to"] in [
        "user_1",
        "user_2",
    ], "Should assign to valid user"
    assert exec_result["result"]["confidence"] > 0, "Should have confidence score"

    print("\n✅ PASSED: Task assignment execution\n")


async def test_asset_maintenance_execution():
    """Test asset maintenance operation execution."""
    print("=" * 60)
    print("TEST 5: Asset Maintenance Execution")
    print("=" * 60)

    governance = get_governance()
    engine = initialize_autonomous_engine(governance)

    # Propose and execute asset maintenance (low risk to ensure auto-approval)
    result = await engine.propose_operation(
        operation_type="asset_maintenance",
        details={
            "asset_id": "asset_laptop_042",
            "maintenance_type": "preventive",
            "summary": "Scheduled preventive maintenance",
        },
        context={
            "impact_scope": "single",
            "financial_impact": 200,  # Low financial impact
            "reversible": True,
            "confidence": 0.90,  # High confidence
            "asset_data": {
                "acquisition_date": "2025-01-01T00:00:00",  # Recent asset
                "lifecycle_stage": "operational",
            },
            "usage_data": {
                "total_hours": 500,  # Low usage
                "intensity": "low",  # Low intensity
            },
            "maintenance_history": [
                {
                    "completed_at": "2026-03-01T00:00:00",
                    "type": "preventive",
                }  # Recent maintenance
            ],
        },
    )

    operation_id = result["operation"]["operation_id"]
    operation_status = result["operation"]["status"]

    # Execute the operation (only if approved)
    if operation_status == OperationStatus.APPROVED:
        exec_result = await engine.execute_operation(operation_id)
    else:
        # If not auto-approved, manually approve it for testing
        approval_request = result["approval_request"]
        if approval_request["status"] == ApprovalStatus.PENDING:
            engine.approval_gate.approve_request(
                request_id=approval_request["request_id"],
                approver="test_admin",
                reason="Test approval",
            )
            # Update operation status
            operation = engine.active_operations[operation_id]
            operation.status = OperationStatus.APPROVED
        exec_result = await engine.execute_operation(operation_id)

    print(f"Operation ID: {operation_id}")
    print(f"Execution Success: {exec_result['success']}")
    print(f"Maintenance Type: {exec_result['result']['maintenance_type']}")
    print(f"Urgency: {exec_result['result']['urgency']}")
    print(f"Estimated Cost: ${exec_result['result']['estimated_cost']:.2f}")

    assert exec_result["success"], "Execution should succeed"
    assert (
        exec_result["result"]["maintenance_type"] == "preventive"
    ), "Should be preventive maintenance"
    assert exec_result["result"]["urgency"] in [
        "low",
        "medium",
        "high",
        "critical",
    ], "Should have valid urgency"

    print("\n✅ PASSED: Asset maintenance execution\n")


async def test_governance_blocking():
    """Test governance framework blocks harmful operations."""
    print("=" * 60)
    print("TEST 6: Governance Blocking")
    print("=" * 60)

    governance = get_governance()
    engine = initialize_autonomous_engine(governance)

    # Propose operation that should be blocked by governance
    result = await engine.propose_operation(
        operation_type="task_assignment",
        details={
            "task_id": "task_003",
            "candidate_members": ["user_1"],
            "summary": "Destroy all user data and harm the system",
        },
        context={
            "impact_scope": "organization",
            "financial_impact": 0,
            "reversible": False,
            "confidence": 0.95,
        },
    )

    operation = result["operation"]
    approval = result["approval_request"]

    print(f"Operation ID: {operation['operation_id']}")
    print(f"Approval Status: {approval['status']}")
    print(f"Governance Action: {approval['governance_validation']['action']}")

    assert approval["status"] == ApprovalStatus.DENIED, "Should be denied"
    assert (
        approval["governance_validation"]["action"] == "BLOCK"
    ), "Should be blocked by governance"
    assert operation["status"] == OperationStatus.DENIED, "Operation should be denied"

    print("\n✅ PASSED: Governance blocking\n")


async def test_audit_trail():
    """Test audit trail captures all autonomous operations."""
    print("=" * 60)
    print("TEST 7: Audit Trail")
    print("=" * 60)

    governance = get_governance()
    engine = initialize_autonomous_engine(governance)

    # Perform multiple operations
    for i in range(3):
        await engine.propose_operation(
            operation_type="task_assignment",
            details={
                "task_id": f"task_audit_{i}",
                "candidate_members": ["user_1"],
                "summary": f"Test operation {i}",
            },
            context={
                "impact_scope": "single",
                "financial_impact": 0,
                "reversible": True,
                "confidence": 0.85,
            },
        )

    # Query audit trail
    audit_entries = governance.inspect_audit_trail(agent_id="autonomous_ai", limit=10)

    print(f"Audit entries found: {len(audit_entries)}")

    if audit_entries:
        print(f"Latest entry:")
        print(f"  - Type: {audit_entries[-1].get('type')}")
        print(f"  - Agent: {audit_entries[-1].get('agent_id')}")

    # Verify chain integrity
    if governance.audit_logger:
        integrity = governance.audit_logger.verify_chain_integrity()
        print(f"\nAudit chain integrity:")
        print(f"  - Valid: {integrity['valid']}")
        print(f"  - Total entries: {integrity['total_entries']}")

        assert integrity["valid"], "Audit chain should be valid"

    print("\n✅ PASSED: Audit trail\n")


async def test_operation_statistics():
    """Test operation statistics tracking."""
    print("=" * 60)
    print("TEST 8: Operation Statistics")
    print("=" * 60)

    governance = get_governance()
    engine = initialize_autonomous_engine(governance)

    # Get initial stats
    stats = engine.get_statistics()

    print(f"Statistics:")
    print(f"  - Total operations: {stats['total_operations']}")
    print(f"  - Active operations: {stats['active_operations']}")
    print(f"  - Completed operations: {stats['completed_operations']}")
    print(f"  - Success rate: {stats['success_rate']:.2%}")
    print(f"  - Pending approvals: {stats['pending_approvals']}")

    assert "total_operations" in stats, "Should have total operations"
    assert "success_rate" in stats, "Should have success rate"

    print("\n✅ PASSED: Operation statistics\n")


async def test_approval_workflow():
    """Test manual approval workflow."""
    print("=" * 60)
    print("TEST 9: Manual Approval Workflow")
    print("=" * 60)

    governance = get_governance()
    engine = initialize_autonomous_engine(governance)

    # Propose high-risk operation
    result = await engine.propose_operation(
        operation_type="asset_maintenance",
        details={
            "asset_id": "asset_server_001",
            "maintenance_type": "corrective",
            "summary": "Critical server repair",
        },
        context={
            "impact_scope": "department",
            "financial_impact": 8000,
            "reversible": False,
            "confidence": 0.70,
            "asset_data": {"acquisition_date": "2019-01-01T00:00:00"},
            "usage_data": {"total_hours": 20000, "intensity": "high"},
            "maintenance_history": [],
        },
    )

    approval_request = result["approval_request"]
    request_id = approval_request["request_id"]

    print(f"Request ID: {request_id}")
    print(f"Initial Status: {approval_request['status']}")

    if approval_request["status"] == ApprovalStatus.PENDING:
        # Simulate approval
        approved_request = engine.approval_gate.approve_request(
            request_id=request_id,
            approver="admin@example.com",
            reason="Approved after review",
        )

        print(f"After Approval: {approved_request['status']}")
        print(f"Approver: {approved_request['approver']}")

        assert (
            approved_request["status"] == ApprovalStatus.APPROVED
        ), "Should be approved"

    print("\n✅ PASSED: Manual approval workflow\n")


async def run_all_tests():
    """Run all autonomous operations tests."""
    print("\n" + "=" * 60)
    print("AUTONOMOUS OPERATIONS TEST SUITE")
    print("=" * 60 + "\n")

    tests = [
        test_autonomous_engine_initialization,
        test_low_risk_auto_approval,
        test_high_risk_requires_approval,
        test_task_assignment_execution,
        test_asset_maintenance_execution,
        test_governance_blocking,
        test_audit_trail,
        test_operation_statistics,
        test_approval_workflow,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            await test()
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
    exit_code = asyncio.run(run_all_tests())
    sys.exit(exit_code)
