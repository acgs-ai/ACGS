"""
Autonomous Operations System for ACGS Enterprise Manager
Provides AI-driven autonomous operations with governance gates
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from backend.utils.timeutil import utcnow
from enum import Enum
import logging
import asyncio

from ..governance.approval_gates import ApprovalGate, ApprovalStatus, RiskLevel

logger = logging.getLogger(__name__)


class OperationStatus(str, Enum):
    """Status of autonomous operation"""

    PENDING = "pending"
    APPROVED = "approved"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    DENIED = "denied"


class AutonomousOperation:
    """Base class for autonomous operations"""

    def __init__(
        self,
        operation_id: str,
        operation_type: str,
        details: Dict[str, Any],
        context: Dict[str, Any],
    ):
        self.operation_id = operation_id
        self.operation_type = operation_type
        self.details = details
        self.context = context
        self.status = OperationStatus.PENDING
        self.created_at = utcnow()
        self.executed_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
        # Link back to the approval request that gates this operation.
        # Populated by AutonomousOperationsEngine.propose_operation and used by
        # AutonomousOperationsEngine.approve_operation to transition the
        # operation status atomically with the approval request.
        self.approval_request_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert operation to dictionary"""
        return {
            "operation_id": self.operation_id,
            "operation_type": self.operation_type,
            "details": self.details,
            "context": self.context,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "completed_at": (
                self.completed_at.isoformat() if self.completed_at else None
            ),
            "result": self.result,
            "error": self.error,
            "approval_request_id": self.approval_request_id,
        }


class AutonomousOperationsEngine:
    """
    Main engine for autonomous AI operations.

    Coordinates autonomous operations across domains with governance gates,
    risk assessment, and audit trails.
    """

    def __init__(self, governance_integration, recommendation_engine=None):
        """
        Initialize autonomous operations engine.

        Args:
            governance_integration: ACGSIntegration instance
            recommendation_engine: Optional RecommendationEngine instance
        """
        self.governance = governance_integration
        self.recommendation_engine = recommendation_engine
        self.approval_gate = ApprovalGate(governance_integration)

        # Operation handlers registry
        self.operation_handlers: Dict[str, Any] = {}
        self._register_handlers()

        # Active operations tracking
        self.active_operations: Dict[str, AutonomousOperation] = {}
        self.operation_history: List[AutonomousOperation] = []

        logger.info("Autonomous operations engine initialized")

    def _register_handlers(self):
        """Register operation handlers"""
        from .operations.task_assignment import TaskAssignmentHandler
        from .operations.asset_maintenance import AssetMaintenanceHandler

        self.operation_handlers["task_assignment"] = TaskAssignmentHandler()
        self.operation_handlers["asset_maintenance"] = AssetMaintenanceHandler()

        logger.info(f"Registered {len(self.operation_handlers)} operation handlers")

    async def propose_operation(
        self,
        operation_type: str,
        details: Dict[str, Any],
        context: Dict[str, Any],
        agent_id: str = "autonomous_ai",
    ) -> Dict[str, Any]:
        """
        Propose an autonomous operation for approval.

        Args:
            operation_type: Type of operation to perform
            details: Operation details
            context: Additional context for risk assessment
            agent_id: AI agent identifier

        Returns:
            Dict containing operation proposal and approval status
        """
        if operation_type not in self.operation_handlers:
            raise ValueError(f"Unknown operation type: {operation_type}")

        # Generate operation ID
        operation_id = self._generate_operation_id()

        # Create operation
        operation = AutonomousOperation(
            operation_id=operation_id,
            operation_type=operation_type,
            details=details,
            context=context,
        )

        # Request approval through governance gate
        approval_request = await self.approval_gate.request_approval(
            operation_type=operation_type,
            operation_details=details,
            context=context,
            agent_id=agent_id,
        )

        # Bind the approval request to the operation so a later manual approve
        # can atomically transition both objects (see approve_operation).
        operation.approval_request_id = approval_request.get("request_id")

        # Update operation status based on approval
        if approval_request["status"] == ApprovalStatus.AUTO_APPROVED:
            operation.status = OperationStatus.APPROVED
            logger.info(f"Operation auto-approved: {operation_id}")
        elif approval_request["status"] == ApprovalStatus.DENIED:
            operation.status = OperationStatus.DENIED
            operation.error = str(
                approval_request.get("denial_reason", "Denied by governance")
            )
            logger.warning(f"Operation denied: {operation_id}")
        elif approval_request["status"] == ApprovalStatus.PENDING:
            operation.status = OperationStatus.PENDING
            logger.info(f"Operation pending approval: {operation_id}")

        # Store operation
        self.active_operations[operation_id] = operation

        return {"operation": operation.to_dict(), "approval_request": approval_request}

    def approve_operation(
        self,
        operation_id: str,
        approver: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Approve a pending operation through the public approval path.

        Looks up the operation, calls the governance approval gate using the
        request_id stored on the operation, and transitions the operation to
        APPROVED in the same call. This is the canonical "human approves
        what the engine queued" entry point; tests and callers must not poke
        operation.status directly.

        Raises ValueError when the operation is unknown, missing its approval
        request linkage, or already past the PENDING state.
        """
        if operation_id not in self.active_operations:
            raise ValueError(f"Operation not found: {operation_id}")

        operation = self.active_operations[operation_id]

        if operation.status != OperationStatus.PENDING:
            raise ValueError(
                f"Operation cannot be approved from status {operation.status}: "
                f"{operation_id}"
            )

        if not operation.approval_request_id:
            raise ValueError(
                f"Operation {operation_id} has no linked approval request; "
                "cannot resolve approval."
            )

        approval = self.approval_gate.approve_request(
            operation.approval_request_id,
            approver=approver,
            reason=reason,
        )
        operation.status = OperationStatus.APPROVED
        logger.info(
            f"Operation approved via gate: {operation_id} by {approver}"
        )
        return {"operation": operation.to_dict(), "approval_request": approval}

    def deny_operation(
        self,
        operation_id: str,
        approver: str,
        reason: str,
    ) -> Dict[str, Any]:
        """
        Deny a pending operation through the public approval path.

        Mirrors approve_operation: flips both the gate request and the
        operation to DENIED in the same call.
        """
        if operation_id not in self.active_operations:
            raise ValueError(f"Operation not found: {operation_id}")

        operation = self.active_operations[operation_id]

        if operation.status != OperationStatus.PENDING:
            raise ValueError(
                f"Operation cannot be denied from status {operation.status}: "
                f"{operation_id}"
            )

        if not operation.approval_request_id:
            raise ValueError(
                f"Operation {operation_id} has no linked approval request; "
                "cannot resolve denial."
            )

        approval = self.approval_gate.deny_request(
            operation.approval_request_id,
            approver=approver,
            reason=reason,
        )
        operation.status = OperationStatus.DENIED
        operation.error = reason
        logger.info(f"Operation denied via gate: {operation_id} by {approver}")
        return {"operation": operation.to_dict(), "approval_request": approval}

    async def execute_operation(
        self, operation_id: str, force: bool = False
    ) -> Dict[str, Any]:
        """
        Execute an approved autonomous operation.

        Args:
            operation_id: ID of operation to execute
            force: If True, skip approval check (use with caution)

        Returns:
            Dict containing execution result
        """
        if operation_id not in self.active_operations:
            raise ValueError(f"Operation not found: {operation_id}")

        operation = self.active_operations[operation_id]

        # Check approval status
        if not force and operation.status != OperationStatus.APPROVED:
            raise ValueError(
                f"Operation not approved: {operation_id} (status: {operation.status})"
            )

        # Update status
        operation.status = OperationStatus.EXECUTING
        operation.executed_at = utcnow()

        try:
            # Get handler
            handler = self.operation_handlers[operation.operation_type]

            # Execute operation
            logger.info(
                f"Executing operation: {operation_id} ({operation.operation_type})"
            )
            result = await handler.execute(operation.details, operation.context)

            # Update operation
            operation.status = OperationStatus.COMPLETED
            operation.completed_at = utcnow()
            operation.result = result

            # Log to audit trail
            if self.governance.audit_logger:
                self.governance.audit_logger.log_enforcement(
                    operation=f"Autonomous {operation.operation_type}",
                    action="EXECUTED",
                    reason=f"Operation {operation_id} completed successfully",
                )

            logger.info(f"Operation completed: {operation_id}")

            # Move to history
            self.operation_history.append(operation)
            del self.active_operations[operation_id]

            return {"success": True, "operation": operation.to_dict(), "result": result}

        except Exception as e:
            # Handle execution failure
            operation.status = OperationStatus.FAILED
            operation.completed_at = utcnow()
            operation.error = str(e)

            logger.error(f"Operation failed: {operation_id} - {e}")

            # Log failure to audit trail
            if self.governance.audit_logger:
                self.governance.audit_logger.log_enforcement(
                    operation=f"Autonomous {operation.operation_type}",
                    action="FAILED",
                    reason=f"Operation {operation_id} failed: {str(e)}",
                )

            return {"success": False, "operation": operation.to_dict(), "error": str(e)}

    async def execute_approved_operations(self) -> List[Dict[str, Any]]:
        """
        Execute all approved operations in queue.

        Returns:
            List of execution results
        """
        approved_ops = [
            op_id
            for op_id, op in self.active_operations.items()
            if op.status == OperationStatus.APPROVED
        ]

        results = []
        for op_id in approved_ops:
            try:
                result = await self.execute_operation(op_id)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to execute operation {op_id}: {e}")
                results.append(
                    {"success": False, "operation_id": op_id, "error": str(e)}
                )

        return results

    def get_operation_status(self, operation_id: str) -> Optional[Dict[str, Any]]:
        """
        Get status of an operation.

        Args:
            operation_id: Operation ID

        Returns:
            Operation dict or None if not found
        """
        if operation_id in self.active_operations:
            return self.active_operations[operation_id].to_dict()

        # Check history
        for op in self.operation_history:
            if op.operation_id == operation_id:
                return op.to_dict()

        return None

    def get_active_operations(
        self,
        operation_type: Optional[str] = None,
        status: Optional[OperationStatus] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get list of active operations.

        Args:
            operation_type: Optional filter by operation type
            status: Optional filter by status

        Returns:
            List of operation dicts
        """
        operations = list(self.active_operations.values())

        if operation_type:
            operations = [
                op for op in operations if op.operation_type == operation_type
            ]

        if status:
            operations = [op for op in operations if op.status == status]

        return [op.to_dict() for op in operations]

    def get_operation_history(
        self, limit: int = 100, operation_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get operation history.

        Args:
            limit: Maximum number of operations to return
            operation_type: Optional filter by operation type

        Returns:
            List of historical operation dicts
        """
        history = self.operation_history[-limit:]

        if operation_type:
            history = [op for op in history if op.operation_type == operation_type]

        return [op.to_dict() for op in history]

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get autonomous operations statistics.

        Returns:
            Dict containing statistics
        """
        total_operations = len(self.operation_history) + len(self.active_operations)

        completed = len(
            [
                op
                for op in self.operation_history
                if op.status == OperationStatus.COMPLETED
            ]
        )
        failed = len(
            [op for op in self.operation_history if op.status == OperationStatus.FAILED]
        )
        denied = len(
            [op for op in self.operation_history if op.status == OperationStatus.DENIED]
        )

        active_by_status = {}
        for op in self.active_operations.values():
            active_by_status[op.status] = active_by_status.get(op.status, 0) + 1

        return {
            "total_operations": total_operations,
            "active_operations": len(self.active_operations),
            "completed_operations": completed,
            "failed_operations": failed,
            "denied_operations": denied,
            "success_rate": completed / total_operations if total_operations > 0 else 0,
            "active_by_status": active_by_status,
            "pending_approvals": len(self.approval_gate.get_pending_approvals()),
        }

    @staticmethod
    def _generate_operation_id() -> str:
        """Generate unique operation ID"""
        import uuid

        return f"auto_op_{uuid.uuid4().hex[:16]}"


# Singleton instance
_autonomous_engine: Optional[AutonomousOperationsEngine] = None


def get_autonomous_engine() -> AutonomousOperationsEngine:
    """Get or create the global autonomous operations engine"""
    global _autonomous_engine
    if _autonomous_engine is None:
        from ..governance import get_governance

        _autonomous_engine = AutonomousOperationsEngine(get_governance())
    return _autonomous_engine


def initialize_autonomous_engine(
    governance_integration, recommendation_engine=None
) -> AutonomousOperationsEngine:
    """
    Initialize the global autonomous operations engine.

    Args:
        governance_integration: ACGSIntegration instance
        recommendation_engine: Optional RecommendationEngine instance

    Returns:
        Initialized AutonomousOperationsEngine instance
    """
    global _autonomous_engine
    _autonomous_engine = AutonomousOperationsEngine(
        governance_integration=governance_integration,
        recommendation_engine=recommendation_engine,
    )
    return _autonomous_engine
