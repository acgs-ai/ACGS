"""
Approval Gates for AI Autonomous Operations
Integrates with ACGS-Lite governance framework to enforce risk-based approval workflows
"""

from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from backend.utils.timeutil import utcnow
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    """Risk levels for autonomous operations"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalStatus(str, Enum):
    """Approval request status"""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    AUTO_APPROVED = "auto_approved"


class ApprovalGate:
    """
    Governance gate for autonomous operations.

    Enforces risk-based approval requirements:
    - LOW risk: Auto-approve with audit
    - MEDIUM risk: Auto-approve with notification
    - HIGH risk: Require human approval
    - CRITICAL risk: Require multi-level approval
    """

    def __init__(self, governance_integration):
        """
        Initialize approval gate.

        Args:
            governance_integration: ACGSIntegration instance
        """
        self.governance = governance_integration
        self.pending_approvals: Dict[str, Dict[str, Any]] = {}
        logger.info("Approval gate initialized")

    def assess_risk(self, operation_type: str, context: Dict[str, Any]) -> RiskLevel:
        """
        Assess risk level of an autonomous operation.

        Args:
            operation_type: Type of operation (e.g., "task_assignment", "asset_maintenance")
            context: Operation context with relevant data

        Returns:
            RiskLevel enum value
        """
        # Risk assessment logic
        risk_score = 0.0

        # Factor 1: Operation type base risk
        operation_risks = {
            "task_assignment": 0.2,
            "task_reassignment": 0.3,
            "asset_maintenance_schedule": 0.4,
            "asset_retirement": 0.8,
            "budget_allocation": 0.7,
            "infrastructure_scaling": 0.6,
            "data_deletion": 0.9,
            "access_grant": 0.7,
        }
        risk_score += operation_risks.get(operation_type, 0.5)

        # Factor 2: Impact scope
        impact_scope = context.get("impact_scope", "single")
        if impact_scope == "team":
            risk_score += 0.2
        elif impact_scope == "department":
            risk_score += 0.3
        elif impact_scope == "organization":
            risk_score += 0.4

        # Factor 3: Financial impact
        financial_impact = context.get("financial_impact", 0)
        if financial_impact > 10000:
            risk_score += 0.3
        elif financial_impact > 5000:
            risk_score += 0.2
        elif financial_impact > 1000:
            risk_score += 0.1

        # Factor 4: Reversibility
        if not context.get("reversible", True):
            risk_score += 0.2

        # Factor 5: AI confidence
        confidence = context.get("confidence", 0.5)
        if confidence < 0.7:
            risk_score += 0.2
        elif confidence < 0.8:
            risk_score += 0.1

        # Determine risk level
        if risk_score >= 0.8:
            return RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            return RiskLevel.HIGH
        elif risk_score >= 0.4:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    async def request_approval(
        self,
        operation_type: str,
        operation_details: Dict[str, Any],
        context: Dict[str, Any],
        agent_id: str = "autonomous_ai",
    ) -> Dict[str, Any]:
        """
        Request approval for an autonomous operation.

        Args:
            operation_type: Type of operation
            operation_details: Details of the operation to be performed
            context: Additional context for risk assessment
            agent_id: AI agent identifier

        Returns:
            Dict containing approval request details and decision
        """
        # Assess risk level
        risk_level = self.assess_risk(operation_type, context)

        # Validate with governance framework
        operation_description = (
            f"Autonomous {operation_type}: {operation_details.get('summary', 'N/A')}"
        )

        governance_result = self.governance.validate_operation(
            operation=operation_description,
            context={
                **context,
                "operation_type": operation_type,
                "risk_level": risk_level,
                "autonomous": True,
            },
            agent_id=agent_id,
        )

        # Create approval request
        request_id = self._generate_request_id()
        approval_request = {
            "request_id": request_id,
            "operation_type": operation_type,
            "operation_details": operation_details,
            "risk_level": risk_level,
            "context": context,
            "agent_id": agent_id,
            "requested_at": utcnow().isoformat(),
            "governance_validation": governance_result,
            "status": ApprovalStatus.PENDING,
        }

        # Determine approval strategy based on risk level and governance
        if governance_result["action"] == "BLOCK":
            approval_request["status"] = ApprovalStatus.DENIED
            approval_request["denial_reason"] = governance_result.get("violations", [])
            logger.warning(f"Operation blocked by governance: {request_id}")

        elif risk_level == RiskLevel.LOW:
            # Auto-approve low-risk operations
            approval_request["status"] = ApprovalStatus.AUTO_APPROVED
            approval_request["approved_at"] = utcnow().isoformat()
            approval_request["approver"] = "system_auto"
            logger.info(f"Auto-approved low-risk operation: {request_id}")

        elif risk_level == RiskLevel.MEDIUM and governance_result["action"] == "ALLOW":
            # Auto-approve medium-risk if governance allows
            approval_request["status"] = ApprovalStatus.AUTO_APPROVED
            approval_request["approved_at"] = utcnow().isoformat()
            approval_request["approver"] = "system_auto"
            approval_request["notification_sent"] = True
            logger.info(
                f"Auto-approved medium-risk operation with notification: {request_id}"
            )

        else:
            # Require human approval for high/critical risk
            approval_request["timeout_seconds"] = (
                3600 if risk_level == RiskLevel.HIGH else 7200
            )
            approval_request["requires_multi_level"] = risk_level == RiskLevel.CRITICAL
            self.pending_approvals[request_id] = approval_request

            # Request approval through governance framework
            governance_approval = self.governance.request_approval(
                operation=operation_description,
                context=context,
                agent_id=agent_id,
                timeout_seconds=approval_request["timeout_seconds"],
            )
            approval_request["governance_request_id"] = governance_approval[
                "request_id"
            ]

            logger.info(
                f"Human approval required for {risk_level} risk operation: {request_id}"
            )

        # Log to audit trail
        if self.governance.audit_logger:
            self.governance.audit_logger.log_decision(
                operation=operation_description,
                context=context,
                validation_result={
                    "valid": approval_request["status"]
                    in [ApprovalStatus.APPROVED, ApprovalStatus.AUTO_APPROVED],
                    "action": approval_request["status"],
                    "risk_level": risk_level,
                },
                agent_id=agent_id,
                duration_ms=0,
            )

        return approval_request

    def check_approval_status(self, request_id: str) -> Optional[Dict[str, Any]]:
        """
        Check status of a pending approval request.

        Args:
            request_id: Approval request ID

        Returns:
            Approval request dict or None if not found
        """
        return self.pending_approvals.get(request_id)

    def approve_request(
        self, request_id: str, approver: str, reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Approve a pending request.

        Args:
            request_id: Request ID to approve
            approver: Identifier of approver
            reason: Optional approval reason

        Returns:
            Updated approval request
        """
        if request_id not in self.pending_approvals:
            raise ValueError(f"Request not found: {request_id}")

        request = self.pending_approvals[request_id]
        request["status"] = ApprovalStatus.APPROVED
        request["approved_at"] = utcnow().isoformat()
        request["approver"] = approver
        request["approval_reason"] = reason

        # Log approval to audit trail
        if self.governance.audit_logger:
            self.governance.audit_logger.log_approval_response(
                request_id=request_id, approved=True, approver=approver, reason=reason
            )

        logger.info(f"Request approved: {request_id} by {approver}")
        return request

    def deny_request(
        self, request_id: str, approver: str, reason: str
    ) -> Dict[str, Any]:
        """
        Deny a pending request.

        Args:
            request_id: Request ID to deny
            approver: Identifier of approver
            reason: Denial reason

        Returns:
            Updated approval request
        """
        if request_id not in self.pending_approvals:
            raise ValueError(f"Request not found: {request_id}")

        request = self.pending_approvals[request_id]
        request["status"] = ApprovalStatus.DENIED
        request["denied_at"] = utcnow().isoformat()
        request["approver"] = approver
        request["denial_reason"] = reason

        # Log denial to audit trail
        if self.governance.audit_logger:
            self.governance.audit_logger.log_approval_response(
                request_id=request_id, approved=False, approver=approver, reason=reason
            )

        logger.info(f"Request denied: {request_id} by {approver}")
        return request

    def cleanup_expired_requests(self) -> int:
        """
        Clean up expired approval requests.

        Returns:
            Number of requests cleaned up
        """
        now = utcnow()
        expired_requests = []

        for request_id, request in self.pending_approvals.items():
            if request["status"] != ApprovalStatus.PENDING:
                continue

            requested_at = datetime.fromisoformat(request["requested_at"])
            timeout_seconds = request.get("timeout_seconds", 3600)

            if (now - requested_at).total_seconds() > timeout_seconds:
                request["status"] = ApprovalStatus.EXPIRED
                request["expired_at"] = now.isoformat()
                expired_requests.append(request_id)

        for request_id in expired_requests:
            logger.warning(f"Request expired: {request_id}")

        return len(expired_requests)

    def get_pending_approvals(
        self, risk_level: Optional[RiskLevel] = None
    ) -> List[Dict[str, Any]]:
        """
        Get list of pending approval requests.

        Args:
            risk_level: Optional filter by risk level

        Returns:
            List of pending approval requests
        """
        pending = [
            req
            for req in self.pending_approvals.values()
            if req["status"] == ApprovalStatus.PENDING
        ]

        if risk_level:
            pending = [req for req in pending if req["risk_level"] == risk_level]

        return pending

    @staticmethod
    def _generate_request_id() -> str:
        """Generate unique request ID."""
        import uuid

        return f"auto_req_{uuid.uuid4().hex[:16]}"
