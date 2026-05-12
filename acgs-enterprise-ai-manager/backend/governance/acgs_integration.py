"""
ACGS-Lite Governance Framework Integration
Enterprise AI Agent Constitutional Governance

This module provides the main integration point for the acgs-lite governance framework,
implementing the MACI pattern (Monitor-Approve-Control-Inspect) for AI agent operations.
"""

import os
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
from backend.utils.timeutil import utcnow
from pathlib import Path

try:
    from acgs_lite import Constitution, GovernanceEngine

    ACGS_AVAILABLE = True
except ImportError:
    ACGS_AVAILABLE = False
    logging.warning("acgs-lite not installed. Install with: pip install acgs-lite")

from .rules_engine import RulesEngine
from .audit_logger import AuditLogger

logger = logging.getLogger(__name__)


class ACGSIntegration:
    """
    Main integration class for ACGS-Lite governance framework.

    Implements fail-closed enforcement with tamper-evident audit trails.
    All AI operations must pass governance validation before execution.
    """

    def __init__(
        self,
        constitution_path: Optional[str] = None,
        fail_closed: bool = True,
        audit_enabled: bool = True,
    ):
        """
        Initialize ACGS governance integration.

        Args:
            constitution_path: Path to YAML constitution file
            fail_closed: If True, block operations on validation failure (default: True)
            audit_enabled: If True, enable tamper-evident audit logging (default: True)
        """
        self.fail_closed = fail_closed
        self.audit_enabled = audit_enabled

        # Set default constitution path
        if constitution_path is None:
            constitution_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                "config",
                "governance_rules.yaml",
            )

        self.constitution_path = constitution_path

        # Initialize components
        self.rules_engine = RulesEngine(constitution_path)
        self.audit_logger = AuditLogger() if audit_enabled else None

        # Initialize acgs-lite engine if available
        self.acgs_engine = None
        if ACGS_AVAILABLE:
            self._initialize_acgs_engine()
        else:
            logger.warning("Running in fallback mode without acgs-lite")

    def _initialize_acgs_engine(self):
        """Initialize the acgs-lite governance engine."""
        try:
            if not os.path.exists(self.constitution_path):
                logger.error(f"Constitution file not found: {self.constitution_path}")
                return

            # Load constitution from YAML file (pass path, not content)
            constitution = Constitution.from_yaml(self.constitution_path)
            self.acgs_engine = GovernanceEngine(constitution)

            logger.info(
                f"ACGS governance engine initialized with constitution: {self.constitution_path}"
            )
        except Exception as e:
            logger.error(f"Failed to initialize ACGS engine: {e}")
            self.acgs_engine = None

    def validate_operation(
        self, operation: str, context: Dict[str, Any], agent_id: str = "default"
    ) -> Dict[str, Any]:
        """
        Validate an AI operation against governance rules (MACI: Monitor phase).

        Args:
            operation: Description of the operation to validate
            context: Additional context for validation
            agent_id: Identifier for the AI agent

        Returns:
            Dict containing validation result with keys:
                - valid: bool
                - action: str (ALLOW, BLOCK, REQUIRE_APPROVAL)
                - violations: List[Dict]
                - decision_id: str
        """
        start_time = utcnow()

        # Validate using rules engine
        validation_result = self.rules_engine.validate(operation, context)

        # If acgs-lite is available, use it for additional validation
        if self.acgs_engine:
            try:
                acgs_result = self.acgs_engine.validate(operation, agent_id=agent_id)
                # Merge results (fail-closed: if either fails, operation is blocked)
                if not acgs_result.valid:
                    validation_result["valid"] = False
                    validation_result["violations"].extend(
                        [
                            {
                                "rule_id": v.rule_id,
                                "severity": v.severity,
                                "description": v.description,
                            }
                            for v in acgs_result.violations
                        ]
                    )
            except Exception as e:
                logger.error(f"ACGS validation error: {e}")
                if self.fail_closed:
                    validation_result["valid"] = False
                    validation_result["violations"].append(
                        {
                            "rule_id": "system-error",
                            "severity": "CRITICAL",
                            "description": f"Governance validation error: {str(e)}",
                        }
                    )

        # Determine action based on validation
        if not validation_result["valid"]:
            action = "BLOCK" if self.fail_closed else "WARN"
        elif validation_result.get("requires_approval", False):
            action = "REQUIRE_APPROVAL"
        else:
            action = "ALLOW"

        validation_result["action"] = action

        # Log to audit trail
        if self.audit_logger:
            decision_id = self.audit_logger.log_decision(
                operation=operation,
                context=context,
                validation_result=validation_result,
                agent_id=agent_id,
                duration_ms=(utcnow() - start_time).total_seconds() * 1000,
            )
            validation_result["decision_id"] = decision_id

        return validation_result

    def request_approval(
        self,
        operation: str,
        context: Dict[str, Any],
        agent_id: str = "default",
        timeout_seconds: int = 3600,
    ) -> Dict[str, Any]:
        """
        Request human approval for an operation (MACI: Approve phase).

        Args:
            operation: Description of the operation requiring approval
            context: Additional context for approval decision
            agent_id: Identifier for the AI agent
            timeout_seconds: Approval timeout in seconds

        Returns:
            Dict containing approval request details
        """
        approval_request = {
            "request_id": self._generate_request_id(),
            "operation": operation,
            "context": context,
            "agent_id": agent_id,
            "requested_at": utcnow().isoformat(),
            "timeout_seconds": timeout_seconds,
            "status": "PENDING",
        }

        if self.audit_logger:
            self.audit_logger.log_approval_request(approval_request)

        logger.info(f"Approval requested: {approval_request['request_id']}")

        return approval_request

    def enforce_decision(
        self, validation_result: Dict[str, Any], operation: str
    ) -> bool:
        """
        Enforce governance decision (MACI: Control phase).

        Args:
            validation_result: Result from validate_operation
            operation: The operation to enforce

        Returns:
            True if operation is allowed to proceed, False otherwise
        """
        action = validation_result.get("action", "BLOCK")

        if action == "ALLOW":
            logger.info(f"Operation allowed: {operation[:100]}")
            return True
        elif action == "BLOCK":
            logger.warning(f"Operation blocked: {operation[:100]}")
            if self.audit_logger:
                self.audit_logger.log_enforcement(
                    operation=operation,
                    action="BLOCKED",
                    reason=validation_result.get("violations", []),
                )
            return False
        elif action == "REQUIRE_APPROVAL":
            logger.info(f"Operation requires approval: {operation[:100]}")
            # In production, this would integrate with approval workflow
            return False
        else:
            # Unknown action - fail closed
            logger.error(f"Unknown action: {action}. Failing closed.")
            return False

    def inspect_audit_trail(
        self,
        agent_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Inspect audit trail (MACI: Inspect phase).

        Args:
            agent_id: Filter by agent ID
            start_time: Filter by start time
            end_time: Filter by end time
            limit: Maximum number of records to return

        Returns:
            List of audit records
        """
        if not self.audit_logger:
            logger.warning("Audit logging not enabled")
            return []

        return self.audit_logger.query_audit_trail(
            agent_id=agent_id, start_time=start_time, end_time=end_time, limit=limit
        )

    def get_governance_status(self) -> Dict[str, Any]:
        """
        Get current governance framework status.

        Returns:
            Dict containing status information
        """
        return {
            "acgs_available": ACGS_AVAILABLE,
            "acgs_engine_initialized": self.acgs_engine is not None,
            "fail_closed": self.fail_closed,
            "audit_enabled": self.audit_enabled,
            "constitution_path": self.constitution_path,
            "rules_count": len(self.rules_engine.rules) if self.rules_engine else 0,
        }

    @staticmethod
    def _generate_request_id() -> str:
        """Generate unique request ID."""
        import uuid

        return f"req_{uuid.uuid4().hex[:16]}"


# Singleton instance for application-wide use
_governance_instance: Optional[ACGSIntegration] = None


def get_governance() -> ACGSIntegration:
    """Get or create the global governance instance."""
    global _governance_instance
    if _governance_instance is None:
        _governance_instance = ACGSIntegration()
    return _governance_instance


def initialize_governance(
    constitution_path: Optional[str] = None,
    fail_closed: bool = True,
    audit_enabled: bool = True,
) -> ACGSIntegration:
    """
    Initialize the global governance instance.

    Args:
        constitution_path: Path to YAML constitution file
        fail_closed: If True, block operations on validation failure
        audit_enabled: If True, enable tamper-evident audit logging

    Returns:
        Initialized ACGSIntegration instance
    """
    global _governance_instance
    _governance_instance = ACGSIntegration(
        constitution_path=constitution_path,
        fail_closed=fail_closed,
        audit_enabled=audit_enabled,
    )
    return _governance_instance
