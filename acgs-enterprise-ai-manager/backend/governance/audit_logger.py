"""
Tamper-Evident Audit Logger
Implements cryptographic audit trails for governance decisions.
"""

import json
import logging
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime
from backend.utils.timeutil import utcnow
from pathlib import Path
import os

logger = logging.getLogger(__name__)


class AuditLogger:
    """
    Tamper-evident audit logger for governance framework.

    Implements cryptographic chaining to ensure audit trail integrity.
    Each audit entry includes a hash of the previous entry, creating
    an immutable chain of evidence.
    """

    def __init__(self, audit_dir: Optional[str] = None):
        """
        Initialize audit logger.

        Args:
            audit_dir: Directory for audit logs (default: backend/governance/audit_logs)
        """
        if audit_dir is None:
            audit_dir = os.getenv(
                "ACGS_AUDIT_DIR", os.path.join(os.path.dirname(__file__), "audit_logs")
            )

        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)

        self.current_log_file = self._get_current_log_file()
        self.last_hash = self._get_last_hash()

        logger.info(f"Audit logger initialized: {self.audit_dir}")

    def _get_current_log_file(self) -> Path:
        """Get current audit log file path (one per day)."""
        date_str = utcnow().strftime("%Y-%m-%d")
        return self.audit_dir / f"audit_{date_str}.jsonl"

    def _get_last_hash(self) -> str:
        """Get hash of last audit entry for chain integrity."""
        if not self.current_log_file.exists():
            return "GENESIS"

        try:
            with open(self.current_log_file, "r") as f:
                lines = f.readlines()
                if lines:
                    last_entry = json.loads(lines[-1])
                    return last_entry.get("entry_hash", "GENESIS")
        except Exception as e:
            logger.error(f"Error reading last hash: {e}")

        return "GENESIS"

    def _compute_entry_hash(self, entry: Dict[str, Any]) -> str:
        """
        Compute cryptographic hash of audit entry.

        Args:
            entry: Audit entry dict

        Returns:
            SHA-256 hash hex string
        """
        # Create deterministic JSON string
        entry_copy = entry.copy()
        entry_copy.pop("entry_hash", None)  # Remove hash field if present

        entry_json = json.dumps(entry_copy, sort_keys=True)
        return hashlib.sha256(entry_json.encode()).hexdigest()

    def _write_audit_entry(self, entry: Dict[str, Any]) -> str:
        """
        Write audit entry to log file with cryptographic chaining.

        Args:
            entry: Audit entry to write

        Returns:
            Entry hash
        """
        # Add chain metadata
        entry["previous_hash"] = self.last_hash
        entry["entry_hash"] = self._compute_entry_hash(entry)

        # Write to log file (append mode)
        try:
            with open(self.current_log_file, "a") as f:
                f.write(json.dumps(entry) + "\n")

            # Update last hash for next entry
            self.last_hash = entry["entry_hash"]

            return entry["entry_hash"]

        except Exception as e:
            logger.error(f"Failed to write audit entry: {e}")
            raise

    def log_decision(
        self,
        operation: str,
        context: Dict[str, Any],
        validation_result: Dict[str, Any],
        agent_id: str,
        duration_ms: float,
    ) -> str:
        """
        Log a governance decision to audit trail.

        Args:
            operation: Operation that was validated
            context: Operation context
            validation_result: Validation result
            agent_id: AI agent identifier
            duration_ms: Validation duration in milliseconds

        Returns:
            Decision ID (entry hash)
        """
        entry = {
            "type": "DECISION",
            "timestamp": utcnow().isoformat(),
            "agent_id": agent_id,
            "operation": operation[:500],  # Truncate for storage
            "context": self._sanitize_context(context),
            "validation_result": {
                "valid": validation_result.get("valid"),
                "action": validation_result.get("action"),
                "violations": validation_result.get("violations", []),
                "matched_rules": validation_result.get("matched_rules", []),
            },
            "duration_ms": duration_ms,
        }

        decision_id = self._write_audit_entry(entry)
        logger.info(f"Logged decision: {decision_id[:16]}")

        return decision_id

    def log_approval_request(self, approval_request: Dict[str, Any]) -> str:
        """
        Log an approval request to audit trail.

        Args:
            approval_request: Approval request details

        Returns:
            Entry hash
        """
        entry = {
            "type": "APPROVAL_REQUEST",
            "timestamp": utcnow().isoformat(),
            "request_id": approval_request["request_id"],
            "agent_id": approval_request["agent_id"],
            "operation": approval_request["operation"][:500],
            "context": self._sanitize_context(approval_request.get("context", {})),
            "timeout_seconds": approval_request["timeout_seconds"],
            "status": approval_request["status"],
        }

        entry_hash = self._write_audit_entry(entry)
        logger.info(f"Logged approval request: {approval_request['request_id']}")

        return entry_hash

    def log_approval_response(
        self,
        request_id: str,
        approved: bool,
        approver: str,
        reason: Optional[str] = None,
    ) -> str:
        """
        Log an approval response to audit trail.

        Args:
            request_id: Original approval request ID
            approved: Whether request was approved
            approver: Identifier of approver
            reason: Optional reason for decision

        Returns:
            Entry hash
        """
        entry = {
            "type": "APPROVAL_RESPONSE",
            "timestamp": utcnow().isoformat(),
            "request_id": request_id,
            "approved": approved,
            "approver": approver,
            "reason": reason,
        }

        entry_hash = self._write_audit_entry(entry)
        logger.info(
            f"Logged approval response: {request_id} - {'APPROVED' if approved else 'DENIED'}"
        )

        return entry_hash

    def log_enforcement(self, operation: str, action: str, reason: Any) -> str:
        """
        Log enforcement action to audit trail.

        Args:
            operation: Operation that was enforced
            action: Enforcement action taken
            reason: Reason for enforcement

        Returns:
            Entry hash
        """
        entry = {
            "type": "ENFORCEMENT",
            "timestamp": utcnow().isoformat(),
            "operation": operation[:500],
            "action": action,
            "reason": str(reason)[:1000],
        }

        entry_hash = self._write_audit_entry(entry)
        logger.info(f"Logged enforcement: {action}")

        return entry_hash

    def query_audit_trail(
        self,
        agent_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        entry_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Query audit trail with filters.

        Args:
            agent_id: Filter by agent ID
            start_time: Filter by start time
            end_time: Filter by end time
            entry_type: Filter by entry type
            limit: Maximum number of entries to return

        Returns:
            List of matching audit entries
        """
        results = []

        # Get all log files in date range
        log_files = sorted(self.audit_dir.glob("audit_*.jsonl"), reverse=True)

        for log_file in log_files:
            try:
                with open(log_file, "r") as f:
                    for line in reversed(f.readlines()):
                        if len(results) >= limit:
                            break

                        entry = json.loads(line)

                        # Apply filters
                        if agent_id and entry.get("agent_id") != agent_id:
                            continue

                        if entry_type and entry.get("type") != entry_type:
                            continue

                        entry_time = datetime.fromisoformat(entry["timestamp"])

                        if start_time and entry_time < start_time:
                            continue

                        if end_time and entry_time > end_time:
                            continue

                        results.append(entry)

            except Exception as e:
                logger.error(f"Error reading log file {log_file}: {e}")

        return results[:limit]

    def verify_chain_integrity(self) -> Dict[str, Any]:
        """
        Verify cryptographic integrity of audit chain.

        Returns:
            Dict with verification results:
                - valid: bool
                - total_entries: int
                - broken_links: List[Dict]
        """
        broken_links = []
        total_entries = 0
        log_files = sorted(self.audit_dir.glob("audit_*.jsonl"))

        for log_file in log_files:
            previous_hash = "GENESIS"
            try:
                with open(log_file, "r") as f:
                    for line_num, line in enumerate(f, 1):
                        entry = json.loads(line)
                        total_entries += 1

                        # Verify previous hash matches
                        if entry.get("previous_hash") != previous_hash:
                            broken_links.append(
                                {
                                    "file": str(log_file),
                                    "line": line_num,
                                    "expected_previous": previous_hash,
                                    "actual_previous": entry.get("previous_hash"),
                                }
                            )

                        # Verify entry hash
                        stored_hash = entry.get("entry_hash")
                        computed_hash = self._compute_entry_hash(entry)

                        if stored_hash != computed_hash:
                            broken_links.append(
                                {
                                    "file": str(log_file),
                                    "line": line_num,
                                    "type": "hash_mismatch",
                                    "expected_hash": computed_hash,
                                    "actual_hash": stored_hash,
                                }
                            )

                        previous_hash = stored_hash

            except Exception as e:
                logger.error(f"Error verifying {log_file}: {e}")
                broken_links.append({"file": str(log_file), "error": str(e)})

        valid = len(broken_links) == 0

        return {
            "valid": valid,
            "total_entries": total_entries,
            "broken_links": broken_links,
        }

    @staticmethod
    def _sanitize_context(context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize context to remove sensitive data before logging.

        Args:
            context: Original context

        Returns:
            Sanitized context
        """
        sanitized = {}
        sensitive_keys = {"password", "token", "secret", "api_key", "credential"}

        def sanitize_value(value: Any) -> Any:
            if isinstance(value, dict):
                return {
                    nested_key: (
                        "***REDACTED***"
                        if any(
                            sensitive in str(nested_key).lower()
                            for sensitive in sensitive_keys
                        )
                        else sanitize_value(nested_value)
                    )
                    for nested_key, nested_value in value.items()
                }
            if isinstance(value, list):
                return [sanitize_value(item) for item in value]
            return value

        for key, value in context.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = sanitize_value(value)

        return sanitized
