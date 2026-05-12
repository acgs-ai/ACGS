"""
Unit tests for AuditLogger
Tests tamper-evident logging and chain integrity.
"""

import pytest
import json
from pathlib import Path
from datetime import datetime
from backend.governance.audit_logger import AuditLogger


@pytest.mark.unit
@pytest.mark.governance
class TestAuditLogger:
    """Test suite for AuditLogger class."""

    def test_initialization(self, temp_dir):
        """Test AuditLogger initializes correctly."""
        audit_dir = temp_dir / "audit_logs"
        logger = AuditLogger(str(audit_dir))

        assert logger is not None
        assert audit_dir.exists()
        assert logger.last_hash == "GENESIS"

    def test_log_decision(self, temp_dir):
        """Test logging a governance decision."""
        audit_dir = temp_dir / "audit_logs"
        logger = AuditLogger(str(audit_dir))

        operation = "Test operation"
        context = {"user_id": "test_user"}
        validation_result = {
            "valid": True,
            "action": "ALLOW",
            "violations": [],
            "matched_rules": [],
        }

        decision_id = logger.log_decision(
            operation=operation,
            context=context,
            validation_result=validation_result,
            agent_id="test_agent",
            duration_ms=10.5,
        )

        assert decision_id is not None
        assert len(decision_id) == 64  # SHA-256 hash length

    def test_log_approval_request(self, temp_dir):
        """Test logging an approval request."""
        audit_dir = temp_dir / "audit_logs"
        logger = AuditLogger(str(audit_dir))

        approval_request = {
            "request_id": "req_123",
            "agent_id": "test_agent",
            "operation": "Delete data",
            "context": {},
            "timeout_seconds": 3600,
            "status": "PENDING",
        }

        entry_hash = logger.log_approval_request(approval_request)

        assert entry_hash is not None
        assert len(entry_hash) == 64

    def test_log_approval_response(self, temp_dir):
        """Test logging an approval response."""
        audit_dir = temp_dir / "audit_logs"
        logger = AuditLogger(str(audit_dir))

        entry_hash = logger.log_approval_response(
            request_id="req_123",
            approved=True,
            approver="admin_user",
            reason="Authorized operation",
        )

        assert entry_hash is not None

    def test_log_enforcement(self, temp_dir):
        """Test logging an enforcement action."""
        audit_dir = temp_dir / "audit_logs"
        logger = AuditLogger(str(audit_dir))

        entry_hash = logger.log_enforcement(
            operation="Dangerous operation", action="BLOCKED", reason="Rule violation"
        )

        assert entry_hash is not None

    def test_chain_integrity_single_entry(self, temp_dir):
        """Test chain integrity with single entry."""
        audit_dir = temp_dir / "audit_logs"
        logger = AuditLogger(str(audit_dir))

        logger.log_decision(
            operation="Test",
            context={},
            validation_result={"valid": True, "action": "ALLOW"},
            agent_id="test",
            duration_ms=1.0,
        )

        integrity = logger.verify_chain_integrity()

        assert integrity["valid"] is True
        assert integrity["total_entries"] == 1
        assert len(integrity["broken_links"]) == 0

    def test_chain_integrity_multiple_entries(self, temp_dir):
        """Test chain integrity with multiple entries."""
        audit_dir = temp_dir / "audit_logs"
        logger = AuditLogger(str(audit_dir))

        # Log multiple entries
        for i in range(5):
            logger.log_decision(
                operation=f"Test operation {i}",
                context={},
                validation_result={"valid": True, "action": "ALLOW"},
                agent_id="test",
                duration_ms=1.0,
            )

        integrity = logger.verify_chain_integrity()

        assert integrity["valid"] is True
        assert integrity["total_entries"] == 5
        assert len(integrity["broken_links"]) == 0

    def test_query_audit_trail(self, temp_dir):
        """Test querying audit trail with filters."""
        audit_dir = temp_dir / "audit_logs"
        logger = AuditLogger(str(audit_dir))

        # Log entries for different agents
        logger.log_decision(
            operation="Op 1",
            context={},
            validation_result={"valid": True, "action": "ALLOW"},
            agent_id="agent_1",
            duration_ms=1.0,
        )
        logger.log_decision(
            operation="Op 2",
            context={},
            validation_result={"valid": False, "action": "BLOCK"},
            agent_id="agent_2",
            duration_ms=2.0,
        )

        # Query all entries
        all_entries = logger.query_audit_trail()
        assert len(all_entries) == 2

        # Query by agent_id
        agent1_entries = logger.query_audit_trail(agent_id="agent_1")
        assert len(agent1_entries) == 1
        assert agent1_entries[0]["agent_id"] == "agent_1"

    def test_query_audit_trail_by_type(self, temp_dir):
        """Test querying audit trail by entry type."""
        audit_dir = temp_dir / "audit_logs"
        logger = AuditLogger(str(audit_dir))

        logger.log_decision(
            operation="Test",
            context={},
            validation_result={"valid": True, "action": "ALLOW"},
            agent_id="test",
            duration_ms=1.0,
        )
        logger.log_enforcement(operation="Test", action="BLOCKED", reason="Test")

        decision_entries = logger.query_audit_trail(entry_type="DECISION")
        enforcement_entries = logger.query_audit_trail(entry_type="ENFORCEMENT")

        assert len(decision_entries) == 1
        assert len(enforcement_entries) == 1

    def test_sanitize_context_removes_sensitive_data(self, temp_dir):
        """Test context sanitization removes sensitive information."""
        audit_dir = temp_dir / "audit_logs"
        logger = AuditLogger(str(audit_dir))

        sensitive_context = {
            "user_id": "123",
            "password": "secret123",
            "api_key": "key_abc",
            "token": "token_xyz",
        }

        sanitized = logger._sanitize_context(sensitive_context)

        assert sanitized["user_id"] == "123"
        assert sanitized["password"] == "***REDACTED***"
        assert sanitized["api_key"] == "***REDACTED***"
        assert sanitized["token"] == "***REDACTED***"

    def test_audit_log_file_format(self, temp_dir):
        """Test audit log file is valid JSONL format."""
        audit_dir = temp_dir / "audit_logs"
        logger = AuditLogger(str(audit_dir))

        logger.log_decision(
            operation="Test",
            context={},
            validation_result={"valid": True, "action": "ALLOW"},
            agent_id="test",
            duration_ms=1.0,
        )

        # Read log file directly
        log_file = logger.current_log_file
        with open(log_file, "r") as f:
            line = f.readline()
            entry = json.loads(line)

        assert "type" in entry
        assert "timestamp" in entry
        assert "previous_hash" in entry
        assert "entry_hash" in entry
        assert entry["previous_hash"] == "GENESIS"
