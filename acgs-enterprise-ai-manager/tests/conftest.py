"""
Shared test fixtures and utilities for ACGS Enterprise Manager tests.
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from typing import Generator, Dict, Any
from datetime import datetime
from backend.utils.timeutil import utcnow


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test files."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path, ignore_errors=True)


@pytest.fixture
def sample_governance_rules(temp_dir: Path) -> Path:
    """Create a sample governance rules YAML file for testing."""
    rules_content = """
constitutional_hash: test_v1

metadata:
  version: "1.0.0"
  created: "2026-04-25"
  description: "Test governance rules"

rules:
  - id: test-block-rule
    pattern: "harm|kill|destroy|attack|dangerous|harmful"
    severity: CRITICAL
    action: BLOCK
    description: "Block dangerous operations"
    maci_phase: MONITOR

  - id: test-approval-rule
    pattern: "delete|remove"
    severity: HIGH
    action: REQUIRE_APPROVAL
    description: "Require approval for deletions"
    maci_phase: APPROVE
    approval_required: true

  - id: test-validate-rule
    pattern: "recommend|suggest"
    severity: MEDIUM
    action: VALIDATE
    description: "Validate recommendations"
    maci_phase: CONTROL
    validation:
      min_confidence: 0.75

enforcement:
  default_action: BLOCK
  fail_mode: CLOSED
  require_explicit_allow: true

audit:
  enabled: true
  tamper_evident: true
  retention_days: 90
"""
    rules_file = temp_dir / "test_rules.yaml"
    rules_file.write_text(rules_content)
    return rules_file


@pytest.fixture
def sample_context() -> Dict[str, Any]:
    """Sample context for governance validation tests."""
    return {
        "user_id": "test_user_123",
        "timestamp": utcnow().isoformat(),
        "confidence": 0.85,
        "amount": 1000,
        "batch_size": 50,
    }


@pytest.fixture
def mock_agent_id() -> str:
    """Mock agent ID for testing."""
    return "test_agent_001"
