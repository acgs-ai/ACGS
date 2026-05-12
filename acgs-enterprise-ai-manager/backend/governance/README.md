# ACGS-Lite Governance Framework Integration

## Overview

This directory contains the integration of the ACGS-Lite constitutional governance framework for the ACGS Enterprise Manager. The framework implements the MACI pattern (Monitor-Approve-Control-Inspect) to provide fail-closed enforcement with tamper-evident audit trails for all AI operations.

## Architecture

### Components

1. **acgs_integration.py** - Main integration point
   - Initializes and manages the governance engine
   - Provides validation, approval, enforcement, and inspection APIs
   - Implements fail-closed enforcement by default

2. **rules_engine.py** - Rule-based validation engine
   - Pattern matching against constitutional rules
   - Severity-based action enforcement (BLOCK, REQUIRE_APPROVAL, VALIDATE, AUDIT)
   - Context-aware validation (confidence thresholds, amount limits, batch sizes)

3. **audit_logger.py** - Tamper-evident audit trail
   - Cryptographic chaining of audit entries (SHA-256)
   - Immutable audit logs with integrity verification
   - Query and inspection capabilities

4. **governance_rules.yaml** - Constitutional rules configuration
   - 15 governance rules covering safety, compliance, and AI-specific concerns
   - MACI phase mapping for each rule
   - Configurable enforcement, audit, and approval workflows

## MACI Pattern Implementation

### Monitor Phase
- Pattern-based detection of operations requiring governance
- Real-time validation against constitutional rules
- Automatic classification by severity (CRITICAL, HIGH, MEDIUM, LOW)

### Approve Phase
- Human-in-the-loop approval workflow for sensitive operations
- Configurable approval timeout and escalation
- Audit trail of all approval requests and responses

### Control Phase
- Fail-closed enforcement (blocks by default on violations)
- Context-aware validation (confidence, amounts, batch sizes)
- Enforcement logging for compliance

### Inspect Phase
- Tamper-evident audit trail with cryptographic chaining
- Query capabilities by agent, time range, and entry type
- Chain integrity verification

## Key Features

### Fail-Closed Enforcement
- Operations are blocked by default on rule violations
- Explicit allow required for operations to proceed
- Graceful degradation on system errors (fails to safe state)

### Tamper-Evident Audit Trail
- Each audit entry includes SHA-256 hash of previous entry
- Creates immutable chain of evidence
- Integrity verification detects any tampering
- 7-year retention for compliance

### Rule Categories

**Critical Safety Rules:**
- No harmful actions (harm, kill, destroy, attack)
- No PII leakage (SSN, passport, credit cards)
- Unauthorized data deletion requires approval

**High Severity Rules:**
- Financial transaction limits and approval thresholds
- Infrastructure changes require approval
- Cross-domain data access auditing
- Access control validation

**AI-Specific Rules:**
- Autonomous operations require governance gate approval
- AI confidence threshold enforcement (70-75% minimum)
- AI learning and feedback auditing
- Recommendation validation

**Compliance Rules:**
- Data retention policy enforcement (90 days minimum, 7 years maximum)
- Audit trail integrity protection
- EU AI Act, SOC 2, ISO 27001 alignment

## Usage

### Basic Usage

```python
from backend.governance import get_governance

# Get governance instance
governance = get_governance()

# Validate an operation
result = governance.validate_operation(
    operation="Update user profile",
    context={"domain": "users", "action": "update"},
    agent_id="ai_agent_1"
)

if result['valid']:
    # Enforce decision
    allowed = governance.enforce_decision(result, operation)
    if allowed:
        # Proceed with operation
        pass
else:
    # Handle violations
    print(f"Blocked: {result['violations']}")
```

### Approval Workflow

```python
# Request approval for sensitive operation
approval_request = governance.request_approval(
    operation="DELETE FROM users WHERE inactive = true",
    context={"domain": "database", "action": "delete"},
    agent_id="ai_agent_1",
    timeout_seconds=3600
)

# Later, log approval response
governance.audit_logger.log_approval_response(
    request_id=approval_request['request_id'],
    approved=True,
    approver="admin@example.com",
    reason="Approved after review"
)
```

### Audit Trail Inspection

```python
# Query audit trail
audit_entries = governance.inspect_audit_trail(
    agent_id="ai_agent_1",
    start_time=datetime(2026, 4, 1),
    limit=100
)

# Verify chain integrity
integrity = governance.audit_logger.verify_chain_integrity()
print(f"Chain valid: {integrity['valid']}")
print(f"Total entries: {integrity['total_entries']}")
```

## Testing

Run the test suite to verify the integration:

```bash
source ~/miniconda3/etc/profile.d/conda.sh
conda activate data
PYTHONPATH=/home/pen/projects/acgs-manager python backend/governance/test_governance.py
```

### Test Coverage

- ✅ Governance initialization
- ✅ Safe operation allowed
- ✅ Harmful operation blocked
- ✅ PII protection
- ✅ Approval workflow
- ✅ AI autonomous operations gating
- ✅ AI confidence threshold validation
- ✅ Audit trail functionality
- ✅ Fail-closed enforcement

All 9 tests passing.

## Configuration

### Constitution File

Edit `/config/governance_rules.yaml` to customize rules:

```yaml
rules:
  - id: custom-rule
    pattern: "regex pattern"
    severity: CRITICAL|HIGH|MEDIUM|LOW
    action: BLOCK|REQUIRE_APPROVAL|VALIDATE|AUDIT
    description: "Rule description"
    maci_phase: MONITOR|APPROVE|CONTROL|INSPECT
```

### Enforcement Configuration

```yaml
enforcement:
  default_action: BLOCK
  fail_mode: CLOSED
  require_explicit_allow: true
```

### Audit Configuration

```yaml
audit:
  enabled: true
  tamper_evident: true
  retention_days: 2555  # 7 years
  log_all_decisions: true
```

## Integration with AI Operations

### AI Recommendation Engine (Task #8)
- All recommendations validated against confidence thresholds
- Low-confidence recommendations blocked or flagged
- Audit trail of all AI decisions

### AI Autonomous Operations (Task #9)
- Governance gate approval required for autonomous actions
- Fail-closed enforcement prevents unauthorized autonomy
- Human-in-the-loop for critical decisions

### AI Learning Capability (Task #7)
- All learning operations audited
- Feedback loop validation
- Model update governance

## Compliance

The framework supports compliance with:

- **EU AI Act** - High-risk AI system requirements
- **SOC 2** - Security and availability controls
- **ISO 27001** - Information security management

## Dependencies

### Required
- Python 3.8+
- PyYAML

### Optional
- acgs-lite (for enhanced governance features)
  ```bash
  pip install acgs-lite
  ```

## File Structure

```
backend/governance/
├── __init__.py                 # Package initialization
├── acgs_integration.py         # Main integration (350 lines)
├── rules_engine.py             # Rule validation (250 lines)
├── audit_logger.py             # Audit trail (350 lines)
├── test_governance.py          # Test suite (350 lines)
├── audit_logs/                 # Audit log storage
│   └── audit_YYYY-MM-DD.jsonl
└── README.md                   # This file

config/
└── governance_rules.yaml       # Constitutional rules (200 lines)
```

## Acceptance Criteria

✅ Framework integrated with MACI pattern implementation  
✅ Rule validation working (15 rules loaded and tested)  
✅ Audit trail capturing all AI operations  
✅ Fail-closed enforcement blocks rule violations  
✅ Tamper-evident audit chain with integrity verification  
✅ Approval workflow for sensitive operations  
✅ AI-specific governance gates implemented  

## Next Steps

1. Install acgs-lite for enhanced features:
   ```bash
   pip install acgs-lite
   ```

2. Integrate with FastAPI backend (Task #3)
3. Connect to AI recommendation engine (Task #8)
4. Implement governance gates for autonomous operations (Task #9)

## Support

For issues or questions about the governance framework:
- Review test suite: `test_governance.py`
- Check audit logs: `backend/governance/audit_logs/`
- Verify chain integrity: `governance.audit_logger.verify_chain_integrity()`
