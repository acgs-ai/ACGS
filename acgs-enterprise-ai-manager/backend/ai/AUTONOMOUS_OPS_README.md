# AI Autonomous Operations with Governance Gates

## Overview

This module implements AI-driven autonomous operations for the ACGS Enterprise Manager with integrated governance gates, risk-based approval workflows, and comprehensive audit trails.

## Architecture

### Components

1. **autonomous_ops.py** - Main autonomous operations engine
   - Coordinates autonomous operations across domains
   - Manages operation lifecycle (propose → approve → execute → complete)
   - Tracks active operations and history
   - Provides statistics and monitoring

2. **approval_gates.py** - Risk-based approval workflow
   - Assesses operation risk levels (LOW, MEDIUM, HIGH, CRITICAL)
   - Enforces approval requirements based on risk
   - Manages pending approval requests
   - Integrates with ACGS-Lite governance framework

3. **operations/task_assignment.py** - Task assignment handler
   - Analyzes team workload and capacity
   - Matches task requirements with member skills
   - Automatically assigns tasks to optimal team members
   - Provides reasoning for assignment decisions

4. **operations/asset_maintenance.py** - Asset maintenance handler
   - Analyzes asset condition and usage patterns
   - Determines maintenance urgency
   - Schedules optimal maintenance windows
   - Estimates duration and costs

## Key Features

### Risk-Based Approval

Operations are automatically assessed for risk based on multiple factors:

**Risk Factors:**
- Operation type (base risk)
- Impact scope (single, team, department, organization)
- Financial impact
- Reversibility
- AI confidence level

**Risk Levels & Actions:**
- **LOW**: Auto-approve with audit trail
- **MEDIUM**: Auto-approve with notification
- **HIGH**: Require human approval (1 hour timeout)
- **CRITICAL**: Require multi-level approval (2 hour timeout)

### Governance Integration

All autonomous operations are validated through the ACGS-Lite governance framework:
- Pattern-based rule matching
- Constitutional compliance checks
- Fail-closed enforcement
- Tamper-evident audit trails

### Operation Lifecycle

```
1. PROPOSE → Risk assessment + governance validation
2. APPROVE → Auto-approval or human approval required
3. EXECUTE → Handler executes the operation
4. COMPLETE → Results logged to audit trail
```

## Usage

### Initialize Engine

```python
from backend.governance import get_governance
from backend.ai import initialize_autonomous_engine

governance = get_governance()
engine = initialize_autonomous_engine(governance)
```

### Propose Operation

```python
result = await engine.propose_operation(
    operation_type='task_assignment',
    details={
        'task_id': 'task_001',
        'candidate_members': ['user_1', 'user_2', 'user_3'],
        'summary': 'Assign code review task'
    },
    context={
        'impact_scope': 'single',
        'financial_impact': 0,
        'reversible': True,
        'confidence': 0.90,
        'workload_data': {
            'user_1': {'active_tasks': 2, 'capacity': 10, 'urgent_tasks': 0},
            'user_2': {'active_tasks': 8, 'capacity': 10, 'urgent_tasks': 3}
        },
        'required_skills': ['code_review', 'python'],
        'member_skills': {
            'user_1': ['code_review', 'python', 'testing'],
            'user_2': ['code_review', 'javascript']
        }
    }
)

operation = result['operation']
approval = result['approval_request']
```

### Execute Approved Operation

```python
if operation['status'] == 'approved':
    exec_result = await engine.execute_operation(operation['operation_id'])
    print(f"Success: {exec_result['success']}")
    print(f"Result: {exec_result['result']}")
```

### Manual Approval

```python
# For high-risk operations requiring approval
if approval['status'] == 'pending':
    # Approve
    engine.approval_gate.approve_request(
        request_id=approval['request_id'],
        approver='admin@example.com',
        reason='Reviewed and approved'
    )
    
    # Or deny
    engine.approval_gate.deny_request(
        request_id=approval['request_id'],
        approver='admin@example.com',
        reason='Risk too high'
    )
```

### Query Operations

```python
# Get active operations
active = engine.get_active_operations(
    operation_type='task_assignment',
    status='pending'
)

# Get operation history
history = engine.get_operation_history(limit=50)

# Get statistics
stats = engine.get_statistics()
print(f"Success rate: {stats['success_rate']:.2%}")
print(f"Pending approvals: {stats['pending_approvals']}")
```

## Domain Operations

### Task Assignment

Automatically assigns tasks based on:
- **Workload analysis**: Active tasks, capacity, urgent tasks
- **Skill matching**: Required skills vs member skills
- **Combined scoring**: 60% workload + 40% skills

**Example:**
```python
result = await engine.propose_operation(
    operation_type='task_assignment',
    details={
        'task_id': 'task_123',
        'candidate_members': ['alice', 'bob', 'charlie']
    },
    context={
        'workload_data': {...},
        'required_skills': ['python', 'testing'],
        'member_skills': {...}
    }
)
```

**Output:**
```python
{
    'task_id': 'task_123',
    'assigned_to': 'alice',
    'confidence': 0.88,
    'reasoning': 'Selected member alice with overall score 0.88. Member has low workload (score: 0.75). Strong skill match (score: 1.00).',
    'alternative_candidates': [...]
}
```

### Asset Maintenance

Automatically schedules maintenance based on:
- **Asset condition**: Age, usage hours, intensity
- **Maintenance history**: Days since last maintenance
- **Urgency determination**: Critical, high, medium, low
- **Optimal scheduling**: Business hours, minimal disruption

**Example:**
```python
result = await engine.propose_operation(
    operation_type='asset_maintenance',
    details={
        'asset_id': 'server_001',
        'maintenance_type': 'preventive'
    },
    context={
        'asset_data': {
            'acquisition_date': '2020-01-01T00:00:00',
            'lifecycle_stage': 'operational'
        },
        'usage_data': {
            'total_hours': 15000,
            'intensity': 'high'
        },
        'maintenance_history': [...]
    }
)
```

**Output:**
```python
{
    'asset_id': 'server_001',
    'maintenance_type': 'preventive',
    'urgency': 'high',
    'scheduled_start': '2026-04-26T09:00:00',
    'scheduled_end': '2026-04-26T13:00:00',
    'estimated_duration_hours': 3.9,
    'estimated_cost': 1300.0,
    'asset_condition': {
        'score': 0.4,
        'status': 'fair',
        'days_since_maintenance': 200
    },
    'maintenance_tasks': [...]
}
```

## Risk Assessment Examples

### Low Risk (Auto-Approved)
- Single user task assignment
- Low financial impact (<$1000)
- Reversible operation
- High AI confidence (>0.8)

### Medium Risk (Auto-Approved with Notification)
- Team-level impact
- Moderate financial impact ($1000-$5000)
- Reversible operation
- Good AI confidence (0.7-0.8)

### High Risk (Requires Approval)
- Department-level impact
- High financial impact ($5000-$10000)
- Non-reversible operation
- Lower AI confidence (<0.7)

### Critical Risk (Requires Multi-Level Approval)
- Organization-wide impact
- Very high financial impact (>$10000)
- Non-reversible operation
- Data deletion or access changes

## Testing

Run the comprehensive test suite:

```bash
source ~/miniconda3/etc/profile.d/conda.sh
conda activate data
PYTHONPATH=/home/pen/projects/acgs-manager python backend/ai/test_autonomous_ops.py
```

### Test Coverage

✅ Autonomous engine initialization  
✅ Low-risk operation auto-approval  
✅ High-risk operation requires approval  
✅ Task assignment execution  
✅ Asset maintenance execution  
✅ Governance blocking harmful operations  
✅ Audit trail functionality  
✅ Operation statistics  
✅ Manual approval workflow  

All 9 tests passing.

## Audit Trail

All autonomous operations are logged to the tamper-evident audit trail:

```python
# Query audit trail
audit_entries = governance.inspect_audit_trail(
    agent_id='autonomous_ai',
    limit=100
)

# Verify chain integrity
integrity = governance.audit_logger.verify_chain_integrity()
print(f"Chain valid: {integrity['valid']}")
```

## Integration Points

### With Recommendation Engine (Task #8)
- Uses recommendations to inform autonomous decisions
- Confidence scores feed into risk assessment
- Shared domain models (TaskPrioritizer, AssetLifecycleRecommender)

### With Governance Framework (Task #2)
- All operations validated against constitutional rules
- Fail-closed enforcement prevents unauthorized actions
- Tamper-evident audit trail for compliance

### With CRUD APIs (Tasks #4, #5)
- Task assignment integrates with Tasks domain API
- Asset maintenance integrates with IT Assets domain API
- Real-time data for workload and asset analysis

## File Structure

```
backend/ai/
├── autonomous_ops.py              # Main engine (400 lines)
├── operations/
│   ├── __init__.py
│   ├── task_assignment.py         # Task assignment handler (250 lines)
│   └── asset_maintenance.py       # Asset maintenance handler (400 lines)
└── test_autonomous_ops.py         # Test suite (450 lines)

backend/governance/
└── approval_gates.py              # Approval workflow (350 lines)
```

## Acceptance Criteria

✅ Autonomous operations working in 2 domains (task assignment, asset maintenance)  
✅ Governance rules enforced via ACGS-Lite integration  
✅ High-risk operations require approval  
✅ Audit trail captures all decisions  
✅ Risk-based approval workflow implemented  
✅ Comprehensive test suite (9 tests passing)  

## Next Steps

1. Integrate with FastAPI endpoints (Task #3)
2. Connect to actual CRUD APIs for real data (Tasks #4, #5)
3. Add more domain operations (infrastructure, projects, financial)
4. Implement notification system for approval requests
5. Build approval dashboard UI

## Monitoring

```python
# Get real-time statistics
stats = engine.get_statistics()

# Monitor pending approvals
pending = engine.approval_gate.get_pending_approvals(
    risk_level=RiskLevel.HIGH
)

# Cleanup expired requests
expired_count = engine.approval_gate.cleanup_expired_requests()
```

## Security Considerations

- All operations validated through governance framework
- Fail-closed enforcement (blocks by default)
- Multi-level approval for critical operations
- Tamper-evident audit trail
- PII protection and harmful action blocking
- Constitutional compliance (EU AI Act, SOC 2, ISO 27001)
