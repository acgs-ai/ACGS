# AI Recommendation Engine

## Overview

The AI Recommendation Engine provides intelligent recommendations across three core domains:
1. **Task Prioritization** - Recommends task priorities based on deadlines, dependencies, and project importance
2. **Asset Lifecycle Management** - Recommends maintenance, upgrades, and retirement for IT assets
3. **Project Risk Assessment** - Identifies budget, schedule, and resource risks with mitigation strategies

## Architecture

```
backend/ai/
├── recommendation_engine.py      # Main engine coordinating all recommenders
├── models/
│   ├── task_prioritizer.py      # Task priority recommendations
│   ├── asset_lifecycle.py       # Asset lifecycle recommendations
│   └── project_risk.py          # Project risk assessments
└── test_recommendation_engine.py # Unit tests
```

## Features

### Core Capabilities
- ✅ Multi-domain recommendation generation
- ✅ Confidence scoring (0-1 scale)
- ✅ Human-readable rationale for each recommendation
- ✅ Governance framework integration (ACGS-Lite)
- ✅ Batch recommendation support
- ✅ Extensible architecture for new domains

### Governance Integration
- All recommendations pass through governance validation
- Three possible outcomes:
  - `ALLOW` - Recommendation approved automatically
  - `REQUIRE_APPROVAL` - Human approval needed
  - `BLOCK` - Recommendation blocked by governance rules
- Fail-closed enforcement: errors block recommendations

## API Endpoints

### Generate Recommendation
```http
POST /api/v1/recommendations/generate
Content-Type: application/json

{
  "domain": "tasks",
  "entity_id": "task-123",
  "context": {
    "task_data": {
      "due_date": "2026-04-30T10:00:00Z",
      "blocks": ["task-456"],
      "project_priority": "high"
    }
  }
}
```

### Batch Generate
```http
POST /api/v1/recommendations/batch
Content-Type: application/json

{
  "domain": "assets",
  "entity_ids": ["asset-1", "asset-2", "asset-3"],
  "context": {}
}
```

### Get Top Recommendations
```http
GET /api/v1/recommendations/top/tasks?limit=10&min_confidence=0.7
```

### Get Supported Domains
```http
GET /api/v1/recommendations/domains
```

### Get Stats
```http
GET /api/v1/recommendations/stats
```

## Integration Status

### ✅ Completed
- Core recommendation engine framework
- Three domain-specific recommenders (task, asset, project)
- Confidence scoring and rationale generation
- Governance integration hooks
- REST API endpoints
- Basic unit tests

### 🔄 Pending (Blocked by Dependencies)
- **Task #2** ✅ COMPLETED - Governance framework integration
- **Task #4** ⏳ PENDING - Tasks CRUD APIs (for real task data)
- **Task #5** ⏳ PENDING - IT Assets CRUD APIs (for real asset data)

### 🚧 Integration Points (Stub Mode)

The recommendation engine currently operates in **stub mode** with mock data. Once CRUD APIs are ready:

1. **Task Prioritizer** will integrate with:
   - `GET /api/v1/tasks/{id}` - Fetch task details
   - `GET /api/v1/tasks?project_id={id}` - Query project tasks
   - Database: `tasks` table

2. **Asset Lifecycle** will integrate with:
   - `GET /api/v1/assets/{id}` - Fetch asset details
   - `GET /api/v1/assets?lifecycle_stage={stage}` - Query by lifecycle
   - Database: `it_assets` table

3. **Project Risk Assessor** will integrate with:
   - `GET /api/v1/projects/{id}` - Fetch project details
   - `GET /api/v1/projects/{id}/tasks` - Get project tasks
   - Database: `projects`, `tasks`, `financial_records` tables

## Usage Example

```python
from backend.ai.recommendation_engine import RecommendationEngine, RecommendationDomain
from backend.governance.acgs_integration import get_governance

# Initialize engine with governance
governance = get_governance()
engine = RecommendationEngine(governance_integration=governance)

# Generate task recommendation
recommendation = await engine.generate_recommendation(
    domain=RecommendationDomain.TASKS,
    entity_id="task-123",
    context={
        "task_data": {
            "due_date": "2026-04-30T10:00:00Z",
            "blocks": ["task-456", "task-789"],
            "project_priority": "high",
            "assignee_id": "user-1"
        }
    }
)

print(f"Suggestion: {recommendation['suggestion']}")
print(f"Confidence: {recommendation['confidence']}")
print(f"Rationale: {recommendation['rationale']}")
print(f"Status: {recommendation['status']}")
```

## Testing

Run unit tests:
```bash
python -m backend.ai.test_recommendation_engine
```

Expected output:
```
✓ Supported domains: ['tasks', 'assets', 'projects']
✓ Task recommendation: Set priority to 'high'
✓ Asset recommendation: Schedule maintenance for server
✓ Project recommendation: Mitigate budget_overrun risk...
✅ All tests passed!
```

## Next Steps

1. **Task #7** - Implement learning capability with feedback loop
2. **Task #9** - Implement autonomous operations with governance gates
3. **Integration** - Connect to CRUD APIs once available (tasks #4, #5)
4. **Database** - Store recommendations in `recommendations` table
5. **Learning** - Implement feedback-based model improvement

## Acceptance Criteria Status

- ✅ Recommendations generated for 3 domains (tasks, assets, projects)
- ✅ Confidence scores included (0-1 scale)
- ✅ Rationale generation working
- ✅ Governance integration hooks in place
- 🔄 Feedback mechanism (pending task #7)
- 🔄 Database storage (pending CRUD APIs)
