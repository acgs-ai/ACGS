# AI Learning System

## Overview

The AI Learning System implements feedback-based learning to continuously improve recommendation quality. It captures user feedback (accepted/rejected/modified), analyzes patterns, and adjusts recommendation models accordingly.

## Components

### Learning Engine (`learning_engine.py`)
- Processes user feedback on recommendations
- Tracks performance metrics per domain
- Triggers model updates based on feedback patterns
- Provides improvement trend analysis

### Feedback Processor (`feedback_processor.py`)
- Validates feedback submissions
- Categorizes feedback types (accepted/rejected/modified)
- Extracts insights from feedback patterns
- Prepares training data for model updates

### Feedback API (`api/feedback.py`)
- REST endpoints for feedback submission
- Performance metrics retrieval
- Trend analysis
- Feature importance analysis

## Features

### ✅ Implemented
- Feedback collection (accepted/rejected/modified)
- Performance metrics tracking per domain
- Automatic model updates (every 10 feedback items)
- Confidence calibration based on acceptance rates
- Improvement trend analysis
- Feature importance tracking
- Rejection reason categorization

### 🔄 Future Enhancements
- Database persistence for feedback history
- Advanced ML model training
- A/B testing framework
- Personalized recommendations based on user history

## API Endpoints

### Submit Feedback
```http
POST /api/v1/feedback/submit
Content-Type: application/json

{
  "recommendation_id": "rec-123",
  "feedback_type": "accepted",
  "domain": "tasks",
  "confidence": 0.85,
  "comment": "Very helpful recommendation"
}
```

### Get Performance Metrics
```http
GET /api/v1/feedback/metrics?domain=tasks
```

Response:
```json
{
  "domain": "tasks",
  "metrics": {
    "total": 100,
    "accepted": 75,
    "rejected": 15,
    "modified": 10,
    "avg_confidence": 0.82
  },
  "acceptance_rate": 0.75
}
```

### Get Improvement Trends
```http
GET /api/v1/feedback/trends/tasks?window_size=10
```

Response:
```json
{
  "domain": "tasks",
  "recent_acceptance_rate": 0.80,
  "previous_acceptance_rate": 0.70,
  "improvement": 0.10,
  "trend": "improving"
}
```

### Get Feature Importance
```http
GET /api/v1/feedback/features/tasks
```

### Get Learning Stats
```http
GET /api/v1/feedback/stats
```

## Learning Algorithm

### Feedback Processing Flow
1. **Validation** - Validate feedback data structure
2. **Categorization** - Classify feedback type and extract insights
3. **Storage** - Store feedback with metadata
4. **Metrics Update** - Update domain-specific performance metrics
5. **Model Update** - Trigger model adjustment every N feedback items

### Confidence Calibration
- **High acceptance rate (>80%)** → Increase confidence by 5%
- **High rejection rate (>50%)** → Decrease confidence by 5%
- Adjustments applied to future recommendations

### Feedback Weights
- **Accepted**: weight = 1.0 (full positive signal)
- **Rejected**: weight = 1.0 (full negative signal)
- **Modified**: weight = 0.5 (partial positive signal)

## Usage Example

```python
from backend.ai.learning_engine import get_learning_engine

# Get learning engine instance
engine = get_learning_engine()

# Process feedback
result = await engine.process_feedback(
    recommendation_id="rec-123",
    feedback_type="accepted",
    feedback_data={
        'domain': 'tasks',
        'confidence': 0.85,
        'recommendation_id': 'rec-123'
    },
    user_id="user-1"
)

print(f"Acceptance rate: {result['acceptance_rate']:.2%}")

# Get performance metrics
metrics = await engine.get_performance_metrics(domain='tasks')
print(f"Total feedback: {metrics['metrics']['total']}")
print(f"Acceptance rate: {metrics['acceptance_rate']:.2%}")

# Analyze trends
trends = await engine.get_improvement_trends(domain='tasks', window_size=10)
print(f"Trend: {trends['trend']}")
```

## Testing

Run tests:
```bash
python -m backend.ai.test_learning_engine
```

Expected output:
```
✓ Accepted feedback processed
✓ Rejected feedback processed
✓ Modified feedback processed
✓ Learning update triggered
✓ Metrics retrieved
✓ Trends analyzed
✓ Learning stats retrieved
✅ All learning engine tests passed!
```

## Performance Metrics

The system tracks:
- **Total feedback count** per domain
- **Acceptance rate** (accepted / total)
- **Rejection rate** (rejected / total)
- **Modification rate** (modified / total)
- **Average confidence** of recommendations
- **Learning updates applied** count

## Integration with Recommendation Engine

The learning system integrates with the recommendation engine to:
1. Collect feedback on generated recommendations
2. Analyze acceptance patterns
3. Adjust confidence scores
4. Improve future recommendations

## Acceptance Criteria Status

- ✅ User feedback captured (accepted/rejected/modified)
- ✅ Learning algorithm adjusts future recommendations
- ✅ Improvement metrics tracked over time
- ✅ Performance metrics per domain
- ✅ Trend analysis implemented
- 🔄 Database persistence (pending CRUD APIs)

## Next Steps

1. **Database Integration** - Store feedback in `recommendations` table
2. **Advanced ML** - Implement sophisticated learning algorithms
3. **Personalization** - User-specific recommendation tuning
4. **A/B Testing** - Compare different recommendation strategies
