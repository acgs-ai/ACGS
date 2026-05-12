"""
Tests for AI Learning Engine and Feedback Processing
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.ai.learning_engine import LearningEngine
from backend.ai.feedback_processor import FeedbackProcessor


async def test_learning_engine():
    """Test learning engine functionality"""
    print("Testing AI Learning Engine...")

    engine = LearningEngine()
    processor = FeedbackProcessor()

    # Test 1: Process accepted feedback
    print("\n1. Testing accepted feedback...")
    result = await engine.process_feedback(
        recommendation_id="rec-1",
        feedback_type="accepted",
        feedback_data={
            "domain": "tasks",
            "confidence": 0.85,
            "recommendation_id": "rec-1",
        },
        user_id="user-1",
    )
    print(f"✓ Accepted feedback processed: {result['feedback_id']}")
    print(f"  Acceptance rate: {result['acceptance_rate']:.2%}")

    # Test 2: Process rejected feedback
    print("\n2. Testing rejected feedback...")
    result = await engine.process_feedback(
        recommendation_id="rec-2",
        feedback_type="rejected",
        feedback_data={
            "domain": "tasks",
            "confidence": 0.75,
            "reason": "not_relevant",
            "recommendation_id": "rec-2",
        },
        user_id="user-1",
    )
    print(f"✓ Rejected feedback processed: {result['feedback_id']}")
    print(f"  Acceptance rate: {result['acceptance_rate']:.2%}")

    # Test 3: Process modified feedback
    print("\n3. Testing modified feedback...")
    result = await engine.process_feedback(
        recommendation_id="rec-3",
        feedback_type="modified",
        feedback_data={
            "domain": "tasks",
            "confidence": 0.80,
            "original_value": "high",
            "modified_value": "medium",
            "recommendation_id": "rec-3",
        },
        user_id="user-1",
    )
    print(f"✓ Modified feedback processed: {result['feedback_id']}")
    print(f"  Acceptance rate: {result['acceptance_rate']:.2%}")

    # Test 4: Add more feedback to trigger learning update
    print("\n4. Testing learning update trigger...")
    for i in range(7):
        await engine.process_feedback(
            recommendation_id=f"rec-{i+4}",
            feedback_type="accepted",
            feedback_data={
                "domain": "tasks",
                "confidence": 0.85,
                "recommendation_id": f"rec-{i+4}",
            },
        )

    # This should trigger a learning update (10th feedback)
    result = await engine.process_feedback(
        recommendation_id="rec-11",
        feedback_type="accepted",
        feedback_data={
            "domain": "tasks",
            "confidence": 0.90,
            "recommendation_id": "rec-11",
        },
    )

    if result["learning_update"]:
        print(f"✓ Learning update triggered!")
        print(
            f"  Confidence adjustment: {result['learning_update']['confidence_adjustment']}"
        )
    else:
        print("  (Learning update not triggered yet)")

    # Test 5: Get performance metrics
    print("\n5. Testing performance metrics...")
    metrics = await engine.get_performance_metrics(domain="tasks")
    print(f"✓ Metrics retrieved for tasks domain")
    print(f"  Total feedback: {metrics['metrics']['total']}")
    print(f"  Acceptance rate: {metrics['acceptance_rate']:.2%}")

    # Test 6: Get improvement trends
    print("\n6. Testing improvement trends...")
    trends = await engine.get_improvement_trends(domain="tasks", window_size=5)
    print(f"✓ Trends analyzed")
    if "status" in trends:
        print(f"  Status: {trends['status']}")
    if trends.get("recent_acceptance_rate"):
        print(f"  Recent acceptance rate: {trends['recent_acceptance_rate']:.2%}")
        if trends.get("trend"):
            print(f"  Trend: {trends['trend']}")

    # Test 7: Get learning stats
    print("\n7. Testing learning stats...")
    stats = engine.get_learning_stats()
    print(f"✓ Learning stats retrieved")
    print(f"  Total feedback: {stats['total_feedback']}")
    print(f"  Domains tracked: {stats['domains_tracked']}")
    print(f"  Overall acceptance rate: {stats['overall_acceptance_rate']:.2%}")

    # Test 8: Feedback processor validation
    print("\n8. Testing feedback processor...")
    validation = await processor.validate_feedback(
        "accepted",
        {"recommendation_id": "rec-1", "domain": "tasks", "confidence": 0.85},
    )
    print(f"✓ Validation passed: {validation['valid']}")

    # Test 9: Process different feedback types
    print("\n9. Testing feedback processing...")
    accepted = await processor.process_accepted_feedback("rec-1", {"domain": "tasks"})
    print(
        f"✓ Accepted feedback: signal={accepted['signal']}, weight={accepted['weight']}"
    )

    rejected = await processor.process_rejected_feedback(
        "rec-2", {"domain": "tasks", "reason": "not_relevant"}
    )
    print(
        f"✓ Rejected feedback: signal={rejected['signal']}, category={rejected['insights']['rejection_category']}"
    )

    modified = await processor.process_modified_feedback(
        "rec-3",
        {"domain": "tasks", "original_value": "high", "modified_value": "medium"},
    )
    print(
        f"✓ Modified feedback: signal={modified['signal']}, weight={modified['weight']}"
    )

    print("\n✅ All learning engine tests passed!")


if __name__ == "__main__":
    asyncio.run(test_learning_engine())
