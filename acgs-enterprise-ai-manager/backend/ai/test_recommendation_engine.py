"""
Basic tests for AI Recommendation Engine
"""

import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.ai.recommendation_engine import RecommendationEngine, RecommendationDomain


async def test_recommendation_engine():
    """Test basic recommendation engine functionality"""
    print("Testing AI Recommendation Engine...")

    # Initialize engine without governance (stub mode)
    engine = RecommendationEngine(governance_integration=None)

    # Test 1: Check supported domains
    domains = engine.get_supported_domains()
    print(f"✓ Supported domains: {domains}")
    assert len(domains) == 3, "Should support 3 domains"

    # Test 2: Generate task recommendation
    task_context = {
        "task_data": {
            "due_date": "2026-04-26T10:00:00Z",
            "blocks": ["task-2", "task-3"],
            "project_priority": "high",
            "assignee_id": "user-1",
        }
    }
    task_rec = await engine.generate_recommendation(
        domain=RecommendationDomain.TASKS, entity_id="task-1", context=task_context
    )
    print(f"✓ Task recommendation: {task_rec['suggestion']}")
    print(f"  Confidence: {task_rec['confidence']}")
    print(f"  Rationale: {task_rec['rationale']}")
    assert task_rec["confidence"] > 0, "Should have confidence score"
    assert task_rec["status"] == "approved", "Should be approved without governance"

    # Test 3: Generate asset recommendation
    asset_context = {
        "asset_data": {
            "type": "server",
            "lifecycle_stage": "aging",
            "purchase_date": "2020-01-01T00:00:00Z",
            "status": "active",
        }
    }
    asset_rec = await engine.generate_recommendation(
        domain=RecommendationDomain.ASSETS, entity_id="asset-1", context=asset_context
    )
    print(f"✓ Asset recommendation: {asset_rec['suggestion']}")
    print(f"  Confidence: {asset_rec['confidence']}")

    # Test 4: Generate project risk assessment
    project_context = {
        "project_data": {
            "budget": 100000,
            "actual_cost": 85000,
            "status": "active",
            "end_date": "2026-05-01T00:00:00Z",
            "team": ["user-1"],
        }
    }
    project_rec = await engine.generate_recommendation(
        domain=RecommendationDomain.PROJECTS,
        entity_id="project-1",
        context=project_context,
    )
    print(f"✓ Project recommendation: {project_rec['suggestion']}")
    print(f"  Confidence: {project_rec['confidence']}")

    # Test 5: Get stats
    stats = engine.get_recommender_stats()
    print(f"✓ Engine stats: {stats}")

    print("\n✅ All tests passed!")


if __name__ == "__main__":
    asyncio.run(test_recommendation_engine())
