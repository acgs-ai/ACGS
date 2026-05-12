"""
Task Prioritization Recommender
Provides intelligent task priority recommendations based on multiple factors
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from backend.utils.timeutil import utcnow
import logging

logger = logging.getLogger(__name__)


class TaskPrioritizer:
    """
    Recommends task priorities based on:
    - Deadlines and urgency
    - Dependencies and blockers
    - Resource availability
    - Project importance
    """

    def __init__(self):
        self.name = "Task Prioritizer"
        logger.info(f"{self.name} initialized")

    async def recommend(self, task_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate priority recommendation for a task.

        Args:
            task_id: Task ID to recommend for
            context: Context including task details, dependencies, resources

        Returns:
            Recommendation with confidence, rationale, and suggested priority
        """
        # Stub implementation - will integrate with actual task data once CRUD APIs are ready
        task_data = context.get("task_data", {})

        # Calculate priority score based on multiple factors
        priority_score = self._calculate_priority_score(task_data)
        confidence = self._calculate_confidence(task_data)

        # Determine recommended priority
        if priority_score >= 0.8:
            recommended_priority = "urgent"
        elif priority_score >= 0.6:
            recommended_priority = "high"
        elif priority_score >= 0.4:
            recommended_priority = "medium"
        else:
            recommended_priority = "low"

        # Generate rationale
        rationale = self._generate_rationale(task_data, priority_score)

        return {
            "suggestion": f"Set priority to '{recommended_priority}'",
            "confidence": confidence,
            "rationale": rationale,
            "metadata": {
                "priority_score": priority_score,
                "recommended_priority": recommended_priority,
                "factors": self._get_priority_factors(task_data),
            },
        }

    def _calculate_priority_score(self, task_data: Dict[str, Any]) -> float:
        """Calculate priority score (0-1) based on task attributes"""
        score = 0.5  # Base score

        # Factor 1: Deadline urgency
        due_date = task_data.get("due_date")
        if due_date:
            days_until_due = self._days_until(due_date)
            if days_until_due <= 1:
                score += 0.3
            elif days_until_due <= 3:
                score += 0.2
            elif days_until_due <= 7:
                score += 0.1

        # Factor 2: Blocking other tasks
        blocks_count = len(task_data.get("blocks", []))
        if blocks_count > 0:
            score += min(0.2, blocks_count * 0.05)

        # Factor 3: Project importance
        project_priority = task_data.get("project_priority", "medium")
        if project_priority == "high":
            score += 0.1
        elif project_priority == "urgent":
            score += 0.15

        return min(1.0, max(0.0, score))

    def _calculate_confidence(self, task_data: Dict[str, Any]) -> float:
        """Calculate confidence in the recommendation"""
        confidence = 0.7  # Base confidence

        # Higher confidence if we have more data
        if task_data.get("due_date"):
            confidence += 0.1
        if task_data.get("estimated_hours"):
            confidence += 0.05
        if task_data.get("assignee_id"):
            confidence += 0.05
        if task_data.get("project_id"):
            confidence += 0.1

        return min(1.0, confidence)

    def _generate_rationale(
        self, task_data: Dict[str, Any], priority_score: float
    ) -> str:
        """Generate human-readable rationale for the recommendation"""
        reasons = []

        due_date = task_data.get("due_date")
        if due_date:
            days_until_due = self._days_until(due_date)
            if days_until_due <= 1:
                reasons.append(
                    f"Due in {days_until_due} day(s) - immediate attention required"
                )
            elif days_until_due <= 7:
                reasons.append(f"Due in {days_until_due} days - approaching deadline")

        blocks_count = len(task_data.get("blocks", []))
        if blocks_count > 0:
            reasons.append(f"Blocks {blocks_count} other task(s)")

        project_priority = task_data.get("project_priority")
        if project_priority in ["high", "urgent"]:
            reasons.append(f"Part of {project_priority}-priority project")

        if not reasons:
            reasons.append("Based on standard priority assessment")

        return ". ".join(reasons) + "."

    def _get_priority_factors(self, task_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract priority factors for transparency"""
        return {
            "has_deadline": task_data.get("due_date") is not None,
            "blocks_count": len(task_data.get("blocks", [])),
            "project_priority": task_data.get("project_priority", "unknown"),
            "has_assignee": task_data.get("assignee_id") is not None,
        }

    def _days_until(self, date_str: str) -> int:
        """Calculate days until a date"""
        try:
            if isinstance(date_str, str):
                target_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            else:
                target_date = date_str
            delta = target_date - utcnow()
            return max(0, delta.days)
        except Exception:
            return 999  # Unknown date

    async def get_top_recommendations(
        self, limit: int = 10, min_confidence: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Get top task priority recommendations.

        Stub implementation - will query actual tasks once CRUD APIs are ready.
        """
        # Placeholder: return empty list until task CRUD is available
        logger.info(
            f"Top recommendations requested (limit={limit}, min_confidence={min_confidence})"
        )
        return []
