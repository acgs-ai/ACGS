"""
AI Learning Engine
Implements feedback-based learning to improve recommendation quality over time
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from backend.utils.timeutil import utcnow
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)


class LearningEngine:
    """
    Learning engine that improves recommendations based on user feedback.

    Tracks:
    - Feedback patterns (accepted/rejected/modified)
    - Domain-specific performance metrics
    - Feature importance adjustments
    - Confidence calibration
    """

    def __init__(self):
        self.name = "Learning Engine"
        # In-memory storage for feedback (will integrate with database later)
        self.feedback_history = []
        self.performance_metrics = defaultdict(
            lambda: {
                "total": 0,
                "accepted": 0,
                "rejected": 0,
                "modified": 0,
                "avg_confidence": 0.0,
            }
        )
        logger.info(f"{self.name} initialized")

    async def process_feedback(
        self,
        recommendation_id: str,
        feedback_type: str,
        feedback_data: Dict[str, Any],
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Process user feedback on a recommendation.

        Args:
            recommendation_id: ID of the recommendation
            feedback_type: Type of feedback (accepted, rejected, modified)
            feedback_data: Additional feedback data
            user_id: User who provided feedback

        Returns:
            Processing result with learning updates
        """
        if feedback_type not in ["accepted", "rejected", "modified"]:
            raise ValueError(f"Invalid feedback type: {feedback_type}")

        # Store feedback
        feedback_record = {
            "recommendation_id": recommendation_id,
            "feedback_type": feedback_type,
            "feedback_data": feedback_data,
            "user_id": user_id,
            "timestamp": utcnow().isoformat(),
        }
        self.feedback_history.append(feedback_record)

        # Extract domain and update metrics
        domain = feedback_data.get("domain", "unknown")
        confidence = feedback_data.get("confidence", 0.0)

        metrics = self.performance_metrics[domain]
        metrics["total"] += 1
        metrics[feedback_type] += 1

        # Update running average confidence
        total = metrics["total"]
        metrics["avg_confidence"] = (
            metrics["avg_confidence"] * (total - 1) + confidence
        ) / total

        # Calculate acceptance rate
        acceptance_rate = (
            metrics["accepted"] / metrics["total"] if metrics["total"] > 0 else 0
        )

        logger.info(
            f"Feedback processed: {domain} - {feedback_type} "
            f"(acceptance rate: {acceptance_rate:.2%})"
        )

        # Trigger learning update if enough feedback accumulated
        learning_update = None
        if metrics["total"] % 10 == 0:  # Every 10 feedback items
            learning_update = await self._update_model(domain)

        return {
            "feedback_id": len(self.feedback_history),
            "processed_at": utcnow().isoformat(),
            "domain_metrics": dict(metrics),
            "acceptance_rate": acceptance_rate,
            "learning_update": learning_update,
        }

    async def _update_model(self, domain: str) -> Dict[str, Any]:
        """
        Update recommendation model based on accumulated feedback.

        Args:
            domain: Domain to update model for

        Returns:
            Update summary
        """
        metrics = self.performance_metrics[domain]

        # Calculate adjustments based on feedback patterns
        acceptance_rate = metrics["accepted"] / metrics["total"]
        rejection_rate = metrics["rejected"] / metrics["total"]

        # Confidence calibration adjustment
        confidence_adjustment = 0.0
        if acceptance_rate > 0.8:
            # High acceptance - can be more confident
            confidence_adjustment = 0.05
        elif rejection_rate > 0.5:
            # High rejection - should be less confident
            confidence_adjustment = -0.05

        update = {
            "domain": domain,
            "updated_at": utcnow().isoformat(),
            "feedback_count": metrics["total"],
            "acceptance_rate": acceptance_rate,
            "confidence_adjustment": confidence_adjustment,
            "status": "applied",
        }

        logger.info(f"Model updated for {domain}: {update}")
        return update

    async def get_performance_metrics(
        self, domain: Optional[str] = None, time_window_days: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Get performance metrics for recommendations.

        Args:
            domain: Optional domain filter
            time_window_days: Optional time window in days

        Returns:
            Performance metrics
        """
        if domain:
            metrics = dict(self.performance_metrics[domain])
            return {
                "domain": domain,
                "metrics": metrics,
                "acceptance_rate": (
                    metrics["accepted"] / metrics["total"]
                    if metrics["total"] > 0
                    else 0
                ),
            }

        # Return all domains
        all_metrics = {}
        for dom, metrics in self.performance_metrics.items():
            all_metrics[dom] = {
                **dict(metrics),
                "acceptance_rate": (
                    metrics["accepted"] / metrics["total"]
                    if metrics["total"] > 0
                    else 0
                ),
            }

        return {"domains": all_metrics, "total_feedback": len(self.feedback_history)}

    async def get_improvement_trends(
        self, domain: str, window_size: int = 10
    ) -> Dict[str, Any]:
        """
        Calculate improvement trends over time.

        Args:
            domain: Domain to analyze
            window_size: Number of recent feedback items to analyze

        Returns:
            Trend analysis
        """
        # Filter feedback for domain
        domain_feedback = [
            f
            for f in self.feedback_history
            if f["feedback_data"].get("domain") == domain
        ]

        if len(domain_feedback) < window_size:
            return {
                "domain": domain,
                "status": "insufficient_data",
                "feedback_count": len(domain_feedback),
                "required": window_size,
            }

        # Calculate acceptance rate for recent window
        recent = domain_feedback[-window_size:]
        recent_accepted = sum(1 for f in recent if f["feedback_type"] == "accepted")
        recent_rate = recent_accepted / len(recent)

        # Calculate acceptance rate for previous window
        if len(domain_feedback) >= window_size * 2:
            previous = domain_feedback[-window_size * 2 : -window_size]
            previous_accepted = sum(
                1 for f in previous if f["feedback_type"] == "accepted"
            )
            previous_rate = previous_accepted / len(previous)
            improvement = recent_rate - previous_rate
        else:
            previous_rate = None
            improvement = None

        return {
            "domain": domain,
            "recent_acceptance_rate": recent_rate,
            "previous_acceptance_rate": previous_rate,
            "improvement": improvement,
            "trend": (
                "improving"
                if improvement and improvement > 0
                else "stable" if improvement == 0 else "declining"
            ),
            "window_size": window_size,
        }

    async def get_feature_importance(self, domain: str) -> Dict[str, Any]:
        """
        Analyze which features are most important for recommendations.

        Args:
            domain: Domain to analyze

        Returns:
            Feature importance analysis
        """
        # Stub implementation - will be enhanced with actual ML analysis
        domain_feedback = [
            f
            for f in self.feedback_history
            if f["feedback_data"].get("domain") == domain
        ]

        if not domain_feedback:
            return {"domain": domain, "status": "no_data", "features": {}}

        # Placeholder feature importance
        features = {
            "confidence_score": 0.8,
            "rationale_quality": 0.7,
            "timeliness": 0.6,
            "relevance": 0.9,
        }

        return {
            "domain": domain,
            "features": features,
            "feedback_count": len(domain_feedback),
        }

    def get_learning_stats(self) -> Dict[str, Any]:
        """Get overall learning system statistics"""
        total_feedback = len(self.feedback_history)
        domains_tracked = len(self.performance_metrics)

        overall_accepted = sum(m["accepted"] for m in self.performance_metrics.values())
        overall_total = sum(m["total"] for m in self.performance_metrics.values())
        overall_acceptance = (
            overall_accepted / overall_total if overall_total > 0 else 0
        )

        return {
            "total_feedback": total_feedback,
            "domains_tracked": domains_tracked,
            "overall_acceptance_rate": overall_acceptance,
            "learning_updates_applied": sum(
                m["total"] // 10 for m in self.performance_metrics.values()
            ),
        }


# Singleton instance
_learning_engine: Optional[LearningEngine] = None


def get_learning_engine() -> LearningEngine:
    """Get or create the global learning engine instance"""
    global _learning_engine
    if _learning_engine is None:
        _learning_engine = LearningEngine()
    return _learning_engine
