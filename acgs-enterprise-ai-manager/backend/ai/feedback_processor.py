"""
Feedback Processor
Processes and validates user feedback on recommendations
"""

from typing import Dict, Any, Optional
from datetime import datetime
from backend.utils.timeutil import utcnow
import logging

logger = logging.getLogger(__name__)


class FeedbackProcessor:
    """
    Processes user feedback on recommendations.
    Validates feedback, extracts insights, and prepares for learning.
    """

    def __init__(self):
        self.name = "Feedback Processor"
        logger.info(f"{self.name} initialized")

    async def validate_feedback(
        self, feedback_type: str, feedback_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate feedback data.

        Args:
            feedback_type: Type of feedback
            feedback_data: Feedback data to validate

        Returns:
            Validation result
        """
        errors = []

        # Validate feedback type
        valid_types = ["accepted", "rejected", "modified"]
        if feedback_type not in valid_types:
            errors.append(f"Invalid feedback type. Must be one of: {valid_types}")

        # Validate required fields
        required_fields = ["recommendation_id", "domain"]
        for field in required_fields:
            if field not in feedback_data:
                errors.append(f"Missing required field: {field}")

        # Validate optional fields
        if "confidence" in feedback_data:
            confidence = feedback_data["confidence"]
            if not isinstance(confidence, (int, float)) or not (0 <= confidence <= 1):
                errors.append("Confidence must be a number between 0 and 1")

        return {"valid": len(errors) == 0, "errors": errors}

    async def process_accepted_feedback(
        self, recommendation_id: str, feedback_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process feedback when recommendation is accepted.

        Args:
            recommendation_id: ID of accepted recommendation
            feedback_data: Additional feedback data

        Returns:
            Processed feedback
        """
        return {
            "recommendation_id": recommendation_id,
            "feedback_type": "accepted",
            "signal": "positive",
            "weight": 1.0,
            "insights": {
                "recommendation_quality": "high",
                "user_satisfaction": "satisfied",
            },
            "processed_at": utcnow().isoformat(),
        }

    async def process_rejected_feedback(
        self, recommendation_id: str, feedback_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process feedback when recommendation is rejected.

        Args:
            recommendation_id: ID of rejected recommendation
            feedback_data: Additional feedback including rejection reason

        Returns:
            Processed feedback
        """
        rejection_reason = feedback_data.get("reason", "not_specified")

        # Categorize rejection reasons
        reason_categories = {
            "not_relevant": "relevance_issue",
            "incorrect": "accuracy_issue",
            "too_late": "timing_issue",
            "already_done": "redundancy_issue",
            "not_specified": "unknown",
        }

        category = reason_categories.get(rejection_reason, "unknown")

        return {
            "recommendation_id": recommendation_id,
            "feedback_type": "rejected",
            "signal": "negative",
            "weight": 1.0,
            "insights": {
                "recommendation_quality": "low",
                "rejection_reason": rejection_reason,
                "rejection_category": category,
                "user_satisfaction": "dissatisfied",
            },
            "processed_at": utcnow().isoformat(),
        }

    async def process_modified_feedback(
        self, recommendation_id: str, feedback_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Process feedback when recommendation is modified before acceptance.

        Args:
            recommendation_id: ID of modified recommendation
            feedback_data: Original and modified values

        Returns:
            Processed feedback with modification insights
        """
        original = feedback_data.get("original_value")
        modified = feedback_data.get("modified_value")

        # Calculate modification significance
        modification_type = feedback_data.get("modification_type", "unknown")

        return {
            "recommendation_id": recommendation_id,
            "feedback_type": "modified",
            "signal": "mixed",
            "weight": 0.5,  # Partial credit
            "insights": {
                "recommendation_quality": "medium",
                "modification_type": modification_type,
                "original_value": original,
                "modified_value": modified,
                "user_satisfaction": "partially_satisfied",
            },
            "processed_at": utcnow().isoformat(),
        }

    async def extract_insights(
        self, feedback_batch: list[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Extract insights from a batch of feedback.

        Args:
            feedback_batch: List of feedback records

        Returns:
            Aggregated insights
        """
        if not feedback_batch:
            return {"status": "no_data"}

        total = len(feedback_batch)
        accepted = sum(
            1 for f in feedback_batch if f.get("feedback_type") == "accepted"
        )
        rejected = sum(
            1 for f in feedback_batch if f.get("feedback_type") == "rejected"
        )
        modified = sum(
            1 for f in feedback_batch if f.get("feedback_type") == "modified"
        )

        # Calculate quality score (0-100)
        quality_score = (accepted + modified * 0.5) / total * 100 if total > 0 else 0

        # Identify common rejection reasons
        rejection_reasons = [
            f.get("insights", {}).get("rejection_reason")
            for f in feedback_batch
            if f.get("feedback_type") == "rejected"
        ]
        common_reasons = {}
        for reason in rejection_reasons:
            if reason:
                common_reasons[reason] = common_reasons.get(reason, 0) + 1

        return {
            "total_feedback": total,
            "accepted": accepted,
            "rejected": rejected,
            "modified": modified,
            "acceptance_rate": accepted / total if total > 0 else 0,
            "quality_score": quality_score,
            "common_rejection_reasons": common_reasons,
            "insights_extracted_at": utcnow().isoformat(),
        }

    async def prepare_training_data(
        self, feedback_records: list[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Prepare feedback data for model training.

        Args:
            feedback_records: List of feedback records

        Returns:
            Training data structure
        """
        training_samples = []

        for record in feedback_records:
            sample = {
                "features": record.get("feedback_data", {}),
                "label": 1 if record.get("feedback_type") == "accepted" else 0,
                "weight": record.get("weight", 1.0),
                "timestamp": record.get("timestamp"),
            }
            training_samples.append(sample)

        return {
            "samples": training_samples,
            "sample_count": len(training_samples),
            "prepared_at": utcnow().isoformat(),
        }
