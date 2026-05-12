"""
Feedback API Endpoints
REST API for submitting and managing recommendation feedback
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from backend.utils.timeutil import utcnow
import logging

from backend.database import get_db
from backend.ai.learning_engine import get_learning_engine, LearningEngine
from backend.ai.feedback_processor import FeedbackProcessor

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize feedback processor
feedback_processor = FeedbackProcessor()


# Pydantic models
class FeedbackSubmission(BaseModel):
    """Request model for submitting feedback"""

    recommendation_id: str = Field(..., description="ID of the recommendation")
    feedback_type: str = Field(
        ..., description="Type of feedback: accepted, rejected, modified"
    )
    reason: Optional[str] = Field(
        None, description="Reason for rejection (if rejected)"
    )
    comment: Optional[str] = Field(None, description="Additional comments")
    original_value: Optional[str] = Field(
        None, description="Original value (if modified)"
    )
    modified_value: Optional[str] = Field(
        None, description="Modified value (if modified)"
    )
    domain: str = Field(..., description="Domain of the recommendation")
    confidence: Optional[float] = Field(
        None, ge=0.0, le=1.0, description="Original confidence score"
    )


class FeedbackResponse(BaseModel):
    """Response model for feedback submission"""

    feedback_id: int
    processed_at: str
    domain_metrics: dict
    acceptance_rate: float
    learning_update: Optional[dict] = None


class PerformanceMetrics(BaseModel):
    """Response model for performance metrics"""

    domain: Optional[str] = None
    metrics: Optional[dict] = None
    domains: Optional[dict] = None
    total_feedback: Optional[int] = None
    acceptance_rate: Optional[float] = None


@router.post(
    "/submit", response_model=FeedbackResponse, status_code=status.HTTP_201_CREATED
)
async def submit_feedback(
    feedback: FeedbackSubmission,
    db: AsyncSession = Depends(get_db),
    learning_engine: LearningEngine = Depends(get_learning_engine),
):
    """
    Submit feedback on a recommendation.

    Args:
        feedback: Feedback submission data
        db: Database session
        learning_engine: Learning engine instance

    Returns:
        Feedback processing result
    """
    try:
        # Validate feedback
        feedback_data = {
            "recommendation_id": feedback.recommendation_id,
            "domain": feedback.domain,
            "confidence": feedback.confidence,
            "reason": feedback.reason,
            "comment": feedback.comment,
            "original_value": feedback.original_value,
            "modified_value": feedback.modified_value,
        }

        validation = await feedback_processor.validate_feedback(
            feedback.feedback_type, feedback_data
        )

        if not validation["valid"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"errors": validation["errors"]},
            )

        # Process feedback based on type
        if feedback.feedback_type == "accepted":
            processed = await feedback_processor.process_accepted_feedback(
                feedback.recommendation_id, feedback_data
            )
        elif feedback.feedback_type == "rejected":
            processed = await feedback_processor.process_rejected_feedback(
                feedback.recommendation_id, feedback_data
            )
        elif feedback.feedback_type == "modified":
            processed = await feedback_processor.process_modified_feedback(
                feedback.recommendation_id, feedback_data
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid feedback type: {feedback.feedback_type}",
            )

        # Submit to learning engine
        result = await learning_engine.process_feedback(
            recommendation_id=feedback.recommendation_id,
            feedback_type=feedback.feedback_type,
            feedback_data=feedback_data,
        )

        logger.info(
            f"Feedback submitted for {feedback.recommendation_id}: {feedback.feedback_type}"
        )

        return FeedbackResponse(**result)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to submit feedback: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to submit feedback",
        )


@router.get("/metrics", response_model=PerformanceMetrics)
async def get_performance_metrics(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    time_window_days: Optional[int] = Query(
        None, ge=1, le=365, description="Time window in days"
    ),
    learning_engine: LearningEngine = Depends(get_learning_engine),
):
    """
    Get performance metrics for recommendations.

    Args:
        domain: Optional domain filter
        time_window_days: Optional time window in days
        learning_engine: Learning engine instance

    Returns:
        Performance metrics
    """
    try:
        metrics = await learning_engine.get_performance_metrics(
            domain=domain, time_window_days=time_window_days
        )

        return PerformanceMetrics(**metrics)

    except Exception as e:
        logger.error(f"Failed to get performance metrics: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get performance metrics",
        )


@router.get("/trends/{domain}")
async def get_improvement_trends(
    domain: str,
    window_size: int = Query(
        10, ge=5, le=100, description="Window size for trend analysis"
    ),
    learning_engine: LearningEngine = Depends(get_learning_engine),
):
    """
    Get improvement trends for a domain.

    Args:
        domain: Domain to analyze
        window_size: Number of recent feedback items to analyze
        learning_engine: Learning engine instance

    Returns:
        Trend analysis
    """
    try:
        trends = await learning_engine.get_improvement_trends(
            domain=domain, window_size=window_size
        )

        return trends

    except Exception as e:
        logger.error(f"Failed to get improvement trends: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get improvement trends",
        )


@router.get("/features/{domain}")
async def get_feature_importance(
    domain: str, learning_engine: LearningEngine = Depends(get_learning_engine)
):
    """
    Get feature importance analysis for a domain.

    Args:
        domain: Domain to analyze
        learning_engine: Learning engine instance

    Returns:
        Feature importance analysis
    """
    try:
        features = await learning_engine.get_feature_importance(domain)

        return features

    except Exception as e:
        logger.error(f"Failed to get feature importance: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get feature importance",
        )


@router.get("/stats")
async def get_learning_stats(
    learning_engine: LearningEngine = Depends(get_learning_engine),
):
    """
    Get overall learning system statistics.

    Returns:
        Learning system stats
    """
    return learning_engine.get_learning_stats()


@router.get("/health")
async def health_check():
    """Health check endpoint for feedback service"""
    return {
        "status": "healthy",
        "service": "feedback",
        "timestamp": utcnow().isoformat(),
    }
