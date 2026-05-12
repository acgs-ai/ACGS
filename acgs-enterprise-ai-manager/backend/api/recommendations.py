"""
Recommendations API Endpoints
Provides REST API for AI recommendation generation and management
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime
from backend.utils.timeutil import utcnow
import logging

from backend.database import get_db
from backend.ai.recommendation_engine import RecommendationEngine, RecommendationDomain
from backend.governance.acgs_integration import get_governance

logger = logging.getLogger(__name__)

router = APIRouter()

# Initialize recommendation engine (will be done at app startup)
_recommendation_engine: Optional[RecommendationEngine] = None


def get_recommendation_engine() -> RecommendationEngine:
    """Dependency to get recommendation engine instance"""
    global _recommendation_engine
    if _recommendation_engine is None:
        governance = get_governance()
        _recommendation_engine = RecommendationEngine(governance_integration=governance)
    return _recommendation_engine


# Pydantic models for request/response
class RecommendationRequest(BaseModel):
    """Request model for generating a recommendation"""

    domain: str = Field(..., description="Domain to generate recommendation for")
    entity_id: str = Field(..., description="Entity ID to recommend for")
    context: dict = Field(default_factory=dict, description="Additional context data")


class RecommendationResponse(BaseModel):
    """Response model for a recommendation"""

    id: Optional[str] = None
    domain: str
    entity_id: str
    suggestion: str
    confidence: float
    rationale: str
    status: str
    metadata: dict
    generated_at: str
    governance_check: Optional[dict] = None


class BatchRecommendationRequest(BaseModel):
    """Request model for batch recommendations"""

    domain: str
    entity_ids: List[str]
    context: dict = Field(default_factory=dict)


@router.post(
    "/generate",
    response_model=RecommendationResponse,
    status_code=status.HTTP_201_CREATED,
)
async def generate_recommendation(
    request: RecommendationRequest,
    db: AsyncSession = Depends(get_db),
    engine: RecommendationEngine = Depends(get_recommendation_engine),
):
    """
    Generate a recommendation for a specific entity.

    Args:
        request: Recommendation request with domain, entity_id, and context
        db: Database session
        engine: Recommendation engine instance

    Returns:
        Generated recommendation with confidence and rationale
    """
    try:
        # Validate domain
        try:
            domain = RecommendationDomain(request.domain)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid domain: {request.domain}. Supported: {engine.get_supported_domains()}",
            )

        # Generate recommendation
        recommendation = await engine.generate_recommendation(
            domain=domain, entity_id=request.entity_id, context=request.context
        )

        # TODO: Store recommendation in database once schema is ready
        # For now, return the generated recommendation
        logger.info(f"Generated recommendation for {domain}:{request.entity_id}")

        return RecommendationResponse(**recommendation)

    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to generate recommendation: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate recommendation",
        )


@router.post("/batch", response_model=List[RecommendationResponse])
async def batch_generate_recommendations(
    request: BatchRecommendationRequest,
    db: AsyncSession = Depends(get_db),
    engine: RecommendationEngine = Depends(get_recommendation_engine),
):
    """
    Generate recommendations for multiple entities.

    Args:
        request: Batch request with domain, entity_ids, and context
        db: Database session
        engine: Recommendation engine instance

    Returns:
        List of generated recommendations
    """
    try:
        # Validate domain
        try:
            domain = RecommendationDomain(request.domain)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid domain: {request.domain}",
            )

        # Generate batch recommendations
        recommendations = await engine.batch_recommend(
            domain=domain, entity_ids=request.entity_ids, context=request.context
        )

        logger.info(f"Generated {len(recommendations)} recommendations for {domain}")

        return [
            RecommendationResponse(**rec)
            for rec in recommendations
            if rec.get("status") != "error"
        ]

    except Exception as e:
        logger.error(f"Failed to generate batch recommendations: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate batch recommendations",
        )


@router.get("/top/{domain}", response_model=List[RecommendationResponse])
async def get_top_recommendations(
    domain: str,
    limit: int = Query(10, ge=1, le=100),
    min_confidence: float = Query(0.5, ge=0.0, le=1.0),
    db: AsyncSession = Depends(get_db),
    engine: RecommendationEngine = Depends(get_recommendation_engine),
):
    """
    Get top recommendations for a domain.

    Args:
        domain: Domain to get recommendations for
        limit: Maximum number of recommendations (1-100)
        min_confidence: Minimum confidence threshold (0.0-1.0)
        db: Database session
        engine: Recommendation engine instance

    Returns:
        List of top recommendations sorted by confidence
    """
    try:
        # Validate domain
        try:
            domain_enum = RecommendationDomain(domain)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid domain: {domain}",
            )

        # Get top recommendations
        recommendations = await engine.get_top_recommendations(
            domain=domain_enum, limit=limit, min_confidence=min_confidence
        )

        return [RecommendationResponse(**rec) for rec in recommendations]

    except Exception as e:
        logger.error(f"Failed to get top recommendations: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get top recommendations",
        )


@router.get("/domains", response_model=List[str])
async def get_supported_domains(
    engine: RecommendationEngine = Depends(get_recommendation_engine),
):
    """
    Get list of supported recommendation domains.

    Returns:
        List of domain names
    """
    return engine.get_supported_domains()


@router.get("/stats", response_model=dict)
async def get_recommender_stats(
    engine: RecommendationEngine = Depends(get_recommendation_engine),
):
    """
    Get recommendation engine statistics.

    Returns:
        Statistics about recommender performance and configuration
    """
    return engine.get_recommender_stats()


@router.get("/health")
async def health_check():
    """Health check endpoint for recommendation service"""
    return {
        "status": "healthy",
        "service": "recommendations",
        "timestamp": utcnow().isoformat(),
    }
