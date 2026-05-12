"""
AI Recommendation Engine for ACGS Enterprise Manager
Provides intelligent recommendations across multiple domains with confidence scoring
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from backend.utils.timeutil import utcnow
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class RecommendationDomain(str, Enum):
    """Supported recommendation domains"""

    TASKS = "tasks"
    ASSETS = "assets"
    INFRASTRUCTURE = "infrastructure"
    PROJECTS = "projects"
    FINANCIAL = "financial"
    DOCUMENTS = "documents"


class RecommendationEngine:
    """
    Main recommendation engine coordinating domain-specific recommenders.
    Integrates with governance framework and learning system.
    """

    def __init__(self, governance_integration=None):
        """
        Initialize recommendation engine.

        Args:
            governance_integration: ACGSIntegration instance for governance checks
        """
        self.governance = governance_integration
        self.recommenders = {}
        self._initialize_recommenders()
        logger.info("Recommendation engine initialized")

    def _initialize_recommenders(self):
        """Initialize domain-specific recommenders"""
        from .models.task_prioritizer import TaskPrioritizer
        from .models.asset_lifecycle import AssetLifecycleRecommender
        from .models.project_risk import ProjectRiskAssessor

        self.recommenders[RecommendationDomain.TASKS] = TaskPrioritizer()
        self.recommenders[RecommendationDomain.ASSETS] = AssetLifecycleRecommender()
        self.recommenders[RecommendationDomain.PROJECTS] = ProjectRiskAssessor()

    async def generate_recommendation(
        self,
        domain: RecommendationDomain,
        entity_id: str,
        context: Dict[str, Any],
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate a recommendation for a specific entity.

        Args:
            domain: The domain to generate recommendation for
            entity_id: ID of the entity to recommend for
            context: Additional context data
            user_id: Optional user ID for personalization

        Returns:
            Dict containing recommendation with confidence, rationale, and metadata
        """
        if domain not in self.recommenders:
            raise ValueError(f"No recommender available for domain: {domain}")

        recommender = self.recommenders[domain]

        # Generate recommendation
        recommendation = await recommender.recommend(entity_id, context)

        # Add metadata
        recommendation["domain"] = domain
        recommendation["entity_id"] = entity_id
        recommendation["generated_at"] = utcnow().isoformat()
        recommendation["user_id"] = user_id

        # Governance check if available
        if self.governance:
            validation = self.governance.validate_operation(
                operation=f"generate_recommendation_{domain}",
                context={
                    "domain": domain,
                    "entity_id": entity_id,
                    "confidence": recommendation.get("confidence", 0),
                },
            )
            recommendation["governance_check"] = validation

            if validation["action"] == "BLOCK":
                recommendation["status"] = "blocked"
                recommendation["blocked_reason"] = validation.get("violations", [])
            elif validation["action"] == "REQUIRE_APPROVAL":
                recommendation["status"] = "pending_approval"
            else:
                recommendation["status"] = "approved"
        else:
            recommendation["status"] = "approved"

        logger.info(
            f"Generated {domain} recommendation for {entity_id}: {recommendation['status']}"
        )
        return recommendation

    async def batch_recommend(
        self,
        domain: RecommendationDomain,
        entity_ids: List[str],
        context: Dict[str, Any],
        user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Generate recommendations for multiple entities.

        Args:
            domain: The domain to generate recommendations for
            entity_ids: List of entity IDs
            context: Shared context data
            user_id: Optional user ID for personalization

        Returns:
            List of recommendations
        """
        recommendations = []
        for entity_id in entity_ids:
            try:
                rec = await self.generate_recommendation(
                    domain, entity_id, context, user_id
                )
                recommendations.append(rec)
            except Exception as e:
                logger.error(f"Failed to generate recommendation for {entity_id}: {e}")
                recommendations.append(
                    {
                        "domain": domain,
                        "entity_id": entity_id,
                        "status": "error",
                        "error": str(e),
                    }
                )

        return recommendations

    async def get_top_recommendations(
        self,
        domain: RecommendationDomain,
        limit: int = 10,
        min_confidence: float = 0.5,
        user_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get top recommendations for a domain.

        Args:
            domain: The domain to get recommendations for
            limit: Maximum number of recommendations
            min_confidence: Minimum confidence threshold
            user_id: Optional user ID for personalization

        Returns:
            List of top recommendations sorted by confidence
        """
        if domain not in self.recommenders:
            raise ValueError(f"No recommender available for domain: {domain}")

        recommender = self.recommenders[domain]
        recommendations = await recommender.get_top_recommendations(
            limit, min_confidence
        )

        # Add metadata and governance checks
        for rec in recommendations:
            rec["domain"] = domain
            rec["generated_at"] = utcnow().isoformat()
            rec["user_id"] = user_id

        return recommendations

    def get_supported_domains(self) -> List[str]:
        """Get list of supported recommendation domains"""
        return [domain.value for domain in self.recommenders.keys()]

    def get_recommender_stats(self) -> Dict[str, Any]:
        """Get statistics about recommender performance"""
        stats = {
            "supported_domains": self.get_supported_domains(),
            "total_recommenders": len(self.recommenders),
            "governance_enabled": self.governance is not None,
        }
        return stats
