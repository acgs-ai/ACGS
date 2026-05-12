"""
Asset Lifecycle Management Recommender
Provides recommendations for IT asset lifecycle decisions
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from backend.utils.timeutil import utcnow
import logging

logger = logging.getLogger(__name__)


class AssetLifecycleRecommender:
    """
    Recommends asset lifecycle actions:
    - Upgrade recommendations based on age and performance
    - Maintenance scheduling based on usage patterns
    - Retirement recommendations for end-of-life assets
    """

    def __init__(self):
        self.name = "Asset Lifecycle Recommender"
        logger.info(f"{self.name} initialized")

    async def recommend(self, asset_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate lifecycle recommendation for an asset.

        Args:
            asset_id: Asset ID to recommend for
            context: Context including asset details, usage, maintenance history

        Returns:
            Recommendation with confidence, rationale, and suggested action
        """
        # Stub implementation - will integrate with actual asset data once CRUD APIs are ready
        asset_data = context.get("asset_data", {})

        # Determine lifecycle stage and recommended action
        lifecycle_stage = asset_data.get("lifecycle_stage", "operational")
        action, confidence, rationale = self._determine_action(
            asset_data, lifecycle_stage
        )

        return {
            "suggestion": action,
            "confidence": confidence,
            "rationale": rationale,
            "metadata": {
                "current_lifecycle_stage": lifecycle_stage,
                "asset_age_days": self._calculate_asset_age(asset_data),
                "factors": self._get_lifecycle_factors(asset_data),
            },
        }

    def _determine_action(
        self, asset_data: Dict[str, Any], lifecycle_stage: str
    ) -> tuple[str, float, str]:
        """Determine recommended action based on asset data"""
        asset_type = asset_data.get("type", "unknown")
        age_days = self._calculate_asset_age(asset_data)
        status = asset_data.get("status", "active")

        # End of life detection
        if lifecycle_stage == "end_of_life" or age_days > 1825:  # 5 years
            return (
                f"Retire {asset_type} and plan replacement",
                0.85,
                f"Asset is {age_days} days old and in end-of-life stage. Retirement recommended to avoid support issues.",
            )

        # Aging assets need maintenance
        if lifecycle_stage == "aging" or age_days > 1095:  # 3 years
            return (
                f"Schedule maintenance for {asset_type}",
                0.75,
                f"Asset is {age_days} days old and entering aging phase. Proactive maintenance recommended.",
            )

        # Check warranty expiry
        warranty_expiry = asset_data.get("warranty_expiry")
        if warranty_expiry:
            days_until_expiry = self._days_until(warranty_expiry)
            if 0 < days_until_expiry <= 90:
                return (
                    f"Renew warranty for {asset_type} (expires in {days_until_expiry} days)",
                    0.80,
                    f"Warranty expires in {days_until_expiry} days. Consider renewal or replacement.",
                )

        # Operational assets - monitor
        if status == "active" and lifecycle_stage in ["new", "operational"]:
            return (
                f"Continue monitoring {asset_type}",
                0.65,
                f"Asset is in good condition ({lifecycle_stage} stage). Continue regular monitoring.",
            )

        # Default recommendation
        return (
            f"Review {asset_type} status",
            0.60,
            "Asset requires review to determine appropriate lifecycle action.",
        )

    def _calculate_asset_age(self, asset_data: Dict[str, Any]) -> int:
        """Calculate asset age in days"""
        purchase_date = asset_data.get("purchase_date")
        if not purchase_date:
            return 0

        try:
            if isinstance(purchase_date, str):
                purchase_dt = datetime.fromisoformat(
                    purchase_date.replace("Z", "+00:00")
                )
            else:
                purchase_dt = purchase_date
            age = utcnow() - purchase_dt
            return max(0, age.days)
        except Exception:
            return 0

    def _days_until(self, date_str: str) -> int:
        """Calculate days until a date"""
        try:
            if isinstance(date_str, str):
                target_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
            else:
                target_date = date_str
            delta = target_date - utcnow()
            return delta.days
        except Exception:
            return 999

    def _get_lifecycle_factors(self, asset_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract lifecycle factors for transparency"""
        return {
            "asset_type": asset_data.get("type", "unknown"),
            "status": asset_data.get("status", "unknown"),
            "age_days": self._calculate_asset_age(asset_data),
            "has_warranty": asset_data.get("warranty_expiry") is not None,
            "lifecycle_stage": asset_data.get("lifecycle_stage", "unknown"),
        }

    async def get_top_recommendations(
        self, limit: int = 10, min_confidence: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Get top asset lifecycle recommendations.

        Stub implementation - will query actual assets once CRUD APIs are ready.
        """
        logger.info(
            f"Top recommendations requested (limit={limit}, min_confidence={min_confidence})"
        )
        return []
