"""
Asset Maintenance Autonomous Operation Handler
Automatically schedules and triggers asset maintenance based on usage patterns
"""

from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from backend.utils.timeutil import utcnow
import logging

logger = logging.getLogger(__name__)


class AssetMaintenanceHandler:
    """
    Handles autonomous asset maintenance operations.

    Analyzes asset usage patterns, maintenance history, and lifecycle stage
    to automatically schedule and trigger maintenance activities.
    """

    def __init__(self):
        self.name = "Asset Maintenance Handler"
        logger.info(f"{self.name} initialized")

    async def execute(
        self, details: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute autonomous asset maintenance scheduling.

        Args:
            details: Maintenance details including asset_id, maintenance_type
            context: Context including asset data, usage patterns, maintenance history

        Returns:
            Dict containing maintenance scheduling result
        """
        asset_id = details.get("asset_id")
        maintenance_type = details.get("maintenance_type", "preventive")

        if not asset_id:
            raise ValueError("asset_id is required")

        logger.info(f"Executing autonomous maintenance scheduling for asset {asset_id}")

        # Analyze asset condition
        asset_condition = self._analyze_asset_condition(asset_id, context)

        # Determine maintenance urgency
        urgency = self._determine_urgency(asset_condition, context)

        # Calculate optimal maintenance window
        maintenance_window = self._calculate_maintenance_window(
            asset_id, urgency, context
        )

        # Estimate maintenance duration and cost
        estimates = self._estimate_maintenance(
            asset_id, maintenance_type, asset_condition, context
        )

        # Prepare maintenance schedule result
        result = {
            "asset_id": asset_id,
            "maintenance_type": maintenance_type,
            "urgency": urgency,
            "scheduled_start": maintenance_window["start"],
            "scheduled_end": maintenance_window["end"],
            "estimated_duration_hours": estimates["duration_hours"],
            "estimated_cost": estimates["cost"],
            "asset_condition": asset_condition,
            "reasoning": self._generate_reasoning(
                asset_id, maintenance_type, urgency, asset_condition, estimates
            ),
            "maintenance_tasks": self._generate_maintenance_tasks(
                maintenance_type, asset_condition
            ),
            "scheduled_at": utcnow().isoformat(),
        }

        logger.info(
            f"Maintenance scheduled for asset {asset_id}: "
            f"{maintenance_type} ({urgency} urgency) "
            f"on {maintenance_window['start']}"
        )

        return result

    def _analyze_asset_condition(
        self, asset_id: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze current condition of the asset.

        Args:
            asset_id: Asset ID
            context: Context with asset data and usage patterns

        Returns:
            Dict containing condition analysis
        """
        asset_data = context.get("asset_data", {})
        usage_data = context.get("usage_data", {})
        maintenance_history = context.get("maintenance_history", [])

        # Calculate asset age
        acquisition_date = asset_data.get("acquisition_date")
        if acquisition_date:
            age_days = (
                utcnow() - datetime.fromisoformat(acquisition_date)
            ).days
        else:
            age_days = 0

        # Analyze usage intensity
        usage_hours = usage_data.get("total_hours", 0)
        usage_intensity = usage_data.get("intensity", "normal")  # low, normal, high

        # Days since last maintenance
        if maintenance_history:
            last_maintenance = max(
                maintenance_history, key=lambda x: x.get("completed_at", "1970-01-01")
            )
            last_maintenance_date = datetime.fromisoformat(
                last_maintenance.get("completed_at", utcnow().isoformat())
            )
            days_since_maintenance = (utcnow() - last_maintenance_date).days
        else:
            days_since_maintenance = age_days

        # Calculate condition score (0-1, higher is better)
        condition_score = 1.0

        # Age factor
        if age_days > 1825:  # 5 years
            condition_score -= 0.3
        elif age_days > 1095:  # 3 years
            condition_score -= 0.2
        elif age_days > 730:  # 2 years
            condition_score -= 0.1

        # Usage factor
        if usage_intensity == "high":
            condition_score -= 0.2
        elif usage_intensity == "low":
            condition_score += 0.1

        # Maintenance factor
        if days_since_maintenance > 180:  # 6 months
            condition_score -= 0.3
        elif days_since_maintenance > 90:  # 3 months
            condition_score -= 0.1

        condition_score = max(0, min(1, condition_score))

        return {
            "score": condition_score,
            "age_days": age_days,
            "usage_hours": usage_hours,
            "usage_intensity": usage_intensity,
            "days_since_maintenance": days_since_maintenance,
            "status": self._get_condition_status(condition_score),
        }

    def _determine_urgency(
        self, asset_condition: Dict[str, Any], context: Dict[str, Any]
    ) -> str:
        """
        Determine maintenance urgency level.

        Args:
            asset_condition: Asset condition analysis
            context: Additional context

        Returns:
            Urgency level: 'low', 'medium', 'high', 'critical'
        """
        condition_score = asset_condition["score"]
        days_since_maintenance = asset_condition["days_since_maintenance"]

        # Critical urgency
        if condition_score < 0.3 or days_since_maintenance > 365:
            return "critical"

        # High urgency
        if condition_score < 0.5 or days_since_maintenance > 180:
            return "high"

        # Medium urgency
        if condition_score < 0.7 or days_since_maintenance > 90:
            return "medium"

        # Low urgency
        return "low"

    def _calculate_maintenance_window(
        self, asset_id: str, urgency: str, context: Dict[str, Any]
    ) -> Dict[str, str]:
        """
        Calculate optimal maintenance window.

        Args:
            asset_id: Asset ID
            urgency: Maintenance urgency level
            context: Context with scheduling constraints

        Returns:
            Dict with start and end datetime strings
        """
        now = utcnow()

        # Determine scheduling based on urgency
        if urgency == "critical":
            # Schedule immediately
            start = now + timedelta(hours=2)
            duration = timedelta(hours=4)
        elif urgency == "high":
            # Schedule within 24 hours
            start = now + timedelta(hours=12)
            duration = timedelta(hours=3)
        elif urgency == "medium":
            # Schedule within 1 week
            start = now + timedelta(days=3)
            duration = timedelta(hours=2)
        else:
            # Schedule within 2 weeks
            start = now + timedelta(days=7)
            duration = timedelta(hours=2)

        # Adjust for business hours (9 AM - 5 PM)
        # This is a simplified version
        if start.hour < 9:
            start = start.replace(hour=9, minute=0)
        elif start.hour > 17:
            start = (start + timedelta(days=1)).replace(hour=9, minute=0)

        end = start + duration

        return {"start": start.isoformat(), "end": end.isoformat()}

    def _estimate_maintenance(
        self,
        asset_id: str,
        maintenance_type: str,
        asset_condition: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Estimate maintenance duration and cost.

        Args:
            asset_id: Asset ID
            maintenance_type: Type of maintenance
            asset_condition: Asset condition analysis
            context: Additional context

        Returns:
            Dict with duration and cost estimates
        """
        # Base estimates by maintenance type
        base_estimates = {
            "preventive": {"hours": 2, "cost": 500},
            "corrective": {"hours": 4, "cost": 1000},
            "predictive": {"hours": 1, "cost": 300},
            "emergency": {"hours": 6, "cost": 2000},
        }

        base = base_estimates.get(maintenance_type, {"hours": 2, "cost": 500})

        # Adjust based on asset condition
        condition_score = asset_condition["score"]
        if condition_score < 0.3:
            multiplier = 1.5
        elif condition_score < 0.5:
            multiplier = 1.3
        elif condition_score < 0.7:
            multiplier = 1.1
        else:
            multiplier = 1.0

        return {
            "duration_hours": base["hours"] * multiplier,
            "cost": base["cost"] * multiplier,
            "confidence": 0.8 if condition_score > 0.5 else 0.6,
        }

    def _generate_reasoning(
        self,
        asset_id: str,
        maintenance_type: str,
        urgency: str,
        asset_condition: Dict[str, Any],
        estimates: Dict[str, Any],
    ) -> str:
        """
        Generate human-readable reasoning for maintenance decision.

        Args:
            asset_id: Asset ID
            maintenance_type: Type of maintenance
            urgency: Urgency level
            asset_condition: Asset condition analysis
            estimates: Maintenance estimates

        Returns:
            Reasoning string
        """
        condition_score = asset_condition["score"]
        days_since = asset_condition["days_since_maintenance"]

        reasoning_parts = [
            f"Scheduled {maintenance_type} maintenance for asset {asset_id} with {urgency} urgency."
        ]

        if condition_score < 0.5:
            reasoning_parts.append(
                f"Asset condition is poor (score: {condition_score:.2f})."
            )
        elif condition_score < 0.7:
            reasoning_parts.append(
                f"Asset condition is fair (score: {condition_score:.2f})."
            )

        if days_since > 180:
            reasoning_parts.append(
                f"Last maintenance was {days_since} days ago, exceeding recommended interval."
            )
        elif days_since > 90:
            reasoning_parts.append(
                f"Last maintenance was {days_since} days ago, approaching recommended interval."
            )

        reasoning_parts.append(
            f"Estimated duration: {estimates['duration_hours']:.1f} hours, "
            f"cost: ${estimates['cost']:.2f}."
        )

        return " ".join(reasoning_parts)

    def _generate_maintenance_tasks(
        self, maintenance_type: str, asset_condition: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """
        Generate list of maintenance tasks to perform.

        Args:
            maintenance_type: Type of maintenance
            asset_condition: Asset condition analysis

        Returns:
            List of maintenance task dicts
        """
        tasks = []

        if maintenance_type == "preventive":
            tasks = [
                {"task": "Inspect hardware components", "priority": "high"},
                {"task": "Clean and lubricate moving parts", "priority": "medium"},
                {"task": "Update firmware/software", "priority": "high"},
                {"task": "Test functionality", "priority": "high"},
                {"task": "Document findings", "priority": "medium"},
            ]
        elif maintenance_type == "corrective":
            tasks = [
                {"task": "Diagnose issue", "priority": "critical"},
                {"task": "Replace faulty components", "priority": "critical"},
                {"task": "Test repairs", "priority": "high"},
                {"task": "Verify functionality", "priority": "high"},
                {"task": "Update maintenance log", "priority": "medium"},
            ]
        elif maintenance_type == "predictive":
            tasks = [
                {"task": "Collect sensor data", "priority": "high"},
                {"task": "Analyze performance metrics", "priority": "high"},
                {"task": "Identify potential issues", "priority": "medium"},
                {"task": "Recommend preventive actions", "priority": "medium"},
            ]

        return tasks

    @staticmethod
    def _get_condition_status(condition_score: float) -> str:
        """Get condition status label from score"""
        if condition_score >= 0.8:
            return "excellent"
        elif condition_score >= 0.6:
            return "good"
        elif condition_score >= 0.4:
            return "fair"
        elif condition_score >= 0.2:
            return "poor"
        else:
            return "critical"

    async def validate(
        self, details: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate asset maintenance parameters before execution.

        Args:
            details: Maintenance details
            context: Context data

        Returns:
            Validation result dict
        """
        errors = []

        if not details.get("asset_id"):
            errors.append("asset_id is required")

        maintenance_type = details.get("maintenance_type", "preventive")
        valid_types = ["preventive", "corrective", "predictive", "emergency"]
        if maintenance_type not in valid_types:
            errors.append(f"maintenance_type must be one of: {', '.join(valid_types)}")

        return {"valid": len(errors) == 0, "errors": errors}
