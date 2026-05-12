"""
Project Risk Assessment Recommender
Provides risk identification and mitigation recommendations for projects
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from backend.utils.timeutil import utcnow
import logging

logger = logging.getLogger(__name__)


class ProjectRiskAssessor:
    """
    Assesses project risks and recommends mitigation strategies:
    - Budget overrun risks
    - Schedule delay risks
    - Resource allocation risks
    - Dependency risks
    """

    def __init__(self):
        self.name = "Project Risk Assessor"
        logger.info(f"{self.name} initialized")

    async def recommend(
        self, project_id: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate risk assessment and mitigation recommendation for a project.

        Args:
            project_id: Project ID to assess
            context: Context including project details, tasks, budget, resources

        Returns:
            Recommendation with confidence, rationale, and risk mitigation strategies
        """
        # Stub implementation - will integrate with actual project data once CRUD APIs are ready
        project_data = context.get("project_data", {})

        # Assess multiple risk dimensions
        risks = self._assess_risks(project_data)
        highest_risk = max(risks, key=lambda r: r["severity"]) if risks else None

        if highest_risk:
            suggestion = (
                f"Mitigate {highest_risk['type']} risk: {highest_risk['mitigation']}"
            )
            confidence = highest_risk["confidence"]
            rationale = highest_risk["rationale"]
        else:
            suggestion = "No significant risks identified. Continue monitoring."
            confidence = 0.70
            rationale = "Project metrics are within acceptable ranges."

        return {
            "suggestion": suggestion,
            "confidence": confidence,
            "rationale": rationale,
            "metadata": {
                "identified_risks": risks,
                "risk_count": len(risks),
                "highest_severity": highest_risk["severity"] if highest_risk else 0,
            },
        }

    def _assess_risks(self, project_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Assess multiple risk dimensions"""
        risks = []

        # Budget risk
        budget_risk = self._assess_budget_risk(project_data)
        if budget_risk:
            risks.append(budget_risk)

        # Schedule risk
        schedule_risk = self._assess_schedule_risk(project_data)
        if schedule_risk:
            risks.append(schedule_risk)

        # Resource risk
        resource_risk = self._assess_resource_risk(project_data)
        if resource_risk:
            risks.append(resource_risk)

        return risks

    def _assess_budget_risk(
        self, project_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Assess budget overrun risk"""
        budget = project_data.get("budget", 0)
        actual_cost = project_data.get("actual_cost", 0)

        if budget <= 0:
            return None

        utilization = actual_cost / budget
        status = project_data.get("status", "planning")

        # High risk if over 80% budget used but project not near completion
        if utilization > 0.8 and status not in ["completed", "cancelled"]:
            return {
                "type": "budget_overrun",
                "severity": min(1.0, utilization),
                "confidence": 0.85,
                "rationale": f"Budget utilization at {utilization*100:.1f}% with project status '{status}'. Risk of overrun.",
                "mitigation": "Review remaining work scope and consider budget adjustment or scope reduction",
            }

        # Medium risk if over 60% budget used
        if utilization > 0.6 and status == "active":
            return {
                "type": "budget_overrun",
                "severity": 0.6,
                "confidence": 0.75,
                "rationale": f"Budget utilization at {utilization*100:.1f}%. Monitor closely to prevent overrun.",
                "mitigation": "Implement stricter cost controls and weekly budget reviews",
            }

        return None

    def _assess_schedule_risk(
        self, project_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Assess schedule delay risk"""
        end_date = project_data.get("end_date")
        status = project_data.get("status", "planning")

        if not end_date or status in ["completed", "cancelled"]:
            return None

        days_remaining = self._days_until(end_date)

        # High risk if deadline is very close
        if days_remaining <= 7 and status != "completed":
            return {
                "type": "schedule_delay",
                "severity": 0.9,
                "confidence": 0.90,
                "rationale": f"Project deadline in {days_remaining} days with status '{status}'. High risk of delay.",
                "mitigation": "Prioritize critical path tasks, consider deadline extension, or reduce scope",
            }

        # Medium risk if deadline approaching
        if days_remaining <= 30 and status == "active":
            return {
                "type": "schedule_delay",
                "severity": 0.6,
                "confidence": 0.75,
                "rationale": f"Project deadline in {days_remaining} days. Monitor progress closely.",
                "mitigation": "Review task completion rates and adjust resource allocation",
            }

        return None

    def _assess_resource_risk(
        self, project_data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Assess resource allocation risk"""
        team = project_data.get("team", [])
        status = project_data.get("status", "planning")

        # Risk if active project has small or no team
        if status == "active" and len(team) < 2:
            return {
                "type": "resource_shortage",
                "severity": 0.7,
                "confidence": 0.80,
                "rationale": f"Active project has only {len(team)} team member(s). Risk of resource bottleneck.",
                "mitigation": "Assign additional team members or adjust project timeline",
            }

        return None

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

    async def get_top_recommendations(
        self, limit: int = 10, min_confidence: float = 0.5
    ) -> List[Dict[str, Any]]:
        """
        Get top project risk recommendations.

        Stub implementation - will query actual projects once CRUD APIs are ready.
        """
        logger.info(
            f"Top recommendations requested (limit={limit}, min_confidence={min_confidence})"
        )
        return []
