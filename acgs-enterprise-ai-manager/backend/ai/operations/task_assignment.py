"""
Task Assignment Autonomous Operation Handler
Automatically assigns tasks to team members based on workload and skills
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
from backend.utils.timeutil import utcnow
import logging

logger = logging.getLogger(__name__)


class TaskAssignmentHandler:
    """
    Handles autonomous task assignment operations.

    Analyzes team workload, task requirements, and member skills
    to automatically assign tasks to optimal team members.
    """

    def __init__(self):
        self.name = "Task Assignment Handler"
        logger.info(f"{self.name} initialized")

    async def execute(
        self, details: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Execute autonomous task assignment.

        Args:
            details: Task assignment details including task_id, candidate_members
            context: Context including workload data, skill requirements

        Returns:
            Dict containing assignment result
        """
        task_id = details.get("task_id")
        candidate_members = details.get("candidate_members", [])

        if not task_id:
            raise ValueError("task_id is required")

        if not candidate_members:
            raise ValueError("candidate_members list is required")

        logger.info(f"Executing autonomous task assignment for task {task_id}")

        # Analyze workload for each candidate
        workload_scores = self._analyze_workload(candidate_members, context)

        # Analyze skill match for each candidate
        skill_scores = self._analyze_skills(candidate_members, context)

        # Calculate combined scores
        combined_scores = {}
        for member_id in candidate_members:
            workload_weight = 0.6
            skill_weight = 0.4

            combined_scores[member_id] = (
                workload_scores.get(member_id, 0) * workload_weight
                + skill_scores.get(member_id, 0) * skill_weight
            )

        # Select best candidate
        best_member = max(combined_scores.items(), key=lambda x: x[1])
        assigned_member_id = best_member[0]
        assignment_confidence = best_member[1]

        # Prepare assignment result
        result = {
            "task_id": task_id,
            "assigned_to": assigned_member_id,
            "confidence": assignment_confidence,
            "assigned_at": utcnow().isoformat(),
            "reasoning": self._generate_reasoning(
                assigned_member_id, workload_scores, skill_scores, combined_scores
            ),
            "alternative_candidates": [
                {"member_id": member_id, "score": score}
                for member_id, score in sorted(
                    combined_scores.items(), key=lambda x: x[1], reverse=True
                )[
                    1:4
                ]  # Top 3 alternatives
            ],
        }

        logger.info(
            f"Task {task_id} assigned to {assigned_member_id} "
            f"(confidence: {assignment_confidence:.2f})"
        )

        return result

    def _analyze_workload(
        self, candidate_members: List[str], context: Dict[str, Any]
    ) -> Dict[str, float]:
        """
        Analyze workload for each candidate member.

        Args:
            candidate_members: List of candidate member IDs
            context: Context with workload data

        Returns:
            Dict mapping member_id to workload score (0-1, higher is better)
        """
        workload_data = context.get("workload_data", {})
        scores = {}

        for member_id in candidate_members:
            member_workload = workload_data.get(member_id, {})

            # Factors: active tasks, upcoming deadlines, capacity
            active_tasks = member_workload.get("active_tasks", 0)
            capacity = member_workload.get("capacity", 10)
            urgent_tasks = member_workload.get("urgent_tasks", 0)

            # Calculate workload score (inverse of utilization)
            utilization = (active_tasks + urgent_tasks * 1.5) / capacity
            workload_score = max(0, 1 - utilization)

            scores[member_id] = workload_score

        return scores

    def _analyze_skills(
        self, candidate_members: List[str], context: Dict[str, Any]
    ) -> Dict[str, float]:
        """
        Analyze skill match for each candidate member.

        Args:
            candidate_members: List of candidate member IDs
            context: Context with skill requirements and member skills

        Returns:
            Dict mapping member_id to skill score (0-1, higher is better)
        """
        required_skills = context.get("required_skills", [])
        member_skills = context.get("member_skills", {})

        if not required_skills:
            # No specific skills required, all members equal
            return {member_id: 0.5 for member_id in candidate_members}

        scores = {}

        for member_id in candidate_members:
            skills = member_skills.get(member_id, [])

            # Calculate skill match percentage
            matched_skills = len(set(required_skills) & set(skills))
            skill_score = (
                matched_skills / len(required_skills) if required_skills else 0.5
            )

            scores[member_id] = skill_score

        return scores

    def _generate_reasoning(
        self,
        assigned_member_id: str,
        workload_scores: Dict[str, float],
        skill_scores: Dict[str, float],
        combined_scores: Dict[str, float],
    ) -> str:
        """
        Generate human-readable reasoning for assignment decision.

        Args:
            assigned_member_id: Selected member ID
            workload_scores: Workload scores for all candidates
            skill_scores: Skill scores for all candidates
            combined_scores: Combined scores for all candidates

        Returns:
            Reasoning string
        """
        workload = workload_scores.get(assigned_member_id, 0)
        skill = skill_scores.get(assigned_member_id, 0)
        combined = combined_scores.get(assigned_member_id, 0)

        reasoning_parts = [
            f"Selected member {assigned_member_id} with overall score {combined:.2f}."
        ]

        if workload > 0.7:
            reasoning_parts.append(f"Member has low workload (score: {workload:.2f}).")
        elif workload < 0.3:
            reasoning_parts.append(
                f"Member has high workload but best available (score: {workload:.2f})."
            )

        if skill > 0.8:
            reasoning_parts.append(f"Strong skill match (score: {skill:.2f}).")
        elif skill > 0.5:
            reasoning_parts.append(f"Adequate skill match (score: {skill:.2f}).")
        else:
            reasoning_parts.append(
                f"Limited skill match but best available (score: {skill:.2f})."
            )

        return " ".join(reasoning_parts)

    async def validate(
        self, details: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Validate task assignment parameters before execution.

        Args:
            details: Task assignment details
            context: Context data

        Returns:
            Validation result dict
        """
        errors = []

        if not details.get("task_id"):
            errors.append("task_id is required")

        if not details.get("candidate_members"):
            errors.append("candidate_members list is required")
        elif len(details.get("candidate_members", [])) == 0:
            errors.append("candidate_members list cannot be empty")

        return {"valid": len(errors) == 0, "errors": errors}
