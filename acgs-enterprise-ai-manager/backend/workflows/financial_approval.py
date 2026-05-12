"""
Financial Approval Workflow
Workflow: Financial approval → update project status → notify team
"""

from typing import Dict, Any
from uuid import UUID
import logging

from backend.workflows.workflow_engine import Workflow
from backend.events.event_bus import EventType
from backend.models.project import Project
from backend.models.financial_record import FinancialRecord
from backend.database import get_db

logger = logging.getLogger(__name__)


async def update_project_status(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 1: Update project status based on financial approval.

    Args:
        context: Workflow context containing financial record data

    Returns:
        Dict with updated project info
    """
    trigger_data = context.get(
        "trigger_event",
    )
    financial_id = trigger_data.get("id")
    project_id = trigger_data.get("project_id")
    amount = trigger_data.get("amount")
    record_type = trigger_data.get("type")

    if not financial_id:
        raise ValueError("Financial record ID not found in trigger event")

    logger.info(f"Processing financial approval for record: {financial_id}")

    updated_project_id = None
    project_status = None

    if project_id:
        async for db in get_db():
            try:
                # Get the project
                from sqlalchemy import select

                result = await db.execute(
                    select(Project).where(Project.id == UUID(project_id))
                )
                project = result.scalar_one_or_none()

                if project:
                    # Update project based on financial record type
                    if record_type == "budget_allocation":
                        # Budget approved - move project to active if it was planning
                        if project.status == "planning":
                            project.status = "active"
                            logger.info(f"Project {project_id} moved to active status")

                    elif record_type == "expense":
                        # Track expenses against budget
                        if project.actual_cost and project.budget:
                            if project.actual_cost >= project.budget * 0.9:
                                logger.warning(
                                    f"Project {project_id} approaching budget limit"
                                )

                    updated_project_id = str(project.id)
                    project_status = project.status

                    await db.commit()
                    logger.info(
                        f"Updated project {project_id} status to {project_status}"
                    )

            except Exception as e:
                await db.rollback()
                logger.error(f"Failed to update project status: {e}")
                raise
            finally:
                break

    return {
        "project_id": updated_project_id,
        "project_status": project_status,
        "financial_id": financial_id,
    }


async def notify_team(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 2: Send notifications to team members.

    Args:
        context: Workflow context

    Returns:
        Dict with notification info
    """
    trigger_data = context.get("trigger_event", {})
    project_id = trigger_data.get("project_id")
    amount = trigger_data.get("amount")
    record_type = trigger_data.get("type")

    update_result = context.get("update_project_status", {})
    project_status = update_result.get("project_status")

    logger.info(f"Sending notifications for financial approval")

    notifications_sent = []

    async for db in get_db():
        try:
            if project_id:
                # Get project details
                from sqlalchemy import select

                result = await db.execute(
                    select(Project).where(Project.id == UUID(project_id))
                )
                project = result.scalar_one_or_none()

                if project:
                    # In a real system, this would send emails/notifications
                    # For now, we'll log the notification
                    notification_message = (
                        f"Financial record approved for project '{project.name}': "
                        f"{record_type} of ${amount}. "
                        f"Project status: {project_status}"
                    )

                    logger.info(f"NOTIFICATION: {notification_message}")

                    # Simulate notification to project owner
                    if project.owner_id:
                        notifications_sent.append(
                            {
                                "recipient_id": str(project.owner_id),
                                "message": notification_message,
                                "type": "financial_approval",
                            }
                        )

                    # Simulate notification to team members
                    if project.team:
                        for member in project.team:
                            if isinstance(member, dict) and "user_id" in member:
                                notifications_sent.append(
                                    {
                                        "recipient_id": member["user_id"],
                                        "message": notification_message,
                                        "type": "financial_approval",
                                    }
                                )

            logger.info(f"Sent {len(notifications_sent)} notifications")

        except Exception as e:
            logger.error(f"Failed to send notifications: {e}")
            # Don't raise - notifications are non-critical
        finally:
            break

    return {
        "notifications_sent": len(notifications_sent),
        "recipients": [n["recipient_id"] for n in notifications_sent],
    }


def create_financial_approval_workflow() -> Workflow:
    """
    Create the financial approval workflow.

    Returns:
        Configured Workflow instance
    """
    workflow = Workflow(
        workflow_id="financial_approval",
        name="Financial Approval Workflow",
        description="Update project status and notify team when financial records are approved",
    )

    workflow.add_step(
        name="update_project_status",
        handler=update_project_status,
        description="Update project status based on financial approval",
        max_retries=2,
    )

    workflow.add_step(
        name="notify_team",
        handler=notify_team,
        description="Send notifications to project team members",
        max_retries=1,
    )

    workflow.triggered_by(EventType.FINANCIAL_APPROVED)

    logger.info("Financial Approval Workflow created")
    return workflow
