"""
Project Initiation Workflow
Workflow: Project creation → auto-generate tasks → allocate assets
"""

from typing import Dict, Any
from uuid import UUID
import logging

from backend.workflows.workflow_engine import Workflow
from backend.events.event_bus import EventType
from backend.models.task import Task
from backend.models.asset import ITAsset
from backend.database import get_db

logger = logging.getLogger(__name__)


async def generate_initial_tasks(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 1: Generate initial tasks for the new project.

    Args:
        context: Workflow context containing project data

    Returns:
        Dict with created task IDs
    """
    trigger_data = context.get("trigger_event", {})
    project_id = trigger_data.get("id")
    project_name = trigger_data.get("name", "New Project")

    if not project_id:
        raise ValueError("Project ID not found in trigger event")

    logger.info(f"Generating initial tasks for project: {project_name} ({project_id})")

    # Define default task templates
    task_templates = [
        {
            "title": f"{project_name} - Planning Phase",
            "description": "Define project scope, requirements, and deliverables",
            "priority": "high",
            "status": "todo",
        },
        {
            "title": f"{project_name} - Resource Allocation",
            "description": "Identify and allocate required resources and team members",
            "priority": "high",
            "status": "todo",
        },
        {
            "title": f"{project_name} - Setup Development Environment",
            "description": "Configure development tools, repositories, and infrastructure",
            "priority": "medium",
            "status": "todo",
        },
        {
            "title": f"{project_name} - Initial Implementation",
            "description": "Begin core feature development",
            "priority": "medium",
            "status": "todo",
        },
    ]

    created_task_ids = []

    async for db in get_db():
        try:
            for template in task_templates:
                task = Task(
                    project_id=UUID(project_id),
                    title=template["title"],
                    description=template["description"],
                    priority=template["priority"],
                    status=template["status"],
                )
                db.add(task)
                await db.flush()
                created_task_ids.append(str(task.id))
                logger.info(f"Created task: {task.title}")

            await db.commit()
            logger.info(
                f"Generated {len(created_task_ids)} tasks for project {project_id}"
            )

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to create tasks: {e}")
            raise
        finally:
            break

    return {"task_ids": created_task_ids, "task_count": len(created_task_ids)}


async def allocate_assets(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 2: Allocate available assets to the project.

    Args:
        context: Workflow context

    Returns:
        Dict with allocated asset IDs
    """
    trigger_data = context.get("trigger_event", {})
    project_id = trigger_data.get("id")

    if not project_id:
        raise ValueError("Project ID not found in context")

    logger.info(f"Allocating assets to project: {project_id}")

    allocated_asset_ids = []

    async for db in get_db():
        try:
            # Find available assets (status = 'available')
            from sqlalchemy import select

            result = await db.execute(
                select(ITAsset).where(ITAsset.status == "available").limit(3)
            )
            available_assets = result.scalars().all()

            if not available_assets:
                logger.warning("No available assets found for allocation")
                return {"asset_ids": [], "asset_count": 0}

            # Allocate assets to project
            for asset in available_assets:
                asset.status = "in_use"
                asset.assigned_to = UUID(
                    project_id
                )  # Assuming assigned_to can be project_id
                allocated_asset_ids.append(str(asset.id))
                logger.info(f"Allocated asset {asset.name} to project {project_id}")

            await db.commit()
            logger.info(
                f"Allocated {len(allocated_asset_ids)} assets to project {project_id}"
            )

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to allocate assets: {e}")
            raise
        finally:
            break

    return {"asset_ids": allocated_asset_ids, "asset_count": len(allocated_asset_ids)}


def create_project_initiation_workflow() -> Workflow:
    """
    Create the project initiation workflow.

    Returns:
        Configured Workflow instance
    """
    workflow = Workflow(
        workflow_id="project_initiation",
        name="Project Initiation Workflow",
        description="Automatically generate tasks and allocate assets when a project is created",
    )

    workflow.add_step(
        name="generate_tasks",
        handler=generate_initial_tasks,
        description="Generate initial project tasks",
        max_retries=2,
    )

    workflow.add_step(
        name="allocate_assets",
        handler=allocate_assets,
        description="Allocate available assets to the project",
        max_retries=2,
    )

    workflow.triggered_by(EventType.PROJECT_CREATED)

    logger.info("Project Initiation Workflow created")
    return workflow
