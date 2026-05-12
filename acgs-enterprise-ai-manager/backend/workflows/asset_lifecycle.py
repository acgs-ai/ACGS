"""
Asset Lifecycle Workflow
Workflow: Asset lifecycle event → trigger maintenance tasks → update project budget
"""

from typing import Dict, Any
from uuid import UUID
from decimal import Decimal
import logging

from backend.workflows.workflow_engine import Workflow
from backend.events.event_bus import EventType
from backend.models.task import Task
from backend.models.project import Project
from backend.models.financial_record import FinancialRecord
from backend.database import get_db

logger = logging.getLogger(__name__)


async def create_maintenance_task(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 1: Create maintenance task for the asset.

    Args:
        context: Workflow context containing asset data

    Returns:
        Dict with created task ID
    """
    trigger_data = context.get("trigger_event", {})
    asset_id = trigger_data.get("id")
    asset_name = trigger_data.get("name", "Asset")
    asset_type = trigger_data.get("type", "unknown")

    if not asset_id:
        raise ValueError("Asset ID not found in trigger event")

    logger.info(f"Creating maintenance task for asset: {asset_name} ({asset_id})")

    task_id = None

    async for db in get_db():
        try:
            # Create maintenance task
            task = Task(
                title=f"Maintenance Required: {asset_name}",
                description=f"Perform scheduled maintenance on {asset_type} asset: {asset_name}",
                priority="high",
                status="todo",
                tags=["maintenance", "asset", asset_type],
            )
            db.add(task)
            await db.flush()
            task_id = str(task.id)

            await db.commit()
            logger.info(f"Created maintenance task: {task_id}")

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to create maintenance task: {e}")
            raise
        finally:
            break

    return {"task_id": task_id, "asset_id": asset_id}


async def update_project_budget(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Step 2: Update project budget with maintenance cost.

    Args:
        context: Workflow context

    Returns:
        Dict with updated budget info
    """
    trigger_data = context.get("trigger_event", {})
    asset_id = trigger_data.get("id")
    asset_name = trigger_data.get("name", "Asset")

    logger.info(f"Updating project budget for asset maintenance: {asset_name}")

    # Estimate maintenance cost based on asset type
    maintenance_cost = Decimal("500.00")  # Default maintenance cost

    updated_projects = []

    async for db in get_db():
        try:
            # Find projects using this asset
            from sqlalchemy import select
            from backend.models.asset import ITAsset

            result = await db.execute(
                select(ITAsset).where(ITAsset.id == UUID(asset_id))
            )
            asset = result.scalar_one_or_none()

            if not asset or not asset.assigned_to:
                logger.warning(f"Asset {asset_id} not assigned to any project")
                return {
                    "updated_projects": [],
                    "maintenance_cost": float(maintenance_cost),
                }

            # Get the project
            project_result = await db.execute(
                select(Project).where(Project.id == asset.assigned_to)
            )
            project = project_result.scalar_one_or_none()

            if project:
                # Update project actual cost
                if project.actual_cost is None:
                    project.actual_cost = Decimal("0.00")
                project.actual_cost += maintenance_cost
                updated_projects.append(str(project.id))

                # Create financial record
                financial_record = FinancialRecord(
                    type="expense",
                    amount=maintenance_cost,
                    currency="USD",
                    date=db.execute(select(db.func.current_date())).scalar(),
                    category="maintenance",
                    project_id=project.id,
                    description=f"Maintenance cost for asset: {asset_name}",
                    approval_status="pending",
                )
                db.add(financial_record)

                await db.commit()
                logger.info(
                    f"Updated project {project.id} budget with maintenance cost: ${maintenance_cost}"
                )

        except Exception as e:
            await db.rollback()
            logger.error(f"Failed to update project budget: {e}")
            raise
        finally:
            break

    return {
        "updated_projects": updated_projects,
        "maintenance_cost": float(maintenance_cost),
    }


def create_asset_lifecycle_workflow() -> Workflow:
    """
    Create the asset lifecycle workflow.

    Returns:
        Configured Workflow instance
    """
    workflow = Workflow(
        workflow_id="asset_lifecycle",
        name="Asset Lifecycle Workflow",
        description="Trigger maintenance tasks and update project budgets when assets require maintenance",
    )

    workflow.add_step(
        name="create_maintenance_task",
        handler=create_maintenance_task,
        description="Create maintenance task for the asset",
        max_retries=2,
    )

    workflow.add_step(
        name="update_project_budget",
        handler=update_project_budget,
        description="Update project budget with maintenance cost",
        max_retries=2,
    )

    workflow.triggered_by(EventType.ASSET_MAINTENANCE_DUE)

    logger.info("Asset Lifecycle Workflow created")
    return workflow
