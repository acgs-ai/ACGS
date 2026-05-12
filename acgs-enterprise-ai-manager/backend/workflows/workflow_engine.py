"""
Workflow Engine
Orchestrates multi-step workflows with state tracking and error handling
"""

from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
from backend.utils.timeutil import utcnow
from uuid import UUID, uuid4
from enum import Enum
import asyncio
import logging

from backend.events.event_bus import Event, EventType, get_event_bus

logger = logging.getLogger(__name__)


class WorkflowStatus(str, Enum):
    """Workflow execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(str, Enum):
    """Workflow step status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class WorkflowStep:
    """Individual step in a workflow."""

    name: str
    handler: Callable
    description: str = ""
    retry_count: int = 0
    max_retries: int = 3
    status: StepStatus = StepStatus.PENDING
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class WorkflowExecution:
    """Tracks a workflow execution instance."""

    workflow_id: str
    execution_id: UUID = field(default_factory=uuid4)
    status: WorkflowStatus = WorkflowStatus.PENDING
    steps: List[WorkflowStep] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    trigger_event: Optional[Event] = None


class Workflow:
    """
    Defines a workflow with multiple steps.
    """

    def __init__(self, workflow_id: str, name: str, description: str = ""):
        self.workflow_id = workflow_id
        self.name = name
        self.description = description
        self.steps: List[WorkflowStep] = []
        self.trigger_events: List[EventType] = []

    def add_step(
        self, name: str, handler: Callable, description: str = "", max_retries: int = 3
    ):
        """Add a step to the workflow."""
        step = WorkflowStep(
            name=name, handler=handler, description=description, max_retries=max_retries
        )
        self.steps.append(step)
        return self

    def triggered_by(self, *event_types: EventType):
        """Define which events trigger this workflow."""
        self.trigger_events.extend(event_types)
        return self


class WorkflowEngine:
    """
    Workflow execution engine with state tracking and error handling.
    """

    def __init__(self):
        self.workflows: Dict[str, Workflow] = {}
        self.executions: Dict[UUID, WorkflowExecution] = {}
        self.event_bus = get_event_bus()

    def register_workflow(self, workflow: Workflow):
        """
        Register a workflow and subscribe to its trigger events.

        Args:
            workflow: Workflow to register
        """
        self.workflows[workflow.workflow_id] = workflow
        logger.info(
            f"Registered workflow: {workflow.name} (ID: {workflow.workflow_id})"
        )

        # Subscribe to trigger events
        for event_type in workflow.trigger_events:
            self.event_bus.subscribe(event_type, self._create_event_handler(workflow))
            logger.info(f"Workflow {workflow.name} subscribed to {event_type}")

    def _create_event_handler(self, workflow: Workflow):
        """Create an event handler for a workflow."""

        async def handler(event: Event):
            logger.info(
                f"Workflow {workflow.name} triggered by event {event.event_type}"
            )
            await self.execute_workflow(workflow.workflow_id, event)

        return handler

    async def execute_workflow(
        self,
        workflow_id: str,
        trigger_event: Optional[Event] = None,
        initial_context: Optional[Dict[str, Any]] = None,
    ) -> WorkflowExecution:
        """
        Execute a workflow.

        Args:
            workflow_id: ID of workflow to execute
            trigger_event: Event that triggered the workflow
            initial_context: Initial context data

        Returns:
            WorkflowExecution instance
        """
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            raise ValueError(f"Workflow {workflow_id} not found")

        # Create execution instance
        execution = WorkflowExecution(
            workflow_id=workflow_id,
            steps=[
                WorkflowStep(
                    name=step.name,
                    handler=step.handler,
                    description=step.description,
                    max_retries=step.max_retries,
                )
                for step in workflow.steps
            ],
            context=initial_context or {},
            trigger_event=trigger_event,
            started_at=utcnow(),
        )

        # Add trigger event data to context
        if trigger_event:
            execution.context["trigger_event"] = trigger_event.payload
            execution.context["event_id"] = str(trigger_event.event_id)

        self.executions[execution.execution_id] = execution
        execution.status = WorkflowStatus.RUNNING

        logger.info(
            f"Starting workflow execution: {workflow.name} (Execution ID: {execution.execution_id})"
        )

        try:
            # Execute steps sequentially
            for step in execution.steps:
                await self._execute_step(step, execution)

                if step.status == StepStatus.FAILED:
                    execution.status = WorkflowStatus.FAILED
                    execution.error = f"Step '{step.name}' failed: {step.error}"
                    break

            if execution.status == WorkflowStatus.RUNNING:
                execution.status = WorkflowStatus.COMPLETED
                logger.info(f"Workflow execution completed: {workflow.name}")

        except Exception as e:
            execution.status = WorkflowStatus.FAILED
            execution.error = str(e)
            logger.error(
                f"Workflow execution failed: {workflow.name} - {e}", exc_info=True
            )

        execution.completed_at = utcnow()
        return execution

    async def _execute_step(self, step: WorkflowStep, execution: WorkflowExecution):
        """Execute a single workflow step with retry logic."""
        step.status = StepStatus.RUNNING
        step.started_at = utcnow()

        logger.info(f"Executing step: {step.name}")

        while step.retry_count <= step.max_retries:
            try:
                # Execute step handler with execution context
                result = await step.handler(execution.context)

                # Update context with step result
                if result:
                    execution.context[step.name] = result

                step.status = StepStatus.COMPLETED
                step.completed_at = utcnow()
                logger.info(f"Step completed: {step.name}")
                return

            except Exception as e:
                step.retry_count += 1
                step.error = str(e)
                logger.error(
                    f"Step {step.name} failed (attempt {step.retry_count}/{step.max_retries}): {e}"
                )

                if step.retry_count > step.max_retries:
                    step.status = StepStatus.FAILED
                    step.completed_at = utcnow()
                    return

                # Wait before retry
                await asyncio.sleep(2**step.retry_count)

    def get_execution(self, execution_id: UUID) -> Optional[WorkflowExecution]:
        """Get a workflow execution by ID."""
        return self.executions.get(execution_id)

    def get_workflow_executions(self, workflow_id: str) -> List[WorkflowExecution]:
        """Get all executions for a workflow."""
        return [e for e in self.executions.values() if e.workflow_id == workflow_id]


# Global workflow engine instance
_workflow_engine: Optional[WorkflowEngine] = None


def get_workflow_engine() -> WorkflowEngine:
    """Get the global workflow engine instance."""
    global _workflow_engine
    if _workflow_engine is None:
        _workflow_engine = WorkflowEngine()
    return _workflow_engine
