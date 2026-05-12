"""
Event Bus System
Asynchronous event-driven architecture for cross-domain communication
"""

from typing import Dict, List, Callable, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from backend.utils.timeutil import utcnow
from uuid import UUID, uuid4
import asyncio
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class EventType(str, Enum):
    """Enumeration of system event types."""

    # Project events
    PROJECT_CREATED = "project.created"
    PROJECT_UPDATED = "project.updated"
    PROJECT_COMPLETED = "project.completed"

    # Task events
    TASK_CREATED = "task.created"
    TASK_COMPLETED = "task.completed"
    TASK_ASSIGNED = "task.assigned"

    # Asset events
    ASSET_CREATED = "asset.created"
    ASSET_ALLOCATED = "asset.allocated"
    ASSET_MAINTENANCE_DUE = "asset.maintenance_due"
    ASSET_DECOMMISSIONED = "asset.decommissioned"

    # Financial events
    FINANCIAL_RECORD_CREATED = "financial.created"
    FINANCIAL_APPROVED = "financial.approved"
    FINANCIAL_REJECTED = "financial.rejected"

    # Infrastructure events
    INFRASTRUCTURE_DEGRADED = "infrastructure.degraded"
    INFRASTRUCTURE_DOWN = "infrastructure.down"


@dataclass
class Event:
    """Event data structure."""

    event_type: EventType
    payload: Dict[str, Any]
    event_id: UUID = field(default_factory=uuid4)
    timestamp: datetime = field(default_factory=utcnow)
    source: Optional[str] = None
    correlation_id: Optional[UUID] = None


class EventBus:
    """
    Asynchronous event bus for pub/sub messaging.
    Supports event handlers, filtering, and async processing.
    """

    def __init__(self):
        self._handlers: Dict[EventType, List[Callable]] = {}
        self._event_history: List[Event] = []
        self._max_history = 1000

    def subscribe(self, event_type: EventType, handler: Callable):
        """
        Subscribe a handler to an event type.

        Args:
            event_type: Type of event to listen for
            handler: Async function to handle the event
        """
        if event_type not in self._handlers:
            self._handlers[event_type] = []
        self._handlers[event_type].append(handler)
        logger.info(f"Subscribed handler {handler.__name__} to {event_type}")

    def unsubscribe(self, event_type: EventType, handler: Callable):
        """Unsubscribe a handler from an event type."""
        if event_type in self._handlers:
            self._handlers[event_type].remove(handler)
            logger.info(f"Unsubscribed handler {handler.__name__} from {event_type}")

    async def publish(self, event: Event):
        """
        Publish an event to all subscribed handlers.

        Args:
            event: Event to publish
        """
        logger.info(f"Publishing event: {event.event_type} (ID: {event.event_id})")

        # Store in history
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history.pop(0)

        # Get handlers for this event type
        handlers = self._handlers.get(event.event_type, [])

        if not handlers:
            logger.warning(f"No handlers registered for event type: {event.event_type}")
            return

        # Execute all handlers concurrently
        tasks = []
        for handler in handlers:
            try:
                task = asyncio.create_task(handler(event))
                tasks.append(task)
            except Exception as e:
                logger.error(f"Error creating task for handler {handler.__name__}: {e}")

        # Wait for all handlers to complete
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    logger.error(f"Handler {handlers[i].__name__} failed: {result}")

    def get_event_history(
        self, event_type: Optional[EventType] = None, limit: int = 100
    ) -> List[Event]:
        """
        Get event history, optionally filtered by type.

        Args:
            event_type: Optional filter by event type
            limit: Maximum number of events to return

        Returns:
            List of events
        """
        events = self._event_history
        if event_type:
            events = [e for e in events if e.event_type == event_type]
        return events[-limit:]


# Global event bus instance
_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    """Get the global event bus instance."""
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus


async def emit_event(
    event_type: EventType,
    payload: Dict[str, Any],
    source: Optional[str] = None,
    correlation_id: Optional[UUID] = None,
):
    """
    Convenience function to emit an event.

    Args:
        event_type: Type of event
        payload: Event data
        source: Optional source identifier
        correlation_id: Optional correlation ID for tracking related events
    """
    event = Event(
        event_type=event_type,
        payload=payload,
        source=source,
        correlation_id=correlation_id,
    )
    bus = get_event_bus()
    await bus.publish(event)
