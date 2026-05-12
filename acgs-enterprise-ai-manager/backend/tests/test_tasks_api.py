"""
Task API Tests
Unit tests for Task CRUD endpoints
"""

import pytest
from httpx import AsyncClient
from uuid import uuid4
from datetime import datetime, timedelta


@pytest.mark.asyncio
async def test_create_task(client: AsyncClient):
    """Test creating a new task."""
    task_data = {
        "title": "Test Task",
        "description": "This is a test task",
        "status": "todo",
        "priority": "high",
        "tags": ["test", "api"],
    }

    response = await client.post("/api/v1/tasks/", json=task_data)
    assert response.status_code == 201

    data = response.json()
    assert data["title"] == task_data["title"]
    assert data["description"] == task_data["description"]
    assert data["status"] == task_data["status"]
    assert data["priority"] == task_data["priority"]
    assert "id" in data
    assert "created_at" in data


@pytest.mark.asyncio
async def test_get_task(client: AsyncClient, sample_task):
    """Test retrieving a task by ID."""
    response = await client.get(f"/api/v1/tasks/{sample_task['id']}")
    assert response.status_code == 200

    data = response.json()
    assert data["id"] == sample_task["id"]
    assert data["title"] == sample_task["title"]


@pytest.mark.asyncio
async def test_list_tasks(client: AsyncClient, sample_task):
    """Test listing tasks with pagination."""
    response = await client.get("/api/v1/tasks/")
    assert response.status_code == 200

    data = response.json()
    assert "items" in data
    assert "total" in data
    assert len(data["items"]) > 0


@pytest.mark.asyncio
async def test_update_task(client: AsyncClient, sample_task):
    """Test updating a task."""
    update_data = {
        "title": "Updated Task Title",
        "status": "in_progress",
        "priority": "urgent",
    }

    response = await client.put(f"/api/v1/tasks/{sample_task['id']}", json=update_data)
    assert response.status_code == 200

    data = response.json()
    assert data["title"] == update_data["title"]
    assert data["status"] == update_data["status"]


@pytest.mark.asyncio
async def test_delete_task(client: AsyncClient, sample_task):
    """Test deleting a task."""
    response = await client.delete(f"/api/v1/tasks/{sample_task['id']}")
    assert response.status_code == 204


# Fixtures
@pytest.fixture
async def sample_task(client: AsyncClient):
    """Create a sample task for testing."""
    task_data = {
        "title": "Sample Task",
        "description": "Sample description",
        "status": "todo",
        "priority": "medium",
        "tags": ["sample"],
    }

    response = await client.post("/api/v1/tasks/", json=task_data)
    return response.json()
