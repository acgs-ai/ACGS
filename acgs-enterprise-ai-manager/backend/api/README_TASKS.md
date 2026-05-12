# Tasks API Documentation

## Overview

The Tasks API provides complete CRUD operations for task management with cross-domain relationships to Projects, Users, IT Assets, and Infrastructure.

## Endpoints

### Create Task
```
POST /api/v1/tasks/
```

**Request Body:**
```json
{
  "title": "Implement user authentication",
  "description": "Add JWT-based authentication to the API",
  "status": "todo",
  "priority": "high",
  "assignee_id": "uuid",
  "project_id": "uuid",
  "due_date": "2026-05-01T00:00:00Z",
  "estimated_hours": 8.5,
  "tags": ["backend", "security"]
}
```

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "title": "Implement user authentication",
  "description": "Add JWT-based authentication to the API",
  "status": "todo",
  "priority": "high",
  "assignee_id": "uuid",
  "project_id": "uuid",
  "due_date": "2026-05-01T00:00:00Z",
  "estimated_hours": 8.5,
  "actual_hours": null,
  "tags": ["backend", "security"],
  "created_at": "2026-04-25T10:00:00Z",
  "updated_at": "2026-04-25T10:00:00Z",
  "completed_at": null,
  "assignee": {...},
  "project": {...},
  "assets": [],
  "infrastructure": []
}
```

### Get Task
```
GET /api/v1/tasks/{task_id}
```

**Response:** `200 OK` - Returns task with all related entities

### List Tasks
```
GET /api/v1/tasks/?page=1&page_size=50&status=todo&priority=high&search=auth
```

**Query Parameters:**
- `page` (int, default: 1) - Page number
- `page_size` (int, default: 50, max: 100) - Items per page
- `status` (string) - Filter by status: todo, in_progress, blocked, review, done, cancelled
- `priority` (string) - Filter by priority: low, medium, high, urgent
- `assignee_id` (uuid) - Filter by assignee
- `project_id` (uuid) - Filter by project
- `search` (string) - Search in title and description
- `include_relations` (bool, default: false) - Include related entities

**Response:** `200 OK`
```json
{
  "items": [...],
  "total": 150,
  "page": 1,
  "page_size": 50,
  "total_pages": 3
}
```

### Update Task
```
PUT /api/v1/tasks/{task_id}
```

**Request Body:** (all fields optional)
```json
{
  "title": "Updated title",
  "status": "in_progress",
  "actual_hours": 4.5
}
```

**Response:** `200 OK` - Returns updated task

### Delete Task
```
DELETE /api/v1/tasks/{task_id}
```

**Response:** `204 No Content`

### Link Asset to Task
```
POST /api/v1/tasks/{task_id}/assets
```

**Request Body:**
```json
{
  "entity_id": "asset-uuid",
  "relationship_type": "uses"
}
```

**Relationship Types:** uses, requires, configures, maintains

**Response:** `200 OK` - Returns task with linked asset

### Link Infrastructure to Task
```
POST /api/v1/tasks/{task_id}/infrastructure
```

**Request Body:**
```json
{
  "entity_id": "infrastructure-uuid",
  "relationship_type": "deploys_to"
}
```

**Relationship Types:** deploys_to, monitors, configures, maintains

**Response:** `200 OK` - Returns task with linked infrastructure

### Get Project Tasks
```
GET /api/v1/tasks/project/{project_id}?page=1&page_size=50
```

**Response:** `200 OK` - Paginated list of tasks for the project

### Get User Tasks
```
GET /api/v1/tasks/user/{user_id}?page=1&page_size=50
```

**Response:** `200 OK` - Paginated list of tasks assigned to the user

## Status Values

- `todo` - Task not started
- `in_progress` - Task is being worked on
- `blocked` - Task is blocked by dependencies
- `review` - Task is in review
- `done` - Task is completed
- `cancelled` - Task was cancelled

## Priority Values

- `low` - Low priority
- `medium` - Medium priority (default)
- `high` - High priority
- `urgent` - Urgent priority

## Cross-Domain Relationships

Tasks can be linked to:
- **Projects** (N:1) - via `project_id`
- **Users** (N:1) - via `assignee_id`
- **IT Assets** (M:N) - via `/tasks/{id}/assets` endpoint
- **Infrastructure** (M:N) - via `/tasks/{id}/infrastructure` endpoint

## Error Responses

- `400 Bad Request` - Invalid input data
- `404 Not Found` - Task not found
- `422 Unprocessable Entity` - Validation error
- `500 Internal Server Error` - Server error

## Examples

### Create a task and link it to assets
```bash
# Create task
curl -X POST http://localhost:8000/api/v1/tasks/ \
  -H "Content-Type: application/json" \
  -d '{
    "title": "Deploy new server",
    "status": "todo",
    "priority": "high",
    "project_id": "project-uuid"
  }'

# Link to asset
curl -X POST http://localhost:8000/api/v1/tasks/{task_id}/assets \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "server-uuid",
    "relationship_type": "configures"
  }'
```

### Search and filter tasks
```bash
# Get all high-priority tasks in progress
curl "http://localhost:8000/api/v1/tasks/?status=in_progress&priority=high"

# Search for authentication-related tasks
curl "http://localhost:8000/api/v1/tasks/?search=authentication"

# Get tasks for a specific project
curl "http://localhost:8000/api/v1/tasks/project/{project_id}"
```

## Implementation Details

- **Service Layer:** `backend/services/task_service.py`
- **Models:** `backend/models/task.py`
- **Schemas:** `backend/schemas/task.py`
- **API Routes:** `backend/api/tasks.py`

## Database Schema

Tasks are stored in the `tasks` table with foreign keys to:
- `users.id` (assignee)
- `projects.id` (project)

Many-to-many relationships via junction tables:
- `task_assets` (tasks ↔ it_assets)
- `task_infrastructure` (tasks ↔ infrastructure)
