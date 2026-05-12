"""
Load testing script for ACGS Enterprise Manager
Uses Locust to simulate 50-500 concurrent users

Run with:
    locust -f tests/load/locustfile.py --host=http://localhost:8000
"""

from locust import HttpUser, task, between, events
import random
import json
import logging

logger = logging.getLogger(__name__)


class ACGSUser(HttpUser):
    """
    Simulates a user interacting with the ACGS Enterprise Manager API.
    """

    # Wait between 1-3 seconds between tasks
    wait_time = between(1, 3)

    # Test data
    auth_token = None
    task_ids = []
    project_ids = []
    asset_ids = []

    def on_start(self):
        """Called when a user starts. Perform login."""
        self.login()

    def login(self):
        """Authenticate and get token."""
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": "test_user", "password": "test_password"},
            name="/auth/login",
        )

        if response.status_code == 200:
            data = response.json()
            self.auth_token = data.get("access_token")
            self.client.headers.update({"Authorization": f"Bearer {self.auth_token}"})
            logger.info("User authenticated successfully")
        else:
            logger.error(f"Login failed: {response.status_code}")

    @task(10)
    def get_tasks(self):
        """Get list of tasks (most common operation)."""
        self.client.get("/api/v1/tasks", name="/tasks [LIST]")

    @task(8)
    def get_projects(self):
        """Get list of projects."""
        self.client.get("/api/v1/projects", name="/projects [LIST]")

    @task(7)
    def get_assets(self):
        """Get list of IT assets."""
        self.client.get("/api/v1/assets", name="/assets [LIST]")

    @task(5)
    def get_infrastructure(self):
        """Get infrastructure list."""
        self.client.get("/api/v1/infrastructure", name="/infrastructure [LIST]")

    @task(5)
    def get_financial(self):
        """Get financial records."""
        self.client.get("/api/v1/financial", name="/financial [LIST]")

    @task(4)
    def get_documents(self):
        """Get documents list."""
        self.client.get("/api/v1/documents", name="/documents [LIST]")

    @task(3)
    def create_task(self):
        """Create a new task."""
        response = self.client.post(
            "/api/v1/tasks",
            json={
                "title": f"Load Test Task {random.randint(1000, 9999)}",
                "description": "Task created during load testing",
                "status": "todo",
                "priority": random.choice(["low", "medium", "high"]),
            },
            name="/tasks [CREATE]",
        )

        if response.status_code == 201:
            task_id = response.json().get("id")
            if task_id:
                self.task_ids.append(task_id)

    @task(2)
    def update_task(self):
        """Update an existing task."""
        if not self.task_ids:
            return

        task_id = random.choice(self.task_ids)
        self.client.put(
            f"/api/v1/tasks/{task_id}",
            json={
                "status": random.choice(["in_progress", "done"]),
                "priority": random.choice(["low", "medium", "high"]),
            },
            name="/tasks/{id} [UPDATE]",
        )

    @task(2)
    def get_task_detail(self):
        """Get details of a specific task."""
        if not self.task_ids:
            return

        task_id = random.choice(self.task_ids)
        self.client.get(f"/api/v1/tasks/{task_id}", name="/tasks/{id} [GET]")

    @task(3)
    def get_recommendations(self):
        """Get AI recommendations."""
        self.client.get("/api/v1/recommendations", name="/recommendations [LIST]")

    @task(2)
    def get_ai_operations(self):
        """Get AI operations history."""
        self.client.get("/api/v1/ai/operations", name="/ai/operations [LIST]")

    @task(1)
    def health_check(self):
        """Check system health."""
        self.client.get("/health", name="/health")

    @task(1)
    def search_tasks(self):
        """Search tasks with filters."""
        params = {
            "status": random.choice(["todo", "in_progress", "done"]),
            "priority": random.choice(["low", "medium", "high"]),
        }
        self.client.get("/api/v1/tasks", params=params, name="/tasks [SEARCH]")


class AdminUser(HttpUser):
    """
    Simulates an admin user with heavier operations.
    """

    wait_time = between(2, 5)
    weight = 1  # 10% of users are admins

    def on_start(self):
        """Login as admin."""
        response = self.client.post(
            "/api/v1/auth/login",
            json={"username": "admin", "password": "admin_password"},
        )

        if response.status_code == 200:
            data = response.json()
            self.auth_token = data.get("access_token")
            self.client.headers.update({"Authorization": f"Bearer {self.auth_token}"})

    @task(5)
    def view_audit_trail(self):
        """View audit trail."""
        self.client.get("/api/v1/audit", name="/audit [LIST]")

    @task(3)
    def view_governance_rules(self):
        """View governance rules."""
        self.client.get("/api/v1/governance/rules", name="/governance/rules [LIST]")

    @task(2)
    def approve_ai_operation(self):
        """Approve pending AI operations."""
        # Get pending operations
        response = self.client.get(
            "/api/v1/ai/operations?status=pending", name="/ai/operations [PENDING]"
        )

        if response.status_code == 200:
            operations = response.json()
            if operations:
                op_id = operations[0].get("id")
                self.client.post(
                    f"/api/v1/ai/operations/{op_id}/approve",
                    name="/ai/operations/{id}/approve",
                )


# Event handlers for metrics
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    """Called when load test starts."""
    logger.info("Load test starting...")


@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    """Called when load test stops."""
    logger.info("Load test completed")
    logger.info(f"Total requests: {environment.stats.total.num_requests}")
    logger.info(f"Total failures: {environment.stats.total.num_failures}")
    logger.info(
        f"Average response time: {environment.stats.total.avg_response_time:.2f}ms"
    )
    logger.info(f"Max response time: {environment.stats.total.max_response_time:.2f}ms")


@events.request.add_listener
def on_request(request_type, name, response_time, response_length, exception, **kwargs):
    """Called after each request."""
    if exception:
        logger.error(f"Request failed: {name} - {exception}")
    elif response_time > 200:
        logger.warning(f"Slow request: {name} - {response_time:.2f}ms")
