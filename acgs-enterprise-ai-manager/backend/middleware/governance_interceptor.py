"""
Governance Interceptor Middleware
Intercepts AI operations and enforces ACGS-Lite governance rules
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import logging
import json
from typing import Any, Callable

from backend.governance.acgs_integration import get_governance

logger = logging.getLogger(__name__)


class GovernanceMiddleware(BaseHTTPMiddleware):
    """
    Middleware to intercept and validate AI operations against governance rules.

    Implements the MACI pattern:
    - Monitor: Detect AI operations
    - Approve: Check if approval required
    - Control: Enforce governance decisions
    - Inspect: Log all decisions to audit trail
    """

    # State-changing paths that trigger governance validation.
    GOVERNED_PATHS = [
        "/api/v1/recommendations/",
        "/api/v1/autonomous/",
        "/api/v1/workflows/",
        "/api/v1/tasks/",
        "/api/v1/projects/",
        "/api/v1/assets/",
        "/api/v1/infrastructure/",
        "/api/v1/documents/",
        "/api/v1/financial/",
    ]

    # Paths that are exempt from governance checks
    EXEMPT_PATHS = [
        "/health",
        "/docs",
        "/openapi.json",
        "/api/v1/auth/",
    ]

    GOVERNED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Intercept requests and apply governance validation for AI operations.
        """
        path = request.url.path

        # Skip governance check for exempt paths
        if any(path.startswith(exempt) for exempt in self.EXEMPT_PATHS):
            return await call_next(request)

        # Check if this is a state-changing operation that needs governance validation.
        normalized_path = path.rstrip("/") + "/"
        is_governed_operation = request.method in self.GOVERNED_METHODS and any(
            normalized_path.startswith(governed_path)
            for governed_path in self.GOVERNED_PATHS
        )

        if is_governed_operation:
            # Extract operation details from request
            operation_context = await self._extract_operation_context(request)

            # Validate against governance rules
            governance = get_governance()
            validation_result = governance.validate_operation(
                operation=operation_context.get("operation", "unknown"),
                context=operation_context,
                agent_id=operation_context.get("agent_id", "default"),
            )

            # Enforce governance decision
            action = validation_result.get("action", "BLOCK")

            if action == "BLOCK":
                logger.warning(f"Governance blocked operation: {path}")
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "Operation blocked by governance rules",
                        "violations": validation_result.get("violations", []),
                        "decision_id": validation_result.get("decision_id"),
                    },
                )

            elif action == "REQUIRE_APPROVAL":
                logger.info(f"Governance requires approval for operation: {path}")

                # Request approval
                approval_request = governance.request_approval(
                    operation=operation_context.get("operation", "unknown"),
                    context=operation_context,
                    agent_id=operation_context.get("agent_id", "default"),
                )

                return JSONResponse(
                    status_code=202,
                    content={
                        "detail": "Operation requires human approval",
                        "approval_request": approval_request,
                        "decision_id": validation_result.get("decision_id"),
                    },
                )

            # Action is ALLOW - proceed with request
            logger.info(f"Governance allowed operation: {path}")

            # Add governance decision to request state for downstream use
            request.state.governance_decision = validation_result

        # Proceed with the request
        response = await call_next(request)

        # Add governance headers to response
        if is_governed_operation and hasattr(request.state, "governance_decision"):
            decision = request.state.governance_decision
            response.headers["X-Governance-Decision"] = decision.get(
                "action", "UNKNOWN"
            )
            if "decision_id" in decision:
                response.headers["X-Governance-Decision-ID"] = decision["decision_id"]

        return response

    async def _extract_operation_context(self, request: Request) -> dict:
        """
        Extract operation context from request for governance validation.
        """
        context = {
            "path": request.url.path,
            "method": request.method,
            "operation": f"{request.method} {request.url.path}",
        }

        # Extract user/agent ID from headers or auth
        if "X-Agent-ID" in request.headers:
            context["agent_id"] = request.headers["X-Agent-ID"]

        # Extract request body for POST/PUT/PATCH
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body = await request.body()
                self._cache_body(request, body)
                if body:
                    request_body = json.loads(body.decode())
                    context["request_body"] = request_body
                    context["operation_text"] = self._flatten_for_matching(request_body)
                    context.update(self._extract_validation_fields(request_body))
            except Exception as e:
                logger.warning(f"Failed to parse request body: {e}")

        # Extract query parameters
        if request.query_params:
            context["query_params"] = dict(request.query_params)

        return context

    def _cache_body(self, request: Request, body: bytes) -> None:
        """Keep the consumed body cached for downstream handlers."""
        request._body = body

    def _flatten_for_matching(self, value: Any) -> str:
        """Create bounded, redacted text for pattern-based governance rules."""
        sensitive_keys = {"password", "token", "secret", "api_key", "credential"}
        parts: list[str] = []

        def visit(item: Any, key: str = "") -> None:
            if len(parts) >= 200:
                return
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                parts.append(f"{key}=***REDACTED***")
                return
            if isinstance(item, dict):
                for child_key, child_value in item.items():
                    visit(child_value, str(child_key))
            elif isinstance(item, list):
                for child in item:
                    visit(child, key)
            elif item is not None:
                parts.append(f"{key}={item}" if key else str(item))

        visit(value)
        return " ".join(parts)[:2000]

    def _extract_validation_fields(self, body: Any) -> dict:
        """Promote common validation fields so existing rules can inspect them."""
        extracted: dict[str, Any] = {}

        def visit(item: Any) -> None:
            if isinstance(item, dict):
                for key, value in item.items():
                    if key in {"amount", "confidence", "batch_size", "retention_days"}:
                        extracted.setdefault(key, value)
                    visit(value)
            elif isinstance(item, list):
                for child in item:
                    visit(child)

        visit(body)
        return extracted
