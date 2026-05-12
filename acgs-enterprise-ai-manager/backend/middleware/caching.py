"""
Caching middleware for FastAPI
Automatically caches GET requests based on URL patterns
"""

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import logging
import hashlib
import json

from backend.cache.redis_client import (
    cache_get,
    cache_set,
    SHORT_TTL,
    DEFAULT_TTL,
    LONG_TTL,
)

logger = logging.getLogger(__name__)


class CachingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to cache GET requests.

    Caches responses based on URL and query parameters.
    Only caches successful GET requests (status 200).
    """

    # URL patterns and their TTL settings
    CACHE_PATTERNS = {
        "/api/v1/tasks": DEFAULT_TTL,
        "/api/v1/assets": DEFAULT_TTL,
        "/api/v1/infrastructure": DEFAULT_TTL,
        "/api/v1/projects": DEFAULT_TTL,
        "/api/v1/financial": DEFAULT_TTL,
        "/api/v1/documents": DEFAULT_TTL,
        "/api/v1/recommendations": SHORT_TTL,
        "/api/v1/ai/operations": SHORT_TTL,
        "/health": LONG_TTL,
    }

    # Paths to exclude from caching
    EXCLUDE_PATTERNS = [
        "/api/v1/auth",
        "/docs",
        "/openapi.json",
        "/redoc",
    ]

    async def dispatch(self, request: Request, call_next):
        """Process request and handle caching."""

        # Only cache GET requests
        if request.method != "GET":
            return await call_next(request)

        # Check if path should be excluded
        if self._should_exclude(request.url.path):
            return await call_next(request)

        # Build cache key
        cache_key = self._build_cache_key(request)

        # Try to get from cache
        cached_response = await cache_get(cache_key)
        if cached_response:
            logger.debug(f"Cache hit for {request.url.path}")
            return JSONResponse(
                content=cached_response["content"],
                status_code=cached_response["status_code"],
                headers={"X-Cache": "HIT"},
            )

        # Execute request
        response = await call_next(request)

        # Cache successful responses
        if response.status_code == 200:
            ttl = self._get_ttl(request.url.path)
            if ttl > 0:
                # Read response body
                body = b""
                async for chunk in response.body_iterator:
                    body += chunk

                # Parse JSON content
                try:
                    content = json.loads(body.decode())

                    # Cache the response
                    await cache_set(
                        cache_key,
                        {"content": content, "status_code": response.status_code},
                        ttl,
                    )
                    logger.debug(
                        f"Cached response for {request.url.path} (TTL: {ttl}s)"
                    )

                    # Return new response with cached content
                    return JSONResponse(
                        content=content,
                        status_code=response.status_code,
                        headers={"X-Cache": "MISS"},
                    )
                except Exception as e:
                    logger.error(f"Failed to cache response: {e}")

        return response

    def _should_exclude(self, path: str) -> bool:
        """Check if path should be excluded from caching."""
        return any(pattern in path for pattern in self.EXCLUDE_PATTERNS)

    def _get_ttl(self, path: str) -> int:
        """Get TTL for given path."""
        for pattern, ttl in self.CACHE_PATTERNS.items():
            if path.startswith(pattern):
                return ttl
        return 0  # Don't cache if no pattern matches

    def _build_cache_key(self, request: Request) -> str:
        """
        Build cache key from request.

        Includes path, query parameters, and relevant headers.
        """
        # Start with path
        key_parts = [request.url.path]

        # Add sorted query parameters
        if request.url.query:
            key_parts.append(request.url.query)

        # Add user context if authenticated
        auth_header = request.headers.get("authorization", "")
        if auth_header:
            # Hash the auth token to include user context
            token_hash = hashlib.md5(auth_header.encode()).hexdigest()[:8]
            key_parts.append(f"user:{token_hash}")

        # Build final key
        cache_key = "http:" + ":".join(key_parts)

        # Hash if too long
        if len(cache_key) > 200:
            cache_key = f"http:hash:{hashlib.md5(cache_key.encode()).hexdigest()}"

        return cache_key


async def invalidate_cache_for_domain(domain: str):
    """
    Invalidate all cache entries for a domain.

    Call this after POST/PUT/DELETE operations to ensure cache consistency.

    Args:
        domain: Domain name (e.g., "tasks", "projects")
    """
    from backend.cache.redis_client import cache_delete_pattern

    pattern = f"http:/api/v1/{domain}*"
    deleted = await cache_delete_pattern(pattern)
    logger.info(f"Invalidated {deleted} cache entries for domain: {domain}")
    return deleted


async def invalidate_cache_for_entity(domain: str, entity_id: str):
    """
    Invalidate cache entries for a specific entity.

    Args:
        domain: Domain name
        entity_id: Entity ID
    """
    from backend.cache.redis_client import cache_delete_pattern

    pattern = f"http:/api/v1/{domain}*{entity_id}*"
    deleted = await cache_delete_pattern(pattern)
    logger.info(f"Invalidated {deleted} cache entries for {domain}/{entity_id}")
    return deleted
