"""
Redis client for caching
Provides async Redis connection with connection pooling
"""

import redis.asyncio as redis
from typing import Optional, Any
import json
import logging
import os

logger = logging.getLogger(__name__)

# Redis configuration from environment
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", None)

# Cache TTL settings (in seconds)
DEFAULT_TTL = 300  # 5 minutes
SHORT_TTL = 60  # 1 minute
LONG_TTL = 3600  # 1 hour

# Redis client instance
_redis_client: Optional[redis.Redis] = None


async def get_redis() -> redis.Redis:
    """Get Redis client instance."""
    global _redis_client

    if _redis_client is None:
        _redis_client = await redis.from_url(
            f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}",
            password=REDIS_PASSWORD,
            encoding="utf-8",
            decode_responses=True,
            max_connections=50,
            socket_connect_timeout=5,
            socket_keepalive=True,
        )
        logger.info("Redis client initialized")

    return _redis_client


async def close_redis():
    """Close Redis connection."""
    global _redis_client

    if _redis_client:
        await _redis_client.close()
        _redis_client = None
        logger.info("Redis connection closed")


async def cache_get(key: str) -> Optional[Any]:
    """
    Get value from cache.

    Args:
        key: Cache key

    Returns:
        Cached value or None if not found
    """
    try:
        client = await get_redis()
        value = await client.get(key)

        if value:
            logger.debug(f"Cache hit: {key}")
            return json.loads(value)

        logger.debug(f"Cache miss: {key}")
        return None
    except Exception as e:
        logger.error(f"Cache get error for key {key}: {e}")
        return None


async def cache_set(key: str, value: Any, ttl: int = DEFAULT_TTL) -> bool:
    """
    Set value in cache.

    Args:
        key: Cache key
        value: Value to cache (will be JSON serialized)
        ttl: Time to live in seconds

    Returns:
        True if successful, False otherwise
    """
    try:
        client = await get_redis()
        serialized = json.dumps(value, default=str)
        await client.setex(key, ttl, serialized)
        logger.debug(f"Cache set: {key} (TTL: {ttl}s)")
        return True
    except Exception as e:
        logger.error(f"Cache set error for key {key}: {e}")
        return False


async def cache_delete(key: str) -> bool:
    """
    Delete key from cache.

    Args:
        key: Cache key

    Returns:
        True if successful, False otherwise
    """
    try:
        client = await get_redis()
        await client.delete(key)
        logger.debug(f"Cache deleted: {key}")
        return True
    except Exception as e:
        logger.error(f"Cache delete error for key {key}: {e}")
        return False


async def cache_delete_pattern(pattern: str) -> int:
    """
    Delete all keys matching pattern.

    Args:
        pattern: Key pattern (e.g., "tasks:*")

    Returns:
        Number of keys deleted
    """
    try:
        client = await get_redis()
        keys = []

        async for key in client.scan_iter(match=pattern):
            keys.append(key)

        if keys:
            deleted = await client.delete(*keys)
            logger.debug(f"Cache pattern deleted: {pattern} ({deleted} keys)")
            return deleted

        return 0
    except Exception as e:
        logger.error(f"Cache delete pattern error for {pattern}: {e}")
        return 0


async def cache_exists(key: str) -> bool:
    """
    Check if key exists in cache.

    Args:
        key: Cache key

    Returns:
        True if key exists, False otherwise
    """
    try:
        client = await get_redis()
        return await client.exists(key) > 0
    except Exception as e:
        logger.error(f"Cache exists error for key {key}: {e}")
        return False


async def cache_ttl(key: str) -> int:
    """
    Get remaining TTL for key.

    Args:
        key: Cache key

    Returns:
        Remaining TTL in seconds, -1 if key has no expiry, -2 if key doesn't exist
    """
    try:
        client = await get_redis()
        return await client.ttl(key)
    except Exception as e:
        logger.error(f"Cache TTL error for key {key}: {e}")
        return -2


async def cache_increment(key: str, amount: int = 1) -> int:
    """
    Increment counter in cache.

    Args:
        key: Cache key
        amount: Amount to increment by

    Returns:
        New value after increment
    """
    try:
        client = await get_redis()
        return await client.incrby(key, amount)
    except Exception as e:
        logger.error(f"Cache increment error for key {key}: {e}")
        return 0


async def cache_health_check() -> bool:
    """
    Check if Redis is healthy and responsive.

    Returns:
        True if healthy, False otherwise
    """
    try:
        client = await get_redis()
        await client.ping()
        return True
    except Exception as e:
        logger.error(f"Redis health check failed: {e}")
        return False


# Cache key builders
def build_cache_key(domain: str, operation: str, *args) -> str:
    """
    Build standardized cache key.

    Args:
        domain: Domain name (e.g., "tasks", "projects")
        operation: Operation name (e.g., "list", "get")
        *args: Additional key components

    Returns:
        Cache key string
    """
    parts = [domain, operation] + [str(arg) for arg in args]
    return ":".join(parts)


# Decorator for caching function results
def cached(ttl: int = DEFAULT_TTL, key_prefix: str = ""):
    """
    Decorator to cache function results.

    Usage:
        @cached(ttl=300, key_prefix="tasks")
        async def get_tasks():
            ...
    """

    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Build cache key from function name and arguments
            key_parts = [key_prefix or func.__name__]
            key_parts.extend(str(arg) for arg in args)
            key_parts.extend(f"{k}={v}" for k, v in sorted(kwargs.items()))
            cache_key = ":".join(key_parts)

            # Try to get from cache
            cached_value = await cache_get(cache_key)
            if cached_value is not None:
                return cached_value

            # Execute function and cache result
            result = await func(*args, **kwargs)
            await cache_set(cache_key, result, ttl)
            return result

        return wrapper

    return decorator
