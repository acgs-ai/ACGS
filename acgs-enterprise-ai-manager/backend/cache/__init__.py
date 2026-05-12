"""Cache module for Redis-based caching."""

from backend.cache.redis_client import (
    get_redis,
    close_redis,
    cache_get,
    cache_set,
    cache_delete,
    cache_delete_pattern,
    cache_exists,
    cache_ttl,
    cache_increment,
    cache_health_check,
    build_cache_key,
    cached,
    DEFAULT_TTL,
    SHORT_TTL,
    LONG_TTL,
)

__all__ = [
    "get_redis",
    "close_redis",
    "cache_get",
    "cache_set",
    "cache_delete",
    "cache_delete_pattern",
    "cache_exists",
    "cache_ttl",
    "cache_increment",
    "cache_health_check",
    "build_cache_key",
    "cached",
    "DEFAULT_TTL",
    "SHORT_TTL",
    "LONG_TTL",
]
