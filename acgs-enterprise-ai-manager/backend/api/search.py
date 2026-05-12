"""
Search API Endpoints
Unified search across all domains with filtering and relevance ranking
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel, Field
import logging
import math

from backend.database import get_db
from backend.search.search_engine import SearchEngine, SearchResult
from backend.search.indexer import SearchIndexer

logger = logging.getLogger(__name__)

router = APIRouter()


# Request/Response schemas
class SearchRequest(BaseModel):
    """Search request schema."""

    query: str = Field(..., min_length=1, max_length=500)
    domains: Optional[List[str]] = Field(None, description="Filter by domains")
    tags: Optional[List[str]] = Field(None, description="Filter by tags")
    limit: int = Field(50, ge=1, le=100)
    offset: int = Field(0, ge=0)
    min_relevance: float = Field(0.0, ge=0.0, le=1.0)


class SearchResponse(BaseModel):
    """Search response schema."""

    results: List[SearchResult]
    total: int
    page: int
    page_size: int
    total_pages: int
    query: str


class IndexStatsResponse(BaseModel):
    """Index statistics response."""

    total_indexed: int
    by_domain: dict


class ReindexResponse(BaseModel):
    """Reindex response."""

    success: bool
    indexed_counts: dict
    message: str


@router.get("/", response_model=SearchResponse)
async def search(
    q: str = Query(..., min_length=1, max_length=500, description="Search query"),
    domains: Optional[str] = Query(
        None, description="Comma-separated domains to search"
    ),
    tags: Optional[str] = Query(None, description="Comma-separated tags to filter"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Results per page"),
    min_relevance: float = Query(
        0.0, ge=0.0, le=1.0, description="Minimum relevance score"
    ),
    db: AsyncSession = Depends(get_db),
):
    """
    Search across all domains with full-text search and relevance ranking.

    Args:
        q: Search query string
        domains: Comma-separated list of domains (tasks, assets, infrastructure, projects, financial, documents)
        tags: Comma-separated list of tags to filter by
        page: Page number (1-indexed)
        page_size: Number of results per page (1-100)
        min_relevance: Minimum relevance score (0.0-1.0)
        db: Database session

    Returns:
        Search results with pagination
    """
    try:
        # Parse domains and tags
        domain_list = [d.strip() for d in domains.split(",")] if domains else None
        tag_list = [t.strip() for t in tags.split(",")] if tags else None

        # Calculate offset
        offset = (page - 1) * page_size

        # Perform search
        results, total = await SearchEngine.search(
            db,
            query=q,
            domains=domain_list,
            tags=tag_list,
            limit=page_size,
            offset=offset,
            min_relevance=min_relevance,
        )

        # Calculate total pages
        total_pages = math.ceil(total / page_size) if total > 0 else 0

        return SearchResponse(
            results=results,
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            query=q,
        )

    except Exception as e:
        logger.error(f"Search failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Search failed"
        )


@router.get("/domain/{domain}", response_model=SearchResponse)
async def search_by_domain(
    domain: str,
    q: str = Query(..., min_length=1, max_length=500),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """
    Search within a specific domain.

    Args:
        domain: Domain to search (tasks, assets, infrastructure, projects, financial, documents)
        q: Search query
        page: Page number
        page_size: Results per page
        db: Database session

    Returns:
        Search results for the domain
    """
    if domain not in SearchEngine.SUPPORTED_DOMAINS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain. Supported: {', '.join(SearchEngine.SUPPORTED_DOMAINS)}",
        )

    offset = (page - 1) * page_size

    results, total = await SearchEngine.search_by_domain(
        db, domain=domain, query=q, limit=page_size, offset=offset
    )

    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return SearchResponse(
        results=results,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        query=q,
    )


@router.get("/tags", response_model=SearchResponse)
async def search_by_tags(
    tags: str = Query(..., description="Comma-separated tags"),
    q: Optional[str] = Query(None, min_length=1, max_length=500),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """
    Search by tags with optional text query.

    Args:
        tags: Comma-separated tags to filter by
        q: Optional text search query
        page: Page number
        page_size: Results per page
        db: Database session

    Returns:
        Search results matching tags
    """
    tag_list = [t.strip() for t in tags.split(",")]
    offset = (page - 1) * page_size

    results, total = await SearchEngine.search_by_tags(
        db, tags=tag_list, query=q, limit=page_size, offset=offset
    )

    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return SearchResponse(
        results=results,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        query=q or f"tags:{tags}",
    )


@router.get("/suggest")
async def search_suggestions(
    q: str = Query(..., min_length=2, max_length=100),
    limit: int = Query(10, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """
    Get search suggestions based on partial query.

    Args:
        q: Partial search query (minimum 2 characters)
        limit: Maximum suggestions (1-50)
        db: Database session

    Returns:
        List of suggested search terms
    """
    suggestions = await SearchEngine.suggest(db, query=q, limit=limit)
    return {"suggestions": suggestions}


@router.get("/tags/popular")
async def get_popular_tags(
    domain: Optional[str] = Query(None, description="Filter by domain"),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """
    Get most popular tags across domains.

    Args:
        domain: Optional domain filter
        limit: Maximum tags to return (1-100)
        db: Database session

    Returns:
        List of popular tags with counts
    """
    if domain and domain not in SearchEngine.SUPPORTED_DOMAINS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid domain. Supported: {', '.join(SearchEngine.SUPPORTED_DOMAINS)}",
        )

    tags = await SearchEngine.get_popular_tags(db, domain=domain, limit=limit)
    return {"tags": [{"tag": tag, "count": count} for tag, count in tags]}


@router.get("/stats", response_model=IndexStatsResponse)
async def get_index_stats(db: AsyncSession = Depends(get_db)):
    """
    Get search index statistics.

    Args:
        db: Database session

    Returns:
        Index statistics including total count and breakdown by domain
    """
    stats = await SearchIndexer.get_index_stats(db)
    return IndexStatsResponse(**stats)


@router.post("/reindex", response_model=ReindexResponse)
async def reindex_all(db: AsyncSession = Depends(get_db)):
    """
    Reindex all entities across all domains.
    This is a maintenance operation that rebuilds the entire search index.

    Args:
        db: Database session

    Returns:
        Reindex results with counts per domain
    """
    try:
        counts = await SearchIndexer.reindex_all(db)
        total = sum(counts.values())

        logger.info(f"Reindexed {total} entities across {len(counts)} domains")

        return ReindexResponse(
            success=True,
            indexed_counts=counts,
            message=f"Successfully reindexed {total} entities",
        )
    except Exception as e:
        logger.error(f"Reindex failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Reindex operation failed",
        )


@router.get("/domains")
async def get_supported_domains():
    """
    Get list of supported search domains.

    Returns:
        List of domain names
    """
    return {
        "domains": SearchEngine.SUPPORTED_DOMAINS,
        "count": len(SearchEngine.SUPPORTED_DOMAINS),
    }
