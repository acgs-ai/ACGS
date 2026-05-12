"""
Search Engine
Full-text search with relevance ranking across all domains
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text, or_, and_
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from uuid import UUID
import logging

from backend.models.search_index import SearchIndex

logger = logging.getLogger(__name__)


class SearchResult(BaseModel):
    """Search result model."""

    entity_type: str
    entity_id: UUID
    domain: str
    title: str
    content: Optional[str]
    tags: List[str]
    metadata: Optional[Dict[str, Any]]
    relevance_score: float
    highlight: Optional[str] = None


class SearchEngine:
    """Full-text search engine with relevance ranking."""

    SUPPORTED_DOMAINS = [
        "tasks",
        "assets",
        "infrastructure",
        "projects",
        "financial",
        "documents",
    ]

    @staticmethod
    async def search(
        db: AsyncSession,
        query: str,
        domains: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        limit: int = 50,
        offset: int = 0,
        min_relevance: float = 0.0,
    ) -> tuple[List[SearchResult], int]:
        """
        Perform full-text search across domains.

        Args:
            db: Database session
            query: Search query string
            domains: Filter by specific domains (None = all domains)
            tags: Filter by tags
            limit: Maximum results to return
            offset: Pagination offset
            min_relevance: Minimum relevance score (0.0-1.0)

        Returns:
            Tuple of (search results, total count)
        """
        if not query or not query.strip():
            return [], 0

        # Build base query with full-text search
        # Use ts_rank for relevance scoring
        search_query = select(
            SearchIndex,
            func.ts_rank(
                SearchIndex.search_vector, func.plainto_tsquery("english", query)
            ).label("rank"),
        ).where(
            SearchIndex.search_vector.op("@@")(func.plainto_tsquery("english", query))
        )

        # Apply domain filter
        if domains:
            valid_domains = [d for d in domains if d in SearchEngine.SUPPORTED_DOMAINS]
            if valid_domains:
                search_query = search_query.where(SearchIndex.domain.in_(valid_domains))

        # Apply tag filter
        if tags:
            for tag in tags:
                search_query = search_query.where(SearchIndex.tags.contains([tag]))

        # Get total count
        count_query = select(func.count()).select_from(search_query.subquery())
        total_result = await db.execute(count_query)
        total = total_result.scalar()

        # Apply ordering by relevance
        search_query = search_query.order_by(text("rank DESC"))

        # Apply pagination
        search_query = search_query.offset(offset).limit(limit)

        # Execute search
        result = await db.execute(search_query)
        rows = result.all()

        # Build search results
        results = []
        for row in rows:
            index_entry = row[0]
            rank = row[1]

            # Normalize rank to 0-1 scale (typical ts_rank values are 0-1, but can be higher)
            relevance_score = min(rank, 1.0)

            # Skip results below minimum relevance
            if relevance_score < min_relevance:
                continue

            # Generate highlight snippet
            highlight = SearchEngine._generate_highlight(
                index_entry.title, index_entry.content, query
            )

            results.append(
                SearchResult(
                    entity_type=index_entry.entity_type,
                    entity_id=index_entry.entity_id,
                    domain=index_entry.domain,
                    title=index_entry.title or "",
                    content=index_entry.content,
                    tags=index_entry.tags or [],
                    metadata=index_entry.extra_data,
                    relevance_score=relevance_score,
                    highlight=highlight,
                )
            )

        return results, total

    @staticmethod
    async def search_by_domain(
        db: AsyncSession, domain: str, query: str, limit: int = 50, offset: int = 0
    ) -> tuple[List[SearchResult], int]:
        """
        Search within a specific domain.

        Args:
            db: Database session
            domain: Domain to search in
            query: Search query
            limit: Maximum results
            offset: Pagination offset

        Returns:
            Tuple of (search results, total count)
        """
        return await SearchEngine.search(
            db, query=query, domains=[domain], limit=limit, offset=offset
        )

    @staticmethod
    async def search_by_tags(
        db: AsyncSession,
        tags: List[str],
        query: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[SearchResult], int]:
        """
        Search by tags with optional text query.

        Args:
            db: Database session
            tags: Tags to filter by
            query: Optional text search query
            limit: Maximum results
            offset: Pagination offset

        Returns:
            Tuple of (search results, total count)
        """
        if query:
            return await SearchEngine.search(
                db, query=query, tags=tags, limit=limit, offset=offset
            )
        else:
            # Tag-only search without full-text
            search_query = select(SearchIndex)

            for tag in tags:
                search_query = search_query.where(SearchIndex.tags.contains([tag]))

            # Get total count
            count_query = select(func.count()).select_from(search_query.subquery())
            total_result = await db.execute(count_query)
            total = total_result.scalar()

            # Apply pagination and ordering
            search_query = search_query.order_by(SearchIndex.updated_at.desc())
            search_query = search_query.offset(offset).limit(limit)

            # Execute
            result = await db.execute(search_query)
            entries = result.scalars().all()

            # Build results
            results = [
                SearchResult(
                    entity_type=entry.entity_type,
                    entity_id=entry.entity_id,
                    domain=entry.domain,
                    title=entry.title or "",
                    content=entry.content,
                    tags=entry.tags or [],
                    metadata=entry.extra_data,
                    relevance_score=1.0,  # No relevance scoring for tag-only search
                    highlight=None,
                )
                for entry in entries
            ]

            return results, total

    @staticmethod
    async def suggest(db: AsyncSession, query: str, limit: int = 10) -> List[str]:
        """
        Get search suggestions based on partial query.

        Args:
            db: Database session
            query: Partial search query
            limit: Maximum suggestions

        Returns:
            List of suggested search terms
        """
        if not query or len(query) < 2:
            return []

        # Search for titles that start with or contain the query
        search_query = (
            select(SearchIndex.title)
            .where(
                or_(
                    SearchIndex.title.ilike(f"{query}%"),
                    SearchIndex.title.ilike(f"% {query}%"),
                )
            )
            .distinct()
            .limit(limit)
        )

        result = await db.execute(search_query)
        suggestions = [row[0] for row in result if row[0]]

        return suggestions

    @staticmethod
    def _generate_highlight(
        title: Optional[str],
        content: Optional[str],
        query: str,
        context_length: int = 150,
    ) -> Optional[str]:
        """
        Generate a highlighted snippet showing query matches.

        Args:
            title: Entity title
            content: Entity content
            query: Search query
            context_length: Length of context around match

        Returns:
            Highlighted snippet or None
        """
        text = content or title or ""
        if not text:
            return None

        query_lower = query.lower()
        text_lower = text.lower()

        # Find first occurrence of query
        pos = text_lower.find(query_lower)

        if pos == -1:
            # Query not found, return beginning of text
            return text[:context_length] + ("..." if len(text) > context_length else "")

        # Calculate snippet boundaries
        start = max(0, pos - context_length // 2)
        end = min(len(text), pos + len(query) + context_length // 2)

        snippet = text[start:end]

        # Add ellipsis if truncated
        if start > 0:
            snippet = "..." + snippet
        if end < len(text):
            snippet = snippet + "..."

        return snippet

    @staticmethod
    async def get_popular_tags(
        db: AsyncSession, domain: Optional[str] = None, limit: int = 20
    ) -> List[tuple[str, int]]:
        """
        Get most popular tags across domains.

        Args:
            db: Database session
            domain: Optional domain filter
            limit: Maximum tags to return

        Returns:
            List of (tag, count) tuples
        """
        # This requires unnesting JSONB arrays and counting
        # Using raw SQL for efficiency
        if domain:
            query = text("""
                SELECT tag, COUNT(*) as count
                FROM search_index, jsonb_array_elements_text(tags) as tag
                WHERE domain = :domain
                GROUP BY tag
                ORDER BY count DESC
                LIMIT :limit
            """)
            result = await db.execute(query, {"domain": domain, "limit": limit})
        else:
            query = text("""
                SELECT tag, COUNT(*) as count
                FROM search_index, jsonb_array_elements_text(tags) as tag
                GROUP BY tag
                ORDER BY count DESC
                LIMIT :limit
            """)
            result = await db.execute(query, {"limit": limit})

        return [(row[0], row[1]) for row in result]
