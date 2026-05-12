"""
Search Indexer
Manages search index updates for all domains
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
from typing import Dict, Any, Optional, List
from uuid import UUID
import logging

from backend.models.search_index import SearchIndex

logger = logging.getLogger(__name__)


class SearchIndexer:
    """Manages search index updates across all domains."""

    DOMAIN_MAPPING = {
        "tasks": "tasks",
        "it_assets": "assets",
        "infrastructure": "infrastructure",
        "projects": "projects",
        "financial_records": "financial",
        "documents": "documents",
    }

    @staticmethod
    async def index_entity(
        db: AsyncSession,
        entity_type: str,
        entity_id: UUID,
        title: str,
        content: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SearchIndex:
        """
        Index or update an entity in the search index.

        Args:
            db: Database session
            entity_type: Type of entity (table name)
            entity_id: Entity UUID
            title: Entity title/name
            content: Entity content/description
            tags: List of tags
            metadata: Additional metadata

        Returns:
            SearchIndex entry
        """
        domain = SearchIndexer.DOMAIN_MAPPING.get(entity_type, entity_type)

        # Create search vector from title and content
        search_text = f"{title} {content or ''}"

        # Check if entry exists
        query = select(SearchIndex).where(
            SearchIndex.entity_type == entity_type, SearchIndex.entity_id == entity_id
        )
        result = await db.execute(query)
        existing = result.scalar_one_or_none()

        if existing:
            # Update existing entry
            existing.title = title
            existing.content = content
            existing.tags = tags or []
            existing.extra_data = metadata

            # Update search vector using PostgreSQL function
            await db.execute(
                text(
                    "UPDATE search_index SET search_vector = to_tsvector('english', :text) "
                    "WHERE entity_type = :entity_type AND entity_id = :entity_id"
                ),
                {
                    "text": search_text,
                    "entity_type": entity_type,
                    "entity_id": str(entity_id),
                },
            )

            await db.commit()
            await db.refresh(existing)
            logger.info(f"Updated search index for {entity_type}:{entity_id}")
            return existing
        else:
            # Create new entry
            index_entry = SearchIndex(
                entity_type=entity_type,
                entity_id=entity_id,
                domain=domain,
                title=title,
                content=content,
                tags=tags or [],
                extra_data=metadata,
            )
            db.add(index_entry)
            await db.flush()

            # Set search vector using PostgreSQL function
            await db.execute(
                text(
                    "UPDATE search_index SET search_vector = to_tsvector('english', :text) "
                    "WHERE id = :id"
                ),
                {"text": search_text, "id": str(index_entry.id)},
            )

            await db.commit()
            await db.refresh(index_entry)
            logger.info(f"Indexed {entity_type}:{entity_id}")
            return index_entry

    @staticmethod
    async def remove_from_index(
        db: AsyncSession, entity_type: str, entity_id: UUID
    ) -> bool:
        """
        Remove an entity from the search index.

        Args:
            db: Database session
            entity_type: Type of entity
            entity_id: Entity UUID

        Returns:
            True if removed, False if not found
        """
        query = select(SearchIndex).where(
            SearchIndex.entity_type == entity_type, SearchIndex.entity_id == entity_id
        )
        result = await db.execute(query)
        entry = result.scalar_one_or_none()

        if entry:
            await db.delete(entry)
            await db.commit()
            logger.info(f"Removed {entity_type}:{entity_id} from search index")
            return True

        return False

    @staticmethod
    async def reindex_all(db: AsyncSession) -> Dict[str, int]:
        """
        Reindex all entities across all domains.
        This is a maintenance operation that rebuilds the entire search index.

        Args:
            db: Database session

        Returns:
            Dictionary with count of indexed entities per domain
        """
        counts = {}

        # Reindex tasks
        result = await db.execute(
            text(
                """
            INSERT INTO search_index (entity_type, entity_id, domain, title, content, tags, search_vector)
            SELECT 
                'tasks' as entity_type,
                id as entity_id,
                'tasks' as domain,
                title,
                description as content,
                tags,
                to_tsvector('english', COALESCE(title, '') || ' ' || COALESCE(description, ''))
            FROM tasks
            ON CONFLICT (entity_type, entity_id) 
            DO UPDATE SET
                title = EXCLUDED.title,
                content = EXCLUDED.content,
                tags = EXCLUDED.tags,
                search_vector = EXCLUDED.search_vector,
                updated_at = CURRENT_TIMESTAMP
        """
            )
        )
        counts["tasks"] = result.rowcount

        # Reindex projects
        result = await db.execute(
            text(
                """
            INSERT INTO search_index (entity_type, entity_id, domain, title, content, tags, search_vector)
            SELECT 
                'projects' as entity_type,
                id as entity_id,
                'projects' as domain,
                name as title,
                description as content,
                '[]'::jsonb as tags,
                to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(description, ''))
            FROM projects
            ON CONFLICT (entity_type, entity_id) 
            DO UPDATE SET
                title = EXCLUDED.title,
                content = EXCLUDED.content,
                search_vector = EXCLUDED.search_vector,
                updated_at = CURRENT_TIMESTAMP
        """
            )
        )
        counts["projects"] = result.rowcount

        # Reindex IT assets
        result = await db.execute(
            text(
                """
            INSERT INTO search_index (entity_type, entity_id, domain, title, content, tags, search_vector)
            SELECT 
                'it_assets' as entity_type,
                id as entity_id,
                'assets' as domain,
                name as title,
                type || ' - ' || status as content,
                '[]'::jsonb as tags,
                to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(type, '') || ' ' || COALESCE(status, ''))
            FROM it_assets
            ON CONFLICT (entity_type, entity_id) 
            DO UPDATE SET
                title = EXCLUDED.title,
                content = EXCLUDED.content,
                search_vector = EXCLUDED.search_vector,
                updated_at = CURRENT_TIMESTAMP
        """
            )
        )
        counts["it_assets"] = result.rowcount

        # Reindex infrastructure
        result = await db.execute(
            text(
                """
            INSERT INTO search_index (entity_type, entity_id, domain, title, content, tags, search_vector)
            SELECT 
                'infrastructure' as entity_type,
                id as entity_id,
                'infrastructure' as domain,
                name as title,
                type || ' - ' || status as content,
                '[]'::jsonb as tags,
                to_tsvector('english', COALESCE(name, '') || ' ' || COALESCE(type, '') || ' ' || COALESCE(status, ''))
            FROM infrastructure
            ON CONFLICT (entity_type, entity_id) 
            DO UPDATE SET
                title = EXCLUDED.title,
                content = EXCLUDED.content,
                search_vector = EXCLUDED.search_vector,
                updated_at = CURRENT_TIMESTAMP
        """
            )
        )
        counts["infrastructure"] = result.rowcount

        # Reindex documents
        result = await db.execute(
            text(
                """
            INSERT INTO search_index (entity_type, entity_id, domain, title, content, tags, search_vector)
            SELECT 
                'documents' as entity_type,
                id as entity_id,
                'documents' as domain,
                title,
                content,
                tags,
                to_tsvector('english', COALESCE(title, '') || ' ' || COALESCE(content, ''))
            FROM documents
            ON CONFLICT (entity_type, entity_id) 
            DO UPDATE SET
                title = EXCLUDED.title,
                content = EXCLUDED.content,
                tags = EXCLUDED.tags,
                search_vector = EXCLUDED.search_vector,
                updated_at = CURRENT_TIMESTAMP
        """
            )
        )
        counts["documents"] = result.rowcount

        # Reindex financial records
        result = await db.execute(
            text(
                """
            INSERT INTO search_index (entity_type, entity_id, domain, title, content, tags, search_vector)
            SELECT 
                'financial_records' as entity_type,
                id as entity_id,
                'financial' as domain,
                type || ' - ' || category as title,
                description as content,
                '[]'::jsonb as tags,
                to_tsvector('english', COALESCE(type, '') || ' ' || COALESCE(category, '') || ' ' || COALESCE(description, ''))
            FROM financial_records
            ON CONFLICT (entity_type, entity_id) 
            DO UPDATE SET
                title = EXCLUDED.title,
                content = EXCLUDED.content,
                search_vector = EXCLUDED.search_vector,
                updated_at = CURRENT_TIMESTAMP
        """
            )
        )
        counts["financial_records"] = result.rowcount

        await db.commit()
        logger.info(f"Reindexed all domains: {counts}")
        return counts

    @staticmethod
    async def get_index_stats(db: AsyncSession) -> Dict[str, Any]:
        """
        Get statistics about the search index.

        Args:
            db: Database session

        Returns:
            Dictionary with index statistics
        """
        # Total count
        total_result = await db.execute(select(func.count(SearchIndex.id)))
        total = total_result.scalar()

        # Count by domain
        domain_result = await db.execute(
            select(SearchIndex.domain, func.count(SearchIndex.id)).group_by(
                SearchIndex.domain
            )
        )
        by_domain = {row[0]: row[1] for row in domain_result}

        return {"total_indexed": total, "by_domain": by_domain}
