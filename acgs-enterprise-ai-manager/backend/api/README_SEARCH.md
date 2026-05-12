# Unified Search API Documentation

## Overview

The Unified Search API provides full-text search across all 6 domains (Tasks, IT Assets, Infrastructure, Projects, Financial Operations, Documents) with relevance ranking, filtering, and tag-based search.

## Features

- **Full-text search** using PostgreSQL tsvector and ts_rank
- **Relevance ranking** with normalized scores (0.0-1.0)
- **Multi-domain search** across all 6 domains simultaneously
- **Domain filtering** to search specific domains
- **Tag-based filtering** for categorized search
- **Search suggestions** for autocomplete
- **Popular tags** discovery
- **Automatic indexing** via database triggers
- **Manual reindexing** for maintenance

## Endpoints

### Search All Domains
```
GET /api/v1/search/?q={query}&domains={domains}&tags={tags}&page={page}&page_size={size}&min_relevance={score}
```

**Query Parameters:**
- `q` (required) - Search query string (1-500 characters)
- `domains` (optional) - Comma-separated domains: tasks, assets, infrastructure, projects, financial, documents
- `tags` (optional) - Comma-separated tags to filter by
- `page` (optional, default: 1) - Page number
- `page_size` (optional, default: 50, max: 100) - Results per page
- `min_relevance` (optional, default: 0.0) - Minimum relevance score (0.0-1.0)

**Response:**
```json
{
  "results": [
    {
      "entity_type": "tasks",
      "entity_id": "uuid",
      "domain": "tasks",
      "title": "Implement authentication",
      "content": "Add JWT-based authentication...",
      "tags": ["backend", "security"],
      "metadata": {},
      "relevance_score": 0.85,
      "highlight": "...JWT-based authentication..."
    }
  ],
  "total": 42,
  "page": 1,
  "page_size": 50,
  "total_pages": 1,
  "query": "authentication"
}
```

### Search by Domain
```
GET /api/v1/search/domain/{domain}?q={query}&page={page}&page_size={size}
```

**Path Parameters:**
- `domain` (required) - Domain to search: tasks, assets, infrastructure, projects, financial, documents

**Example:**
```bash
curl "http://localhost:8000/api/v1/search/domain/tasks?q=authentication"
```

### Search by Tags
```
GET /api/v1/search/tags?tags={tags}&q={query}&page={page}&page_size={size}
```

**Query Parameters:**
- `tags` (required) - Comma-separated tags
- `q` (optional) - Text search query
- `page`, `page_size` - Pagination

**Example:**
```bash
# Tag-only search
curl "http://localhost:8000/api/v1/search/tags?tags=backend,security"

# Tags + text search
curl "http://localhost:8000/api/v1/search/tags?tags=backend&q=authentication"
```

### Search Suggestions
```
GET /api/v1/search/suggest?q={partial_query}&limit={limit}
```

**Query Parameters:**
- `q` (required) - Partial query (minimum 2 characters)
- `limit` (optional, default: 10, max: 50) - Maximum suggestions

**Response:**
```json
{
  "suggestions": [
    "authentication",
    "authorization",
    "auth middleware"
  ]
}
```

### Popular Tags
```
GET /api/v1/search/tags/popular?domain={domain}&limit={limit}
```

**Query Parameters:**
- `domain` (optional) - Filter by domain
- `limit` (optional, default: 20, max: 100) - Maximum tags

**Response:**
```json
{
  "tags": [
    {"tag": "backend", "count": 45},
    {"tag": "security", "count": 32},
    {"tag": "api", "count": 28}
  ]
}
```

### Index Statistics
```
GET /api/v1/search/stats
```

**Response:**
```json
{
  "total_indexed": 1250,
  "by_domain": {
    "tasks": 450,
    "projects": 120,
    "assets": 280,
    "infrastructure": 150,
    "financial": 180,
    "documents": 70
  }
}
```

### Reindex All
```
POST /api/v1/search/reindex
```

Rebuilds the entire search index from all domains. Use for maintenance or after bulk data changes.

**Response:**
```json
{
  "success": true,
  "indexed_counts": {
    "tasks": 450,
    "projects": 120,
    "assets": 280,
    "infrastructure": 150,
    "financial_records": 180,
    "documents": 70
  },
  "message": "Successfully reindexed 1250 entities"
}
```

### Supported Domains
```
GET /api/v1/search/domains
```

**Response:**
```json
{
  "domains": ["tasks", "assets", "infrastructure", "projects", "financial", "documents"],
  "count": 6
}
```

## Search Features

### Full-Text Search

Uses PostgreSQL's full-text search with:
- **tsvector** for indexed search vectors
- **plainto_tsquery** for query parsing
- **ts_rank** for relevance scoring
- **English language** stemming and stop words

### Relevance Ranking

Results are ranked by relevance score (0.0-1.0):
- **1.0** - Perfect match
- **0.7-0.9** - High relevance
- **0.4-0.6** - Medium relevance
- **0.0-0.3** - Low relevance

Use `min_relevance` parameter to filter low-quality results.

### Highlighting

Each result includes a `highlight` field showing a snippet of text around the matched query with context.

### Automatic Indexing

The search index is automatically updated when entities are created or modified via database triggers on:
- tasks
- projects
- it_assets
- infrastructure
- documents
- financial_records

## Examples

### Basic Search
```bash
# Search all domains
curl "http://localhost:8000/api/v1/search/?q=server"

# Search with pagination
curl "http://localhost:8000/api/v1/search/?q=server&page=1&page_size=20"
```

### Filtered Search
```bash
# Search only tasks and projects
curl "http://localhost:8000/api/v1/search/?q=deployment&domains=tasks,projects"

# Search with minimum relevance
curl "http://localhost:8000/api/v1/search/?q=security&min_relevance=0.5"

# Search by tags
curl "http://localhost:8000/api/v1/search/?q=api&tags=backend,security"
```

### Domain-Specific Search
```bash
# Search only IT assets
curl "http://localhost:8000/api/v1/search/domain/assets?q=server"

# Search only documents
curl "http://localhost:8000/api/v1/search/domain/documents?q=policy"
```

### Autocomplete
```bash
# Get suggestions for "auth"
curl "http://localhost:8000/api/v1/search/suggest?q=auth&limit=5"
```

### Tag Discovery
```bash
# Get popular tags across all domains
curl "http://localhost:8000/api/v1/search/tags/popular?limit=20"

# Get popular tags in tasks domain
curl "http://localhost:8000/api/v1/search/tags/popular?domain=tasks&limit=10"
```

## Implementation Details

- **Search Engine:** `backend/search/search_engine.py`
- **Indexer:** `backend/search/indexer.py`
- **Model:** `backend/models/search_index.py`
- **API Routes:** `backend/api/search.py`

## Database Schema

Search index table:
```sql
CREATE TABLE search_index (
    id UUID PRIMARY KEY,
    entity_type VARCHAR(50) NOT NULL,
    entity_id UUID NOT NULL,
    domain VARCHAR(50) NOT NULL,
    title VARCHAR(255),
    content TEXT,
    tags JSONB DEFAULT '[]',
    metadata JSONB,
    search_vector tsvector,
    created_at TIMESTAMP WITH TIME ZONE,
    updated_at TIMESTAMP WITH TIME ZONE,
    UNIQUE (entity_type, entity_id)
);

CREATE INDEX idx_search_index_search_vector ON search_index USING gin(search_vector);
CREATE INDEX idx_search_index_tags ON search_index USING gin(tags);
CREATE INDEX idx_search_index_domain ON search_index(domain);
```

## Performance Considerations

- **GIN indexes** on search_vector and tags for fast lookups
- **Automatic updates** via triggers (no manual indexing needed)
- **Pagination** to limit result set size
- **Relevance filtering** to reduce low-quality results
- **Domain filtering** to narrow search scope

## Error Responses

- `400 Bad Request` - Invalid domain or parameters
- `422 Unprocessable Entity` - Validation error
- `500 Internal Server Error` - Search engine error
