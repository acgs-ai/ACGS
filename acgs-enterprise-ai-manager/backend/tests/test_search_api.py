"""
Search API Tests
Unit tests for unified search endpoints
"""

import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_search_all_domains(client: AsyncClient):
    """Test searching across all domains."""
    response = await client.get("/api/v1/search/?q=test")
    assert response.status_code == 200

    data = response.json()
    assert "results" in data
    assert "total" in data
    assert "page" in data
    assert "query" in data
    assert data["query"] == "test"


@pytest.mark.asyncio
async def test_search_with_domain_filter(client: AsyncClient):
    """Test searching with domain filter."""
    response = await client.get("/api/v1/search/?q=test&domains=tasks,projects")
    assert response.status_code == 200

    data = response.json()
    for result in data["results"]:
        assert result["domain"] in ["tasks", "projects"]


@pytest.mark.asyncio
async def test_search_by_domain(client: AsyncClient):
    """Test searching within a specific domain."""
    response = await client.get("/api/v1/search/domain/tasks?q=test")
    assert response.status_code == 200

    data = response.json()
    for result in data["results"]:
        assert result["domain"] == "tasks"


@pytest.mark.asyncio
async def test_search_invalid_domain(client: AsyncClient):
    """Test searching with invalid domain."""
    response = await client.get("/api/v1/search/domain/invalid?q=test")
    assert response.status_code == 400


@pytest.mark.asyncio
async def test_search_with_tags(client: AsyncClient):
    """Test searching by tags."""
    response = await client.get("/api/v1/search/tags?tags=backend,api&q=test")
    assert response.status_code == 200

    data = response.json()
    assert "results" in data


@pytest.mark.asyncio
async def test_search_pagination(client: AsyncClient):
    """Test search pagination."""
    response = await client.get("/api/v1/search/?q=test&page=1&page_size=10")
    assert response.status_code == 200

    data = response.json()
    assert data["page"] == 1
    assert data["page_size"] == 10
    assert len(data["results"]) <= 10


@pytest.mark.asyncio
async def test_search_suggestions(client: AsyncClient):
    """Test search suggestions."""
    response = await client.get("/api/v1/search/suggest?q=te")
    assert response.status_code == 200

    data = response.json()
    assert "suggestions" in data
    assert isinstance(data["suggestions"], list)


@pytest.mark.asyncio
async def test_get_popular_tags(client: AsyncClient):
    """Test getting popular tags."""
    response = await client.get("/api/v1/search/tags/popular")
    assert response.status_code == 200

    data = response.json()
    assert "tags" in data
    assert isinstance(data["tags"], list)


@pytest.mark.asyncio
async def test_get_index_stats(client: AsyncClient):
    """Test getting search index statistics."""
    response = await client.get("/api/v1/search/stats")
    assert response.status_code == 200

    data = response.json()
    assert "total_indexed" in data
    assert "by_domain" in data


@pytest.mark.asyncio
async def test_get_supported_domains(client: AsyncClient):
    """Test getting supported domains."""
    response = await client.get("/api/v1/search/domains")
    assert response.status_code == 200

    data = response.json()
    assert "domains" in data
    assert "count" in data
    assert len(data["domains"]) == 6


@pytest.mark.asyncio
async def test_search_relevance_ranking(client: AsyncClient):
    """Test that results are ranked by relevance."""
    response = await client.get("/api/v1/search/?q=authentication")
    assert response.status_code == 200

    data = response.json()
    if len(data["results"]) > 1:
        # Check that relevance scores are in descending order
        scores = [r["relevance_score"] for r in data["results"]]
        assert scores == sorted(scores, reverse=True)


@pytest.mark.asyncio
async def test_search_min_relevance_filter(client: AsyncClient):
    """Test minimum relevance score filter."""
    response = await client.get("/api/v1/search/?q=test&min_relevance=0.5")
    assert response.status_code == 200

    data = response.json()
    for result in data["results"]:
        assert result["relevance_score"] >= 0.5
