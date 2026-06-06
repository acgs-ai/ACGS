"""Tavily-backed :class:`SearchClient` (lazy SDK import, injectable client)."""

from __future__ import annotations

from typing import Any

from delve.backends.base import SearchClient, SearchHit


class TavilySearch(SearchClient):
    def __init__(self, *, api_key: str | None = None, client: Any | None = None) -> None:
        if client is not None:
            self._client = client
        else:
            from tavily import TavilyClient

            self._client = TavilyClient(api_key=api_key) if api_key else TavilyClient()

    def search(self, query: str, *, limit: int = 5) -> list[SearchHit]:
        response = self._client.search(query, max_results=limit)
        results = response.get("results", []) if isinstance(response, dict) else []
        hits: list[SearchHit] = []
        for result in results:
            hits.append(
                SearchHit(
                    url=result.get("url", "") or "",
                    title=result.get("title", "") or "",
                    snippet=(result.get("content", "") or "")[:500],
                    source="tavily",
                    score=float(result.get("score", 0.0) or 0.0),
                )
            )
        return hits
