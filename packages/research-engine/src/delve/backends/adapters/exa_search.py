"""Exa-backed :class:`SearchClient` (lazy SDK import, injectable client)."""

from __future__ import annotations

from typing import Any

from delve.backends.base import SearchClient, SearchHit


class ExaSearch(SearchClient):
    def __init__(self, *, api_key: str | None = None, client: Any | None = None) -> None:
        if client is not None:
            self._client = client
        else:
            from exa_py import Exa

            self._client = Exa(api_key) if api_key else Exa()

    def search(self, query: str, *, limit: int = 5) -> list[SearchHit]:
        response = self._client.search_and_contents(
            query, num_results=limit, text={"max_characters": 500}
        )
        hits: list[SearchHit] = []
        for result in getattr(response, "results", []):
            hits.append(
                SearchHit(
                    url=getattr(result, "url", "") or "",
                    title=getattr(result, "title", "") or "",
                    snippet=(getattr(result, "text", "") or "")[:500],
                    source="exa",
                    score=float(getattr(result, "score", 0.0) or 0.0),
                )
            )
        return hits
