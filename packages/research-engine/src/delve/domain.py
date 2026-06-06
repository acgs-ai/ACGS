"""Core domain models for the delve knowledge graph.

All models are immutable (``frozen=True`` + ``tuple`` collection fields). The
:class:`~delve.graph.KnowledgeGraph` is the *only* mutator — it produces new
instances via :func:`dataclasses.replace` when merging. Every model exposes a
stable, deterministic ``id`` derived purely from its normalized content, so the
same finding/claim/citation discovered in different research waves collapses to
one node. Ids never depend on wall-clock time or randomness.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_WHITESPACE = re.compile(r"\s+")
_TRAILING_PUNCT = ".!?,;: \t\n"
# Query params that identify a *session/campaign*, not the content.
_TRACKING_PREFIXES = ("utm_",)
_TRACKING_KEYS = frozenset({"fbclid", "gclid", "ref", "ref_src", "mc_cid", "mc_eid"})


def normalize_text(text: str) -> str:
    """Collapse whitespace, lowercase, and strip trailing punctuation.

    Used for content-derived ids so trivially different phrasings of the same
    string hash identically.
    """
    return _WHITESPACE.sub(" ", text.strip()).lower().rstrip(_TRAILING_PUNCT)


def normalize_url(url: str) -> str:
    """Canonicalize a URL for dedup.

    Lowercases scheme+host, drops the fragment, removes tracking query params,
    sorts the remaining params, and strips a trailing slash. The same page
    cited across two waves with different tracking tails collapses to one id.
    """
    parts = urlsplit(url.strip())
    scheme = (parts.scheme or "https").lower()
    host = parts.netloc.lower()
    path = parts.path.rstrip("/") or "/"
    kept = [
        (k, v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if not k.lower().startswith(_TRACKING_PREFIXES) and k.lower() not in _TRACKING_KEYS
    ]
    kept.sort()
    return urlunsplit((scheme, host, path, urlencode(kept), ""))


def _hash_id(prefix: str, key: str) -> str:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


class ClaimStatus(StrEnum):
    """Lifecycle of a claim. ``REFUTED`` is a *tombstone*: refuted claims stay
    in the graph permanently so later waves recognize and skip them instead of
    rediscovering and re-verifying dead assertions forever."""

    UNVERIFIED = "unverified"
    SUPPORTED = "supported"
    REFUTED = "refuted"


class GapStatus(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


@dataclass(frozen=True, slots=True)
class Citation:
    """A source backing a finding or claim."""

    url: str
    title: str = ""
    source: str = ""  # backend that produced it, e.g. "exa", "tavily"
    snippet: str = ""
    retrieved_at: str | None = None  # ISO string; injected by adapters, never auto-set in core

    @property
    def normalized_url(self) -> str:
        return normalize_url(self.url)

    @property
    def id(self) -> str:
        return _hash_id("cit", self.normalized_url)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "url": self.url,
            "title": self.title,
            "source": self.source,
            "snippet": self.snippet,
            "retrieved_at": self.retrieved_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Citation:
        return cls(
            url=data["url"],
            title=data.get("title", ""),
            source=data.get("source", ""),
            snippet=data.get("snippet", ""),
            retrieved_at=data.get("retrieved_at"),
        )


@dataclass(frozen=True, slots=True)
class Finding:
    """A raw piece of information returned by one research query in one wave."""

    text: str
    query: str
    wave: int
    citations: tuple[Citation, ...] = ()

    @property
    def id(self) -> str:
        return _hash_id("fnd", normalize_text(self.text))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "text": self.text,
            "query": self.query,
            "wave": self.wave,
            "citations": [c.to_dict() for c in sorted(self.citations, key=lambda c: c.id)],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        return cls(
            text=data["text"],
            query=data.get("query", ""),
            wave=int(data.get("wave", 0)),
            citations=tuple(Citation.from_dict(c) for c in data.get("citations", [])),
        )


@dataclass(frozen=True, slots=True)
class Claim:
    """A normalized assertion promoted from one or more findings.

    Carries provenance (``first_seen_wave`` + originating ``finding_ids``) so the
    completeness critic and brief can reason about recency and origin.
    """

    text: str
    status: ClaimStatus = ClaimStatus.UNVERIFIED
    support: tuple[Citation, ...] = ()
    verdict_reason: str = ""
    first_seen_wave: int = 0
    finding_ids: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        return _hash_id("clm", normalize_text(self.text))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "text": self.text,
            "status": self.status.value,
            "support": [c.to_dict() for c in sorted(self.support, key=lambda c: c.id)],
            "verdict_reason": self.verdict_reason,
            "first_seen_wave": self.first_seen_wave,
            "finding_ids": sorted(self.finding_ids),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Claim:
        return cls(
            text=data["text"],
            status=ClaimStatus(data.get("status", ClaimStatus.UNVERIFIED.value)),
            support=tuple(Citation.from_dict(c) for c in data.get("support", [])),
            verdict_reason=data.get("verdict_reason", ""),
            first_seen_wave=int(data.get("first_seen_wave", 0)),
            finding_ids=tuple(data.get("finding_ids", [])),
        )


@dataclass(frozen=True, slots=True)
class Gap:
    """An open question the completeness critic wants a future wave to close."""

    question: str
    rationale: str = ""
    status: GapStatus = GapStatus.OPEN
    wave: int = 0

    @property
    def id(self) -> str:
        return _hash_id("gap", normalize_text(self.question))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "question": self.question,
            "rationale": self.rationale,
            "status": self.status.value,
            "wave": self.wave,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Gap:
        return cls(
            question=data["question"],
            rationale=data.get("rationale", ""),
            status=GapStatus(data.get("status", GapStatus.OPEN.value)),
            wave=int(data.get("wave", 0)),
        )
