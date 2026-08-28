import hashlib
from dataclasses import dataclass
from typing import Any
from uuid import UUID, uuid5

from second_brain.parsers import ParsedDocument

CHUNKER_VERSION = "chars-v1"


@dataclass(frozen=True)
class Chunk:
    id: UUID
    ordinal: int
    text: str
    char_start: int
    char_end: int
    location: dict[str, Any]


def chunk_document(
    source_version_id: UUID,
    document: ParsedDocument,
    *,
    size: int = 1200,
    overlap: int = 120,
    max_chunks: int,
) -> tuple[Chunk, ...]:
    if overlap >= size:
        raise ValueError("chunk overlap must be smaller than chunk size")
    chunks: list[Chunk] = []
    passage_ranges: list[tuple[int, int, dict[str, Any]]] = []
    passage_start = 0
    for passage in document.passages:
        passage_end = passage_start + len(passage.text)
        passage_ranges.append((passage_start, passage_end, passage.location))
        passage_start = passage_end + 2
    start = 0
    while start < len(document.text):
        end = min(start + size, len(document.text))
        text = document.text[start:end]
        location: dict[str, Any] = {"char_start": start, "char_end": end}
        for passage_start, passage_end, passage_location in passage_ranges:
            if passage_start < end and passage_end > start:
                location.update(passage_location)
                break
        digest = hashlib.sha256(f"{CHUNKER_VERSION}:{start}:{end}:{text}".encode()).hexdigest()
        chunks.append(
            Chunk(uuid5(source_version_id, digest), len(chunks), text, start, end, location)
        )
        if len(chunks) > max_chunks:
            raise ValueError("chunk count exceeds configured limit")
        if end == len(document.text):
            break
        start = end - overlap
    return tuple(chunks)
