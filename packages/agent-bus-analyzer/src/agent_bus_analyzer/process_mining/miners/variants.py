"""Canonical process variant detection."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from statistics import fmean

from agent_bus_analyzer.process_mining.miners.discovery import reconstruct_workflows
from agent_bus_analyzer.process_mining.schemas.process_event import ProcessEvent

VARIANT_ALGORITHM_VERSION = "variants-1.0"


@dataclass(frozen=True, slots=True)
class ProcessVariant:
    signature: tuple[str, ...]
    case_ids: tuple[str, ...]
    count: int
    frequency: float
    average_duration_seconds: float
    incomplete_case_count: int


@dataclass(frozen=True, slots=True)
class VariantAnalysis:
    tenant_id: str
    algorithm_version: str
    case_count: int
    variants: tuple[ProcessVariant, ...]


def detect_variants(events: Iterable[ProcessEvent]) -> VariantAnalysis:
    """Group case reconstructions by their exact activity sequence."""
    reconstructions = reconstruct_workflows(events)
    grouped: dict[tuple[str, ...], list[tuple[str, float, bool]]] = defaultdict(list)
    for reconstruction in reconstructions:
        signature = tuple(step.activity for step in reconstruction.steps)
        grouped[signature].append(
            (
                reconstruction.case_id,
                reconstruction.duration_seconds,
                reconstruction.complete,
            )
        )
    case_count = len(reconstructions)
    variants = []
    for signature, cases in grouped.items():
        case_ids = tuple(sorted(case_id for case_id, _, _ in cases))
        variants.append(
            ProcessVariant(
                signature=signature,
                case_ids=case_ids,
                count=len(cases),
                frequency=len(cases) / case_count if case_count else 0.0,
                average_duration_seconds=fmean(duration for _, duration, _ in cases),
                incomplete_case_count=sum(not complete for _, _, complete in cases),
            )
        )
    variants.sort(key=lambda variant: (-variant.count, variant.signature))
    tenant_id = reconstructions[0].tenant_id if reconstructions else ""
    return VariantAnalysis(
        tenant_id=tenant_id,
        algorithm_version=VARIANT_ALGORITHM_VERSION,
        case_count=case_count,
        variants=tuple(variants),
    )
