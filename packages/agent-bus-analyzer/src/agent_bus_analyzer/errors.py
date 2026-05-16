"""Custom exceptions raised by the public API.

Anything else surfacing out of the analyzer is a bug. The exception names
encode the spec / FR clause they correspond to so reviewers can map
behaviour back to the requirement.
"""

from __future__ import annotations


class IntegrityStoreUnavailable(RuntimeError):
    """The audit JSONL / integrity store is missing or unreadable.

    FR-008: observer MUST fail closed on integrity-store loss. New events
    MUST NOT be recorded in a non-hash-chained form.
    """


class ReadOnlyViolation(RuntimeError):
    """An attempt was made to mutate a read-only upstream surface.

    FR-003 / FR-010: observer MUST NOT mutate bus events, gove-zone
    receipts, or the audit JSONL. Raised by internal guards that catch a
    mutation attempt before it lands.
    """


class BackpressureDropped(RuntimeWarning):
    """The capture queue dropped an event due to backpressure.

    FR-013: backpressure surfaces as an `ingest-gap` marker, never as a
    bus block. This warning is emitted on every drop; the gap marker is
    emitted on resumption.
    """


class CorrelationSynthesized(UserWarning):
    """A correlation_id was synthesized because the upstream event lacked one.

    Observer contract §Upstream Surface A: missing correlation_id triggers
    a synthetic id derived from (source_agent, time-window). The trace is
    flagged `correlation_synthesized` for the reviewer.
    """
