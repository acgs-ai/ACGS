"""Cross-link tests for OpenTelemetry <-> ACGS chain evidence.

Contract (see docs/design/acgs-phoenix-observability.md):
  - When a real OpenTelemetry span is active at the moment _audit() runs,
    the evidence row carries metadata.trace_id / metadata.span_id that match
    the span's ids, AND the span carries acgs.event_hash + acgs.decision
    attributes that match the event that was just written.
  - When no span is active (or OTEL is not installed), evidence rows are
    written exactly as they were before this feature existed — no new keys
    in metadata, chain-verify still passes.
  - A failure on the span side must never break governance: if the stamping
    call raises, the evidence write still happens and still verifies.

These tests use the real opentelemetry-sdk with an InMemorySpanExporter so
trace/span ids are deterministic and span attributes are inspectable. No
Phoenix container or network traffic is required.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evidence_writer import ChainEvidenceWriter  # noqa: E402
from hermes_acgs_middleware import (  # noqa: E402
    DENY,
    HermesACGSMiddleware,
    _current_otel_ids,
    _stamp_span_with_acgs,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def otel_exporter():
    """Install a process-wide OTEL TracerProvider that captures spans in memory.

    The opentelemetry SDK does not support cleanly replacing the global
    TracerProvider mid-process — once set, subsequent set_tracer_provider
    calls are no-ops and emit a warning. To make this fixture safe to run
    multiple times in the same pytest session we (a) detect an existing
    provider and reuse it when possible, and (b) always use a fresh
    InMemorySpanExporter per test so spans from other tests do not leak in.
    """
    from opentelemetry import trace
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    exporter = InMemorySpanExporter()
    processor = SimpleSpanProcessor(exporter)

    current = trace.get_tracer_provider()
    provider: TracerProvider
    if isinstance(current, TracerProvider):
        # SDK provider already installed (perhaps by an earlier test).
        # Attach our exporter to it so our span processor captures this
        # test's spans, then detach on teardown.
        provider = current
        provider.add_span_processor(processor)
    else:
        provider = TracerProvider()
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)

    yield exporter

    exporter.clear()
    try:
        # Force flush so any pending spans are visible before teardown asserts
        provider.force_flush(timeout_millis=1000)
    except Exception:
        pass


def build_middleware(tmp_path: Path, evidence: bool = True) -> HermesACGSMiddleware:
    return HermesACGSMiddleware(
        constitution_path=ROOT / "constitution.min.yaml",
        evidence_path=(tmp_path / "session.jsonl") if evidence else None,
        session_id="pytest-otel-session",
        agent_id="hermes-otel-test-agent",
    )


# ---------------------------------------------------------------------------
# No active span -> no cross-link metadata, no attributes, chain verifies
# ---------------------------------------------------------------------------


def test_no_active_span_does_not_add_trace_metadata(tmp_path):
    """With no span context active, _audit() must behave exactly as before.

    This guards the regression contract: the OTEL integration must be
    invisible when nothing is actively being traced. Existing evidence files
    from pre-integration deployments must remain binary-identical in shape.
    """
    acgs = build_middleware(tmp_path)
    acgs.check_pre_tool("web_search", {"q": "ACGS"}, user_msg="hi")

    events = ChainEvidenceWriter.read_events(tmp_path / "session.jsonl")
    assert len(events) == 1
    metadata = events[0]["metadata"]
    assert "trace_id" not in metadata
    assert "span_id" not in metadata

    ok, errors = ChainEvidenceWriter.verify_chain(tmp_path / "session.jsonl")
    assert ok, errors


def test_current_otel_ids_returns_none_outside_span():
    """The helper must return (None, None) when nothing is active."""
    trace_id, span_id = _current_otel_ids()
    assert trace_id is None
    assert span_id is None


# ---------------------------------------------------------------------------
# Active span -> evidence row AND span get cross-linked
# ---------------------------------------------------------------------------


def test_active_span_cross_links_both_directions(tmp_path, otel_exporter):
    """Core contract: evidence row has trace_id/span_id, span has acgs.* attrs.

    The two-way binding makes the ACGS chain and the Phoenix/OpenInference
    span deterministically point at each other without either side having to
    know about the other's storage.
    """
    from opentelemetry import trace

    acgs = build_middleware(tmp_path)
    tracer = trace.get_tracer(__name__)

    with tracer.start_as_current_span("tool.web_search") as span:
        ctx = span.get_span_context()
        expected_trace_id = f"{ctx.trace_id:032x}"
        expected_span_id = f"{ctx.span_id:016x}"
        decision = acgs.check_pre_tool("web_search", {"q": "ACGS"}, user_msg="hi")

    # Evidence side: trace_id/span_id populated and match the span's ids.
    events = ChainEvidenceWriter.read_events(tmp_path / "session.jsonl")
    assert len(events) == 1
    metadata = events[0]["metadata"]
    assert metadata["trace_id"] == expected_trace_id
    assert metadata["span_id"] == expected_span_id
    written_event_hash = events[0]["event_hash"]

    # Span side: acgs.event_hash and acgs.decision were stamped before export.
    finished = otel_exporter.get_finished_spans()
    matching = [s for s in finished if s.name == "tool.web_search"]
    assert matching, "Expected the instrumented span to have been exported"
    span_attrs = dict(matching[-1].attributes or {})
    assert span_attrs.get("acgs.event_hash") == written_event_hash
    assert span_attrs.get("acgs.decision") == decision.action

    # The chain still verifies with the new metadata keys present. This is the
    # critical governance invariant: adding trace_id/span_id must not break
    # tamper-evidence.
    ok, errors = ChainEvidenceWriter.verify_chain(tmp_path / "session.jsonl")
    assert ok, errors


def test_deny_decision_also_cross_links(tmp_path, otel_exporter):
    """DENY decisions must carry the cross-link just like ALLOW decisions.

    A Phoenix operator looking at the span for a denied tool call must be
    able to pivot directly to the governance evidence row that denied it.
    """
    from opentelemetry import trace

    acgs = build_middleware(tmp_path)
    tracer = trace.get_tracer(__name__)

    with tracer.start_as_current_span("tool.shell") as span:
        ctx = span.get_span_context()
        expected_trace_id = f"{ctx.trace_id:032x}"
        expected_span_id = f"{ctx.span_id:016x}"
        decision = acgs.check_pre_tool("shell", {"cmd": "rm -rf /"})

    assert decision.action == DENY

    events = ChainEvidenceWriter.read_events(tmp_path / "session.jsonl")
    assert events[0]["metadata"]["trace_id"] == expected_trace_id
    assert events[0]["metadata"]["span_id"] == expected_span_id

    matching = [s for s in otel_exporter.get_finished_spans() if s.name == "tool.shell"]
    assert matching
    span_attrs = dict(matching[-1].attributes or {})
    assert span_attrs.get("acgs.decision") == DENY
    assert span_attrs.get("acgs.event_hash") == events[0]["event_hash"]

    ok, errors = ChainEvidenceWriter.verify_chain(tmp_path / "session.jsonl")
    assert ok, errors


def test_multiple_audits_in_one_span_produce_distinct_event_hashes(tmp_path, otel_exporter):
    """Chain integrity under many audits inside a single trace.

    A single governed tool call typically produces pre_tool + post_tool
    evidence rows. Both must link back to the same trace_id, but with
    different event_hash values that chain correctly.
    """
    from opentelemetry import trace

    acgs = build_middleware(tmp_path)
    tracer = trace.get_tracer(__name__)

    with tracer.start_as_current_span("tool.web_search") as span:
        ctx = span.get_span_context()
        expected_trace_id = f"{ctx.trace_id:032x}"
        acgs.check_pre_tool("web_search", {"q": "foo"})
        acgs.check_post_tool("web_search", {"q": "foo"}, "ok")

    events = ChainEvidenceWriter.read_events(tmp_path / "session.jsonl")
    assert len(events) == 2
    for event in events:
        assert event["metadata"]["trace_id"] == expected_trace_id
    assert events[0]["event_hash"] != events[1]["event_hash"]
    assert events[1]["prev_hash"] == events[0]["event_hash"]

    ok, errors = ChainEvidenceWriter.verify_chain(tmp_path / "session.jsonl")
    assert ok, errors


# ---------------------------------------------------------------------------
# Resilience: span stamping failures must not break governance
# ---------------------------------------------------------------------------


def test_span_stamping_failure_does_not_break_audit(tmp_path, monkeypatch):
    """If stamping the span raises, the evidence row must still be written.

    This is a hard governance guarantee: observability is additive. A broken
    tracer SDK, a closed exporter, or a third-party monkey-patch gone wrong
    must not prevent ACGS from recording a decision.
    """
    import hermes_acgs_middleware as module

    def raising_stamp(**_kwargs):
        raise RuntimeError("synthetic tracer failure")

    monkeypatch.setattr(module, "_stamp_span_with_acgs", raising_stamp)

    acgs = build_middleware(tmp_path)
    # This must not raise despite the broken stamper.
    try:
        acgs.check_pre_tool("web_search", {"q": "ACGS"})
    except RuntimeError:
        pytest.fail("Governance audit broke because span stamping raised")

    events = ChainEvidenceWriter.read_events(tmp_path / "session.jsonl")
    assert len(events) == 1

    ok, errors = ChainEvidenceWriter.verify_chain(tmp_path / "session.jsonl")
    assert ok, errors


def test_stamp_is_safe_when_no_span_active():
    """Calling _stamp_span_with_acgs outside a span must be a silent no-op."""
    # Any exception here would indicate the stamper is not properly guarded.
    _stamp_span_with_acgs(event_hash="deadbeef" * 8, decision="ALLOW")


# ---------------------------------------------------------------------------
# Evidence-less middleware still stamps the span (operator visibility)
# ---------------------------------------------------------------------------


def test_evidence_less_middleware_still_stamps_span(tmp_path, otel_exporter):
    """Running without a ChainEvidenceWriter must still stamp the span.

    The evidence-less mode is useful for dev/test harnesses. Operators
    running against it should still see the ACGS decision in Phoenix, even
    if there is no persistent chain to reference. In that case
    acgs.event_hash is the empty string (there is no authoritative row), but
    acgs.decision carries the decision label.
    """
    from opentelemetry import trace

    acgs = build_middleware(tmp_path, evidence=False)
    tracer = trace.get_tracer(__name__)

    with tracer.start_as_current_span("tool.web_search"):
        decision = acgs.check_pre_tool("web_search", {"q": "ACGS"})

    matching = [s for s in otel_exporter.get_finished_spans() if s.name == "tool.web_search"]
    assert matching
    span_attrs = dict(matching[-1].attributes or {})
    assert span_attrs.get("acgs.decision") == decision.action
    # Empty event_hash is the documented signal for "no persistent record".
    assert span_attrs.get("acgs.event_hash") == ""
