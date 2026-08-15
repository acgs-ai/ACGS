"""BPMN 2.0.2 semantic XML export tests."""

from __future__ import annotations

from collections import Counter
from xml.etree import ElementTree as ET

from agent_bus_analyzer.process_mining.miners.bpmn import (
    ACGS_ANALYTICS_NAMESPACE,
    BPMN_MODEL_NAMESPACE,
    export_bpmn,
)
from agent_bus_analyzer.process_mining.miners.discovery import discover_dfg
from tests.test_process_discovery_support import make_event


def _q(name: str) -> str:
    return f"{{{BPMN_MODEL_NAMESPACE}}}{name}"


def _aq(name: str) -> str:
    return f"{{{ACGS_ANALYTICS_NAMESPACE}}}{name}"


def _branching_events() -> list[object]:
    paths = {
        "case-a": ("Start", "Review & Approve", "Complete"),
        "case-b": ("Start", "Manual Review", "Complete"),
    }
    return [
        make_event(
            event_id=f"{case_id}-{sequence}",
            case_id=case_id,
            sequence=sequence,
            minute=case_index * 10 + sequence,
            activity=activity,
        )
        for case_index, (case_id, path) in enumerate(paths.items())
        for sequence, activity in enumerate(path)
    ]


def test_bpmn_uses_official_semantic_namespace_and_valid_references() -> None:
    xml = export_bpmn(discover_dfg(_branching_events(), process_id="approval"))
    root = ET.fromstring(xml)

    assert root.tag == _q("definitions")
    process = root.find(_q("process"))
    assert process is not None
    assert process.attrib["isExecutable"] == "false"
    assert process.find(_q("startEvent")) is not None
    assert process.find(_q("endEvent")) is not None
    assert process.findall(_q("parallelGateway")) == []
    assert process.findall(_q("exclusiveGateway")) == []

    metadata = process.find(f"{_q('extensionElements')}/{_aq('discoveryMetadata')}")
    assert metadata is not None
    assert metadata.attrib == {
        "analyticalOnly": "true",
        "controlFlowSemantics": "observed-directly-follows",
        "executionAuthority": "none",
    }

    ids = {element.attrib["id"] for element in process if "id" in element.attrib}
    flows = process.findall(_q("sequenceFlow"))
    assert flows
    assert all(flow.attrib["sourceRef"] in ids for flow in flows)
    assert all(flow.attrib["targetRef"] in ids for flow in flows)


def test_branching_and_merging_use_unknown_complex_gateway_semantics() -> None:
    root = ET.fromstring(export_bpmn(discover_dfg(_branching_events())))
    process = root.find(_q("process"))
    assert process is not None
    gateways = process.findall(_q("complexGateway"))
    assert {gateway.attrib["gatewayDirection"] for gateway in gateways} == {
        "Converging",
        "Diverging",
    }
    assert process.findall(_q("exclusiveGateway")) == []
    assert process.findall(_q("parallelGateway")) == []
    assert all(
        gateway.find(f"{_q('extensionElements')}/{_aq('observedMultiplicity')}") is not None
        for gateway in gateways
    )
    assert all(
        gateway.find(f"{_q('extensionElements')}/{_aq('observedMultiplicity')}").attrib
        == {
            "analyticalOnly": "true",
            "gatewaySemantics": "unknown",
        }
        for gateway in gateways
    )

    task_ids = {task.attrib["id"] for task in process.findall(_q("task"))}
    direct_outgoing = Counter(
        flow.attrib["sourceRef"] for flow in process.findall(_q("sequenceFlow"))
    )
    assert all(direct_outgoing[task_id] <= 1 for task_id in task_ids)


def test_bpmn_is_byte_deterministic_and_xml_escapes_labels() -> None:
    events = _branching_events()
    first = export_bpmn(discover_dfg(events, process_id="approval"))
    second = export_bpmn(discover_dfg(reversed(events), process_id="approval"))
    assert first == second
    assert b"Review &amp; Approve" in first
    assert b"raw_args" not in first
    assert b"/home/" not in first
