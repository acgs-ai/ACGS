"""BPMN 2.0.2 semantic XML export for a discovered process graph."""

from __future__ import annotations

import hashlib
import re
from typing import cast
from xml.etree import ElementTree as ET

from agent_bus_analyzer.process_mining.miners.discovery import DirectlyFollowsGraph

BPMN_MODEL_NAMESPACE = "http://www.omg.org/spec/BPMN/20100524/MODEL"
XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"
ACGS_ANALYTICS_NAMESPACE = "urn:acgs:process-intelligence:analytics:1"
BPMN_EXPORTER_VERSION = "bpmn-analytical-1.1"

ET.register_namespace("bpmn", BPMN_MODEL_NAMESPACE)
ET.register_namespace("xsi", XSI_NAMESPACE)
ET.register_namespace("acgs", ACGS_ANALYTICS_NAMESPACE)


def _qname(local_name: str) -> str:
    return f"{{{BPMN_MODEL_NAMESPACE}}}{local_name}"


def _analytics_qname(local_name: str) -> str:
    return f"{{{ACGS_ANALYTICS_NAMESPACE}}}{local_name}"


def _stable_id(prefix: str, value: str) -> str:
    readable = re.sub(r"[^A-Za-z0-9_]", "_", value).strip("_")[:32] or "item"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}_{readable}_{digest}"


def _add_observed_gateway(
    process: ET.Element,
    *,
    gateway_id: str,
    name: str,
    direction: str,
) -> None:
    """Add a non-executable complex gateway without claiming XOR or AND semantics."""
    gateway = ET.SubElement(
        process,
        _qname("complexGateway"),
        {
            "id": gateway_id,
            "name": name,
            "gatewayDirection": direction,
        },
    )
    documentation = ET.SubElement(gateway, _qname("documentation"))
    documentation.text = (
        "Observed DFG multiplicity only. Branch selection and synchronization semantics "
        "are unknown; this gateway is not executable authority."
    )
    extension_elements = ET.SubElement(gateway, _qname("extensionElements"))
    ET.SubElement(
        extension_elements,
        _analytics_qname("observedMultiplicity"),
        {
            "analyticalOnly": "true",
            "gatewaySemantics": "unknown",
        },
    )


def export_bpmn(graph: DirectlyFollowsGraph) -> bytes:
    """Return deterministic, non-executable BPMN semantic XML.

    The export intentionally omits BPMN-DI coordinates.  It is a semantic BPMN
    model suitable for interchange; a renderer may add diagram coordinates as
    a separate derived artifact.
    """
    definitions = ET.Element(
        _qname("definitions"),
        {
            "id": _stable_id("Definitions", f"{graph.tenant_id}:{graph.process_id}"),
            "targetNamespace": f"urn:acgs:process-intelligence:{graph.tenant_id}",
            "exporter": "ACGS Process Intelligence Engine",
            "exporterVersion": BPMN_EXPORTER_VERSION,
        },
    )
    process = ET.SubElement(
        definitions,
        _qname("process"),
        {
            "id": _stable_id("Process", graph.process_id),
            "name": graph.process_id,
            "isExecutable": "false",
        },
    )
    documentation = ET.SubElement(process, _qname("documentation"))
    documentation.text = (
        "Observer-only discovered process. This analytical artifact grants no execution authority. "
        "Complex gateways mark observed DFG multiplicity only; exclusive, inclusive, event-based, "
        "and parallel control-flow semantics are not inferred."
    )
    extension_elements = ET.SubElement(process, _qname("extensionElements"))
    ET.SubElement(
        extension_elements,
        _analytics_qname("discoveryMetadata"),
        {
            "analyticalOnly": "true",
            "controlFlowSemantics": "observed-directly-follows",
            "executionAuthority": "none",
        },
    )

    start_id = _stable_id("StartEvent", graph.process_id)
    end_id = _stable_id("EndEvent", graph.process_id)
    ET.SubElement(process, _qname("startEvent"), {"id": start_id, "name": "Start"})
    ET.SubElement(process, _qname("endEvent"), {"id": end_id, "name": "End"})

    task_ids = {
        frequency.activity: _stable_id("Task", frequency.activity)
        for frequency in graph.activity_counts
    }
    for activity in sorted(task_ids):
        ET.SubElement(
            process,
            _qname("task"),
            {"id": task_ids[activity], "name": activity},
        )

    incoming_counts = {activity: 0 for activity in task_ids}
    outgoing_counts = {activity: 0 for activity in task_ids}
    for frequency in graph.start_activity_counts:
        incoming_counts[frequency.activity] += 1
    for edge in graph.edges:
        outgoing_counts[edge.source] += 1
        incoming_counts[edge.target] += 1
    for frequency in graph.end_activity_counts:
        outgoing_counts[frequency.activity] += 1

    merge_ids: dict[str, str] = {}
    split_ids: dict[str, str] = {}
    for activity in sorted(task_ids):
        if incoming_counts[activity] > 1:
            merge_id = _stable_id("ObservedMerge", activity)
            merge_ids[activity] = merge_id
            _add_observed_gateway(
                process,
                gateway_id=merge_id,
                name=f"Observed merge before {activity}",
                direction="Converging",
            )
        if outgoing_counts[activity] > 1:
            split_id = _stable_id("ObservedSplit", activity)
            split_ids[activity] = split_id
            _add_observed_gateway(
                process,
                gateway_id=split_id,
                name=f"Observed paths after {activity}",
                direction="Diverging",
            )

    flows: list[tuple[str, str, str]] = []
    for activity in sorted(merge_ids):
        flows.append((merge_ids[activity], task_ids[activity], f"merge-task:{activity}"))
    for activity in sorted(split_ids):
        flows.append((task_ids[activity], split_ids[activity], f"task-split:{activity}"))

    start_activities = tuple(frequency.activity for frequency in graph.start_activity_counts)
    if len(start_activities) > 1:
        start_split = _stable_id("ObservedStartSplit", graph.process_id)
        _add_observed_gateway(
            process,
            gateway_id=start_split,
            name="Observed start paths",
            direction="Diverging",
        )
        flows.append((start_id, start_split, "start:alternatives"))
        for activity in start_activities:
            flows.append(
                (
                    start_split,
                    merge_ids.get(activity, task_ids[activity]),
                    f"start:{activity}",
                )
            )
    else:
        for activity in start_activities:
            flows.append(
                (
                    start_id,
                    merge_ids.get(activity, task_ids[activity]),
                    f"start:{activity}",
                )
            )

    for edge in graph.edges:
        flows.append(
            (
                split_ids.get(edge.source, task_ids[edge.source]),
                merge_ids.get(edge.target, task_ids[edge.target]),
                f"edge:{edge.source}->{edge.target}",
            )
        )

    end_activities = tuple(frequency.activity for frequency in graph.end_activity_counts)
    if len(end_activities) > 1:
        end_merge = _stable_id("ObservedEndMerge", graph.process_id)
        _add_observed_gateway(
            process,
            gateway_id=end_merge,
            name="Observed end paths",
            direction="Converging",
        )
        for activity in end_activities:
            flows.append(
                (
                    split_ids.get(activity, task_ids[activity]),
                    end_merge,
                    f"end:{activity}",
                )
            )
        flows.append((end_merge, end_id, "end:alternatives"))
    else:
        for activity in end_activities:
            flows.append(
                (
                    split_ids.get(activity, task_ids[activity]),
                    end_id,
                    f"end:{activity}",
                )
            )

    for source, target, semantic_key in sorted(flows, key=lambda item: item[2]):
        ET.SubElement(
            process,
            _qname("sequenceFlow"),
            {
                "id": _stable_id("Flow", semantic_key),
                "sourceRef": source,
                "targetRef": target,
            },
        )

    ET.indent(definitions, space="  ")
    return cast(bytes, ET.tostring(definitions, encoding="utf-8", xml_declaration=True))
