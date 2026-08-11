#!/usr/bin/env python3
"""Regression suite for the hardened exclusivity model.

Run: python3 -m unittest discover -s tests -v      (from the package root)

The model is pure, so every case here is deterministic and needs no host, no
container and no privilege. The last class is different in kind: it runs the
real `verify_v3.conditions_from` and the real model against the evidence
recorded on disk, so the suite also proves the hardening is wired into the
verifier rather than sitting beside it as dead code.
"""

from __future__ import annotations

import copy
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE = os.path.dirname(HERE)
sys.path.insert(0, PACKAGE)

import exclusivity_model as model  # noqa: E402

with open(os.path.join(PACKAGE, "ROOT_EQUIVALENCE_REGISTRY.json"), encoding="utf-8") as handle:
    HOST_CONTEXT = json.load(handle)["measurement_context"]
SANDBOX_CONTEXT = copy.deepcopy(HOST_CONTEXT)
SANDBOX_CONTEXT["status"]["Groups"] = "10 1000"
SANDBOX_CONTEXT["host_representative"] = True  # ignored: raw credential decides

CLEAN_REGISTRY = {
    "measurement_context": HOST_CONTEXT,
    "root_equivalent_paths": [],
    "authority_equivalent_paths": [],
    "unknown_paths": [],
    "agent_is_root_equivalent": False,
}
CLEAN_TOPOLOGY = {
    "measurement_context": HOST_CONTEXT,
    "root_equivalent_paths": [],
    "unknown_privilege_paths": [],
    "requires_operator_evidence_paths": [],
    "non_root_equivalent_paths": ["setuid:/usr/bin/mount"],
    # Coverage is derived from these keys: an inventory that names no path on a
    # required surface has not measured it. See TestSurfaceCoverage.
    "paths": {
        "container_runtimes:podman_rootless": {},
        "filecaps:/usr/bin/arping": {},
        "groups:membership_docker": {},
        "polkit:pkexec": {},
        "setuid:/usr/bin/mount": {},
        "sudo:sudo": {},
        "systemd:systemd_unit_control": {},
    },
}
CLOSED_GRAPH = {
    "closed": True,
    "conditions": {
        "no_path_to_authority_principal": {"holds": True},
        "no_unauthorized_path_to_canonical_mutation": {"holds": True},
    },
}
OPEN_GRAPH = {
    "closed": False,
    "conditions": {
        "no_path_to_authority_principal": {"holds": False},
        "no_unauthorized_path_to_canonical_mutation": {"holds": False},
    },
}


def conditions(met: bool = True, **overrides) -> dict:
    """All conditions met by default; override individual keys by number."""
    out = {f"{n:02d}": {"text": f"condition {n}", "met": met} for n in range(1, 20)}
    # 18 is repeatability across runs; the verifier excludes it and so do we.
    out["18"] = {"text": "repeatability", "met": False}
    for key, value in overrides.items():
        out[key.lstrip("c")] = {"text": f"condition {key}", "met": value}
    return out


def classified(inventory: dict) -> dict:
    """Convert concise test declarations into authoritative per-entry facts."""
    result = copy.deepcopy(inventory)
    container = "mechanisms" if "agent_is_root_equivalent" in result else "paths"
    entries = result.setdefault(container, {})
    for entry in entries.values():
        entry.setdefault("classification", "NON_ROOT_EQUIVALENT")
    mappings = (
        ("root_equivalent_paths", "ROOT_EQUIVALENT"),
        ("authority_equivalent_paths", "AUTHORITY_EQUIVALENT"),
        ("unknown_paths", "UNKNOWN"),
        ("unknown_privilege_paths", "UNKNOWN"),
        ("requires_operator_evidence_paths", "REQUIRES_OPERATOR_EVIDENCE"),
    )
    for key, classification in mappings:
        for path_id in result.get(key, []):
            entries.setdefault(path_id, {})["classification"] = classification
    return result


def compute(registry=CLEAN_REGISTRY, topology=CLEAN_TOPOLOGY, graph=CLOSED_GRAPH, conds=None):
    return model.compute(
        classified(registry),
        classified(topology),
        graph,
        conds if conds is not None else conditions(),
        ignore_conditions={"18"},
    )


class TestPassingHost(unittest.TestCase):
    """PASS: fully cut over -- no docker, no sudo/polkit, no unknown paths."""

    def test_fully_cut_over_host_verifies(self):
        result = compute()
        self.assertEqual(result["verdict"], model.VERIFIED)
        self.assertEqual(result["root_equivalent_paths"], [])
        self.assertEqual(result["unknown_privilege_paths"], [])

    def test_repeatability_condition_does_not_block(self):
        # 18 is false in the fixture by construction; excluding it is the only
        # exclusion the verifier makes, and it must not turn a clean host red.
        self.assertEqual(compute()["verdict"], model.VERIFIED)

    def test_non_root_equivalent_paths_do_not_block(self):
        topology = dict(
            CLEAN_TOPOLOGY,
            non_root_equivalent_paths=[
                "setuid:/usr/bin/mount",
                "container:podman_rootless",
            ],
        )
        self.assertEqual(compute(topology=topology)["verdict"], model.VERIFIED)


class TestRootEquivalence(unittest.TestCase):
    """FAIL: docker socket reachable, docker group present."""

    def test_docker_socket_reachable_blocks(self):
        topology = dict(
            CLEAN_TOPOLOGY,
            root_equivalent_paths=["container_runtimes:docker_rootful_socket"],
        )
        result = compute(topology=topology)
        self.assertEqual(result["verdict"], model.BLOCKED_ROOT)
        self.assertIn("container_runtimes:docker_rootful_socket", result["root_equivalent_paths"])

    def test_docker_group_membership_blocks(self):
        topology = dict(CLEAN_TOPOLOGY, root_equivalent_paths=["groups:membership_docker"])
        self.assertEqual(compute(topology=topology)["verdict"], model.BLOCKED_ROOT)

    def test_registry_only_root_path_still_blocks(self):
        # the registry probes by executing a container; the topology probes
        # read-only. Either finding alone must block.
        registry = dict(
            CLEAN_REGISTRY,
            root_equivalent_paths=["docker_rootful"],
            agent_is_root_equivalent=True,
        )
        self.assertEqual(compute(registry=registry)["verdict"], model.BLOCKED_ROOT)

    def test_root_equivalence_outranks_uncertainty(self):
        registry = dict(
            CLEAN_REGISTRY,
            root_equivalent_paths=["docker_rootful"],
            unknown_paths=["sudo_polkit_interactive"],
        )
        result = compute(registry=registry)
        self.assertEqual(result["verdict"], model.BLOCKED_ROOT)
        # the uncertainty is still reported, just not as the headline
        self.assertIn("sudo_polkit_interactive", result["unknown_privilege_paths"])


class TestPrivilegeUncertainty(unittest.TestCase):
    """FAIL: sudo unknown, pkexec unknown -- UNKNOWN never becomes VERIFIED."""

    def test_sudo_unknown_blocks(self):
        registry = dict(CLEAN_REGISTRY, unknown_paths=["sudo_polkit_interactive"])
        result = compute(registry=registry)
        self.assertEqual(result["verdict"], model.BLOCKED_UNCERTAIN)

    def test_pkexec_unknown_blocks(self):
        topology = dict(CLEAN_TOPOLOGY, unknown_privilege_paths=["polkit:pkexec"])
        result = compute(topology=topology)
        self.assertEqual(result["verdict"], model.BLOCKED_UNCERTAIN)
        self.assertEqual(result["unknown_privilege_paths"], ["polkit:pkexec"])

    def test_unknown_can_never_be_verified(self):
        """The property the whole hardening exists for, stated as a test."""
        for source in ("registry", "topology"):
            for path in (
                "sudo",
                "polkit:pkexec",
                "setuid:/usr/bin/su",
                "polkit:dbus_system_bus",
                "membership_wheel",
            ):
                registry = dict(CLEAN_REGISTRY)
                topology = dict(CLEAN_TOPOLOGY)
                if source == "registry":
                    registry["unknown_paths"] = [path]
                else:
                    topology["unknown_privilege_paths"] = [path]
                verdict = compute(registry=registry, topology=topology)["verdict"]
                self.assertNotEqual(verdict, model.VERIFIED, f"{source}:{path} produced VERIFIED")
                self.assertEqual(verdict, model.BLOCKED_UNCERTAIN)

    def test_missing_inventory_fails_closed(self):
        self.assertEqual(
            model.compute(None, None, CLOSED_GRAPH, conditions())["verdict"],
            model.BLOCKED_UNCERTAIN,
        )

    def test_uncomputed_graph_closure_fails_closed(self):
        self.assertEqual(compute(graph=None)["verdict"], model.BLOCKED_UNCERTAIN)
        self.assertEqual(compute(graph={})["verdict"], model.BLOCKED_UNCERTAIN)


class TestOperatorEvidence(unittest.TestCase):
    """REQUIRES_OPERATOR_EVIDENCE is a rename of UNKNOWN, not a resolution.

    Phase 2 of the closure task asks that no UNKNOWN remain. The laundering
    move is to rename all 36 into REQUIRES_OPERATOR_EVIDENCE, report "0
    UNKNOWN", and let the verdict go green over an unmeasured surface. These
    cases make that impossible.
    """

    def test_operator_evidence_is_not_a_pass(self):
        topology = dict(
            CLEAN_TOPOLOGY,
            requires_operator_evidence_paths=["setuid:/usr/bin/sudo"],
        )
        result = compute(topology=topology)
        self.assertEqual(result["verdict"], model.BLOCKED_UNCERTAIN)
        self.assertNotEqual(result["verdict"], model.VERIFIED)
        self.assertIn("setuid:/usr/bin/sudo", result["unresolved_privilege_paths"])

    def test_renaming_unknown_to_operator_evidence_does_not_move_the_verdict(self):
        as_unknown = compute(
            topology=dict(CLEAN_TOPOLOGY, unknown_privilege_paths=["polkit:pkexec"])
        )
        as_operator = compute(
            topology=dict(
                CLEAN_TOPOLOGY,
                requires_operator_evidence_paths=["polkit:pkexec"],
            )
        )
        self.assertEqual(as_unknown["verdict"], as_operator["verdict"])
        self.assertEqual(as_operator["verdict"], model.BLOCKED_UNCERTAIN)

    def test_operator_evidence_can_never_be_verified(self):
        for path in (
            "sudo:sudo",
            "polkit:pkexec",
            "setuid:/usr/bin/su",
            "groups:membership_wheel",
            "container_runtimes:libvirt_socket",
        ):
            for source, key in (
                ("topology", "requires_operator_evidence_paths"),
                ("registry", "requires_operator_evidence_paths"),
            ):
                registry = dict(CLEAN_REGISTRY)
                topology = dict(CLEAN_TOPOLOGY)
                (registry if source == "registry" else topology)[key] = [path]
                verdict = compute(registry=registry, topology=topology)["verdict"]
                self.assertNotEqual(verdict, model.VERIFIED, f"{source}:{path} produced VERIFIED")

    def test_condition_19_consumes_operator_evidence(self):
        cond = model.unknown_condition(
            classified(CLEAN_REGISTRY),
            classified(
                dict(
                    CLEAN_TOPOLOGY,
                    requires_operator_evidence_paths=["setuid:/usr/bin/pkexec"],
                )
            ),
        )
        self.assertFalse(cond["met"])
        self.assertEqual(cond["evidence"]["count"], 1)


class TestMeasurementContext(unittest.TestCase):
    """An inventory is evidence about the host only if it measured the host.

    Measured, not hypothesised: running the collector inside the agent sandbox
    emits `root_equivalent_paths == []` on a host where the docker gid is still
    in `/etc/group` and the socket is still group-writable. The clean inventory
    is produced by the namespace, not by a cutover.
    """

    def test_sandboxed_inventory_is_inadmissible(self):
        topology = dict(CLEAN_TOPOLOGY, measurement_context=SANDBOX_CONTEXT)
        result = compute(topology=topology)
        self.assertEqual(result["verdict"], model.BLOCKED_UNCERTAIN)
        self.assertFalse(result["inventory_admissibility"]["PRIVILEGE_TOPOLOGY"])

    def test_contextless_inventory_is_inadmissible(self):
        topology = {k: v for k, v in CLEAN_TOPOLOGY.items() if k != "measurement_context"}
        self.assertEqual(compute(topology=topology)["verdict"], model.BLOCKED_UNCERTAIN)

    def test_inadmissible_inventory_is_not_silently_dropped(self):
        """Dropping it would delete its findings and improve the verdict."""
        topology = dict(
            CLEAN_TOPOLOGY,
            measurement_context=SANDBOX_CONTEXT,
            root_equivalent_paths=["container_runtimes:docker_rootful_socket"],
        )
        result = compute(topology=topology)
        self.assertNotEqual(result["verdict"], model.VERIFIED)
        self.assertTrue(
            any(p.startswith("inventory:") for p in result["unresolved_privilege_paths"])
        )

    def test_a_sandbox_cannot_manufacture_a_pass(self):
        """The whole point: same host, restricted context, still not VERIFIED."""
        registry = dict(CLEAN_REGISTRY, measurement_context=SANDBOX_CONTEXT)
        topology = dict(CLEAN_TOPOLOGY, measurement_context=SANDBOX_CONTEXT)
        self.assertEqual(
            compute(registry=registry, topology=topology)["verdict"],
            model.BLOCKED_UNCERTAIN,
        )


class TestSurfaceCoverage(unittest.TestCase):
    """A partial inventory must never be able to improve a verdict.

    Admissibility answers "measured as whom"; coverage answers "measured of
    what". An inventory that looked only at `groups`, from a perfect context,
    is silent about setuid -- and silence is not absence.
    """

    def test_full_coverage_is_required_for_the_host_measured_flag(self):
        self.assertTrue(compute()["every_inventory_host_measured"])

    def test_missing_surface_blocks(self):
        topology = dict(CLEAN_TOPOLOGY)
        topology["paths"] = {"groups:membership_docker": {}}
        result = compute(topology=topology)
        self.assertEqual(result["verdict"], model.BLOCKED_UNCERTAIN)
        self.assertFalse(result["every_inventory_host_measured"])
        self.assertIn("setuid", result["surfaces_missing"])
        self.assertIn(
            "coverage:setuid_not_successfully_completed",
            result["unresolved_privilege_paths"],
        )

    def test_partial_inventory_cannot_improve_a_verdict(self):
        """Deleting the surface that carries the finding must not help."""
        full = dict(CLEAN_TOPOLOGY)
        full["paths"] = {f"{s}:probe": {} for s in model.REQUIRED_SURFACES}
        full["root_equivalent_paths"] = ["container_runtimes:docker_rootful_socket"]
        blocked = compute(topology=full)

        trimmed = dict(full)
        trimmed["paths"] = {k: v for k, v in full["paths"].items() if not k.startswith("container")}
        trimmed["root_equivalent_paths"] = []
        after = compute(topology=trimmed)

        self.assertEqual(blocked["verdict"], model.BLOCKED_ROOT)
        self.assertNotEqual(after["verdict"], model.VERIFIED)
        self.assertEqual(after["verdict"], model.BLOCKED_UNCERTAIN)

    def test_coverage_is_derived_from_paths_not_self_declared(self):
        """An inventory cannot claim coverage it did not demonstrate."""
        topology = dict(CLEAN_TOPOLOGY)
        topology["paths"] = {}
        topology["surfaces_measured"] = list(model.REQUIRED_SURFACES)
        result = compute(topology=topology)
        self.assertEqual(result["surfaces_covered"], [])
        self.assertEqual(result["verdict"], model.BLOCKED_UNCERTAIN)

    def test_coverage_names_its_own_reason(self):
        topology = dict(CLEAN_TOPOLOGY)
        topology["paths"] = {"groups:membership_docker": {}}
        self.assertEqual(
            compute(topology=topology)["specific_reason"],
            "BLOCKED_PRIVILEGE_UNCERTAIN_INCOMPLETE_SURFACE_COVERAGE",
        )


class TestSpecificReason(unittest.TestCase):
    """`BLOCKED_<specific_reason>` is derived from paths, never hand-picked."""

    def test_docker_root_path_names_docker(self):
        topology = dict(
            CLEAN_TOPOLOGY,
            root_equivalent_paths=["container_runtimes:docker_rootful_socket"],
        )
        self.assertEqual(
            compute(topology=topology)["specific_reason"],
            "BLOCKED_ROOT_EQUIVALENCE_DOCKER",
        )

    def test_operator_evidence_names_itself(self):
        topology = dict(CLEAN_TOPOLOGY, requires_operator_evidence_paths=["sudo:sudo"])
        self.assertEqual(
            compute(topology=topology)["specific_reason"],
            "BLOCKED_PRIVILEGE_UNCERTAIN_OPERATOR_EVIDENCE_REQUIRED",
        )

    def test_clean_host_names_the_closure(self):
        self.assertEqual(compute()["specific_reason"], "VERIFIED_AUTHORITY_EXCLUSIVE")


class TestAuthorityEquivalence(unittest.TestCase):
    """FAIL: UID delegation conflict, open privilege graph."""

    def test_uid_delegation_conflict_blocks(self):
        # condition 02 is "the authority uid/gid is not agent-delegable"; a uid
        # inside /etc/subuid fails it, and a failing condition may never verify.
        result = compute(conds=conditions(**{"c02": False}))
        self.assertEqual(result["verdict"], model.BLOCKED_AUTHORITY)
        self.assertIn("02", result["failed_conditions"])

    def test_open_graph_blocks(self):
        self.assertEqual(compute(graph=OPEN_GRAPH)["verdict"], model.BLOCKED_AUTHORITY)

    def test_authority_equivalent_path_blocks(self):
        registry = dict(CLEAN_REGISTRY, authority_equivalent_paths=["setns_into_940"])
        self.assertEqual(compute(registry=registry)["verdict"], model.BLOCKED_AUTHORITY)


class TestHiddenPathIntroduced(unittest.TestCase):
    """FAIL: a privilege path that only one inventory knows about."""

    def test_hidden_root_path_seen_only_by_topology(self):
        topology = dict(CLEAN_TOPOLOGY, root_equivalent_paths=["systemd:systemd_unit_control"])
        result = compute(topology=topology)
        self.assertEqual(result["verdict"], model.BLOCKED_ROOT)
        self.assertIn("systemd:systemd_unit_control", result["root_equivalent_paths"])

    def test_hidden_unknown_path_seen_only_by_topology(self):
        topology = dict(CLEAN_TOPOLOGY, unknown_privilege_paths=["setuid:/opt/vendor/helper"])
        self.assertEqual(compute(topology=topology)["verdict"], model.BLOCKED_UNCERTAIN)

    def test_a_new_setuid_binary_cannot_be_ignored(self):
        topology = dict(CLEAN_TOPOLOGY, unknown_privilege_paths=["setuid:/usr/local/bin/newthing"])
        result = compute(topology=topology)
        self.assertNotEqual(result["verdict"], model.VERIFIED)

    def test_union_is_not_intersection(self):
        registry = dict(CLEAN_REGISTRY, unknown_paths=["a"])
        topology = dict(CLEAN_TOPOLOGY, unknown_privilege_paths=["b"])
        result = compute(registry=registry, topology=topology)
        self.assertEqual(result["unknown_privilege_paths"], ["a", "b"])


class TestUnknownCondition(unittest.TestCase):
    """Condition 19, in the shape verify_v3.py stores conditions."""

    def test_condition_met_when_nothing_unknown(self):
        cond = model.unknown_condition(classified(CLEAN_REGISTRY), classified(CLEAN_TOPOLOGY))
        self.assertTrue(cond["met"])
        self.assertTrue(cond["cutover_dependent"])

    def test_condition_fails_and_names_the_paths(self):
        cond = model.unknown_condition(
            classified(dict(CLEAN_REGISTRY, unknown_paths=["sudo_polkit_interactive"])),
            classified(dict(CLEAN_TOPOLOGY, unknown_privilege_paths=["polkit:pkexec"])),
        )
        self.assertFalse(cond["met"])
        self.assertEqual(cond["evidence"]["count"], 2)


class TestWiredIntoVerifier(unittest.TestCase):
    """Dispatcher-level: the hardening must be in the real execution path.

    A passing unit test on the model proves nothing about the verifier. These
    cases import `verify_v3` itself and run its real condition builder over the
    evidence recorded on disk.
    """

    @classmethod
    def setUpClass(cls):
        cls.verify = __import__("verify_v3")
        cls.artifacts = {}
        for key, name in (
            ("attacks", "attack_results.json"),
            ("registry", "ROOT_EQUIVALENCE_REGISTRY.json"),
            ("analysis", "AUTHORITY_PRINCIPAL_ANALYSIS.json"),
            ("graph", "PRIVILEGE_GRAPH.json"),
            # The resolved, context-bound inventory -- the file the verifier
            # actually computes its verdict from.
            ("topology", "PRIVILEGE_TOPOLOGY_FINAL.json"),
            ("topology_raw", "PRIVILEGE_TOPOLOGY.json"),
        ):
            path = os.path.join(PACKAGE, name)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as handle:
                    cls.artifacts[key] = json.load(handle)

    def test_verifier_imports_the_model(self):
        self.assertIs(self.verify.BLOCKED_UNCERTAIN, model.BLOCKED_UNCERTAIN)
        self.assertIn("19", self.verify.CUTOVER_DEPENDENT)

    def test_verifier_is_not_dead_code(self):
        with open(os.path.join(PACKAGE, "verify_v3.py"), encoding="utf-8") as fh:
            source = fh.read()
        self.assertIn("exclusivity_model.compute(", source)
        self.assertIn("privilege_topology.py", source)
        # the resolution stage, and the file whose verdict it binds
        self.assertIn("privilege_resolution.py", source)
        self.assertIn("TOPOLOGY_FINAL", source)

    def test_registry_producer_stamps_its_measurement_context(self):
        """Otherwise the registry is inadmissible forever and cannot close."""
        with open(os.path.join(PACKAGE, "root_equivalence.py"), encoding="utf-8") as fh:
            source = fh.read()
        self.assertIn("privilege_context.capture()", source)
        self.assertIn("measurement_context", source)

    def test_real_conditions_include_19_and_it_fails_here(self):
        needed = ("attacks", "registry", "analysis", "graph", "topology")
        if not all(key in self.artifacts for key in needed):
            self.skipTest("recorded evidence artifacts are not all present")
        conds = self.verify.conditions_from(
            self.artifacts["attacks"],
            self.artifacts["registry"],
            self.artifacts["analysis"],
            self.artifacts["graph"],
            self.artifacts["topology"],
        )
        self.assertIn("19", conds)
        self.assertFalse(
            conds["19"]["met"],
            "this host has unresolved privilege paths, so 19 must fail",
        )

    def test_real_evidence_yields_blocked_root_equivalence(self):
        if "registry" not in self.artifacts or "topology" not in self.artifacts:
            self.skipTest("recorded evidence artifacts are not present")
        result = model.compute(
            self.artifacts["registry"],
            self.artifacts["topology"],
            self.artifacts.get("graph", {}).get("closure"),
            conditions(),
            ignore_conditions={"18"},
        )
        self.assertEqual(result["verdict"], model.BLOCKED_ROOT)

    def test_removing_docker_summary_cannot_erase_per_entry_finding(self):
        """Summary tampering cannot erase the classified Docker mechanism."""
        if "registry" not in self.artifacts or "topology" not in self.artifacts:
            self.skipTest("recorded evidence artifacts are not present")
        registry = dict(
            self.artifacts["registry"],
            root_equivalent_paths=[],
            agent_is_root_equivalent=False,
        )
        topology = dict(self.artifacts["topology"], root_equivalent_paths=[])
        # The recorded graph is closed only through the docker edges, so it must
        # be replaced along with the paths -- after a real cutover the graph is
        # recomputed too. Leaving the recorded closure in would make this case
        # pass for the wrong reason (BLOCKED_AUTHORITY_EQUIVALENCE), which is
        # exactly what it did before this line existed.
        result = model.compute(
            registry,
            topology,
            CLOSED_GRAPH,
            conditions(),
            ignore_conditions={"18"},
        )
        self.assertEqual(result["verdict"], model.BLOCKED_ROOT)
        self.assertNotEqual(result["verdict"], model.VERIFIED)
        self.assertIn("docker_rootful", result["root_equivalent_paths"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
