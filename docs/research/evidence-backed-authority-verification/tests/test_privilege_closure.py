#!/usr/bin/env python3
"""Regression suite for the privilege closure: resolution + context binding.

Run: python3 -m unittest discover -s tests      (from the package root)

`test_exclusivity_model.py` proves the *verdict model* cannot be fooled. This
file proves the *inventory* feeding it is complete and honestly labelled: no
UNKNOWN survives, no classification is asserted without a discriminator, and
the two findings this pass turned up -- the sandbox-clean inventory and the
setuid bit with no vendor provenance -- stay caught.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from typing import ClassVar

HERE = os.path.dirname(os.path.abspath(__file__))
PACKAGE = os.path.dirname(HERE)
sys.path.insert(0, PACKAGE)

import privilege_context  # noqa: E402
import privilege_resolution as resolution  # noqa: E402

FINAL = os.path.join(PACKAGE, "PRIVILEGE_TOPOLOGY_FINAL.json")


def load_final() -> dict | None:
    if not os.path.exists(FINAL):
        return None
    with open(FINAL, encoding="utf-8") as handle:
        return json.load(handle)


class TestResolvedInventory(unittest.TestCase):
    """Phase 2: every UNKNOWN reaches a terminal state, and none is a pass."""

    @classmethod
    def setUpClass(cls):
        cls.final = load_final()

    def setUp(self):
        if self.final is None:
            self.skipTest("PRIVILEGE_TOPOLOGY_FINAL.json has not been produced")
        if not self.final.get("admissible"):
            self.skipTest(
                "the recorded inventory was taken in a non-host context; "
                "its refusal is asserted by TestResolutionRefusesSandbox"
            )

    def test_no_unknown_remains(self):
        self.assertEqual(self.final["unknown_privilege_paths"], [])
        self.assertEqual(self.final["counts"]["unknown"], 0)

    def test_every_path_has_a_terminal_classification(self):
        for path_id, entry in self.final["paths"].items():
            self.assertIn(entry["classification"], resolution.TERMINAL, f"{path_id} is unterminal")

    def test_every_path_carries_a_discriminator(self):
        for path_id, entry in self.final["paths"].items():
            self.assertTrue(entry.get("discriminator"), f"{path_id} was classified without one")

    def test_every_operator_path_names_the_command_that_answers_it(self):
        for path_id in self.final["requires_operator_evidence_paths"]:
            self.assertTrue(
                self.final["paths"][path_id].get("operator_action"),
                f"{path_id} blocks without telling the operator what to run",
            )

    def test_counts_add_up(self):
        counts = self.final["counts"]
        self.assertEqual(
            counts["total"],
            counts["root_equivalent"]
            + counts["non_root_equivalent"]
            + counts["not_present"]
            + counts["requires_operator_evidence"]
            + counts["unknown"],
        )

    def test_blocking_set_is_root_plus_unresolved(self):
        expected = set(self.final["root_equivalent_paths"])
        expected |= set(self.final["requires_operator_evidence_paths"])
        expected |= set(self.final["unknown_privilege_paths"])
        self.assertEqual(set(self.final["blocking_paths"]), expected)

    def test_setuid_entries_carry_the_required_fields(self):
        """Phase 5: path, owner, mode, hash, capabilities, package, effect."""
        for path_id, entry in self.final["paths"].items():
            if not path_id.startswith("setuid:"):
                continue
            if entry["classification"] == resolution.NOT_PRESENT:
                continue
            evidence = entry["evidence"]
            if entry.get("prior_classification") in (
                resolution.ROOT_EQUIVALENT,
                resolution.NON_ROOT_EQUIVALENT,
            ):
                continue  # carried forward with the source inventory's evidence
            self.assertIn("file", evidence, path_id)
            self.assertIn("mode", evidence["file"], path_id)
            self.assertIn("owner_uid", evidence["file"], path_id)
            self.assertIn("capabilities", evidence, path_id)
            self.assertIn("integrity", evidence, path_id)
            self.assertTrue(entry.get("privilege_effect"), path_id)


class TestKnownFindingsStayCaught(unittest.TestCase):
    """The two false-positive/false-negative traps found in this package."""

    @classmethod
    def setUpClass(cls):
        cls.final = load_final()

    def setUp(self):
        if self.final is None or not self.final.get("admissible"):
            self.skipTest("no admissible inventory on disk")

    def test_libvirt_is_not_root_equivalent_and_still_blocks(self):
        """The corrected false positive: connect() != authority, and != safe."""
        for path_id in (
            "container_runtimes:libvirt_socket",
            "container_runtimes:libvirt_ro_socket",
        ):
            entry = self.final["paths"].get(path_id)
            if entry is None:
                continue
            self.assertNotEqual(
                entry["classification"],
                resolution.ROOT_EQUIVALENT,
                f"{path_id}: a completed connect() to a 0666 polkit-gated "
                "socket is not a measurement of authority",
            )
            self.assertTrue(entry["blocking"], f"{path_id}: unresolved is not the same as safe")

    def test_docker_remains_the_measured_root_path(self):
        self.assertIn(
            "container_runtimes:docker_rootful_socket",
            self.final["root_equivalent_paths"],
        )

    def test_setuid_bit_without_vendor_provenance_is_not_bounded(self):
        """Bytes matching the package do not attest a privilege the package
        never declared: /opt/1Password/chrome-sandbox is digest-MATCH at mode
        4755 while its rpm records 100755."""
        classification, _, discriminator, _, action = resolution._packaged_bound(
            {
                "packaged": True,
                "integrity": "MATCH",
                "expected_mode": "100755",
                "setuid_declared_by_package": False,
                "setuid_on_disk": True,
            },
            "effect",
            "bound",
        )
        self.assertEqual(classification, resolution.OPERATOR)
        self.assertIn("setuid", discriminator)
        self.assertTrue(action)

    def test_unreadable_binary_cannot_be_attested(self):
        """4711 setuid binaries: no bytes to hash means no provenance."""
        classification, _, _, _, _ = resolution._packaged_bound(
            {"packaged": True, "integrity": "FILE_UNREADABLE_BY_AGENT"},
            "effect",
            "bound",
        )
        self.assertEqual(classification, resolution.OPERATOR)

    def test_a_verified_package_with_a_declared_setuid_bit_is_bounded(self):
        """The positive control: the rule can still say NON_ROOT_EQUIVALENT."""
        classification, _, _, _, action = resolution._packaged_bound(
            {
                "packaged": True,
                "integrity": "MATCH",
                "expected_mode": "104755",
                "setuid_declared_by_package": True,
                "setuid_on_disk": True,
            },
            "effect",
            "bound",
        )
        self.assertEqual(classification, resolution.NON_ROOT_EQUIVALENT)
        self.assertIsNone(action)


class TestResolutionRefusesSandbox(unittest.TestCase):
    """Dispatcher-level: the refusal is in `build()`, not in a caller's manners."""

    def test_build_refuses_when_context_is_not_host_representative(self):
        real = privilege_context.capture
        privilege_context.capture = lambda: {
            "host_representative": False,
            "disqualifiers": ["uid_map is a namespace slice: [(1000, 1000, 1)]"],
        }
        try:
            result = resolution.build()
        finally:
            privilege_context.capture = real
        self.assertFalse(result["admissible"])
        self.assertEqual(result["paths"], {})
        self.assertIn("sandbox", result["refusal"])

    def test_refusal_does_not_clobber_a_host_measured_inventory(self):
        """Failing closed must not also fail destructively."""
        before = load_final()
        if before is None:
            self.skipTest("no inventory on disk to protect")
        real = privilege_context.capture
        privilege_context.capture = lambda: {
            "host_representative": False,
            "disqualifiers": ["uid_map is a namespace slice: [(1000, 1000, 1)]"],
        }
        try:
            rc = resolution.main()
        finally:
            privilege_context.capture = real
        self.assertEqual(rc, 2)
        self.assertEqual(load_final(), before)

    def test_context_check_fails_closed_on_garbage(self):
        for value in (
            None,
            {},
            [],
            "host_representative",
            {"host_representative": "yes"},
        ):
            self.assertFalse(privilege_context.is_host_representative(value))

    def test_full_range_map_is_the_admissible_shape(self):
        self.assertEqual(privilege_context.FULL_RANGE_MAP, (0, 0, 4294967295))


class TestFileCapabilities(unittest.TestCase):
    """The surface `find -perm -4000` is structurally incapable of finding.

    File capabilities confer authority with no setuid bit. Before this surface
    existed, `/usr/bin/suexec cap_setgid,cap_setuid=ep` was absent from the
    inventory entirely -- and an inventory that never enumerates a surface is
    silent about it, which is the failure mode this package exists to prevent.
    """

    @classmethod
    def setUpClass(cls):
        cls.final = load_final()

    def setUp(self):
        if self.final is None or not self.final.get("admissible"):
            self.skipTest("no admissible inventory on disk")

    def test_filecaps_is_a_required_surface(self):
        import exclusivity_model

        self.assertIn("filecaps", exclusivity_model.REQUIRED_SURFACES)

    def test_capability_binaries_are_inventoried(self):
        caps = [k for k in self.final["paths"] if k.startswith("filecaps:")]
        self.assertTrue(caps, "the file-capability surface produced no paths")
        # the specific binary the setuid sweep could never have found
        self.assertIn("filecaps:/usr/bin/suexec", self.final["paths"])

    def test_a_capability_binary_is_not_also_found_by_the_setuid_sweep(self):
        """Proves the surfaces are disjoint, i.e. that this one was needed."""
        self.assertNotIn("setuid:/usr/bin/suexec", self.final["paths"])

    def test_parse_caps_separates_permitted_from_inheritable_only(self):
        import privilege_topology

        permitted = privilege_topology.parse_caps("cap_setgid,cap_setuid=ep")
        inheritable = privilege_topology.parse_caps("cap_setuid,cap_net_raw=ei")
        self.assertTrue(permitted["permitted"])
        self.assertFalse(permitted["inheritable_only"])
        self.assertFalse(inheritable["permitted"])
        self.assertTrue(inheritable["inheritable_only"])
        self.assertEqual(permitted["capabilities"], ["cap_setgid", "cap_setuid"])

    def test_non_executable_capability_binary_is_bounded_by_dac(self):
        entry = self.final["paths"].get("filecaps:/usr/bin/suexec")
        if entry is None:
            self.skipTest("suexec not present on this host")
        self.assertEqual(entry["classification"], resolution.NON_ROOT_EQUIVALENT)
        self.assertFalse(entry["evidence"]["executable_by_agent"])
        self.assertIn("cannot execute", entry["discriminator"])

    def test_inheritable_only_grant_is_computed_not_assumed(self):
        entry = self.final["paths"].get("filecaps:/usr/bin/warp-svc")
        if entry is None:
            self.skipTest("warp-svc not present on this host")
        evidence = entry["evidence"]
        self.assertTrue(evidence["capabilities"]["inheritable_only"])
        self.assertEqual(evidence["capabilities_the_agent_could_activate"], [])
        self.assertEqual(entry["classification"], resolution.NON_ROOT_EQUIVALENT)

    def test_cap_bit_table_is_correct_where_it_decided_something(self):
        """CapInh 0x800000000 is bit 35 = cap_wake_alarm, not cap_bpf."""
        self.assertEqual(resolution.CAP_BITS["cap_wake_alarm"], 35)
        self.assertEqual(resolution.CAP_BITS["cap_bpf"], 39)
        self.assertEqual(resolution.CAP_BITS["cap_setuid"], 7)


class TestRepeatability(unittest.TestCase):
    """Repeated runs must produce an identical graph and evidence digest.

    Determinism is what makes condition 18 meaningful: if the digest moved on
    its own, "4 consecutive identical runs" would be unreachable for reasons
    that have nothing to do with the host's privilege state.
    """

    def test_consecutive_runs_share_an_evidence_digest(self):
        history = os.path.join(PACKAGE, "run_history.jsonl")
        if not os.path.exists(history):
            self.skipTest("no run history recorded")
        rows = []
        with open(history, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except ValueError:
                    continue  # a malformed line is skipped, not fatal
                if isinstance(parsed, dict) and "evidence_digest" in parsed:
                    rows.append(parsed)
        if len(rows) < 2:
            self.skipTest("fewer than two recorded runs")
        last_two = rows[-2:]
        self.assertEqual(
            last_two[0]["evidence_digest"],
            last_two[1]["evidence_digest"],
            "consecutive verifier runs disagreed on the evidence digest",
        )
        self.assertEqual(last_two[0]["verdict"], last_two[1]["verdict"])

    def test_graph_is_a_pure_function_of_its_inputs(self):
        """The graph is rebuilt from attacks+registry; same in, same out."""
        import privilege_graph

        attacks_path = os.path.join(PACKAGE, "attack_results.json")
        registry_path = os.path.join(PACKAGE, "ROOT_EQUIVALENCE_REGISTRY.json")
        graph_path = os.path.join(PACKAGE, "PRIVILEGE_GRAPH.json")
        for path in (attacks_path, registry_path, graph_path):
            if not os.path.exists(path):
                self.skipTest("recorded evidence is not present")
        with open(attacks_path, encoding="utf-8") as handle:
            attacks = json.load(handle)
        with open(registry_path, encoding="utf-8") as handle:
            registry = json.load(handle)
        with open(graph_path, encoding="utf-8") as handle:
            recorded = json.load(handle)
        # build() returns nodes+edges; build_and_save() adds the closure. Use
        # build()+closure() so the test recomputes without writing to disk.
        first = privilege_graph.build(attacks, registry)
        second = privilege_graph.build(attacks, registry)
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
        self.assertEqual(privilege_graph.closure(first), recorded["closure"])

    def test_evidence_digest_covers_the_privilege_inventory(self):
        """A digest blind to the inventory makes condition 18 vacuous.

        Measured, not hypothesised: adding the entire `filecaps` surface took
        the inventory from 46 paths to 57 and left the digest bit-identical,
        because only condition 19's boolean reached it and that boolean did not
        flip.
        """
        verify = __import__("verify_v3")
        needed = (
            "attack_results.json",
            "ROOT_EQUIVALENCE_REGISTRY.json",
            "AUTHORITY_PRINCIPAL_ANALYSIS.json",
            "PRIVILEGE_GRAPH.json",
            "PRIVILEGE_TOPOLOGY_FINAL.json",
            "verification_result.json",
        )
        blobs = {}
        for name in needed:
            path = os.path.join(PACKAGE, name)
            if not os.path.exists(path):
                self.skipTest(f"{name} is not present")
            with open(path, encoding="utf-8") as handle:
                blobs[name] = json.load(handle)

        args = (
            blobs["attack_results.json"],
            blobs["ROOT_EQUIVALENCE_REGISTRY.json"],
            blobs["AUTHORITY_PRINCIPAL_ANALYSIS.json"],
            blobs["PRIVILEGE_GRAPH.json"],
            blobs["verification_result.json"]["conditions"],
        )
        topology = blobs["PRIVILEGE_TOPOLOGY_FINAL.json"]
        baseline = verify.evidence_digest(*args, topology)

        # a path that changes terminal state must move the digest
        mutated = json.loads(json.dumps(topology))
        victim = sorted(mutated["paths"])[0]
        mutated["paths"][victim]["classification"] = "ROOT_EQUIVALENT"
        self.assertNotEqual(baseline, verify.evidence_digest(*args, mutated))

        # a surface that disappears must move the digest
        dropped = json.loads(json.dumps(topology))
        dropped["paths"] = {
            k: v for k, v in dropped["paths"].items() if not k.startswith("filecaps:")
        }
        self.assertNotEqual(baseline, verify.evidence_digest(*args, dropped))

        # and it is still deterministic for identical input
        self.assertEqual(baseline, verify.evidence_digest(*args, topology))

    def test_context_fingerprint_is_stable_within_a_context(self):
        a = privilege_context.capture()["fingerprint_sha256"]
        b = privilege_context.capture()["fingerprint_sha256"]
        self.assertEqual(a, b)


class TestSetuidRuleTable(unittest.TestCase):
    """An unrecognised setuid binary must degrade the verdict, not be ignored."""

    def test_unknown_binary_falls_to_operator_evidence(self):
        self.assertIsNone(resolution.SETUID_RULES.get("some-new-vendor-helper"))

    def test_arbitrary_root_exec_binaries_are_never_auto_cleared(self):
        for name in ("su", "sudo", "pkexec", "userhelper"):
            rule = resolution.SETUID_RULES[name]
            classification, _, _, _, action = rule(
                f"/usr/bin/{name}",
                _StubFacts(),
                {"packaged": True, "integrity": "MATCH"},
            )
            self.assertEqual(classification, resolution.OPERATOR, name)
            self.assertTrue(action, name)


class _StubFacts:
    """Only the attributes `rule_arbitrary_root_exec` reads."""

    sudoers: ClassVar[dict] = {
        "readable_by_agent": False,
        "mode": "0o440",
    }
    polkit_local: ClassVar[dict] = {"listable_by_agent": False}


if __name__ == "__main__":
    unittest.main(verbosity=2)
