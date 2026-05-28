"""Benchmark-result adapters that emit claim-safe evaluation reports."""

from governance.benchmarks.agentdojo_adapter import agentdojo_report_from_fixture
from governance.benchmarks.injecagent_adapter import injecagent_report_from_fixture
from governance.benchmarks.toolemu_adapter import toolemu_report_from_fixture

__all__ = [
    "agentdojo_report_from_fixture",
    "injecagent_report_from_fixture",
    "toolemu_report_from_fixture",
]
