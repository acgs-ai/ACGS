"""Guards for ``gove_zone.adapters.langgraph`` when langchain-core is absent.

Scope note, stated rather than hidden: the main package gate installs the
package without the declared ``langchain`` extra, so here
``LANGCHAIN_AVAILABLE`` is ``False`` and the wrapping behaviour of
``GovernedTool`` — attribute mapping, ``_run``/``_arun`` dispatch through the
kernel — is **not reachable** and is not covered by this file. That installed
path is covered by the positive and deny-path tests in
``test_framework_adapters.py``, which CI exercises in a dedicated lane that
installs the extra (see ``.github/workflows/python-gove-zone.yml``).

What is reachable, and what matters most, is the fallback posture: with the
dependency missing the module still imports (so nothing downstream breaks at
import time) but every governed entry point refuses to construct. The failure
mode this prevents is an ungoverned passthrough — a stub ``BaseTool`` that
silently accepts the call and runs the tool without a policy check.
"""

from __future__ import annotations

import pytest

from gove_zone.adapters import langgraph as adapter


class _Tool:
    name = "file.write"
    description = "write a file"
    args_schema = None
    return_direct = False
    verbose = False

    def _run(self, **kwargs: object) -> str:
        return "ran"


@pytest.fixture
def agent(tmp_path):
    from gove_zone.agent import ManagedAgent
    from gove_zone.policy import AllowAllPolicy

    return ManagedAgent(
        name="langgraph-guard-test",
        policy=AllowAllPolicy(),
        audit_path=str(tmp_path / "audit.jsonl"),
    )


def test_the_module_imports_without_langchain_installed():
    """A missing optional dependency must not break importing the package."""
    assert hasattr(adapter, "GovernedTool")
    assert hasattr(adapter, "govern_langgraph_tools")
    assert isinstance(adapter.LANGCHAIN_AVAILABLE, bool)


@pytest.mark.skipif(adapter.LANGCHAIN_AVAILABLE, reason="langchain-core is installed here")
def test_the_fallback_base_tool_accepts_any_construction_signature():
    """The stub exists only so the module body parses; it must not raise on
    construction, or the import guard above would fail."""
    adapter.BaseTool("positional", keyword=1)


@pytest.mark.skipif(adapter.LANGCHAIN_AVAILABLE, reason="langchain-core is installed here")
def test_constructing_a_governed_tool_without_langchain_fails_loudly(agent):
    """Fail closed: refusing is the only safe option, because the fallback
    ``BaseTool`` would otherwise yield an object that looks like a governed tool
    and enforces nothing."""
    with pytest.raises(ImportError, match="langchain-core is required"):
        adapter.GovernedTool(_Tool(), agent)


@pytest.mark.skipif(adapter.LANGCHAIN_AVAILABLE, reason="langchain-core is installed here")
def test_wrapping_a_tool_list_without_langchain_fails_loudly(agent):
    with pytest.raises(ImportError, match="langchain-core is required"):
        adapter.govern_langgraph_tools([_Tool()], agent)


@pytest.mark.skipif(adapter.LANGCHAIN_AVAILABLE, reason="langchain-core is installed here")
def test_an_empty_tool_list_is_refused_too(agent):
    """The guard is on the entry point, not on the loop body — wrapping nothing
    must not be a way to get a "successful" ungoverned call."""
    with pytest.raises(ImportError, match="langchain-core is required"):
        adapter.govern_langgraph_tools([], agent)


@pytest.mark.skipif(adapter.LANGCHAIN_AVAILABLE, reason="langchain-core is installed here")
def test_the_tool_side_effect_never_runs_when_construction_is_refused(agent):
    tool = _Tool()
    ran: list[str] = []
    tool._run = lambda **kwargs: ran.append("ran")  # type: ignore[method-assign]

    with pytest.raises(ImportError):
        adapter.govern_langgraph_tools([tool], agent)

    assert ran == []
