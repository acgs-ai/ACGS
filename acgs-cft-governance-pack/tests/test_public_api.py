from __future__ import annotations

import acgs_cft_governance_pack as cft


def test_package_facade_exports_stable_evaluation_api() -> None:
    assert callable(cft.evaluate_plan)
    assert callable(cft.load_policies)
    assert callable(cft.write_evidence_jsonl)
    assert cft.__all__ == ["evaluate_plan", "load_policies", "write_evidence_jsonl"]
