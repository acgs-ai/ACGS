from __future__ import annotations

import json
from pathlib import Path

import pytest

from acgs_cft_governance_pack.policy_io import load_policies, write_evidence_jsonl


def test_load_policies_reads_yaml_files_from_directory(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
id: sample-policy
controls: []
""".lstrip(),
        encoding="utf-8",
    )

    assert load_policies(tmp_path) == [
        {"id": "sample-policy", "controls": [], "source": str(policy)},
    ]


def test_load_policies_rejects_non_mapping_yaml(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("- not-a-mapping\n", encoding="utf-8")

    with pytest.raises(ValueError, match="must contain a mapping"):
        load_policies(tmp_path)


def test_write_evidence_jsonl_writes_one_canonical_event(tmp_path: Path) -> None:
    output = tmp_path / "nested" / "evidence.jsonl"

    write_evidence_jsonl(output, {"b": 2, "a": 1})

    assert output.read_text(encoding="utf-8") == '{"a":1,"b":2}\n'
    assert json.loads(output.read_text(encoding="utf-8")) == {"a": 1, "b": 2}
