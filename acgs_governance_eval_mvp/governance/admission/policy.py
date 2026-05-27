"""Admission Gate policy bundle: minimal v0.1 rule format.

A bundle is a JSON document::

    {
      "bundle_id": "legalguard_ca",
      "version": "1.2.0",
      "default_action": "deny",
      "rules": [
        {
          "id": "prohibited_client_facing_advice",
          "when": {"requested_capabilities_any": ["client_facing_legal_advice"]},
          "action": "deny",
          "reason_code": "prohibited_output",
          "matched_constraint": "no_client_facing_legal_advice"
        }
      ]
    }

Rule precedence applied by :func:`governance.admission.gate.decide`:
``deny`` > ``require_review`` > ``transform`` > ``allow``. When no rule
matches, the gate falls back to ``default_action`` (defaulting to ``deny``
— fail closed). Bundles that want a permissive default must opt in
explicitly by setting ``default_action: "allow"``.

The bundle hash covers every byte of the canonical-JSON representation of
the bundle dict, so any edit (including ``default_action``) produces a
different ``policy_bundle_hash``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from governance.models import sha256_json

_ACTIONS = {"allow", "deny", "transform", "require_review"}
_WHEN_KEYS = {
    "allowed_outputs_contains_any",
    "disallowed_outputs_contains_any",
    "environment",
    "phase",
    "requested_capabilities_all",
    "requested_capabilities_any",
    "requested_capabilities_subset_of",
    "risk_class",
}

# MUST stay in sync with gate.py.
_WHEN_ENUMS: dict[str, tuple[str, ...]] = {
    "phase": ("workflow_admission", "step_admission", "final_output"),
    "risk_class": ("low", "medium", "high", "critical"),
    "environment": ("local", "ci", "hosted", "production"),
}


@dataclass(frozen=True)
class PolicyBundle:
    bundle_id: str
    version: str
    rules: list[dict[str, Any]] = field(default_factory=list)
    default_action: str = "deny"
    raw: dict[str, Any] = field(default_factory=dict)

    def hash(self) -> str:
        return sha256_json(self.raw)


def load_policy_bundle(path: str | Path) -> PolicyBundle:
    """Load + validate a v0.1 policy bundle from JSON on disk."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return policy_bundle_from_dict(raw)


def policy_bundle_from_dict(raw: dict[str, Any]) -> PolicyBundle:
    """Validate a raw policy-bundle dict and wrap it in :class:`PolicyBundle`."""
    missing = [k for k in ("bundle_id", "version", "rules") if k not in raw]
    if missing:
        raise ValueError(f"policy bundle missing required keys: {missing}")
    rules = raw["rules"]
    if not isinstance(rules, list):
        raise ValueError("policy bundle 'rules' must be a list")
    for i, rule in enumerate(rules):
        for key in ("id", "when", "action", "reason_code"):
            if key not in rule:
                raise ValueError(f"rule[{i}] missing required key: {key}")
        if rule["action"] not in _ACTIONS:
            raise ValueError(f"rule[{i}].action must be one of {sorted(_ACTIONS)}, got {rule['action']!r}")
        _validate_when(rule, i)
    default_action = raw.get("default_action", "deny")
    if default_action not in _ACTIONS:
        raise ValueError(f"policy bundle default_action must be one of {sorted(_ACTIONS)}, got {default_action!r}")
    return PolicyBundle(
        bundle_id=str(raw["bundle_id"]),
        version=str(raw["version"]),
        rules=list(rules),
        default_action=str(default_action),
        raw=raw,
    )


def policy_bundle_hash(bundle: PolicyBundle | dict[str, Any]) -> str:
    if isinstance(bundle, PolicyBundle):
        return bundle.hash()
    return sha256_json(bundle)


def _validate_when(rule: dict[str, Any], index: int) -> None:
    rule_ref = f"rule[{index}] id={rule.get('id', '<missing>')!r}"
    when = rule.get("when", {})
    if not isinstance(when, dict):
        raise ValueError(f"{rule_ref}.when must be a dict")

    for key, value in when.items():
        if key not in _WHEN_KEYS:
            raise ValueError(f"{rule_ref}.when contains unknown key {key!r}; allowed keys: {sorted(_WHEN_KEYS)}")
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise ValueError(f"{rule_ref}.when[{key!r}] must be list[str]")
        if key in _WHEN_ENUMS:
            allowed = _WHEN_ENUMS[key]
            invalid = [item for item in value if item not in allowed]
            if invalid:
                raise ValueError(
                    f"{rule_ref}.when[{key!r}] contains invalid values {invalid!r}; allowed values: {list(allowed)}"
                )
