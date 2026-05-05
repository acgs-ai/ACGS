from __future__ import annotations

from typing import Any


class FormalPolicyHooks:
    """Extension seam for OPA and Z3.

    This scaffold does not require OPA/Z3 at runtime. In production, wire these hooks into
    PolicyRecallGate after deterministic matching and before allow.
    """

    def __init__(self, *, require_opa: bool = False, require_z3: bool = False):
        self.require_opa = require_opa
        self.require_z3 = require_z3

    def evaluate_opa(self, input_doc: dict[str, Any]) -> dict[str, Any]:
        """Return {'allow': bool, 'reasons': list[str], 'rule_ids': list[str]}.

        Fail closed when require_opa=True and no OPA adapter is configured.
        """
        if self.require_opa:
            return {
                "allow": False,
                "reasons": ["OPA adapter is required but not configured."],
                "rule_ids": [],
            }
        return {"allow": True, "reasons": ["OPA hook not required."], "rule_ids": []}

    def prove_z3(self, claim: dict[str, Any]) -> dict[str, Any]:
        """Return {'satisfiable': bool, 'model': dict, 'reasons': list[str]}.

        Fail closed when require_z3=True and no Z3 adapter is configured.
        """
        if self.require_z3:
            return {
                "satisfiable": False,
                "model": {},
                "reasons": ["Z3 hook is required but not configured."],
            }
        return {"satisfiable": True, "model": {}, "reasons": ["Z3 hook not required."]}
