"""Governance profile — the named secure-by-default posture selector.

gove-zone has two coherent operating postures, and the secure one is the
**default**:

* **production** (default) — signed Decision Receipts are required at the
  side-effect-authorizing gates (``require_signature=True``). The operator must
  supply a verifier (and, at issuance, a signer); a production gate with no
  verifier fails closed *loud* (:class:`~gove_zone.errors.ProductionProfileError`)
  rather than silently downgrading. It NEVER auto-generates an ephemeral key —
  that would be false security.
* **dev** — explicitly unsigned (``require_signature=False``). This is the
  backward-compatible escape hatch: callers opt out of signing deliberately.

A :class:`GovernanceProfile` resolves to a coherent
``(require_signature, signer, verifier)`` bundle that gate constructors and
``execute_with_receipt`` can consume directly via :meth:`as_gate_kwargs`.

Selection mirrors :func:`gove_zone.integration.current_gate_mode` /
``GOVE_ZONE_GATE_MODE``: :meth:`from_env` reads ``GOVE_ZONE_PROFILE`` (values
``production`` | ``dev``); when the variable is unset the default is
**production**.

This profile is ORTHOGONAL to :class:`gove_zone.integration.GateMode`
(OBSERVE/ENFORCE). GateMode controls whether the passive runtime-hook auditor
records-only or fails closed on emission; the profile controls whether the
side-effect gate demands a signature. A passive OBSERVE auditor may legitimately
stay unsigned even under the production profile.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from gove_zone.signing import ReceiptSigner

_ENV_VAR = "GOVE_ZONE_PROFILE"
_PRODUCTION = "production"
_DEV = "dev"

# A verifier is either a single signer or a key_id→signer registry, matching the
# gate surfaces' ``verifier`` parameter type.
Verifier = ReceiptSigner | Mapping[str, ReceiptSigner]


@dataclass(frozen=True)
class GovernanceProfile:
    """A named, coherent governance posture for the side-effect gates.

    Construct via the named constructors rather than directly:

    * :meth:`production` — ``require_signature=True`` (the secure default).
    * :meth:`dev` — ``require_signature=False`` (explicit unsigned opt-out).
    * :meth:`from_env` — select via ``$GOVE_ZONE_PROFILE`` (default production).

    ``signer`` is the issuance-side private-key signer (used when minting
    receipts); ``verifier`` is the gate-side public-key verifier (used when
    checking them). Both are optional on the value object; the production profile
    only *requires* one to be present at the moment a gate actually runs, so that
    profile selection and key configuration can happen independently.
    """

    name: str
    require_signature: bool
    signer: ReceiptSigner | None = None
    verifier: Verifier | None = None

    @property
    def is_production(self) -> bool:
        return self.name == _PRODUCTION

    @classmethod
    def production(
        cls,
        *,
        signer: ReceiptSigner | None = None,
        verifier: Verifier | None = None,
    ) -> GovernanceProfile:
        """The default secure posture: signed receipts required at the gate.

        ``verifier`` is what the gate checks signatures against; ``signer`` is the
        private-key signer used at issuance. Either may be omitted here and
        supplied later, but a gate that actually runs in this posture with no
        verifier fails closed loud (:class:`~gove_zone.errors.ProductionProfileError`).
        """
        return cls(name=_PRODUCTION, require_signature=True, signer=signer, verifier=verifier)

    @classmethod
    def dev(cls) -> GovernanceProfile:
        """The explicit unsigned opt-out — backward-compatible dev mode.

        ``require_signature=False`` and no signer/verifier: unsigned receipts are
        accepted at the gate. This is the deliberate escape hatch, not the default.
        """
        return cls(name=_DEV, require_signature=False, signer=None, verifier=None)

    @classmethod
    def from_env(
        cls,
        *,
        signer: ReceiptSigner | None = None,
        verifier: Verifier | None = None,
        env: Mapping[str, str] | None = None,
    ) -> GovernanceProfile:
        """Select a profile from ``$GOVE_ZONE_PROFILE``.

        * ``production`` (or unset / empty) → :meth:`production` (the default).
        * ``dev`` → :meth:`dev`.

        Mirrors :func:`gove_zone.integration.current_gate_mode`: an unrecognized
        value falls back to the secure default (production) rather than silently
        downgrading. ``signer`` / ``verifier`` are forwarded to the production
        profile (ignored for dev); pass ``env`` to read from an explicit mapping
        instead of :data:`os.environ` (testability).
        """
        source = env if env is not None else os.environ
        raw = (source.get(_ENV_VAR) or "").strip().lower()
        if raw == _DEV:
            return cls.dev()
        # production is the default for "production", unset, empty, or unknown.
        return cls.production(signer=signer, verifier=verifier)

    def as_gate_kwargs(self) -> dict[str, Any]:
        """Resolve to the keyword bundle the side-effect gates consume.

        Returns ``{"require_signature": ..., "verifier": ...}`` — the exact
        keywords accepted by :func:`gove_zone.executor.execute_with_receipt`,
        :class:`gove_zone.executor.GovernedExecutor`, and
        :class:`gove_zone.contracts.ReceiptVerifier`. The ``signer`` is issuance-
        side and is intentionally NOT part of the gate kwargs.
        """
        return {"require_signature": self.require_signature, "verifier": self.verifier}
