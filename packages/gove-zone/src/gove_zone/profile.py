"""Governance profile — the named secure-by-default posture selector.

gove-zone has two coherent operating postures, and the secure one is the
**default**:

* **production** (default) — signed Decision Receipts are required at the
  side-effect-authorizing gates (``require_signature=True``). The operator must
  supply a verifier (and, at issuance, a signer); a production gate with no
  verifier fails closed *loud* (:class:`~gove_zone.errors.ProductionProfileError`)
  rather than silently downgrading. It NEVER auto-generates an ephemeral key —
  that would be false security.
* **production-strict** (opt-in) — the hardened production posture. Everything
  ``production`` makes optional becomes mandatory: a required single-use
  consumption ledger (anti-replay), a required TTL/expiry (liveness), and a
  policy-evaluation watchdog timeout. Selected explicitly via
  :meth:`GovernanceProfile.production_strict`; it never changes the plain
  ``production`` defaults or any gate default.
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
from typing import TYPE_CHECKING, Any

from gove_zone.errors import PRODUCTION_NO_VERIFIER_MSG, ProductionProfileError
from gove_zone.signing import ReceiptSigner

if TYPE_CHECKING:
    from gove_zone.consumption import ReceiptConsumptionLedger

_ENV_VAR = "GOVE_ZONE_PROFILE"
_PRODUCTION = "production"
_PRODUCTION_STRICT = "production-strict"
_DEV = "dev"

# Default policy-evaluation watchdog timeout (seconds) for the strict profile.
# Plain ``production()`` leaves ``Kernel.policy_timeout`` unset (no watchdog);
# the strict profile pins a finite bound so a hung/adversarial policy fails
# closed rather than blocking the gate forever.
_DEFAULT_STRICT_POLICY_TIMEOUT = 5.0

STRICT_NO_LEDGER_MSG = (
    "production_strict profile requires a consumption_ledger: the strict posture "
    "mandates single-use (anti-replay) receipts, but no ReceiptConsumptionLedger "
    "was supplied. Without a ledger one valid receipt authorizes N executions. "
    "Supply a ReceiptConsumptionLedger, or select GovernanceProfile.production() "
    "for the non-strict (replayable) posture."
)

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
    # Strict-profile fields. All default to today's behavior so ``production()``
    # and ``dev()`` value objects are byte-for-byte unchanged.
    consumption_ledger: ReceiptConsumptionLedger | None = None
    require_expiry: bool = False
    policy_timeout: float | None = None

    @property
    def is_production(self) -> bool:
        # Both the plain and strict production postures are "production": they
        # require a signature. Callers gating on this property keep working when
        # the strict profile is selected.
        return self.name in (_PRODUCTION, _PRODUCTION_STRICT)

    @property
    def is_strict(self) -> bool:
        """``True`` only for the strict production posture
        (:meth:`production_strict`) — anti-replay + TTL enforced at the gate, plus
        a policy-timeout the caller wires into the kernel (see
        :meth:`production_strict`).
        """
        return self.name == _PRODUCTION_STRICT

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
    def production_strict(
        cls,
        *,
        verifier: Verifier,
        consumption_ledger: ReceiptConsumptionLedger,
        signer: ReceiptSigner | None = None,
        policy_timeout: float | None = _DEFAULT_STRICT_POLICY_TIMEOUT,
        require_expiry: bool = True,
    ) -> GovernanceProfile:
        """The opt-in *hardened* production posture — bundles the defense-in-depth
        controls that plain :meth:`production` leaves opt-in.

        Plain ``production()`` requires only a signature; a valid receipt with no
        TTL, no single-use ledger, and no policy watchdog can be replayed N times,
        live forever, and block on a hung policy. ``production_strict`` carries the
        configuration for all three additively, without changing ``production()``
        or any gate default. **Two of the three are active the moment this profile
        is used as the gate profile** (i.e. splatted via :meth:`as_gate_kwargs`
        into the side-effect gate); **the third is a separate wiring seam the
        caller must connect at kernel construction** (see the policy-watchdog
        warning below):

        * **Anti-replay (single-use) — active on selection at the gate.**
          ``consumption_ledger`` is **required** — ``None`` raises
          :class:`~gove_zone.errors.ProductionProfileError`. :meth:`as_gate_kwargs`
          emits it so the gate burns the receipt's audit anchor before the side
          effect; a replay raises
          :class:`~gove_zone.errors.ReceiptAlreadyUsedError`.
        * **Liveness / TTL — active on selection at the gate.** ``require_expiry``
          (default ``True``) is emitted by :meth:`as_gate_kwargs` and makes the
          gate reject a receipt whose ``expires_at`` is empty
          (:data:`~gove_zone.errors.ReceiptRejectionReason.EXPIRY_REQUIRED`), so a
          long-lived bearer receipt cannot authorize indefinitely.
        * **Policy watchdog — SEPARATE seam, NOT active on selection.**
          ``policy_timeout`` (default ``5.0`` s) is carried on the profile and
          exposed *only* via :meth:`as_kernel_kwargs` for
          :class:`gove_zone.kernel.Kernel` construction. It is **not** part of the
          receipt gate and is **not** auto-applied — the caller must thread it into
          the kernel themselves (see the warning below) or it is INERT.

        .. warning::

           **``policy_timeout`` is INERT unless you thread it into the Kernel.**
           Selecting this profile and feeding ``as_gate_kwargs()`` to the
           side-effect gate delivers only **2 of the 3** controls (single-use +
           TTL). The watchdog lives on a *different* construction seam — the
           kernel — and there is no profile→Kernel auto-wiring in the library
           today. You MUST pass :meth:`as_kernel_kwargs` to the kernel explicitly,
           or a hung/adversarial policy evaluation will block forever despite the
           strict profile being selected::

               profile = GovernanceProfile.production_strict(
                   verifier=my_verifier,
                   consumption_ledger=my_ledger,
               )
               # 2 of 3 controls (single-use + TTL) — at the side-effect gate:
               execute_with_receipt(..., **profile.as_gate_kwargs())
               # The 3rd control (policy watchdog) — MUST be wired separately,
               # at kernel construction, or policy_timeout is inert:
               kernel = Kernel(policy=..., audit=..., **profile.as_kernel_kwargs())

        ``verifier`` is **required** (reusing ``production()``'s fail-closed
        contract — a strict gate with no verifier can never enforce signing).
        ``signer`` is the issuance-side private key and stays optional here.
        """
        if verifier is None:
            raise ProductionProfileError(PRODUCTION_NO_VERIFIER_MSG)
        if consumption_ledger is None:
            raise ProductionProfileError(STRICT_NO_LEDGER_MSG)
        return cls(
            name=_PRODUCTION_STRICT,
            require_signature=True,
            signer=signer,
            verifier=verifier,
            consumption_ledger=consumption_ledger,
            require_expiry=require_expiry,
            policy_timeout=policy_timeout,
        )

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

        Always returns ``{"require_signature": ..., "verifier": ...}`` — the exact
        keywords accepted by :func:`gove_zone.executor.execute_with_receipt`,
        :class:`gove_zone.executor.GovernedExecutor`, and
        :class:`gove_zone.contracts.ReceiptVerifier`. The ``signer`` is issuance-
        side and is intentionally NOT part of the gate kwargs.

        For the strict profile (:meth:`production_strict`) the bundle additionally
        carries ``consumption_ledger`` (single-use enforcement) and
        ``require_expiry`` (TTL enforcement) — both keywords the same three gate
        surfaces now accept. These keys are emitted **only** when set/enabled, so
        the plain :meth:`production` and :meth:`dev` bundles remain the exact
        two-key dict their callers expect (no surprise kwargs into a splat).

        ``policy_timeout`` is intentionally NOT in this bundle — it configures
        :class:`gove_zone.kernel.Kernel`, not the receipt gate. See
        :meth:`as_kernel_kwargs`.
        """
        kwargs: dict[str, Any] = {
            "require_signature": self.require_signature,
            "verifier": self.verifier,
        }
        if self.consumption_ledger is not None:
            kwargs["consumption_ledger"] = self.consumption_ledger
        if self.require_expiry:
            kwargs["require_expiry"] = self.require_expiry
        return kwargs

    def as_kernel_kwargs(self) -> dict[str, Any]:
        """Resolve to the keyword bundle :class:`gove_zone.kernel.Kernel` consumes.

        Returns ``{"policy_timeout": ...}`` — the watchdog bound for policy
        evaluation. The strict profile pins a finite default
        (``5.0`` s); plain :meth:`production` / :meth:`dev` leave it ``None``
        (watchdog off, today's behavior). Kept separate from
        :meth:`as_gate_kwargs` because it threads into kernel construction, not
        the receipt-verification gate.
        """
        return {"policy_timeout": self.policy_timeout}
