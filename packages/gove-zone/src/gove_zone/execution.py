"""Execution-environment governance — structural classification of execution events.

ADR-0010 (P11). The kernel has always governed *tool* calls. This module extends
the same kernel to *execution-environment* side effects — shell commands,
package-manager invocations, dependency installs, git mutations, artifact
generation, release publication — without adding a second decision path.

What is genuinely new here is one thing: a **structural classifier**. Everything
downstream is existing machinery:

* the decision is a :class:`~gove_zone.policy.Policy` (a ``CompositePolicy`` over
  a ``RuleSetPolicy`` and a ``RiskTierPolicy`` — both existing, both sealed and
  content-addressed);
* the authorization artifact is a :class:`~gove_zone.receipt.DecisionReceipt` —
  no new receipt schema (ADR-0010 D3);
* the gate is :class:`~gove_zone.gateway.UniversalGateway`, whose
  ``execution_boundary`` is set to :data:`EXECUTION_BOUNDARY`;
* the adversaries are the existing ADV6 / ADV9 rows — no new ``ADV*`` number
  (ADR-0010 D4).

Why classification has to be structural
---------------------------------------

The mechanism this replaces matched **substrings of command text**. That
technique produced three observed false positives in one session: a
``git commit -m "fix team dashboard"`` reads as the orchestration command
``team``; a ``grep`` whose *pattern* contained ``autopilot`` was audited as an
``autopilot`` orchestration event (record ``ev_de6629e1f60f41ea`` in the live
chain, ``matched_rules: ["action_kind:autopilot"]``); and a seal guard flagged
this package's ``gateway.py`` as sealed because it defines ``SealedTool``. A
classifier that can be fooled by a quoted string is not a security control.

:func:`classify_command` therefore tokenizes with :mod:`shlex` and decides on the
**argv prefix** — the invoked binary and its leading non-option arguments. A
quoted argument can never promote a command into a governed surface.

What this module deliberately does NOT claim
--------------------------------------------

* **A shell command's effect is not decidable.** ``>``, ``|``, ``cp``, ``mv`` and
  ``$(...)`` mutate tracked source without naming a governed binary. When an
  operator token is present, :func:`classify_command` marks the event
  ``decidable=False`` and does **not** route it to a risk-bearing surface — it is
  recorded and attributed as :data:`ACTION_SHELL_EXEC`, nothing more. Detection
  of those effects belongs to commit-time controls, not to this gate.
* **Lifecycle scripts are not mediated at execution.** They run inside the
  package manager's own process with no callback. :data:`ACTION_PACKAGE_LIFECYCLE_ENABLE`
  records the *enablement decision taken before the manager runs*; it does not
  gate the script.
* **This module is not a ``PATH`` shim.** It sees what a runtime hook shows it.
  A manager invoked from an interactive terminal is not observed at all — the
  named residual of ADV9.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import shlex
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from gove_zone.integration import (
    individual_tool_payloads,
    tool_call_from_hook_payload,
    tool_name_and_input,
)
from gove_zone.policy import (
    CompositePolicy,
    Policy,
    RiskTierPolicy,
    RuleSetPolicy,
)
from gove_zone.tool import ToolCall

__all__ = [
    "EXECUTION_BOUNDARY",
    "ACTION_SHELL_EXEC",
    "ACTION_PACKAGE_INVOKE",
    "ACTION_PACKAGE_INSTALL",
    "ACTION_PACKAGE_LIFECYCLE_ENABLE",
    "ACTION_GIT_MUTATE",
    "ACTION_ARTIFACT_GENERATE",
    "ACTION_RELEASE_PUBLISH",
    "EXECUTION_ACTIONS",
    "TIER_UNCLASSIFIED",
    "TIER_READ_ONLY",
    "TIER_WORKSPACE",
    "TIER_SOURCE",
    "TIER_DEPENDENCY",
    "TIER_CONTROL_SURFACE",
    "TIER_TRUST_ROOT",
    "TIER_PUBLICATION",
    "ExecutionEvent",
    "classify_command",
    "declared_package_manager",
    "build_execution_policy",
    "execution_tool_calls_from_hook_payload",
    "make_execution_call_factory",
    "verify_execution_chain",
    "resolve_execution_actor",
    "build_execution_gateway",
    "UNATTRIBUTED_ACTOR",
    "EXECUTION_VALIDATOR_ID",
    "EXECUTION_TIER_BUNDLE",
    "EXECUTION_RULE_BUNDLE",
]

# -- canonical vocabulary ---------------------------------------------------- #

#: The ``execution_boundary`` every decision on this layer is bound to. An
#: existing canonical ``DecisionReceipt`` field; no new field is introduced.
EXECUTION_BOUNDARY = "execution-environment"

ACTION_SHELL_EXEC = "env.shell.exec"
ACTION_PACKAGE_INVOKE = "env.package.invoke"
ACTION_PACKAGE_INSTALL = "env.package.install"
ACTION_PACKAGE_LIFECYCLE_ENABLE = "env.package.lifecycle_enable"
ACTION_GIT_MUTATE = "env.git.mutate"
ACTION_ARTIFACT_GENERATE = "env.artifact.generate"
ACTION_RELEASE_PUBLISH = "env.release.publish"

#: The seven surfaces of ADR-0010 D2, in table order.
EXECUTION_ACTIONS: tuple[str, ...] = (
    ACTION_SHELL_EXEC,
    ACTION_PACKAGE_INVOKE,
    ACTION_PACKAGE_INSTALL,
    ACTION_PACKAGE_LIFECYCLE_ENABLE,
    ACTION_GIT_MUTATE,
    ACTION_ARTIFACT_GENERATE,
    ACTION_RELEASE_PUBLISH,
)

TIER_UNCLASSIFIED = "unclassified"
TIER_READ_ONLY = "read-only"
TIER_WORKSPACE = "workspace"
TIER_SOURCE = "source"
TIER_DEPENDENCY = "dependency"
TIER_CONTROL_SURFACE = "control-surface"
TIER_TRUST_ROOT = "trust-root"
TIER_PUBLICATION = "publication"

# -- argv-prefix classification tables --------------------------------------- #

# Tokens that, standing alone as their own token, mean the command line contains
# more than one command, a redirection, or a substitution. shlex with
# punctuation_chars=True emits these as separate tokens ONLY when unquoted, which
# is exactly the property a substring matcher lacks.
_OPERATOR_CHARS = frozenset("();<>|&")

# Leading tokens that wrap another command rather than being the command.
_WRAPPERS = frozenset({"sudo", "env", "command", "nohup", "time", "nice", "exec", "doas"})

_INSTALL_SUBCOMMANDS: Mapping[str, frozenset[str]] = {
    "npm": frozenset({"install", "i", "ci", "add", "update", "up"}),
    "pnpm": frozenset({"install", "i", "add", "update", "up"}),
    "yarn": frozenset({"install", "add", "up", "upgrade"}),
    "bun": frozenset({"install", "i", "add", "update"}),
    "pip": frozenset({"install"}),
    "pip3": frozenset({"install"}),
    "uv": frozenset({"add", "sync", "pip"}),
    "poetry": frozenset({"add", "install", "update"}),
    "cargo": frozenset({"add", "install", "update"}),
    "gem": frozenset({"install", "update"}),
    "composer": frozenset({"install", "require", "update"}),
    "go": frozenset({"get", "install"}),
}

#: Managers whose *node* ecosystem participates in the pnpm/npm/yarn/bun
#: canonical-manager contract declared by ``package.json``'s ``packageManager``.
_JS_MANAGERS = frozenset({"npm", "pnpm", "yarn", "bun"})

#: Flags that disable lifecycle-script execution, per manager family. Absence is
#: treated as "not disabled" — fail-closed, because an unknown manager cannot be
#: assumed safe.
_IGNORE_SCRIPTS_FLAGS = frozenset({"--ignore-scripts", "--no-scripts"})

_PUBLISH_SUBCOMMANDS: Mapping[str, frozenset[str]] = {
    "npm": frozenset({"publish"}),
    "pnpm": frozenset({"publish"}),
    "yarn": frozenset({"publish"}),
    "bun": frozenset({"publish"}),
    "cargo": frozenset({"publish"}),
    "poetry": frozenset({"publish"}),
    "uv": frozenset({"publish"}),
    "twine": frozenset({"upload"}),
    "gem": frozenset({"push"}),
    "gh": frozenset({"release"}),
}

_GIT_MUTATING = frozenset(
    {
        "add",
        "am",
        "apply",
        "checkout",
        "cherry-pick",
        "clean",
        "commit",
        "filter-branch",
        "fetch",
        "gc",
        "merge",
        "mv",
        "pull",
        "push",
        "rebase",
        "reset",
        "restore",
        "revert",
        "rm",
        "stash",
        "submodule",
        "switch",
        "tag",
        "update-index",
        "update-ref",
        "worktree",
    }
)

#: git subcommands that move published history or rewrite it in place. These
#: escalate rather than record — they are the control surface of the repository.
_GIT_CONTROL_SURFACE = frozenset(
    {"push", "reset", "rebase", "filter-branch", "update-ref", "clean", "tag"}
)

#: Binaries whose second-position token has declared meaning. Everything else is
#: read as a bare binary — see :func:`_subcommand`.
_GRAMMAR_BINARIES: frozenset[str] = frozenset({"git", *_INSTALL_SUBCOMMANDS, *_PUBLISH_SUBCOMMANDS})

#: A subcommand is a lowercase word. A secret, a path, or an option value is
#: essentially never one.
_SUBCOMMAND_RE = re.compile(r"^[a-z][a-z0-9-]*$")


@dataclasses.dataclass(frozen=True)
class ExecutionEvent:
    """One structurally classified execution-environment event.

    ``facts`` is the decision-relevant classification: JSON-safe scalars only, so
    it survives canonical hashing unchanged. It is published two ways on purpose:

    * :meth:`to_args` — becomes ``ToolCall.args``, which every policy hashes into
      ``DecisionRecord.argument_hash`` and which
      :meth:`~gove_zone.receipt.DecisionReceipt.from_record` binds into
      ``receipt_hash``. **This is what makes the classification attestable**: a
      receipt for ``env.package.install`` carries the hash of the facts the
      decision was made on, so the receipt can be checked against the claim.
    * :meth:`to_state` — becomes ``ToolCall.state``, which
      :meth:`~gove_zone.policy.PolicyRule.matches` reads. ``PolicyRule`` matches
      on ``state`` and never on ``args``, so a declarative rule can only see the
      facts through this door.

    Both are required. ``state`` alone would decide but not attest (``state`` is
    not a receipt field); ``args`` alone would attest but not decide.
    """

    action: str
    binary: str
    argv_prefix: tuple[str, ...]
    tier_hint: str
    decidable: bool
    undecidable_reasons: tuple[str, ...] = ()
    facts: Mapping[str, Any] = dataclasses.field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "argv_prefix", tuple(str(t) for t in self.argv_prefix))
        object.__setattr__(
            self, "undecidable_reasons", tuple(str(r) for r in self.undecidable_reasons)
        )
        object.__setattr__(self, "facts", dict(self.facts))

    def to_args(self) -> dict[str, Any]:
        """Receipt-bound projection (hashed into ``argument_hash``).

        The raw command string is deliberately **not** included: it may carry
        secrets, and the receipt would then be an exfiltration channel. The argv
        prefix — binary plus leading non-option tokens — is what the decision was
        actually taken on, and is what a verifier needs to re-derive it.
        """
        return {
            "action": self.action,
            "binary": self.binary,
            "argv_prefix": list(self.argv_prefix),
            "decidable": self.decidable,
            "undecidable_reasons": list(self.undecidable_reasons),
            "facts": dict(self.facts),
        }

    def to_state(self) -> dict[str, Any]:
        """Policy-matched projection (read by ``PolicyRule.state_equals``)."""
        state: dict[str, Any] = {
            "execution_surface": self.action,
            "execution_binary": self.binary,
            "execution_decidable": self.decidable,
            "execution_tier_hint": self.tier_hint,
        }
        state.update(self.facts)
        return state


def _strip_wrappers(argv: Sequence[str]) -> tuple[list[str], list[str], bool]:
    """Peel leading ``VAR=value`` assignments and command wrappers off *argv*.

    ``sudo npm install`` and ``FOO=bar npm install`` are ``npm install``. Not
    peeling them would be a trivially exploitable classifier hole. Option-bearing
    wrapper syntax is deliberately not parsed: the option value could otherwise
    be mistaken for the executable, so classification stops at the wrapper and
    returns an undecidable event.
    """
    wrappers: list[str] = []
    rest = list(argv)
    while rest:
        head = rest[0]
        if "=" in head and not head.startswith("=") and "/" not in head.split("=", 1)[0]:
            wrappers.append(head.split("=", 1)[0] + "=")
            rest = rest[1:]
            continue
        if Path(head).name in _WRAPPERS:
            wrapper = Path(head).name
            wrappers.append(wrapper)
            rest = rest[1:]
            if rest and rest[0].startswith("-"):
                return [wrapper], wrappers, True
            continue
        break
    return rest, wrappers, False


def _subcommand(binary: str, argv: Sequence[str]) -> str:
    """The declared subcommand for *binary*, or ``""``.

    Two guards, both necessary. Only binaries with a **declared subcommand
    grammar** are read at all — an arbitrary program has no second-position
    meaning to recover. And the token must look like a subcommand
    (:data:`_SUBCOMMAND_RE`) before it is accepted.

    Without the second guard this function returns the *value* of a
    value-taking option: ``curl -H 'Authorization: Bearer <token>' ...`` yields
    the bearer token, which then lands in ``argv_prefix`` and is hashed into a
    receipt. The receipt would become an exfiltration channel. A subcommand
    always matches the pattern; a secret essentially never does.
    """
    if binary not in _GRAMMAR_BINARIES:
        return ""
    for token in argv[1:]:
        if token.startswith("-"):
            continue
        return token if _SUBCOMMAND_RE.match(token) else ""
    return ""


def declared_package_manager(root: str | Path | None = None) -> str:
    """The manager declared by ``package.json``'s ``packageManager``, or ``""``.

    ``"pnpm@9.15.4"`` → ``"pnpm"``. An absent, unreadable, or malformed
    declaration returns ``""``, which the canonical-manager rule reads as "no
    declaration to violate" — this control cannot invent a contract the
    repository never stated.
    """
    base = Path(root) if root is not None else Path.cwd()
    try:
        raw = json.loads((base / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    if not isinstance(raw, dict):
        return ""
    declared = raw.get("packageManager")
    if not isinstance(declared, str) or not declared.strip():
        return ""
    return declared.strip().split("@", 1)[0].strip()


def classify_command(command: str, *, canonical_package_manager: str = "") -> ExecutionEvent:
    """Classify one shell command string into an execution surface, structurally.

    Decides on the argv prefix only. Never matches substrings of the command
    text: ``git commit -m "fix team dashboard"`` is a git mutation, not an
    orchestration command, and ``grep -rn "autopilot" .`` is an unclassified
    shell exec.

    An unquoted shell operator (``|``, ``>``, ``;``, ``&&``, ``$(``, a backtick)
    means the line runs more than one command or redirects output. The effect is
    then not recoverable from the argv prefix, so the event is returned with
    ``decidable=False`` on :data:`ACTION_SHELL_EXEC` — recorded and attributed,
    **not** routed to a risk-bearing surface. Claiming otherwise would classify
    ``echo x > tracked-file`` as a harmless ``echo``.
    """
    text = command if isinstance(command, str) else ""
    reasons: list[str] = []

    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        # Unbalanced quotes: the tokenization a shell would perform is not
        # reproducible here, so nothing downstream may be trusted.
        return ExecutionEvent(
            action=ACTION_SHELL_EXEC,
            binary="",
            argv_prefix=(),
            tier_hint=TIER_UNCLASSIFIED,
            decidable=False,
            undecidable_reasons=("unparseable-command",),
            facts={"operator_present": False},
        )

    operators = [t for t in tokens if t and set(t) <= _OPERATOR_CHARS]
    if operators:
        reasons.append("shell-operator")
    if any("`" in t for t in tokens):
        reasons.append("command-substitution")

    words = [t for t in tokens if not (t and set(t) <= _OPERATOR_CHARS)]
    argv, wrappers, unsupported_wrapper_options = _strip_wrappers(words)
    if unsupported_wrapper_options:
        reasons.append("unsupported-wrapper-options")
    if not argv:
        return ExecutionEvent(
            action=ACTION_SHELL_EXEC,
            binary="",
            argv_prefix=(),
            tier_hint=TIER_UNCLASSIFIED,
            decidable=False,
            undecidable_reasons=tuple(reasons or ["empty-command"]),
            facts={"operator_present": bool(operators)},
        )

    binary = Path(argv[0]).name
    subcommand = _subcommand(binary, argv)
    argv_prefix = (binary, subcommand) if subcommand else (binary,)
    flags = frozenset(t for t in argv[1:] if t.startswith("-"))

    base_facts: dict[str, Any] = {
        "operator_present": bool(operators),
        "invoked_by_absolute_path": argv[0] != binary,
        "wrapped": bool(wrappers),
    }
    if unsupported_wrapper_options:
        base_facts["wrapper_options_supported"] = False

    if reasons:
        # Undecidable lines stop here: attributed, never promoted to a surface
        # whose verdict would be wrong more often than right.
        return ExecutionEvent(
            action=ACTION_SHELL_EXEC,
            binary=binary,
            argv_prefix=argv_prefix,
            tier_hint=TIER_UNCLASSIFIED,
            decidable=False,
            undecidable_reasons=tuple(reasons),
            facts=base_facts,
        )

    publish_subs = _PUBLISH_SUBCOMMANDS.get(binary, frozenset())
    if subcommand and subcommand in publish_subs:
        return ExecutionEvent(
            action=ACTION_RELEASE_PUBLISH,
            binary=binary,
            argv_prefix=argv_prefix,
            tier_hint=TIER_PUBLICATION,
            decidable=True,
            facts={**base_facts, "publisher": binary, "subcommand": subcommand},
        )

    if binary == "git":
        mutating = subcommand in _GIT_MUTATING
        return ExecutionEvent(
            action=ACTION_GIT_MUTATE if mutating else ACTION_SHELL_EXEC,
            binary=binary,
            argv_prefix=argv_prefix,
            tier_hint=TIER_SOURCE if mutating else TIER_READ_ONLY,
            decidable=True,
            facts={
                **base_facts,
                "subcommand": subcommand,
                "git_control_surface": subcommand in _GIT_CONTROL_SURFACE,
            },
        )

    install_subs = _INSTALL_SUBCOMMANDS.get(binary)
    if install_subs is not None:
        installing = subcommand in install_subs
        canonical = canonical_package_manager.strip()
        # A canonical-manager contract binds only the ecosystem that declared it.
        # Denying `pip install` because package.json names pnpm would be a
        # category error, and the rule would be discredited by its first
        # false positive.
        in_contract = bool(canonical) and binary in _JS_MANAGERS and canonical in _JS_MANAGERS
        facts = {
            **base_facts,
            "manager": binary,
            "subcommand": subcommand,
            "canonical_manager": canonical if in_contract else "",
            "manager_is_canonical": (binary == canonical) if in_contract else True,
            "manager_contract_applies": in_contract,
            "scripts_disabled": bool(flags & _IGNORE_SCRIPTS_FLAGS),
        }
        return ExecutionEvent(
            action=ACTION_PACKAGE_INSTALL if installing else ACTION_PACKAGE_INVOKE,
            binary=binary,
            argv_prefix=argv_prefix,
            tier_hint=TIER_DEPENDENCY,
            decidable=True,
            facts=facts,
        )

    return ExecutionEvent(
        action=ACTION_SHELL_EXEC,
        binary=binary,
        argv_prefix=argv_prefix,
        tier_hint=TIER_UNCLASSIFIED,
        decidable=True,
        facts={**base_facts, "subcommand": subcommand},
    )


# -- policy bundles ---------------------------------------------------------- #

#: Risk tiers as ``RiskTierPolicy`` configuration — policy data, not a new
#: taxonomy and not a new enforcement path.
#:
#: ``default_tier`` is deliberately omitted: ``RiskTierPolicy`` then resolves an
#: unassigned tool to the most restrictive declared tier (``trust-root`` → DENY).
#: A tool nobody classified cannot execute.
EXECUTION_TIER_BUNDLE: dict[str, Any] = {
    "id": "execution-governance/v1",
    "tiers": [
        {
            "name": TIER_UNCLASSIFIED,
            "enforcement": "allow",
            "description": (
                "Recorded and attributed, NOT risk-classified. A shell command whose "
                "effect is not recoverable from its argv prefix lands here. Allowing "
                "it is an honest statement that this gate does not decide it — not a "
                "judgement that it is safe."
            ),
            "requirements": ["receipt"],
        },
        {
            "name": TIER_READ_ONLY,
            "enforcement": "allow",
            "description": "Inspection; no mutation of tracked state.",
            "requirements": ["receipt"],
        },
        {
            "name": TIER_WORKSPACE,
            "enforcement": "allow",
            "description": "Writes confined to untracked or ignored paths.",
            "requirements": ["receipt"],
        },
        {
            "name": TIER_SOURCE,
            "enforcement": "allow",
            "description": "Tracked source mutation.",
            "requirements": ["receipt"],
        },
        {
            "name": TIER_DEPENDENCY,
            "enforcement": "escalate",
            "description": (
                "Package-manager surfaces. Escalate by default: the 2026-08-09 "
                "incident was an unreviewed dependency admission, and lifecycle "
                "execution is irreversible."
            ),
            "requirements": ["receipt", "human-approval"],
        },
        {
            "name": TIER_CONTROL_SURFACE,
            "enforcement": "escalate",
            "description": "CI, policy, hooks, tool config, tracked generated artifacts.",
            "requirements": ["receipt", "human-approval", "distinct-validator"],
        },
        {
            "name": TIER_PUBLICATION,
            "enforcement": "escalate",
            "description": "Release publication; always second-party.",
            "requirements": ["receipt", "human-approval", "distinct-validator"],
        },
        {
            "name": TIER_TRUST_ROOT,
            "enforcement": "deny",
            "description": (
                "Keys, approvers, enforcement mode, actor allowlists — and the "
                "fail-closed home of every unassigned tool."
            ),
            "requirements": ["distinct-validator"],
        },
    ],
    "tools": {
        # Execution-environment surfaces.
        ACTION_SHELL_EXEC: TIER_UNCLASSIFIED,
        ACTION_PACKAGE_INVOKE: TIER_DEPENDENCY,
        ACTION_PACKAGE_INSTALL: TIER_DEPENDENCY,
        ACTION_PACKAGE_LIFECYCLE_ENABLE: TIER_CONTROL_SURFACE,
        ACTION_GIT_MUTATE: TIER_SOURCE,
        ACTION_ARTIFACT_GENERATE: TIER_CONTROL_SURFACE,
        ACTION_RELEASE_PUBLISH: TIER_PUBLICATION,
        # Host-runtime file mutation surfaces, named as the runtime adapter names
        # them. Every tool a hook matcher can deliver MUST appear here or the
        # fail-closed default denies it — see test_execution_hook_wiring.
        "runtime.Edit": TIER_SOURCE,
        "runtime.Write": TIER_SOURCE,
        "runtime.MultiEdit": TIER_SOURCE,
        "runtime.NotebookEdit": TIER_SOURCE,
        "runtime.Bash": TIER_UNCLASSIFIED,
        # An unparseable batch is escalated, not denied: it is a parsing failure,
        # not evidence of intent, and a human can see what the runtime sent.
        "runtime.malformed_batch": TIER_CONTROL_SURFACE,
    },
}

#: Declarative rules evaluated *before* the tier baseline (CompositePolicy is
#: first-non-ALLOW-wins). ``RuleSetPolicy`` rules may only deny or escalate,
#: which is why positive authorization never appears here.
EXECUTION_RULE_BUNDLE: dict[str, Any] = {
    "id": "execution-governance-rules/v1",
    "rules": [
        {
            "id": "deny-unsupported-wrapper-options",
            "effect": "deny",
            "tools": [ACTION_SHELL_EXEC],
            "state_equals": {"wrapper_options_supported": False},
            "reason": (
                "wrapper options are not interpreted; deny rather than classify "
                "an option or its value as the executed binary"
            ),
        },
        {
            "id": "deny-non-canonical-package-manager",
            "effect": "deny",
            "tools": [ACTION_PACKAGE_INVOKE, ACTION_PACKAGE_INSTALL],
            "state_equals": {"manager_contract_applies": True, "manager_is_canonical": False},
            "reason": (
                "repository declares a canonical packageManager; a different manager "
                "splits dependency resolution and is denied before any fetch"
            ),
        },
        {
            "id": "escalate-install-with-lifecycle-scripts-enabled",
            "effect": "escalate",
            "tools": [ACTION_PACKAGE_INSTALL],
            "state_equals": {"scripts_disabled": False},
            "reason": (
                "install would run lifecycle scripts; script execution is irreversible "
                "and unmediable once the manager starts (ADR-0010 D2)"
            ),
        },
        {
            "id": "escalate-git-control-surface",
            "effect": "escalate",
            "tools": [ACTION_GIT_MUTATE],
            "state_equals": {"git_control_surface": True},
            "reason": "git subcommand moves or rewrites published history",
        },
    ],
}


def build_execution_policy(
    *,
    tier_bundle: Mapping[str, Any] | None = None,
    rule_bundle: Mapping[str, Any] | None = None,
) -> Policy:
    """The composite policy for the ``execution-environment`` boundary.

    Order is part of the identity (``CompositePolicy`` is first-non-ALLOW-wins):
    the declarative rules run first so a specific denial — a non-canonical
    package manager — is recorded with its own ``rule_id`` in ``matched_rules``,
    rather than being flattened into the tier's generic escalation.
    """
    rules = RuleSetPolicy.from_dict(dict(rule_bundle or EXECUTION_RULE_BUNDLE))
    tiers = RiskTierPolicy.from_dict(dict(tier_bundle or EXECUTION_TIER_BUNDLE))
    return CompositePolicy([rules, tiers])


# -- deployment wiring ------------------------------------------------------- #

#: Actor string used when no identity can be resolved. Deliberately not a
#: plausible-looking name: a receipt naming an anonymous actor is an audit
#: record, not an authorization, and the string should say so at a glance.
UNATTRIBUTED_ACTOR = "unattributed"

#: The validating principal for this layer. It must differ from every actor or
#: :meth:`~gove_zone.receipt.DecisionReceipt.from_record` refuses to mint —
#: which is the self-validation control doing its job.
EXECUTION_VALIDATOR_ID = "gove-zone-execution-gate"


def resolve_execution_actor(env: Mapping[str, str] | None = None) -> tuple[str, str]:
    """Resolve ``(actor, attribution_source)`` from the environment.

    Precedence: an explicit ``GOVE_ZONE_ACTOR``, then the agent id
    ``PAPERCLIP_AGENT_ID``, then the POSIX login name (prefixed ``local:`` so it
    is never mistaken for an authenticated principal), then
    :data:`UNATTRIBUTED_ACTOR`.

    **None of these is an authenticated identity.** They are environment
    variables, and a process that can set them can choose its own actor string.
    Real attribution requires an authenticated principal from the integrating
    surface; this function makes the current, weaker basis explicit and
    machine-readable instead of hiding it behind a hardcoded constant. The
    returned source is what makes the weakness auditable.
    """
    environ = dict(env if env is not None else os.environ)
    for key, source in (
        ("GOVE_ZONE_ACTOR", "explicit"),
        ("PAPERCLIP_AGENT_ID", "agent-id"),
    ):
        value = (environ.get(key) or "").strip()
        if value:
            return value, source
    for key in ("USER", "LOGNAME"):
        value = (environ.get(key) or "").strip()
        if value:
            return f"local:{value}", "posix-user"
    return UNATTRIBUTED_ACTOR, "none"


def build_execution_gateway(
    *,
    tenant_id: str = "local-workspace",
    authority: str = "execution-governance",
    audit_path: str | Path | None = None,
    ledger_path: str | Path | None = None,
    profile: Any | None = None,
    validator_id: str = EXECUTION_VALIDATOR_ID,
    allowed_actors: frozenset[str] | set[str] | None = None,
    policy: Policy | None = None,
) -> Any:
    """A :class:`~gove_zone.gateway.UniversalGateway` for this boundary.

    ``audit_path`` defaults to :func:`gove_zone.integration.resolve_audit_path`
    — the chain the passive hook auditor already writes. This is deliberate and
    load-bearing: ``UniversalGateway`` otherwise defaults to a *different* file
    (``.gove-zone/gateway-audit.jsonl``), and taking that default during cutover
    would fork the audit chain in two, leaving the pre-cutover history in one
    file and everything after it in another.
    """
    from gove_zone.errors import ProductionProfileError
    from gove_zone.gateway import UniversalGateway
    from gove_zone.integration import resolve_audit_path
    from gove_zone.profile import GovernanceProfile
    from gove_zone.receipt import Validator

    resolved_profile = profile if profile is not None else GovernanceProfile.from_env()
    if getattr(resolved_profile, "require_signature", False) and (
        getattr(resolved_profile, "signer", None) is None
    ):
        # Anti-downgrade (ADV10). A production posture with no signer would mint
        # receipts carrying signature_algorithm="none" — indistinguishable at a
        # glance from signed ones, and accepted by nothing that checks. Fail loud
        # at construction rather than emitting an unsigned receipt under a
        # profile that demands a signed one.
        raise ProductionProfileError(
            "profile requires signed receipts but no signer is configured; "
            "supply a signer or select the dev profile explicitly "
            "(GOVE_ZONE_PROFILE=dev)"
        )

    resolved_audit = Path(audit_path) if audit_path is not None else resolve_audit_path()
    resolved_ledger = (
        Path(ledger_path) if ledger_path is not None else resolved_audit.parent / "ledger.jsonl"
    )
    return UniversalGateway(
        tenant_id=tenant_id,
        execution_boundary=EXECUTION_BOUNDARY,
        policy=policy if policy is not None else build_execution_policy(),
        profile=resolved_profile,
        validator=Validator(validator_id=validator_id),
        authority=authority,
        audit_path=resolved_audit,
        ledger_path=resolved_ledger,
        allowed_actors=allowed_actors,
    )


# -- hook surface ------------------------------------------------------------ #


def _command_from_payload(child: Mapping[str, Any]) -> str | None:
    try:
        _name, tool_input = tool_name_and_input(dict(child))
        command = tool_input.get("command")
    except Exception:  # noqa: BLE001 - an unreadable shell payload must fail closed
        return None
    return command if isinstance(command, str) else None


def execution_tool_calls_from_hook_payload(
    payload: dict[str, Any],
    *,
    action_kind: str,
    actor: str,
    canonical_package_manager: str = "",
    run_context: Mapping[str, Any] | None = None,
) -> tuple[ToolCall, ...]:
    """Normalize a runtime hook event into governed calls, classifying shells.

    Drop-in replacement for
    :func:`gove_zone.integration.tool_calls_from_hook_payload`: non-shell calls
    are produced by that function unchanged, so file mutations keep their
    existing ``runtime.*`` names and audit shape. A ``Bash`` call is additionally
    passed through :func:`classify_command` and re-emitted under its ``env.*``
    surface, carrying the classification in both ``args`` (receipt-bound) and
    ``state`` (policy-matched).

    Batch payloads are expanded per call before classification, so wrapping an
    install inside a batch cannot evade the classifier.

    ``run_context`` (e.g. ``{"run_id": ...}``) is merged into **both** ``args``
    and ``state`` of every call, shell or not. It goes into ``args`` because the
    prior hook path accepted a ``run_id`` and then dropped it before the receipt
    was constructed, leaving decisions correlated to nothing. Anything placed
    here is hashed into the receipt, so it must not carry secrets.
    """
    context = {str(k): v for k, v in dict(run_context or {}).items()}
    calls: list[ToolCall] = []
    for child in individual_tool_payloads(dict(payload)):
        call = tool_call_from_hook_payload(child, action_kind=action_kind, actor=actor)
        if call.name == "runtime.Bash":
            command = _command_from_payload(child)
            if command is None:
                calls.append(
                    ToolCall(
                        name="runtime.malformed_batch",
                        args={
                            "action_kind": action_kind,
                            "summary": {
                                "batch_shape": "single.Bash",
                                "reason": "missing, non-string, or unreadable command",
                                "item_count": 1,
                                "parseable_count": 0,
                                "unparseable_count": 1,
                            },
                            **context,
                        },
                        goal=call.goal,
                        actor=actor,
                        path=call.path,
                        state={**dict(call.state), **context},
                    )
                )
                continue
            event = classify_command(
                command,
                canonical_package_manager=canonical_package_manager,
            )
            calls.append(
                ToolCall(
                    name=event.action,
                    args={"action_kind": action_kind, **event.to_args(), **context},
                    goal=call.goal,
                    actor=actor,
                    path=call.path,
                    state={**dict(call.state), **event.to_state(), **context},
                )
            )
            continue

        if not context:
            calls.append(call)
            continue
        calls.append(
            ToolCall(
                name=call.name,
                args={**dict(call.args), **context},
                goal=call.goal,
                actor=actor,
                path=call.path,
                state={**dict(call.state), **context},
            )
        )
    return tuple(calls)


def make_execution_call_factory(
    canonical_package_manager: str = "",
    *,
    run_context: Mapping[str, Any] | None = None,
) -> Any:
    """Bind deployment configuration into a ``call_factory`` for the gateway.

    :meth:`~gove_zone.gateway.UniversalGateway.handle_claude_hook` calls its
    factory as ``factory(payload, action_kind=..., actor=...)``. The canonical
    manager and the run context are deployment/session facts, not per-call data,
    so they are closed over here rather than read from the payload — a payload
    that could name its own canonical manager would be able to exempt itself.
    """
    bound_context = dict(run_context or {})

    def factory(payload: dict[str, Any], *, action_kind: str, actor: str) -> tuple[ToolCall, ...]:
        return execution_tool_calls_from_hook_payload(
            payload,
            action_kind=action_kind,
            actor=actor,
            canonical_package_manager=canonical_package_manager,
            run_context=bound_context,
        )

    return factory


# -- independent verification ------------------------------------------------ #


def verify_execution_chain(
    events: Sequence[Mapping[str, Any]],
    *,
    require_attributed: bool = True,
    fallback_actors: Sequence[str] = ("govern-zone-hook", "anonymous", ""),
) -> dict[str, Any]:
    """Re-derive execution-governance invariants over persisted audit events.

    Deliberately **independent of the writer**: it takes already-parsed chain
    events and re-checks properties the emitting path is supposed to guarantee,
    rather than trusting that it did. It complements — and does not replace —
    :meth:`gove_zone.audit.ChainHashAuditStore.verify_chain`, which proves the
    hash linkage. Note the limitation documented there: an internal walk cannot
    detect a truncated tail, so neither can this.

    Checks:

    * ``unassigned_tier`` — a decision whose ``matched_rules`` contains
      ``RISK_TIER:default`` means the tool had no tier assignment and was denied
      by the fail-closed default. Correct behavior, but a wiring gap to report.
    * ``unattributed`` — records carrying a fallback actor. These are audit
      records, not authorizations.
    * ``unconditional_allow`` — an ``env.*`` decision with no ``matched_rules``
      is not traceable to a policy and is reported.
    * ``legacy_observer_path`` — records whose ``matched_rules`` is an
      ``action_kind:*`` marker. Every one of these came from the retired
      ``_ObserverPolicy``, which returned ``ALLOW`` unconditionally, so the
      marker names the *hook classification*, not a policy rule. This flags the
      whole legacy path (including ``action_kind:edit``), not only the three
      substring-matched orchestration kinds — the count is the pre-cutover
      boundary, and it must never grow after cutover.

    Returns a report dict; ``ok`` is ``True`` only when every enabled check is
    clean.
    """
    findings: dict[str, list[dict[str, Any]]] = {
        "unassigned_tier": [],
        "unattributed": [],
        "unconditional_allow": [],
        "legacy_observer_path": [],
    }
    fallbacks = frozenset(fallback_actors) | {UNATTRIBUTED_ACTOR}
    checked = 0
    execution_records = 0

    for event in events:
        if not isinstance(event, Mapping):
            continue
        checked += 1
        tool = str(event.get("tool", ""))
        actor = str(event.get("actor", ""))
        matched = event.get("matched_rules")
        matched_list = [str(m) for m in matched] if isinstance(matched, Sequence) else []
        anchor = {
            "event_id": event.get("event_id", ""),
            "tool": tool,
            "actor": actor,
            "decision": event.get("decision", ""),
        }

        if any(m.startswith("action_kind:") for m in matched_list):
            findings["legacy_observer_path"].append(anchor)
        if "RISK_TIER:default" in matched_list:
            findings["unassigned_tier"].append(anchor)
        if require_attributed and actor in fallbacks:
            findings["unattributed"].append(anchor)
        if tool in EXECUTION_ACTIONS:
            execution_records += 1
            if not matched_list:
                findings["unconditional_allow"].append(anchor)

    return {
        "ok": not any(findings.values()),
        "checked": checked,
        "execution_records": execution_records,
        "findings": {name: list(items) for name, items in findings.items()},
        "counts": {name: len(items) for name, items in findings.items()},
    }
