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
  recorded and attributed as :data:`ACTION_SHELL_EXEC`. The policy side fails
  closed on that marker: the ``escalate-undecidable-shell`` rule sends every
  undecidable command to a human rather than letting it inherit the
  unclassified allow tier. Detection of the actual effects still belongs to
  commit-time controls, not to this gate.
* **Lifecycle scripts are not mediated at execution.** They run inside the
  package manager's own process with no callback. :data:`ACTION_PACKAGE_LIFECYCLE_ENABLE`
  records the *enablement decision taken before the manager runs*; it does not
  gate the script.
* **This module is not a ``PATH`` shim.** It sees what a runtime hook shows it.
  A manager invoked from an interactive terminal is not observed at all — the
  named residual of ADV9.
* **Build-system targets are structurally opaque.** ``make dist`` or
  ``make package`` may generate artifacts, but a Makefile target name carries
  no declared meaning this classifier could recover; such commands remain
  :data:`ACTION_SHELL_EXEC`. Only package managers with a declared artifact
  grammar (``npm pack``, ``cargo package``, ``poetry build``, …) reach
  :data:`ACTION_ARTIFACT_GENERATE` — a named residual, not a claim of coverage.
* **Git inherits executable configuration.** Repository and ambient Git
  configuration can launch hooks, fsmonitor, diff, pager, signature, remote,
  credential, and content-filter helpers even when the visible argv looks
  ordinary. This hook does not sanitize that configuration in a trusted
  executor, so every declared Git command is undecidable and escalates without
  a receipt. Mutations retain explicit :data:`ACTION_GIT_MUTATE` attribution;
  that attribution is not authorization to execute them.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import json
import os
import re
import shlex
import shutil
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

# Characters that, reachable by the shell (unquoted and unescaped), make the
# command line contain more than one command, a redirection, or a substitution.
# Detection happens on the RAW command text with quote tracking
# (:func:`_has_unquoted_operator`), NOT on the shlex token stream: shlex in
# POSIX mode strips quotes, so a standalone quoted operator argument —
# ``git commit -m ';'`` or ``grep -F '|' file`` — reaches the token list as a
# bare ``;`` / ``|``, indistinguishable from a real separator. Only an
# occurrence the shell would actually parse as an operator counts; quoted or
# escaped punctuation is argument data.
_OPERATOR_CHARS = frozenset("();<>|&")

# Characters that begin a shell expansion inside a word. shlex strips quotes,
# so after tokenization ``$'npm'`` (ANSI-C quoting) and ``"$PM"`` both reach
# the argv as ``$npm`` — indistinguishable from a literal token — while bash
# expands them before execution. An executable word carrying one of these
# names a binary this classifier never saw, so it must fail closed rather
# than classify the unexpanded spelling.
_EXPANSION_CHARS = frozenset("$`")

# Characters that trigger pathname expansion (globbing) inside a word. Bash
# expands an executable word carrying an unquoted glob *before* command
# lookup: with npm installed at ``/opt/node/bin/npm``,
# ``/opt/node/bin/n?m install left-pad`` executes npm while the classifier
# would record the binary as ``n?m`` and mint an allowed ``env.shell.exec`` —
# bypassing the canonical-manager denial exactly as a parameter expansion
# would. The expansion is not emulated (it depends on the host filesystem),
# so a glob-bearing executable word fails closed as undecidable. shlex strips
# quotes, so a quoted literal (``'n?m' install``) — and the ``[`` test
# builtin — are over-approximated as expansions: an escalation, never a
# false allow.
_GLOB_CHARS = frozenset("*?[")

# Leading tokens that wrap another command rather than being the command.
# These pass their remaining arguments through as an argv — the wrapped
# command's structure is preserved — which is why peeling them is sound.
# ``builtin`` is included: it routes to the named builtin with argv semantics,
# and leaving it out would hide ``builtin eval '<command>'`` behind an
# unclassified token.
_WRAPPERS = frozenset(
    {"sudo", "env", "command", "builtin", "nohup", "time", "nice", "exec", "doas"}
)

#: Shell builtins that evaluate a *string* (or file contents) as a new shell
#: command line. ``eval 'npm install left-pad'`` concatenates its arguments and
#: re-parses the result as a second command line — one this classifier never
#: tokenizes and that carries no unquoted operator of its own — while
#: ``source`` / ``.`` execute a script's contents in the current shell. Unlike
#: the :data:`_WRAPPERS`, the payload is unparsed program text, not an argv
#: this classifier could recurse into, so every such invocation is returned
#: undecidable (fail-closed) rather than classified as a decidable plain exec.
_SHELL_EVAL_BUILTINS = frozenset({"eval", "source", "."})

#: Shell interpreter binaries. Invoking one delegates the real program — an
#: inline ``-c`` string, a script file, or stdin — that this classifier never
#: tokenizes: ``bash -c 'npm install left-pad'`` contains no unquoted operator,
#: so without this table it would classify as a decidable, allowed
#: ``env.shell.exec`` while executing a governed dependency mutation. The inner
#: program's effect is not recoverable from the outer argv prefix (option
#: grammars, ``$0`` argument slots, and script contents are all out of reach),
#: so every shell-interpreter invocation is returned undecidable (fail-closed)
#: rather than parsed on a guess. Version suffixes cover executable names such
#: as ``bash5.2``; ``.exe`` is normalized separately.
_SHELL_INTERPRETER_RE = re.compile(
    r"^(?:ash|bash|csh|dash|fish|ksh|mksh|rbash|sh|tcsh|yash|zsh)(?:\d+(?:\.\d+)*)?$"
)
_SHELL_LIKE_EXECUTABLE_RE = re.compile(r"^[a-z0-9+_.-]*sh(?:\d+(?:\.\d+)*)?$")

#: Utilities that execute a *nested command* given as operands. ``xargs npm
#: install left-pad``, ``timeout 60 npm install left-pad``, and ``watch 'npm
#: install left-pad'`` all run the governed manager while the outer binary
#: classified as an allowed ``env.shell.exec`` — bypassing the
#: canonical-manager denial and the dependency escalation exactly as shell
#: delegation did. Unlike the :data:`_WRAPPERS`, these are not plain argv
#: pass-throughs: each has its own operand grammar (durations, replacement
#: strings, intervals, trace options) that would have to be modeled to
#: recover the nested argv, so every invocation is returned undecidable
#: (fail-closed) rather than peeled on a guess.
_COMMAND_LAUNCHERS = frozenset(
    {
        "xargs",
        "timeout",
        "watch",
        "parallel",
        "setsid",
        "stdbuf",
        "ionice",
        "chrt",
        "taskset",
        "flock",
        "strace",
        "ltrace",
        "script",
    }
)

#: ``find`` primaries that execute a nested command once per matched path
#: (``find /tmp -maxdepth 0 -exec npm install left-pad \;``). A find without
#: one of these still falls to the unknown-grammar fail-closed floor; with one
#: present the nested argv is identified explicitly and is not recovered —
#: the invocation fails closed. shlex
#: strips quotes, so a quoted pattern spelling a primary (``-name '-exec'``)
#: is over-approximated: an escalation, never a false allow.
_FIND_EXEC_PRIMARIES = frozenset({"-exec", "-execdir", "-ok", "-okdir"})

#: Executable aliases the manager distributions themselves ship next to the
#: primary binary. Yarn installs ``yarnpkg`` alongside ``yarn`` (the same CLI
#: under a second name; its ``add --help`` describes adding dependencies to
#: the project), so ``yarnpkg add left-pad`` performs Yarn's dependency
#: mutation while appearing in no manager table — it classified as an
#: undecidable ``env.shell.exec`` and returned an approvable ask instead of
#: the hard ``deny-non-canonical-package-manager`` produced for ``yarn add``.
#: Normalized before any table lookup so the alias and the primary name share
#: one manager contract.
_MANAGER_EXECUTABLE_ALIASES: Mapping[str, str] = {"yarnpkg": "yarn"}

#: Abbreviated and typo spellings npm's own CLI declares as ``install``
#: aliases (``npm install --help`` on npm 11 lists them verbatim). Each runs
#: the same install with lifecycle scripts enabled, so a spelling missing
#: from the npm row would classify as a plain ``env.package.invoke`` and skip
#: the separately recorded lifecycle-enablement decision.
_NPM_INSTALL_ALIASES = frozenset(
    {"in", "ins", "inst", "insta", "instal", "isnt", "isnta", "isntal", "isntall"}
)

_INSTALL_SUBCOMMANDS: Mapping[str, frozenset[str]] = {
    "npm": frozenset({"install", "i", "ci", "add", "update", "up"}) | _NPM_INSTALL_ALIASES,
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

#: Runner front-ends that fetch and execute a package in one step (``npx -y
#: <pkg>`` and friends). Absent from this table they would classify as allowed
#: ``env.shell.exec`` — remote package code executing without the dependency
#: escalation or the canonical-manager check — so each maps to the manager
#: ecosystem whose contract it participates in.
_PACKAGE_RUNNERS: Mapping[str, str] = {
    "npx": "npm",
    "pnpx": "pnpm",
    "bunx": "bun",
}

#: Managers Corepack can proxy. Corepack is the Node package-manager
#: front-end: ``corepack npm ...`` routes the call to a pinned npm release,
#: fetching it over the network first when it is not cached (Corepack 0.34.6
#: attempts to fetch ``npm-11.8.0.tgz`` for a bare ``corepack npm --version``).
#: Absent from the package surfaces, every such invocation classified as an
#: allowed plain exec — bypassing the canonical-manager denial and the
#: dependency escalation.
_COREPACK_MANAGERS = frozenset({"npm", "pnpm", "yarn"})

#: Corepack's own operations that fetch a manager release and/or mutate
#: declared dependency state: ``use`` retrieves a release, rewrites
#: ``package.json``, and performs an install; ``install`` and ``up`` fetch and
#: activate manager releases. These classify as dependency mutations.
_COREPACK_INSTALL_SUBCOMMANDS = frozenset({"use", "install", "up"})

#: Corepack operations that mutate the shim/cache environment without a
#: declared install (``enable`` writes manager shims onto the ``PATH``). They
#: stay on the package surface — dependency tier, escalated — rather than
#: falling through to an unclassified allow.
_COREPACK_SHIM_SUBCOMMANDS = frozenset({"enable", "disable", "cache", "hydrate", "pack", "prepare"})

#: Windows installs expose package tools through ``.cmd`` / ``.bat`` shims and
#: sometimes ``.exe`` launchers. Strip those suffixes only when the remaining
#: stem is a package executable whose grammar is declared below; arbitrary
#: executable names keep their suffix and continue to fail closed. Path trust
#: is determined from the original argv token before this normalization.
_WINDOWS_PACKAGE_EXECUTABLE_SUFFIXES = (".cmd", ".bat", ".exe")

#: Flags that disable lifecycle-script execution, per manager. Keyed by the
#: manager because the spelling is not portable: npm 11 declares only
#: ``--ignore-scripts`` (``--no-scripts`` draws "Unknown cli config" and the
#: install scripts still run), while Composer's is ``--no-scripts``. A flag a
#: manager does not declare must never record ``scripts_disabled: true``: the
#: claim would suppress the lifecycle-enablement decision while the scripts
#: execute. A manager absent from this table is treated as "not disabled",
#: fail-closed, because an unknown manager cannot be assumed safe.
_LIFECYCLE_DISABLE_FLAGS: Mapping[str, frozenset[str]] = {
    "npm": frozenset({"--ignore-scripts"}),
    "pnpm": frozenset({"--ignore-scripts"}),
    "yarn": frozenset({"--ignore-scripts"}),
    "bun": frozenset({"--ignore-scripts"}),
    "composer": frozenset({"--no-scripts"}),
}


def _lifecycle_scripts_disabled(manager: str, flags: frozenset[str]) -> bool:
    """True only when the manager's own declared disable flag is present."""
    return bool(flags & _LIFECYCLE_DISABLE_FLAGS.get(manager, frozenset()))


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

#: Managers whose declared grammar includes an artifact-generation subcommand.
#: These route to :data:`ACTION_ARTIFACT_GENERATE` (control-surface tier): a
#: generated artifact is one ``publish`` away from release. Build-system targets
#: (``make dist``) are structurally opaque and deliberately absent — see the
#: module docstring's "does NOT claim" section.
_ARTIFACT_SUBCOMMANDS: Mapping[str, frozenset[str]] = {
    "npm": frozenset({"pack"}),
    "pnpm": frozenset({"pack"}),
    "yarn": frozenset({"pack"}),
    "cargo": frozenset({"package"}),
    "poetry": frozenset({"build"}),
    "uv": frozenset({"build"}),
    "gem": frozenset({"build"}),
}

#: ``gh`` subcommand groups that reach *remote* GitHub state through the API.
#: ``gh pr merge`` mutates the remote base branch exactly as a ``git push``
#: would — and a host permission grant for the prefix makes an unclassified
#: allow a real authorization, not a deferral — so pull-request, issue, and
#: repository mutations must not fall through to the unclassified allow tier.
#: Operations declared read-only stay decidable inspection; declared mutating
#: operations classify as remote mutations on the same control surface as
#: ``git push``; an operation in neither table is returned undecidable
#: (fail-closed). ``gh api`` is an arbitrary authenticated REST call whose
#: effect lives in its method and path, not its argv prefix, and is always
#: undecidable.
_GH_REMOTE_READ_ONLY: Mapping[str, frozenset[str]] = {
    "pr": frozenset({"checks", "diff", "list", "status", "view"}),
    "issue": frozenset({"list", "status", "view"}),
    "repo": frozenset({"list", "view"}),
}

_GH_REMOTE_MUTATING: Mapping[str, frozenset[str]] = {
    "pr": frozenset(
        {
            "close",
            "comment",
            "create",
            "edit",
            "lock",
            "merge",
            "ready",
            "reopen",
            "review",
            "unlock",
            "update-branch",
        }
    ),
    "issue": frozenset(
        {
            "close",
            "comment",
            "create",
            "delete",
            "develop",
            "edit",
            "lock",
            "pin",
            "reopen",
            "transfer",
            "unlock",
            "unpin",
        }
    ),
    "repo": frozenset(
        {
            "archive",
            "create",
            "delete",
            "edit",
            "fork",
            "rename",
            "set-default",
            "sync",
            "unarchive",
        }
    ),
}

_GH_READ_ONLY_SHORT_VALUE_OPTIONS: Mapping[tuple[str, str], frozenset[str]] = {
    ("pr", "checks"): frozenset({"R", "i", "q", "t"}),
    ("pr", "diff"): frozenset({"R", "e"}),
    ("pr", "list"): frozenset({"A", "B", "H", "L", "R", "S", "a", "l", "q", "s", "t"}),
    ("pr", "status"): frozenset({"R", "q", "t"}),
    ("pr", "view"): frozenset({"R", "q", "t"}),
    ("issue", "list"): frozenset({"A", "L", "R", "S", "a", "l", "m", "q", "s", "t"}),
    ("issue", "status"): frozenset({"R", "q", "t"}),
    ("issue", "view"): frozenset({"R", "q", "t"}),
    ("repo", "list"): frozenset({"L", "l", "q", "t"}),
    ("repo", "view"): frozenset({"b", "q", "t"}),
}

#: Every gh group the classifier resolves beyond the group token. ``api`` is
#: included so it can be forced undecidable rather than falling through.
_GH_REMOTE_GROUPS = frozenset({"api", *_GH_REMOTE_READ_ONLY, *_GH_REMOTE_MUTATING})

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

#: git subcommands known to read repository state without mutating it. A git
#: subcommand in neither this set nor :data:`_GIT_MUTATING` is **not** presumed
#: read-only: it may be a user-defined alias expanding to anything, or a
#: mutating subcommand this table simply does not enumerate, so the command is
#: returned undecidable (fail-closed) instead.
_GIT_READ_ONLY = frozenset(
    {
        "annotate",
        "blame",
        "cat-file",
        "check-attr",
        "check-ignore",
        "cherry",
        "count-objects",
        "describe",
        "diff",
        "diff-files",
        "diff-index",
        "diff-tree",
        "for-each-ref",
        "fsck",
        "grep",
        "log",
        "ls-files",
        "ls-remote",
        "ls-tree",
        "merge-base",
        "name-rev",
        "range-diff",
        "rev-list",
        "rev-parse",
        "shortlog",
        "show",
        "show-branch",
        "show-ref",
        "status",
        "var",
        "verify-commit",
        "verify-tag",
        "version",
        "whatchanged",
    }
)

#: Options that make an otherwise read-only git subcommand write a file chosen
#: on the command line. Git documents ``--output <file>`` for the diff family
#: (``log``, ``show``, ``diff``, ``range-diff``, ...) and ``--output-directory``
#: for ``format-patch``: ``git log --output=.gove-zone/gate.mode -1`` replaces
#: the gate-mode file even though ``log`` never mutates repository state, so a
#: host-whitelisted read-only prefix (``Bash(git log:*)``) must not carry one.
#: Matched on the exact option name (``--output`` / ``--output=<file>``), never
#: on a prefix, so ``--output-indicator-new=<char>`` stays untouched.
_GIT_OUTPUT_REDIRECT_OPTIONS = frozenset({"--output", "--output-directory"})

#: Options that make an otherwise read-only git subcommand execute a helper
#: program: ``--ext-diff`` runs the configured external diff command and
#: ``--textconv`` runs configured textconv filters (both documented in
#: ``git help log`` / ``git help diff``). The helper itself is declared by
#: repository or host configuration this classifier never reads, so the
#: read-only claim the tier assignment rests on is false whenever one of
#: these appears — fail closed.
_GIT_HELPER_ENABLE_OPTIONS = frozenset({"--ext-diff", "--textconv"})

#: git global options that consume the *following* token as their value when
#: not written in ``--option=value`` form. ``git -h`` explicitly permits these
#: before the command (``git [-C <path>] [-c <name>=<value>] ... <command>``);
#: skipping only the option token would return its value as the subcommand.
_GIT_VALUE_GLOBAL_OPTIONS = frozenset(
    {
        "-C",
        "-c",
        "--attr-source",
        "--config-env",
        "--exec-path",
        "--git-dir",
        "--namespace",
        "--super-prefix",
        "--work-tree",
    }
)

#: git global options known to take no value. An option in neither table is
#: not guessed at — the command is returned undecidable (fail-closed).
_GIT_FLAG_GLOBAL_OPTIONS = frozenset(
    {
        "-h",
        "--help",
        "--version",
        "--html-path",
        "--man-path",
        "--info-path",
        "-p",
        "--paginate",
        "-P",
        "--no-pager",
        "--bare",
        "--no-replace-objects",
        "--no-lazy-fetch",
        "--no-optional-locks",
        "--no-advice",
        "--literal-pathspecs",
        "--glob-pathspecs",
        "--noglob-pathspecs",
        "--icase-pathspecs",
    }
)

#: Binaries whose second-position token has declared meaning. Everything else is
#: read as a bare binary — see :func:`_subcommand`.
_GRAMMAR_BINARIES: frozenset[str] = frozenset(
    {"git", *_INSTALL_SUBCOMMANDS, *_PUBLISH_SUBCOMMANDS, *_ARTIFACT_SUBCOMMANDS}
)

#: Python modules whose argv is deliberately recovered into an existing
#: governed package-manager grammar. A module merely sharing a binary name
#: (for example ``python -m git``) is not evidence that it implements that
#: binary's declared command-line contract.
_PYTHON_GOVERNED_MODULES = frozenset({"pip", "pip3", "poetry", "uv"})

#: Non-delegating read-only commands whose outer argv grammar is intentionally
#: accepted as an unclassified shell execution. Everything else needs a declared
#: grammar or a recognized interpreter family; an executable name alone is not
#: evidence that its arguments cannot delegate a governed effect. The name is
#: trusted only after :func:`_ambient_resolution_reason` confirms the bare
#: spelling actually reaches the system implementation.
_PLAIN_EXECUTABLES = frozenset({"cat", "grep", "ls"})

#: Root-owned system directories a plain executable must resolve into for the
#: bare name to be trusted. Deliberately excludes ``/usr/local/bin`` and other
#: commonly user-writable prefixes: an implementation installed there is a
#: replacement, not the system one.
_TRUSTED_EXECUTABLE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin"


def _ambient_resolution_reason(binary: str, environ: Mapping[str, str]) -> str:
    """Why bash's ambient resolution of a bare name is untrusted, or ``""``.

    Bash resolves a bare word through functions and ``PATH`` before any
    binary runs, so the name alone is not evidence that the system
    implementation executes: an exported function or a ``PATH``-shadowing
    executable named ``ls`` runs arbitrary code while the argv still reads
    ``ls``. Exported functions are visible in the inherited environment
    (``BASH_FUNC_<name>%%``, older bash ``BASH_FUNC_<name>()``), and ``PATH``
    shadowing is detected by requiring the ambient lookup to land on the same
    file (by identity, not spelling) as a lookup restricted to
    :data:`_TRUSTED_EXECUTABLE_PATH`. Anything unresolvable fails closed.
    """
    if f"BASH_FUNC_{binary}%%" in environ or f"BASH_FUNC_{binary}()" in environ:
        return "exported-function-shadowing"
    ambient = shutil.which(binary, path=environ.get("PATH") or os.defpath)
    trusted = shutil.which(binary, path=_TRUSTED_EXECUTABLE_PATH)
    if not ambient or not trusted:
        return "ambient-path-resolution"
    with contextlib.suppress(OSError, RuntimeError, ValueError):
        if os.path.samefile(ambient, trusted):
            return ""
    return "ambient-path-resolution"


#: A subcommand is a lowercase word. A secret, a path, or an option value is
#: essentially never one.
_SUBCOMMAND_RE = re.compile(r"^[a-z][a-z0-9-]*$")

#: A valid shell variable name. Bash treats a leading ``word=value`` as an
#: environment assignment only when ``word`` is a valid identifier.
_ASSIGNMENT_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

#: Python-family executables, including Windows GUI launchers and PyPy.
_PYTHON_BINARY_RE = re.compile(
    r"^(?:pyw?|jython(?:\d+(?:\.\d+)*)?|(?:[a-z]+)?pythonw?(?:\d+(?:\.\d+)*)?t?|pypy(?:\d+(?:\.\d+)*)?)$"
)

#: Other interpreter/launcher families that can hide arbitrary effects inside
#: an inline program, script, module, or applet. Numeric suffixes cover common
#: distro/versioned binaries such as ``php8.2``, ``lua5.4``, and ``ruby3.1``.
_DELEGATING_INTERPRETER_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^busybox(?:\d+(?:\.\d+)*)?$"), "launcher"),
    (re.compile(r"^cmd(?:\d+(?:\.\d+)*)?$"), "cmd"),
    (re.compile(r"^lua(?:jit)?(?:\d+(?:\.\d+)*)?$"), "lua"),
    (re.compile(r"^node(?:js)?(?:\d+(?:\.\d+)*)?$"), "node"),
    (re.compile(r"^perl(?:\d+(?:\.\d+)*)?$"), "perl"),
    (
        re.compile(r"^php(?:(?:\d+(?:\.\d+)*)?(?:-cgi)?|(?:-cgi)(?:\d+(?:\.\d+)*)?)$"),
        "php",
    ),
    (re.compile(r"^(?:powershell|pwsh)(?:\d+(?:\.\d+)*)?$"), "powershell"),
    (re.compile(r"^(?:ruby|jruby)(?:\d+(?:\.\d+)*)?$"), "ruby"),
)
_SAFE_INTERPRETER_PROBES: Mapping[str, frozenset[str]] = {
    "cmd": frozenset({"/?"}),
    "launcher": frozenset({"--help", "--version"}),
    "lua": frozenset({"-v", "--version"}),
    "node": frozenset({"-h", "--help", "-v", "--version"}),
    "perl": frozenset({"-h", "--help", "-v", "--version"}),
    "php": frozenset({"-h", "--help", "-v", "--version"}),
    "powershell": frozenset({"-help", "--help", "-version", "--version"}),
    "python": frozenset({"-h", "--help", "-V", "-VV", "--version"}),
    "ruby": frozenset({"-h", "--help", "-v", "--version"}),
    "shell": frozenset({"--help", "--version"}),
}

#: Environment variables that inject a preload/startup program into an
#: otherwise-benign help/version probe, keyed by interpreter family. Node
#: honors ``NODE_OPTIONS`` (``--require``/``--import``) before printing help,
#: so ``node --help`` under an inherited ``NODE_OPTIONS=--require=/tmp/x.js``
#: executes arbitrary JavaScript with the genuine node binary; verified on
#: Node 24. Only families with a documented preload channel are listed; a
#: probe whose family is absent stays trusted.
_PROBE_PRELOAD_ENV: Mapping[str, tuple[str, ...]] = {
    "node": ("NODE_OPTIONS",),
}


def _interpreter_probe_preload_reason(family: str, environ: Mapping[str, str]) -> str:
    """Why a declared probe is unsafe under the inherited environment, or ``""``.

    A help/version probe is only benign if nothing runs before the banner.
    An inherited preload variable (:data:`_PROBE_PRELOAD_ENV`) breaks that:
    the genuine interpreter executes the injected module first, so the probe
    must fail closed rather than mint a decidable allow.
    """
    for var in _PROBE_PRELOAD_ENV.get(family, ()):
        if (environ.get(var) or "").strip():
            return "interpreter-probe-preload-env"
    return ""


#: Long-form inline-program options are self-describing enough to fail closed
#: even when the executable name is not a known interpreter family. Ambiguous
#: short flags remain family-scoped so ordinary tools are not rejected merely
#: because they reuse a flag.
_GENERIC_INLINE_PROGRAM_OPTIONS = frozenset(
    {"--command", "--eval", "--execute", "--execute-command", "-encodedcommand"}
)

#: python interpreter options known to take no value.
_PYTHON_FLAG_OPTIONS = frozenset(
    {
        "-b",
        "-B",
        "-d",
        "-E",
        "-h",
        "--help",
        "-i",
        "-I",
        "-O",
        "-OO",
        "-P",
        "-q",
        "-s",
        "-S",
        "-u",
        "-v",
        "-V",
        "--version",
        "-x",
    }
)

#: python interpreter options that consume the *following* token as their value
#: when the value is not attached (``-W ignore`` vs ``-Wignore``).
_PYTHON_VALUE_OPTIONS = frozenset({"-W", "-X", "--check-hash-based-pycs"})


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
    command_sha256: str = ""

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

        ``command_sha256`` binds the receipt to the *complete* command text
        without disclosing it: ``npm install left-pad`` and
        ``npm install malware`` share an argv prefix but not a digest, so a
        receipt cannot be presented as authorization for a different command
        with the same prefix. A verifier holding the plaintext can recompute
        the digest; one who does not learns nothing from it.
        """
        return {
            "action": self.action,
            "binary": self.binary,
            "argv_prefix": list(self.argv_prefix),
            "command_sha256": self.command_sha256,
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
        if "=" in head and _ASSIGNMENT_NAME_RE.match(head.split("=", 1)[0]):
            # Bash performs the assignment only for a valid identifier name;
            # `${PM:=npm} install` is an executable word, not an assignment,
            # and peeling it would hide the expansion from the
            # executable-word check in classify_command.
            wrappers.append(head.split("=", 1)[0] + "=")
            rest = rest[1:]
            continue
        if Path(head).name in _WRAPPERS and not (_EXPANSION_CHARS & set(head)):
            wrapper = Path(head).name
            wrappers.append(wrapper)
            rest = rest[1:]
            if rest and rest[0].startswith("-"):
                return [wrapper], wrappers, True
            continue
        break
    return rest, wrappers, False


def _declared_subcommands(binary: str) -> frozenset[str]:
    """Every subcommand this module declares meaning for on *binary*."""
    return (
        _INSTALL_SUBCOMMANDS.get(binary, frozenset())
        | _PUBLISH_SUBCOMMANDS.get(binary, frozenset())
        | _ARTIFACT_SUBCOMMANDS.get(binary, frozenset())
    )


def _subcommand(binary: str, argv: Sequence[str]) -> tuple[str, str]:
    """``(subcommand, undecidable_reason)`` for *binary*'s argv.

    Three guards, all necessary. Only binaries with a **declared subcommand
    grammar** are read at all — an arbitrary program has no second-position
    meaning to recover. The token must look like a subcommand
    (:data:`_SUBCOMMAND_RE`) before it is accepted.

    Without the second guard this function returns the *value* of a
    value-taking option: ``curl -H 'Authorization: Bearer <token>' ...`` yields
    the bearer token, which then lands in ``argv_prefix`` and is hashed into a
    receipt. The receipt would become an exfiltration channel. A subcommand
    always matches the pattern; a secret essentially never does.

    The third guard covers option *values* that happen to look like
    subcommands: option grammars per binary are not modeled here, so once an
    option token has been skipped, the next word may be that option's value
    rather than a subcommand — ``gh --repo owner/name release create`` must not
    read ``release`` out of position, but neither may ``owner/name`` be trusted
    as "not a subcommand". After a skipped option, a word is accepted only if
    it is a subcommand this module declared for the binary; anything else is
    returned undecidable (``option-value-ambiguity``, fail-closed) rather than
    silently classified as a bare invoke.
    """
    if binary not in _GRAMMAR_BINARIES:
        return "", ""
    saw_option = False
    for token in argv[1:]:
        if token.startswith("-"):
            saw_option = True
            continue
        if not saw_option:
            return (token, "") if _SUBCOMMAND_RE.match(token) else ("", "")
        if _SUBCOMMAND_RE.match(token) and token in _declared_subcommands(binary):
            return token, ""
        return "", "option-value-ambiguity"
    return "", ""


def _gh_operation(argv: Sequence[str], group: str) -> tuple[str, str]:
    """``(operation, undecidable_reason)`` for a ``gh <group> <operation>`` argv.

    Mirrors the option guards of :func:`_subcommand`: gh option grammars are
    not modeled here, so once an option token appears before the operation the
    next word may be that option's value — ``gh pr -R owner/name merge`` must
    not read ``owner/name`` as the operation, and neither may a word after a
    skipped option be trusted unless it is an operation this module declared
    for the group. Anything else is returned undecidable (fail-closed).
    """
    declared = _GH_REMOTE_READ_ONLY.get(group, frozenset()) | _GH_REMOTE_MUTATING.get(
        group, frozenset()
    )
    saw_option = False
    for token in argv[2:]:
        if token.startswith("-"):
            saw_option = True
            continue
        if not saw_option:
            return (token, "") if _SUBCOMMAND_RE.match(token) else ("", "non-subcommand-token")
        if _SUBCOMMAND_RE.match(token) and token in declared:
            return token, ""
        return "", "option-value-ambiguity"
    return "", "missing-gh-operation"


def _has_active_substitution(text: str) -> bool:
    """True when ``$(`` or a backtick is reachable by the shell in *text*.

    :mod:`shlex` in POSIX mode strips quotes, so a substitution *inside double
    quotes* — ``git status "$(npm install left-pad)"`` — survives tokenization
    as ordinary argument text: no operator token is emitted and a token-level
    backtick check never fires, while bash executes the inner command before
    the outer one. Substitution is inert inside single quotes, and a backslash
    escapes the character that follows it (both unquoted and inside double
    quotes, where ``\\$`` and ``\\``` are the documented escapes), so only
    occurrences the shell would actually expand count.
    """
    in_single = False
    in_double = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_single:
            if char == "'":
                in_single = False
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if char == "'" and not in_double:
            in_single = True
        elif char == '"':
            in_double = not in_double
        elif char == "`" or char == "$" and index + 1 < len(text) and text[index + 1] == "(":
            return True
        index += 1
    return False


def _has_unquoted_operator(text: str) -> bool:
    """True when a shell operator character is reachable by the shell in *text*.

    The check runs on the raw command text because :mod:`shlex` in POSIX mode
    strips quotes: a standalone quoted operator — ``git commit -m ';'`` or
    ``grep -F '|' file`` — survives tokenization as a bare ``;`` / ``|`` token,
    so a token-value test cannot tell data from a separator and would mark an
    explicitly permitted single command undecidable. Quoting semantics mirror
    :func:`_has_active_substitution`: operator characters are inert inside
    single quotes, inside double quotes, and behind a backslash escape; only
    occurrences the shell would actually parse as operators count.
    """
    in_single = False
    in_double = False
    index = 0
    while index < len(text):
        char = text[index]
        if in_single:
            if char == "'":
                in_single = False
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if char == "'" and not in_double:
            in_single = True
        elif char == '"':
            in_double = not in_double
        elif not in_double and char in _OPERATOR_CHARS:
            return True
        index += 1
    return False


def _git_subcommand(argv: Sequence[str]) -> tuple[str, str]:
    """``(subcommand, undecidable_reason)`` for a git argv.

    git's global-option grammar permits value-taking options before the
    command. The generic :func:`_subcommand` skip-options loop would return the
    *value* of such an option — ``git -C repo push --force`` yields ``repo``,
    silently downgrading a control-surface mutation to an allowed shell exec.
    Value-taking global options can switch repository/config/exec context, and
    command-local config can install execution hooks such as ``core.fsmonitor``,
    ``diff.external``, or ``help.browser``. Pager flags likewise delegate to an
    external process. Those shapes fail closed rather than trusting a known
    subcommand under an attacker-selected execution context.
    """
    index = 1
    while index < len(argv):
        token = argv[index]
        if not token.startswith("-"):
            return (token, "") if _SUBCOMMAND_RE.match(token) else ("", "non-subcommand-token")
        if token == "-c" or token.startswith("-c") and len(token) > 2:
            return "", "git-config-injection"
        option = token.split("=", 1)[0]
        if option == "--config-env":
            return "", "git-config-injection"
        if option in _GIT_VALUE_GLOBAL_OPTIONS:
            return "", "git-execution-context-option"
        if option in {"-p", "--paginate"}:
            return "", "git-execution-hook-option"
        if token.startswith("--") and "=" in token:
            if option in _GIT_FLAG_GLOBAL_OPTIONS:
                index += 1
                continue
            return "", "unrecognized-git-global-option"
        if token in _GIT_FLAG_GLOBAL_OPTIONS:
            index += 1
            continue
        return "", "unrecognized-git-global-option"
    return "", ""


_FALSE_BOOLEAN_OPTION_VALUES = frozenset({"0", "f", "false"})


def _short_boolean_option_active(token: str, target: str, *, value_options: frozenset[str]) -> bool:
    """Whether a short boolean option is active in a parsed option cluster."""
    if not token.startswith("-") or token.startswith("--") or token == "-":
        return False
    cluster = token[1:]
    for index, option in enumerate(cluster):
        if option == target:
            remainder = cluster[index + 1 :]
            if remainder.startswith("="):
                return remainder[1:].casefold() not in _FALSE_BOOLEAN_OPTION_VALUES
            return True
        if option in value_options:
            return False
    return False


def _gh_external_helper_reason(argv: Sequence[str], subcommand: str, operation: str) -> str:
    """Return a declared read-only GH option that opens an external browser."""
    active_argv = argv[: argv.index("--")] if "--" in argv else argv
    value_options = _GH_READ_ONLY_SHORT_VALUE_OPTIONS.get((subcommand, operation), frozenset())
    if any(
        _short_boolean_option_active(token, "w", value_options=value_options)
        or token == "--web"
        or (
            token.startswith("--web=")
            and token.split("=", 1)[1].casefold() not in _FALSE_BOOLEAN_OPTION_VALUES
        )
        for token in active_argv
    ):
        return "gh-web-helper-option"
    return ""


def _gh_pager_external_context(environ: Mapping[str, str]) -> bool:
    """Whether an inherited pager makes a gh read able to run a program.

    GitHub CLI pipes read output through a pager (``gh help environment``):
    ``GH_PAGER`` takes precedence over ``PAGER``, and either set to the empty
    string disables paging. A non-empty configured pager is an executable gh
    launches, so a ``gh pr view`` under an attacker-controlled ``GH_PAGER``
    runs arbitrary code despite being a modeled read-only operation. An unset
    pager leaves gh's built-in default, which is not environment-injectable,
    so it stays trusted.
    """
    value = environ["GH_PAGER"] if "GH_PAGER" in environ else environ.get("PAGER", "")
    return bool(value.strip())


def _git_option_present(argv: Sequence[str], options: frozenset[str]) -> str:
    """The first token on a git argv whose option name is in *options*, or ``""``.

    A bare ``--`` ends option parsing for git: everything after it is a
    pathspec, so a file literally named ``--output`` is an argument there,
    not a redirection. Only the option *name* is compared (attached
    ``--output=<file>`` and separate ``--output <file>`` forms both match);
    prefix lookalikes such as ``--output-indicator-new=<char>`` do not.
    """
    for token in argv[1:]:
        if token == "--":
            break
        if not token.startswith("-"):
            continue
        if token.split("=", 1)[0] in options:
            return token
    return ""


def _python_module_argv(argv: Sequence[str]) -> tuple[list[str] | None, str]:
    """``(module_argv, undecidable_reason)`` for a python interpreter argv.

    ``python -m pip install x`` executes pip exactly as ``pip install x``
    would; not recovering the module would leave an interpreter-shaped alias
    for every governed manager. Returns the argv *after* ``-m`` (module name
    first) when a module is invoked, ``(None, "")`` for a plain script run
    (the caller marks that delegation undecidable),
    ``(None, "inline-interpreter-program")`` for a ``-c`` / stdin program —
    inline program text is a second command line this classifier never
    tokenizes, so ``python -c "open('.gove-zone/gate.mode','w')..."`` must not
    pass as a decidable plain exec — and
    ``(None, "unrecognized-python-option")`` when an interpreter option this
    table does not declare appears before the program: an unknown option may
    consume the next token, so nothing after it can be trusted (fail-closed).
    """
    index = 1
    while index < len(argv):
        token = argv[index]
        if token == "-m":
            if index + 1 < len(argv):
                return list(argv[index + 1 :]), ""
            return None, "unrecognized-python-option"
        if token == "-c" or token == "-":
            return None, "inline-interpreter-program"
        if not token.startswith("-"):
            # A script path: no module to recover. The caller fails closed
            # because the script contents are outside this argv classifier.
            return None, ""
        if token in _PYTHON_VALUE_OPTIONS:
            index += 2
            continue
        if token in _PYTHON_FLAG_OPTIONS:
            index += 1
            continue
        if len(token) > 2 and token[:2] in ("-W", "-X"):
            # Attached value forms: -Wignore, -Xdev.
            index += 1
            continue
        return None, "unrecognized-python-option"
    return None, ""


def _normalized_executable(binary: str) -> str:
    """Normalize a basename for case-insensitive family matching."""
    normalized = binary.casefold()
    return normalized.removesuffix(".exe")


def _portable_basename(executable: str) -> str:
    """Return a basename for either POSIX or Windows-style command tokens."""
    return executable.replace("\\", "/").rsplit("/", 1)[-1]


def _normalized_package_executable(binary: str) -> str:
    """Normalize declared package-tool shims without trusting arbitrary names.

    Recognized manager names, runners, and aliases are compared casefolded in
    the unsuffixed branch too: on a case-insensitive filesystem (macOS and
    Windows defaults) ``NPM install`` resolves to the normal ``npm``
    executable, so keeping the mixed-case spelling would demote the manager
    contract to an approvable undecidable-shell ask instead of the hard
    non-canonical-manager deny. On a case-sensitive filesystem this
    over-approximates (a genuinely distinct ``NPM`` binary is still governed
    as ``npm``), which is a deny/escalation, never a false allow. Names
    outside the declared tables keep their original spelling.
    """
    folded = binary.casefold()
    for suffix in _WINDOWS_PACKAGE_EXECUTABLE_SUFFIXES:
        if not folded.endswith(suffix):
            continue
        candidate = folded.removesuffix(suffix)
        if (
            candidate == "corepack"
            or candidate in _INSTALL_SUBCOMMANDS
            or candidate in _PACKAGE_RUNNERS
            or candidate in _MANAGER_EXECUTABLE_ALIASES
        ):
            return _MANAGER_EXECUTABLE_ALIASES.get(candidate, candidate)
        break
    if (
        folded == "corepack"
        or folded in _INSTALL_SUBCOMMANDS
        or folded in _PACKAGE_RUNNERS
        or folded in _MANAGER_EXECUTABLE_ALIASES
    ):
        return _MANAGER_EXECUTABLE_ALIASES.get(folded, folded)
    return binary


def _interpreter_family(binary: str) -> str:
    """Return the normalized family for a known delegating executable."""
    normalized = _normalized_executable(binary)
    if _PYTHON_BINARY_RE.fullmatch(normalized):
        return "python"
    family = next(
        (
            family
            for pattern, family in _DELEGATING_INTERPRETER_PATTERNS
            if pattern.fullmatch(normalized)
        ),
        "",
    )
    if family:
        return family
    return "shell" if _SHELL_INTERPRETER_RE.fullmatch(normalized) else ""


def _is_exact_interpreter_probe(family: str, argv: Sequence[str]) -> bool:
    """Whether argv is exactly a declared non-executing help/version probe."""
    if len(argv) != 2:
        return False
    probe = argv[1]
    safe_probes = _SAFE_INTERPRETER_PROBES[family]
    if family == "powershell":
        return probe.casefold() in safe_probes
    return probe in safe_probes


def _has_generic_inline_delegation(binary: str, argv: Sequence[str]) -> bool:
    """Detect inline execution outside known interpreter families."""
    for token in argv[1:]:
        if token == "--":
            break
        normalized = token.casefold()
        if normalized in _GENERIC_INLINE_PROGRAM_OPTIONS or any(
            normalized.startswith(option + "=") for option in _GENERIC_INLINE_PROGRAM_OPTIONS
        ):
            return True
    normalized = _normalized_executable(binary)
    if _SHELL_LIKE_EXECUTABLE_RE.fullmatch(normalized) is None:
        return False
    saw_short_option = False
    for token in argv[1:]:
        if token == "--":
            return False
        if token == "-" or not token.startswith("-"):
            # Unknown short-option grammars may consume this operand as a value.
            return saw_short_option
        if token.startswith("--"):
            # An unknown long option may itself delegate or consume the next
            # token, so guessing where its value ends would be unsafe.
            return True
        saw_short_option = True
        option_cluster = token[1:].split("=", 1)[0]
        if "c" in option_cluster:
            return True
    return saw_short_option


def _corepack_argv(argv: Sequence[str]) -> tuple[list[str] | None, str, str]:
    """``(delegated_argv, own_operation, undecidable_reason)`` for a corepack argv.

    Corepack is a package-manager front-end, not an ordinary binary. A proxied
    manager — ``corepack npm install left-pad``, version-pinned ``corepack
    yarn@4.1.0 add left-pad`` — returns the delegated manager argv so the
    ordinary classification (and the canonical-manager contract) applies to
    the manager that actually runs; the proxying itself may fetch the pinned
    manager release first. Corepack's own operations return the operation
    name for surface routing. Options before the first word are not modeled —
    an option may consume the following token — and fail closed, as does an
    operation this table does not declare.
    """
    if len(argv) < 2:
        return None, "", "missing-corepack-operation"
    token = argv[1]
    if token.startswith("-"):
        return None, "", "corepack-option-ambiguity"
    base = token.split("@", 1)[0]
    if base in _COREPACK_MANAGERS:
        return [base, *argv[2:]], "", ""
    if token in _COREPACK_INSTALL_SUBCOMMANDS or token in _COREPACK_SHIM_SUBCOMMANDS:
        return None, token, ""
    return None, "", "undeclared-corepack-operation"


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


def classify_command(
    command: str,
    *,
    canonical_package_manager: str = "",
    environ: Mapping[str, str] | None = None,
) -> ExecutionEvent:
    """Classify one shell command string into an execution surface, structurally.

    ``environ`` is the environment the executing shell inherits (defaults to
    this process's, which the hook shares with the host tool). It is consulted
    only to validate that a bare :data:`_PLAIN_EXECUTABLES` name actually
    resolves to the system implementation; see
    :func:`_ambient_resolution_reason`.

    Decides on the argv prefix only. Never matches substrings of the command
    text: ``git commit -m "fix team dashboard"`` is a git mutation, not an
    orchestration command, and ``grep -rn "autopilot" .`` is an unclassified
    shell exec.

    An unquoted shell operator (``|``, ``>``, ``;``, ``&&``, ``$(``, a backtick)
    means the line runs more than one command or redirects output. The effect is
    then not recoverable from the argv prefix, so the event is returned with
    ``decidable=False`` on :data:`ACTION_SHELL_EXEC` — recorded and attributed,
    **not** routed to a risk-bearing surface. Claiming otherwise would classify
    ``echo x > tracked-file`` as a harmless ``echo``. The policy bundle fails
    closed on the marker instead: ``escalate-undecidable-shell`` requires a
    human for every undecidable command, so appending ``; npm install`` to a
    harmless command cannot buy an allow the direct invocation would not get.
    """
    text = command if isinstance(command, str) else ""
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    resolved_environ = environ if environ is not None else os.environ
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
            command_sha256=digest,
        )

    # Checked on the raw text with quote tracking, not on the token values:
    # shlex strips quotes, so `git commit -m ';'` emits a bare `;` token that a
    # token-value test cannot tell from a real separator, while the shell
    # passes the quoted punctuation as data.
    operator_present = _has_unquoted_operator(text)
    if operator_present:
        reasons.append("shell-operator")
    if _has_active_substitution(text):
        # Checked on the raw text, not the tokens: a `$(...)` or backtick
        # inside double quotes survives shlex as plain argument text while the
        # shell executes it first. Single-quoted substitution text is inert
        # and deliberately not flagged.
        reasons.append("command-substitution")
    # An unquoted literal newline (or carriage return) separates commands just
    # like `;` does, but shlex consumes it as whitespace and emits no operator
    # token for it. A newline that survives inside a token was quoted — an
    # argument, not a separator — so only the raw-vs-token difference counts.
    raw_newlines = text.count("\n") + text.count("\r")
    if raw_newlines > sum(t.count("\n") + t.count("\r") for t in tokens):
        reasons.append("newline-separator")

    if operator_present:
        # Attribution on a multi-command line is best-effort: operator tokens
        # are dropped so the leading argv can still be attributed. The line is
        # already undecidable, so this never feeds a positive verdict.
        words = [t for t in tokens if not (t and set(t) <= _OPERATOR_CHARS)]
    else:
        # No unquoted operator exists, so any punctuation-only token was
        # quoted or escaped argument data (`grep -F '|' file`), not a
        # separator, and must stay in the argv.
        words = list(tokens)
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
            facts={"operator_present": operator_present},
            command_sha256=digest,
        )

    binary = _portable_basename(argv[0])
    invoked_by_absolute_path = argv[0] != binary
    # Windows package-tool shims and standard aliases (`yarnpkg`) resolve to
    # the declared package grammar only after path trust was determined from
    # the original argv token. This preserves untrusted-context escalation for
    # path-qualified shims while retaining their manager contract facts.
    binary = _normalized_package_executable(binary)
    untrusted_invocation_context = bool(wrappers) or invoked_by_absolute_path
    if untrusted_invocation_context and not reasons:
        reasons.append("untrusted-execution-context")
    interpreter = ""
    interpreter_family = _interpreter_family(binary)
    package_frontend = ""
    corepack_operation = ""
    if _EXPANSION_CHARS & set(argv[0]):
        reasons.append("executable-word-expansion")
    if _GLOB_CHARS & set(argv[0]):
        # `/opt/node/bin/n?m install left-pad`: bash performs pathname
        # expansion on the executable word before command lookup, so the
        # token this classifier sees (`n?m`) is not the binary that will run
        # (`npm`). Resolving the glob would require the host filesystem, so
        # the event fails closed as undecidable instead of classifying the
        # unexpanded spelling.
        reasons.append("executable-word-glob")
    if binary in _SHELL_EVAL_BUILTINS:
        reasons.append("shell-eval-builtin")
    exact_probe = (
        bool(interpreter_family)
        and not wrappers
        and not invoked_by_absolute_path
        and _is_exact_interpreter_probe(interpreter_family, argv)
    )
    if exact_probe:
        # A probe is benign only if nothing runs before the banner. An
        # inherited preload variable (NODE_OPTIONS --require) executes an
        # injected module first with the genuine interpreter, so the probe
        # must fail closed instead of falling through to a decidable allow.
        probe_preload_reason = _interpreter_probe_preload_reason(
            interpreter_family, resolved_environ
        )
        if probe_preload_reason:
            reasons.append(probe_preload_reason)
            exact_probe = False
    if not reasons and interpreter_family == "shell" and not exact_probe:
        # The real program is whatever the shell is handed — inline `-c` text,
        # a script, or stdin — none of which is recoverable from this argv.
        reasons.append("shell-interpreter-delegation")
    if binary in _COMMAND_LAUNCHERS:
        # `xargs npm install left-pad` / `timeout 60 npm install left-pad`:
        # the outer utility executes a nested command whose argv is embedded
        # in an operand grammar this classifier does not model, so the outer
        # binary must not mint an allow for whatever the nested command does.
        reasons.append("command-launcher-delegation")
    if binary == "find" and any(token in _FIND_EXEC_PRIMARIES for token in argv[1:]):
        # `find ... -exec <command> \;` runs the embedded command per matched
        # path; without the marker the governed nested argv rode an allowed
        # `env.shell.exec` for the outer find.
        reasons.append("find-exec-delegation")
    if not reasons and interpreter_family == "python" and not exact_probe:
        # `python -m pip install x` IS `pip install x`; leaving it unrecovered
        # would make the interpreter an alias for every governed manager.
        module_argv, python_reason = _python_module_argv(argv)
        if python_reason:
            reasons.append(python_reason)
        elif module_argv is not None:
            if module_argv[0] in _PYTHON_GOVERNED_MODULES:
                interpreter = binary
                argv = module_argv
                binary = argv[0]
            else:
                reasons.append("python-module-delegation")
        else:
            reasons.append("python-interpreter-delegation")
    elif not reasons and interpreter_family and not exact_probe:
        reasons.append("interpreter-delegation")
    elif not reasons and not interpreter_family and _has_generic_inline_delegation(binary, argv):
        reasons.append("inline-program-delegation")

    recoverable_package_context = reasons == ["untrusted-execution-context"] and (
        binary in _INSTALL_SUBCOMMANDS or binary == "corepack"
    )
    if binary == "corepack" and (not reasons or recoverable_package_context):
        delegated, corepack_operation, corepack_reason = _corepack_argv(argv)
        if corepack_reason:
            reasons.append(corepack_reason)
        elif delegated is not None:
            package_frontend = binary
            argv = delegated
            binary = argv[0]

    trusted_plain_executable = False
    if not reasons and binary in _PLAIN_EXECUTABLES:
        # The bare name is trusted only when ambient resolution provably
        # reaches the system implementation: an exported function or a
        # PATH-shadowing executable named `ls` runs arbitrary code while the
        # argv this classifier sees still reads `ls`, so a name-only
        # allowlist would mint a decidable allow for the replacement.
        ambient_reason = _ambient_resolution_reason(binary, resolved_environ)
        if ambient_reason:
            reasons.append(ambient_reason)
        else:
            trusted_plain_executable = True
    if (
        not reasons
        and not interpreter_family
        and binary not in _GRAMMAR_BINARIES
        and binary not in _PACKAGE_RUNNERS
        and binary != "corepack"
        and not trusted_plain_executable
    ):
        reasons.append("unknown-execution-grammar")

    if reasons:
        subcommand, sub_reason = "", ""
    elif binary == "git":
        subcommand, sub_reason = _git_subcommand(argv)
    else:
        subcommand, sub_reason = _subcommand(binary, argv)
    if sub_reason:
        reasons.append(sub_reason)
    elif binary == "git" and subcommand in _GIT_READ_ONLY:
        if _git_option_present(argv, _GIT_OUTPUT_REDIRECT_OPTIONS):
            reasons.append("git-output-redirection")
        elif _git_option_present(argv, _GIT_HELPER_ENABLE_OPTIONS):
            reasons.append("git-helper-option")
        else:
            reasons.append("git-read-only-external-context")
    argv_prefix = (binary, subcommand) if subcommand else (binary,)
    flags = frozenset(t for t in argv[1:] if t.startswith("-"))

    base_facts: dict[str, Any] = {
        "operator_present": operator_present,
        "invoked_by_absolute_path": invoked_by_absolute_path,
        "trusted_invocation_context": not untrusted_invocation_context,
        "wrapped": bool(wrappers),
    }
    if interpreter:
        base_facts["interpreter"] = interpreter
    elif interpreter_family:
        base_facts["interpreter_family"] = interpreter_family
    if package_frontend:
        base_facts["package_frontend"] = package_frontend
    if unsupported_wrapper_options:
        base_facts["wrapper_options_supported"] = False

    if (
        reasons in (["option-value-ambiguity"], ["untrusted-execution-context"])
        and binary in _INSTALL_SUBCOMMANDS
    ):
        # Two shapes hide HOW the manager runs, but not WHICH manager runs. A
        # value-taking option this module does not model — `npm --prefix <dir>
        # install <pkg>` — hides the subcommand. An explicit executable path
        # or a peeled optionless wrapper — `/usr/bin/npm install <pkg>`,
        # `env npm install <pkg>` — makes the execution context untrusted. In
        # both, the manager identity was successfully recovered and no
        # operator, substitution, or delegation reason accompanies it, so this
        # is a single invocation of that manager. Returning the generic
        # undecidable shell event here would drop the contract facts and let
        # the option or the spelling downgrade the canonical-manager DENY into
        # the undecidable-shell ask. The event stays on the package surface
        # instead, undecidable, with the contract facts intact:
        # deny-non-canonical-package-manager still matches, and a canonical
        # manager falls to the dependency tier's escalation — the fail-closed
        # floor is never an allow.
        canonical = canonical_package_manager.strip()
        in_contract = bool(canonical) and binary in _JS_MANAGERS and canonical in _JS_MANAGERS
        return ExecutionEvent(
            action=ACTION_PACKAGE_INVOKE,
            binary=binary,
            argv_prefix=argv_prefix,
            tier_hint=TIER_DEPENDENCY,
            decidable=False,
            undecidable_reasons=tuple(reasons),
            facts={
                **base_facts,
                "manager": binary,
                "subcommand": subcommand,
                "canonical_manager": canonical if in_contract else "",
                "manager_is_canonical": (binary == canonical) if in_contract else True,
                "manager_contract_applies": in_contract,
                "scripts_disabled": _lifecycle_scripts_disabled(binary, flags),
            },
            command_sha256=digest,
        )

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
            command_sha256=digest,
        )

    if binary == "corepack" and corepack_operation:
        # Corepack's own operations are dependency-surface work: `use`
        # retrieves a manager release, rewrites package.json, and performs an
        # install; `install`/`up` fetch and activate releases; the shim
        # operations mutate which manager the PATH resolves to. None of them
        # may fall through to an unclassified allow.
        spec = ""
        if corepack_operation == "use":
            for token in argv[2:]:
                if token.startswith("-"):
                    # An unmodeled option may consume the following token, so
                    # the manager spec cannot be trusted out of position.
                    return ExecutionEvent(
                        action=ACTION_SHELL_EXEC,
                        binary=binary,
                        argv_prefix=(binary, corepack_operation),
                        tier_hint=TIER_UNCLASSIFIED,
                        decidable=False,
                        undecidable_reasons=("corepack-option-ambiguity",),
                        facts={**base_facts, "subcommand": corepack_operation},
                        command_sha256=digest,
                    )
                spec = token.split("@", 1)[0]
                break
        manager = spec or binary
        canonical = canonical_package_manager.strip()
        in_contract = bool(canonical) and manager in _JS_MANAGERS and canonical in _JS_MANAGERS
        return ExecutionEvent(
            action=ACTION_PACKAGE_INSTALL
            if corepack_operation in _COREPACK_INSTALL_SUBCOMMANDS
            else ACTION_PACKAGE_INVOKE,
            binary=binary,
            argv_prefix=(binary, corepack_operation),
            tier_hint=TIER_DEPENDENCY,
            decidable=True,
            facts={
                **base_facts,
                "manager": manager,
                "subcommand": corepack_operation,
                "canonical_manager": canonical if in_contract else "",
                "manager_is_canonical": (manager == canonical) if in_contract else True,
                "manager_contract_applies": in_contract,
                # Corepack has no script-disable grammar: `use` runs the
                # manager's own install with lifecycle scripts enabled, and
                # `install`/`up` fetch and activate manager releases.
                "scripts_disabled": False,
            },
            command_sha256=digest,
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
            command_sha256=digest,
        )

    artifact_subs = _ARTIFACT_SUBCOMMANDS.get(binary, frozenset())
    if subcommand and subcommand in artifact_subs:
        return ExecutionEvent(
            action=ACTION_ARTIFACT_GENERATE,
            binary=binary,
            argv_prefix=argv_prefix,
            tier_hint=TIER_CONTROL_SURFACE,
            decidable=True,
            facts={**base_facts, "builder": binary, "subcommand": subcommand},
            command_sha256=digest,
        )

    if binary == "gh" and subcommand in _GH_REMOTE_GROUPS:
        if subcommand == "api":
            # An arbitrary authenticated REST call: the method and path decide
            # the effect, not the argv prefix. Fail closed.
            return ExecutionEvent(
                action=ACTION_SHELL_EXEC,
                binary=binary,
                argv_prefix=argv_prefix,
                tier_hint=TIER_UNCLASSIFIED,
                decidable=False,
                undecidable_reasons=("gh-api-passthrough",),
                facts={**base_facts, "subcommand": subcommand},
                command_sha256=digest,
            )
        operation, op_reason = _gh_operation(argv, subcommand)
        if operation and operation in _GH_REMOTE_MUTATING[subcommand]:
            # `gh pr merge` moves the remote base branch exactly as `git push`
            # would; it gets the same control-surface escalation, not a
            # deferral to host permissions that explicitly allow the prefix.
            return ExecutionEvent(
                action=ACTION_GIT_MUTATE,
                binary=binary,
                argv_prefix=(binary, subcommand, operation),
                tier_hint=TIER_CONTROL_SURFACE,
                decidable=True,
                facts={
                    **base_facts,
                    "subcommand": subcommand,
                    "operation": operation,
                    "remote_mutation": True,
                    "git_control_surface": True,
                },
                command_sha256=digest,
            )
        if operation and operation in _GH_REMOTE_READ_ONLY.get(subcommand, frozenset()):
            helper_reason = _gh_external_helper_reason(argv, subcommand, operation)
            if not helper_reason and _gh_pager_external_context(resolved_environ):
                # A modeled read (`gh pr view`) still pipes stdout through the
                # configured pager, so an inherited GH_PAGER/PAGER is a program
                # gh launches; fail closed rather than mint a read-only allow.
                helper_reason = "gh-pager-external-context"
            if helper_reason:
                return ExecutionEvent(
                    action=ACTION_SHELL_EXEC,
                    binary=binary,
                    argv_prefix=(binary, subcommand, operation),
                    tier_hint=TIER_UNCLASSIFIED,
                    decidable=False,
                    undecidable_reasons=(helper_reason,),
                    facts={**base_facts, "subcommand": subcommand, "operation": operation},
                    command_sha256=digest,
                )
            return ExecutionEvent(
                action=ACTION_SHELL_EXEC,
                binary=binary,
                argv_prefix=(binary, subcommand, operation),
                tier_hint=TIER_READ_ONLY,
                decidable=True,
                facts={**base_facts, "subcommand": subcommand, "operation": operation},
                command_sha256=digest,
            )
        # An operation in neither table may be anything — including a future
        # mutating verb — so it is not presumed harmless.
        return ExecutionEvent(
            action=ACTION_SHELL_EXEC,
            binary=binary,
            argv_prefix=argv_prefix,
            tier_hint=TIER_UNCLASSIFIED,
            decidable=False,
            undecidable_reasons=(op_reason or "undeclared-gh-operation",),
            facts={**base_facts, "subcommand": subcommand},
            command_sha256=digest,
        )

    if binary == "gh":
        # Reached only for a top-level group outside `release` (handled by the
        # publish table above) and the declared remote groups. These are not
        # presumed harmless: `gh extension install` downloads and installs
        # executable code (release artifacts or cloned scripts), `gh workflow
        # run` / `gh run rerun` trigger remote CI with repository credentials,
        # `gh secret set` mutates remote secrets, and future groups may do
        # anything. An authenticated CLI group this table does not model must
        # not fall through to the unclassified allow tier.
        return ExecutionEvent(
            action=ACTION_SHELL_EXEC,
            binary=binary,
            argv_prefix=argv_prefix,
            tier_hint=TIER_UNCLASSIFIED,
            decidable=False,
            undecidable_reasons=("unmodeled-gh-group",),
            facts={**base_facts, "subcommand": subcommand},
            command_sha256=digest,
        )

    if binary == "git":
        mutating = subcommand in _GIT_MUTATING
        if subcommand and not mutating and subcommand not in _GIT_READ_ONLY:
            # Not a subcommand this table declares. It may be a user-defined
            # alias — potentially defined by config outside this command line —
            # so its effect is not recoverable structurally. Fail closed rather
            # than presume read-only.
            return ExecutionEvent(
                action=ACTION_SHELL_EXEC,
                binary=binary,
                argv_prefix=argv_prefix,
                tier_hint=TIER_UNCLASSIFIED,
                decidable=False,
                undecidable_reasons=("unknown-git-subcommand",),
                facts={**base_facts, "subcommand": subcommand},
                command_sha256=digest,
            )
        if not mutating and _git_option_present(argv, _GIT_OUTPUT_REDIRECT_OPTIONS):
            # `git log --output=<file>` writes the file git would otherwise
            # print to stdout, so the "read-only" claim the tier assignment
            # rests on is false and the destination path is not governed
            # here. Fail closed rather than mint an allow receipt for a
            # file write dressed as an inspection command.
            return ExecutionEvent(
                action=ACTION_SHELL_EXEC,
                binary=binary,
                argv_prefix=argv_prefix,
                tier_hint=TIER_UNCLASSIFIED,
                decidable=False,
                undecidable_reasons=("git-output-redirection",),
                facts={**base_facts, "subcommand": subcommand},
                command_sha256=digest,
            )
        if not mutating and _git_option_present(argv, _GIT_HELPER_ENABLE_OPTIONS):
            # `git log --ext-diff` runs the configured external diff command
            # and `--textconv` runs configured textconv filters: the helper
            # is arbitrary code declared by configuration this classifier
            # never reads, so the read-only claim is false. Fail closed
            # rather than mint an allow receipt for helper execution dressed
            # as an inspection command.
            return ExecutionEvent(
                action=ACTION_SHELL_EXEC,
                binary=binary,
                argv_prefix=argv_prefix,
                tier_hint=TIER_UNCLASSIFIED,
                decidable=False,
                undecidable_reasons=("git-helper-option",),
                facts={**base_facts, "subcommand": subcommand},
                command_sha256=digest,
            )
        if mutating:
            # A mutation's argv prefix identifies the governed surface but not
            # every process Git may execute. Repository and ambient config can
            # supply hooks, filters, signing programs, fsmonitor, credential
            # and remote helpers, or maintenance commands. This adapter does
            # not execute Git with sanitized config and hooks disabled, so the
            # mutation remains attributed as env.git.mutate while failing
            # closed before an allow receipt can be minted.
            return ExecutionEvent(
                action=ACTION_GIT_MUTATE,
                binary=binary,
                argv_prefix=argv_prefix,
                tier_hint=TIER_SOURCE,
                decidable=False,
                undecidable_reasons=("git-mutation-external-context",),
                facts={
                    **base_facts,
                    "subcommand": subcommand,
                    "git_control_surface": subcommand in _GIT_CONTROL_SURFACE,
                },
                command_sha256=digest,
            )
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
            command_sha256=digest,
        )

    runner_ecosystem = _PACKAGE_RUNNERS.get(binary)
    if runner_ecosystem is not None:
        canonical = canonical_package_manager.strip()
        in_contract = (
            bool(canonical) and runner_ecosystem in _JS_MANAGERS and canonical in _JS_MANAGERS
        )
        return ExecutionEvent(
            action=ACTION_PACKAGE_INVOKE,
            binary=binary,
            argv_prefix=argv_prefix,
            tier_hint=TIER_DEPENDENCY,
            decidable=True,
            facts={
                **base_facts,
                "manager": runner_ecosystem,
                "runner": binary,
                "subcommand": subcommand,
                "canonical_manager": canonical if in_contract else "",
                "manager_is_canonical": (runner_ecosystem == canonical) if in_contract else True,
                "manager_contract_applies": in_contract,
                "scripts_disabled": _lifecycle_scripts_disabled(runner_ecosystem, flags),
            },
            command_sha256=digest,
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
            "scripts_disabled": _lifecycle_scripts_disabled(binary, flags),
        }
        return ExecutionEvent(
            action=ACTION_PACKAGE_INSTALL if installing else ACTION_PACKAGE_INVOKE,
            binary=binary,
            argv_prefix=argv_prefix,
            tier_hint=TIER_DEPENDENCY,
            decidable=True,
            facts=facts,
            command_sha256=digest,
        )

    return ExecutionEvent(
        action=ACTION_SHELL_EXEC,
        binary=binary,
        argv_prefix=argv_prefix,
        tier_hint=TIER_UNCLASSIFIED,
        decidable=True,
        facts={**base_facts, "subcommand": subcommand},
        command_sha256=digest,
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
                "Recorded and attributed, NOT risk-classified. A decidable command "
                "naming no governed surface lands here. An UNDECIDABLE command — "
                "operator, substitution, unparseable syntax — does not inherit this "
                "allow: the escalate-undecidable-shell rule runs first and fails "
                "closed to a human."
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
            "tools": [
                ACTION_PACKAGE_INVOKE,
                ACTION_PACKAGE_INSTALL,
                ACTION_PACKAGE_LIFECYCLE_ENABLE,
            ],
            "state_equals": {"manager_contract_applies": True, "manager_is_canonical": False},
            "reason": (
                "repository declares a canonical packageManager; a different manager "
                "splits dependency resolution and is denied before any fetch"
            ),
        },
        {
            "id": "deny-trust-root-path-mutation",
            "effect": "deny",
            "tools": [
                "runtime.Edit",
                "runtime.MultiEdit",
                "runtime.NotebookEdit",
                "runtime.Write",
            ],
            "state_equals": {"governance_path_tier": TIER_TRUST_ROOT},
            "reason": (
                "path holds the gate mode or audit evidence this layer is judged by; "
                "a governed call may not rewrite its own trust root"
            ),
        },
        {
            "id": "escalate-undecidable-shell",
            "effect": "escalate",
            "tools": [ACTION_SHELL_EXEC],
            "state_equals": {"execution_decidable": False},
            "reason": (
                "command effect is not recoverable from the argv prefix (operator, "
                "substitution, or unparseable syntax); an undecidable command must "
                "not inherit the unclassified allow tier"
            ),
        },
        {
            "id": "escalate-control-surface-path-mutation",
            "effect": "escalate",
            "tools": [
                "runtime.Edit",
                "runtime.MultiEdit",
                "runtime.NotebookEdit",
                "runtime.Write",
            ],
            "state_equals": {"governance_path_tier": TIER_CONTROL_SURFACE},
            "reason": (
                "path holds runtime hook code or permission configuration; mutation "
                "requires human approval, not a source-tier allow"
            ),
        },
        {
            "id": "escalate-dependency-manifest-path-mutation",
            "effect": "escalate",
            "tools": [
                "runtime.Edit",
                "runtime.MultiEdit",
                "runtime.NotebookEdit",
                "runtime.Write",
            ],
            "state_equals": {"governance_path_tier": TIER_DEPENDENCY},
            "reason": (
                "path declares or locks the dependency graph; a manifest or "
                "lockfile edit admits dependencies and install scripts a later "
                "install will fetch and execute, so it requires the same human "
                "approval as a package-manager mutation"
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
            "id": "escalate-undecidable-git-mutation",
            "effect": "escalate",
            "tools": [ACTION_GIT_MUTATE],
            "state_equals": {"execution_decidable": False},
            "reason": (
                "Git may execute repository or ambient hooks and helpers that are not "
                "recoverable from the argv prefix; an undecidable mutation requires "
                "human approval"
            ),
        },
        {
            "id": "escalate-git-control-surface",
            "effect": "escalate",
            "tools": [ACTION_GIT_MUTATE],
            "state_equals": {"git_control_surface": True},
            "reason": (
                "subcommand moves or rewrites published history (git push/reset "
                "family, or a gh remote mutation such as pr merge)"
            ),
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
    receipt_ttl_seconds: float | None = None,
) -> Any:
    """A :class:`~gove_zone.gateway.UniversalGateway` for this boundary.

    ``audit_path`` defaults to :func:`gove_zone.integration.resolve_audit_path`
    — the chain the passive hook auditor already writes. This is deliberate and
    load-bearing: ``UniversalGateway`` otherwise defaults to a *different* file
    (``.gove-zone/gateway-audit.jsonl``), and taking that default during cutover
    would fork the audit chain in two, leaving the pre-cutover history in one
    file and everything after it in another.

    ``receipt_ttl_seconds`` is forwarded to ``UniversalGateway`` so minted
    receipts carry a hash-bound ``expires_at``. A profile that requires expiry
    (``GovernanceProfile.production_strict``) makes ``UniversalGateway`` fail
    closed at construction when no TTL is configured; without this argument
    the hardened posture would be unreachable through this public builder.
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
        receipt_ttl_seconds=receipt_ttl_seconds,
    )


# -- hook surface ------------------------------------------------------------ #

#: Path segments whose files decide whether this gate enforces at all (the
#: ``.gove-zone`` gate-mode file) or constitute its evidence (audit chain,
#: ledger). A governed call may never rewrite the trust root it is judged by.
_TRUST_ROOT_PATH_SEGMENTS = frozenset({".gove-zone"})

#: Path segments carrying runtime hook code and permission configuration —
#: the checkout-resident control surface of this gate.
_CONTROL_SURFACE_PATH_SEGMENTS = frozenset({".claude", ".codex"})

#: Adjacent segment pairs marking control-surface directories that a single
#: segment cannot identify. ``.github/workflows`` files define CI jobs that
#: later run with repository credentials, so replacing CI logic is a
#: control-surface mutation, not an ordinary source edit — while the rest of
#: ``.github`` (issue templates, CODEOWNERS-adjacent docs) stays on the source
#: tier.
_CONTROL_SURFACE_PATH_SEGMENT_PAIRS: frozenset[tuple[str, str]] = frozenset(
    {(".github", "workflows")}
)

#: Final path segments that declare or lock the dependency graph, per manager
#: ecosystem this classifier already governs. An ``Edit``/``Write`` to one of
#: these admits a dependency (and its install scripts) into tracked state
#: directly — the same M3 dependency-graph change a package-manager mutation
#: performs (docs/governance/developer-tool-mutation-governance.md), so it
#: must not inherit the ordinary source-tier allow. Stored casefolded; matched
#: against the casefolded final segment.
_DEPENDENCY_MANIFEST_FILENAMES = frozenset(
    {
        # Node: npm / pnpm / yarn / bun.
        "package.json",
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
        # Python: pip / uv / poetry / pipenv.
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "pipfile",
        "pipfile.lock",
        # Rust.
        "cargo.toml",
        "cargo.lock",
        # Ruby.
        "gemfile",
        "gemfile.lock",
        "gems.rb",
        "gems.locked",
        # PHP.
        "composer.json",
        "composer.lock",
        # Go.
        "go.mod",
        "go.sum",
    }
)

#: pip requirements manifests: ``requirements.txt`` plus the common split
#: spellings (``requirements-dev.txt``, ``requirements_test.in``). Matched on
#: the casefolded final segment.
_REQUIREMENTS_FILENAME_RE = re.compile(r"^requirements[a-z0-9._-]*\.(?:txt|in)$")

#: Host-runtime file-mutation surfaces the governance-path rules apply to.
_FILE_MUTATION_TOOLS = frozenset(
    {"runtime.Edit", "runtime.MultiEdit", "runtime.NotebookEdit", "runtime.Write"}
)

#: Target keys a file-mutation payload may carry, in the same precedence order
#: as :func:`gove_zone.integration.tool_call_from_hook_payload` uses to build
#: ``ToolCall.path`` — the evidence-target check must judge the same target the
#: segment rules judge.
_FILE_MUTATION_TARGET_KEYS = ("file_path", "path", "notebook_path")


def _casefolded_path_spellings(path: Path) -> tuple[str, ...]:
    """Comparable spellings of a filesystem path: absolute and symlink-resolved.

    Both are kept: :func:`os.path.abspath` normalizes ``.``/``..`` and anchors a
    relative spelling to the working directory without touching symlinks, while
    :meth:`~pathlib.Path.resolve` also follows symlinks — and a write may name
    the evidence file through either spelling. Casefolded for the same reason as
    :func:`_governance_path_tier`: on a case-insensitive filesystem a respelled
    path resolves to the protected file, and the over-approximation on a
    case-sensitive one is a deny, never a false allow.
    """
    expanded = path.expanduser()
    spellings = {Path(os.path.abspath(expanded)).as_posix().casefold()}
    # An unresolvable spelling (symlink loop, permission error) still leaves
    # the abspath form above to compare against.
    with contextlib.suppress(OSError, RuntimeError):
        spellings.add(expanded.resolve().as_posix().casefold())
    return tuple(spellings)


def _path_identity_token(path: Path) -> str:
    """A device/inode identity token for an existing file, or ``""``.

    ``Path.resolve()`` normalizes spellings and follows symlinks but cannot
    see hard links: a hard-linked alias of a protected file resolves to the
    alias pathname while naming the same inode, so a spelling comparison
    misses it. Device and inode identify the file itself. The token starts
    with no ``/`` so it can never collide with an absolute path spelling. A
    zero inode (some Windows filesystems) identifies nothing and yields no
    token rather than a token every such file would share.
    """
    with contextlib.suppress(OSError, RuntimeError, ValueError):
        stat = os.stat(path.expanduser())
        if stat.st_ino:
            return f"identity:{stat.st_dev}:{stat.st_ino}"
    return ""


def _protected_trust_root_targets(
    audit_path: str | Path | None, ledger_path: str | Path | None
) -> frozenset[str]:
    """Casefolded spellings of the gate-mode, audit-chain, and ledger files.

    :func:`_governance_path_tier` protects the default ``.gove-zone`` directory
    by segment name, but ``GOVE_ZONE_AUDIT_PATH`` — or the public ``audit_path``
    / ``ledger_path`` arguments — may place the evidence anywhere. A ``Write``
    naming that exact configured file previously evaluated as an ordinary
    source-tier allow, so the host write could truncate the chain right after
    the decision was appended to it. Defaults mirror
    :func:`build_execution_gateway` exactly, so the files the gateway writes
    are the files this protects.

    The gate-mode file (:func:`gove_zone.integration.resolve_gate_mode_path`)
    is protected by the same exact-target rule: its spellings include the
    symlink-resolved form, so when ``.gove-zone`` is itself a symlink the
    write that reaches the real file through the resolved location (a
    spelling carrying no protected segment) still lands on the trust-root
    tier.

    Existing protected files also contribute a device/inode identity token
    (:func:`_path_identity_token`): a hard link to the audit chain resolves
    to the alias pathname, so only file identity ties the alias back to the
    protected inode.
    """
    from gove_zone.integration import resolve_audit_path, resolve_gate_mode_path

    resolved_audit = Path(audit_path) if audit_path is not None else resolve_audit_path()
    resolved_ledger = (
        Path(ledger_path) if ledger_path is not None else resolved_audit.parent / "ledger.jsonl"
    )
    targets: set[str] = set()
    for protected in (resolve_gate_mode_path(), resolved_audit, resolved_ledger):
        targets.update(_casefolded_path_spellings(protected))
        identity = _path_identity_token(protected)
        if identity:
            targets.add(identity)
    return frozenset(targets)


def _mutation_target(child: Mapping[str, Any]) -> str | None:
    """The raw file-mutation target a hook payload names, or ``None``."""
    try:
        _name, tool_input = tool_name_and_input(dict(child))
    except Exception:  # noqa: BLE001 - an unreadable payload has no readable target
        return None
    for key in _FILE_MUTATION_TARGET_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _mutation_targets_trust_root(target: str, trust_root_targets: frozenset[str]) -> bool:
    """True when a file-mutation target names a protected trust-root file.

    Compared by spelling and, for existing targets, by file identity: a hard
    link to a protected file keeps its own pathname under ``resolve()`` while
    a write through it truncates the protected inode, so the alias is caught
    only by the device/inode comparison.
    """
    if not trust_root_targets:
        return False
    if any(spelling in trust_root_targets for spelling in _casefolded_path_spellings(Path(target))):
        return True
    identity = _path_identity_token(Path(target))
    return bool(identity) and identity in trust_root_targets


def _governance_path_tier(path: Sequence[str]) -> str:
    """The governance tier a file path belongs to, or ``""`` for ordinary paths.

    Segment-based on purpose: the hook may deliver the path absolute, relative,
    or ``~``-anchored, and a prefix rule would miss all but one spelling. A
    ``.gove-zone`` or ``.claude`` segment anywhere in the normalized path marks
    the target as governance configuration or evidence, never an ordinary
    source edit. An adjacent ``.github/workflows`` pair marks CI definitions —
    code that later runs with repository credentials — as the same
    control surface. A final segment naming a dependency manifest or lockfile
    is a dependency-graph mutation, not an ordinary source edit.

    Segments are compared casefolded: on a case-insensitive filesystem
    (macOS and Windows defaults) ``.GOVE-ZONE/gate.mode`` resolves to the
    protected ``.gove-zone/gate.mode``, so an exact comparison would let a
    respelled path switch the gate into observe mode. On a case-sensitive
    filesystem this over-approximates — a genuinely distinct ``.GOVE-ZONE``
    directory is still tiered — which is a deny/escalation, never a false
    allow.
    """
    normalized = tuple(segment.casefold() for segment in path)
    for segment in normalized:
        if segment in _TRUST_ROOT_PATH_SEGMENTS:
            return TIER_TRUST_ROOT
    for segment in normalized:
        if segment in _CONTROL_SURFACE_PATH_SEGMENTS:
            return TIER_CONTROL_SURFACE
    for pair in zip(normalized, normalized[1:], strict=False):
        if pair in _CONTROL_SURFACE_PATH_SEGMENT_PAIRS:
            return TIER_CONTROL_SURFACE
    if normalized:
        final = normalized[-1]
        if final in _DEPENDENCY_MANIFEST_FILENAMES or _REQUIREMENTS_FILENAME_RE.fullmatch(final):
            return TIER_DEPENDENCY
    return ""


#: Governance path tiers ordered strictest-first. A mutation is judged by the
#: strictest tier any spelling of its target reaches, literal or
#: symlink-resolved, so an alias cannot select a weaker tier.
_GOVERNANCE_PATH_TIERS_STRICTEST_FIRST = (
    TIER_TRUST_ROOT,
    TIER_CONTROL_SURFACE,
    TIER_DEPENDENCY,
)


def _strictest_governance_tier(*tiers: str) -> str:
    for tier in _GOVERNANCE_PATH_TIERS_STRICTEST_FIRST:
        if tier in tiers:
            return tier
    return ""


def _resolved_governance_path_tier(target: str) -> str:
    """Governance tier of a mutation target after symlink resolution.

    :func:`_governance_path_tier` judges the segments the payload spelled, but
    the host write follows directory symlinks: with ``mode-link ->
    .gove-zone`` in the checkout, a ``Write`` to ``mode-link/gate.mode``
    carries no protected segment yet replaces the real gate-mode file.
    :meth:`~pathlib.Path.resolve` anchors a relative spelling to the working
    directory (as the host tool does), normalizes ``..``, and follows
    symlinks, so the segments judged here are the segments of the file
    actually written. An unresolvable spelling (symlink loop, permission
    error) contributes no tier; the literal-segment tier still applies.
    """
    with contextlib.suppress(OSError, RuntimeError):
        return _governance_path_tier(Path(target).expanduser().resolve().parts)
    return ""


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
    audit_path: str | Path | None = None,
    ledger_path: str | Path | None = None,
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
    here is hashed into the receipt, so it must not carry secrets. It merges at
    the **lowest** precedence: caller metadata carrying a reserved key such as
    ``execution_decidable`` must not be able to replace classifier facts,
    normalizer state, or governance path tiers — a context that could disable
    the fail-closed rules would be a policy bypass one dict key wide.

    An install that would run lifecycle scripts additionally emits the
    :data:`ACTION_PACKAGE_LIFECYCLE_ENABLE` call *before* the install call:
    ADR-0010 D2 declares script enablement a separately recorded, escalated
    decision taken before the manager runs. It records that decision; it does
    not gate the scripts (see the module docstring).

    ``audit_path`` / ``ledger_path`` name the evidence files this boundary
    writes, defaulting exactly as :func:`build_execution_gateway` defaults them
    (``GOVE_ZONE_AUDIT_PATH`` via
    :func:`gove_zone.integration.resolve_audit_path`, ledger beside the audit
    chain). A file mutation whose target resolves to either configured file
    carries the trust-root path tier even when the file lives outside a
    ``.gove-zone`` directory: the chain that records a decision must not be
    rewritable by the call it judged.

    File-mutation targets are tiered by their symlink-resolved segments as
    well as their literal ones (strictest tier wins), and the resolved
    gate-mode file is protected by exact target alongside the evidence files:
    a directory symlink such as ``mode-link -> .gove-zone`` must not let a
    write reach the real gate-mode file under a source-tier allow.
    """
    context = {str(k): v for k, v in dict(run_context or {}).items()}
    trust_root_targets: frozenset[str] | None = None
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
                            **context,
                            "action_kind": action_kind,
                            "summary": {
                                "batch_shape": "single.Bash",
                                "reason": "missing, non-string, or unreadable command",
                                "item_count": 1,
                                "parseable_count": 0,
                                "unparseable_count": 1,
                            },
                        },
                        goal=call.goal,
                        actor=actor,
                        path=call.path,
                        state={**context, **dict(call.state)},
                    )
                )
                continue
            event = classify_command(
                command,
                canonical_package_manager=canonical_package_manager,
            )
            if event.action == ACTION_PACKAGE_INSTALL and not event.facts.get(
                "scripts_disabled", False
            ):
                # ADR-0010 D2: enabling lifecycle scripts is a separately
                # declared, escalated decision, recorded on its own surface
                # *before* the manager runs. The classification facts and the
                # command digest are identical — same command, second decision.
                enable_event = dataclasses.replace(
                    event,
                    action=ACTION_PACKAGE_LIFECYCLE_ENABLE,
                    tier_hint=TIER_CONTROL_SURFACE,
                )
                calls.append(
                    ToolCall(
                        name=enable_event.action,
                        args={**context, "action_kind": action_kind, **enable_event.to_args()},
                        goal=call.goal,
                        actor=actor,
                        path=call.path,
                        state={**context, **dict(call.state), **enable_event.to_state()},
                    )
                )
            # Classifier facts merge after the caller-supplied context: a
            # run_context key like `execution_decidable` must not be able to
            # replace the classifier's trusted state.
            calls.append(
                ToolCall(
                    name=event.action,
                    args={**context, "action_kind": action_kind, **event.to_args()},
                    goal=call.goal,
                    actor=actor,
                    path=call.path,
                    state={**context, **dict(call.state), **event.to_state()},
                )
            )
            continue

        extra: dict[str, Any] = {}
        if call.name in _FILE_MUTATION_TOOLS:
            target = _mutation_target(child)
            governance_tier = _governance_path_tier(call.path)
            if governance_tier != TIER_TRUST_ROOT and target is not None:
                # The host write follows directory symlinks, so the target is
                # tiered by its resolved segments too and the strictest tier
                # wins: a `mode-link -> .gove-zone` alias must not hide the
                # trust root behind an unprotected literal spelling.
                governance_tier = _strictest_governance_tier(
                    governance_tier, _resolved_governance_path_tier(target)
                )
            if governance_tier != TIER_TRUST_ROOT and target is not None:
                # GOVE_ZONE_AUDIT_PATH (or explicit audit_path/ledger_path
                # arguments) may place the evidence outside any `.gove-zone`
                # directory; a mutation naming that exact configured file, or
                # the resolved gate-mode file, must hit the same trust-root
                # deny as the default chain location.
                if trust_root_targets is None:
                    trust_root_targets = _protected_trust_root_targets(audit_path, ledger_path)
                if _mutation_targets_trust_root(target, trust_root_targets):
                    governance_tier = TIER_TRUST_ROOT
            if governance_tier:
                # Fail-closed path rule input: a Write to the gate-mode file,
                # the hook, or the audit chain must not evaluate as an ordinary
                # RISK_TIER:source edit — see deny-trust-root-path-mutation and
                # escalate-control-surface-path-mutation.
                extra["governance_path_tier"] = governance_tier
        if not context and not extra:
            calls.append(call)
            continue
        calls.append(
            ToolCall(
                name=call.name,
                args={**context, **dict(call.args), **extra},
                goal=call.goal,
                actor=actor,
                path=call.path,
                state={**context, **dict(call.state), **extra},
            )
        )
    return tuple(calls)


def make_execution_call_factory(
    canonical_package_manager: str = "",
    *,
    run_context: Mapping[str, Any] | None = None,
    audit_path: str | Path | None = None,
    ledger_path: str | Path | None = None,
) -> Any:
    """Bind deployment configuration into a ``call_factory`` for the gateway.

    :meth:`~gove_zone.gateway.UniversalGateway.handle_claude_hook` calls its
    factory as ``factory(payload, action_kind=..., actor=...)``. The canonical
    manager, the run context, and the evidence locations are deployment/session
    facts, not per-call data, so they are closed over here rather than read from
    the payload — a payload that could name its own canonical manager would be
    able to exempt itself.

    ``audit_path`` / ``ledger_path`` default exactly as
    :func:`build_execution_gateway` defaults them; a caller that passes explicit
    evidence paths to the gateway must pass the same paths here so mutations of
    those exact files stay on the trust-root tier.
    """
    bound_context = dict(run_context or {})

    def factory(payload: dict[str, Any], *, action_kind: str, actor: str) -> tuple[ToolCall, ...]:
        return execution_tool_calls_from_hook_payload(
            payload,
            action_kind=action_kind,
            actor=actor,
            canonical_package_manager=canonical_package_manager,
            run_context=bound_context,
            audit_path=audit_path,
            ledger_path=ledger_path,
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
    * ``unattributed`` — records carrying a fallback actor, or an ``actor``
      field that is not a nonempty string (missing, ``None``, numeric,
      mapping, or whitespace-only). Stringifying such values would mint a
      spelling like ``"None"`` that no fallback list contains, so a record
      with no real attribution would verify clean; instead any non-string or
      blank actor is treated as unattributed. These are audit records, not
      authorizations.
    * ``unconditional_allow`` — an ``env.*`` decision with no ``matched_rules``
      is not traceable to a policy and is reported. Matched by namespace, not
      by the current action tuple, so an execution surface added or misspelled
      without a tier assignment is still validated.
    * ``legacy_observer_path`` — records whose ``matched_rules`` is an
      ``action_kind:*`` marker. Every one of these came from the retired
      ``_ObserverPolicy``, which returned ``ALLOW`` unconditionally, so the
      marker names the *hook classification*, not a policy rule. This flags the
      whole legacy path (including ``action_kind:edit``), not only the three
      substring-matched orchestration kinds — the count is the pre-cutover
      boundary, and it must never grow after cutover.
    * ``malformed_matched_rules`` — a present ``matched_rules`` that is not a
      list of string rule identifiers. A JSON string like
      ``"RISK_TIER:default"`` is a ``Sequence`` of characters: iterated naively
      it matches no predicate while staying nonempty, silently passing every
      check above. A list with non-string members (``[{}]``, ``[null]``,
      ``[1]``) has the same failure shape once stringified. The invalid shape
      is reported instead of being reinterpreted.

    Returns a report dict; ``ok`` is ``True`` only when every enabled check is
    clean.
    """
    findings: dict[str, list[dict[str, Any]]] = {
        "unassigned_tier": [],
        "unattributed": [],
        "unconditional_allow": [],
        "legacy_observer_path": [],
        "malformed_matched_rules": [],
    }
    fallbacks = frozenset(fallback_actors) | {UNATTRIBUTED_ACTOR}
    checked = 0
    execution_records = 0

    for event in events:
        if not isinstance(event, Mapping):
            continue
        checked += 1
        tool = str(event.get("tool", ""))
        raw_actor = event.get("actor", "")
        # str()-ing a non-string actor would coin spellings like "None" or
        # "0" that no fallback list contains, letting a record with no real
        # attribution verify clean. Only a nonempty (non-blank) string is a
        # valid attribution; anything else is treated as unattributed.
        actor_valid = isinstance(raw_actor, str) and bool(raw_actor.strip())
        actor = raw_actor if isinstance(raw_actor, str) else repr(raw_actor)
        matched = event.get("matched_rules")
        # A str/bytes value IS a Sequence: iterating it yields characters that
        # match no predicate while keeping the list nonempty, so a string like
        # "RISK_TIER:default" would silently pass every check. And a list of
        # non-string members ([{}], [null], [1]) stringifies to entries that
        # match no predicate while keeping the list nonempty, silently passing
        # the unconditional-allow check. Only a list-like whose every member is
        # a string rule identifier is trusted; any other present shape is
        # reported as malformed rather than reinterpreted.
        matched_valid = False
        matched_list: list[str] = []
        if isinstance(matched, Sequence) and not isinstance(matched, (str, bytes, bytearray)):
            candidate: list[str] = []
            for member in matched:
                if not isinstance(member, str):
                    break
                candidate.append(member)
            else:
                matched_valid = True
                matched_list = candidate
        anchor = {
            "event_id": event.get("event_id", ""),
            "tool": tool,
            "actor": actor,
            "decision": event.get("decision", ""),
        }

        if matched is not None and not matched_valid:
            findings["malformed_matched_rules"].append(anchor)
        if any(m.startswith("action_kind:") for m in matched_list):
            findings["legacy_observer_path"].append(anchor)
        if "RISK_TIER:default" in matched_list:
            findings["unassigned_tier"].append(anchor)
        if require_attributed and (not actor_valid or actor in fallbacks):
            findings["unattributed"].append(anchor)
        # Namespace-based on purpose: limiting this to the current
        # EXECUTION_ACTIONS tuple would blind the verifier to exactly the
        # records that most need it — an execution surface added (or misspelled)
        # without a tier assignment. Any `env.*` decision is an execution
        # record.
        if tool.startswith("env."):
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
