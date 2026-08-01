"""Artifact-integrity gate for agent skill files.

Every ``SKILL.md`` under ``.agents/skills/**`` and ``.claude/skills/**`` must carry
parseable ``---``-delimited YAML frontmatter declaring at least a ``name`` and a
``description``.

Why this exists: ``.agents/skills/govern-zone/SKILL.md`` and its mirrored twin under
``.claude/skills/`` both opened with a literal ```` ```markdown ```` fence instead of
frontmatter. Codex logged ``missing YAML frontmatter delimited by ---`` and the skill
silently never loaded, even though its ``agents/openai.yaml`` sets
``allow_implicit_invocation: true``. NVIDIA's SkillSpector surfaced the same file as
``Skill: unknown``. Nothing in CI noticed, in either copy, for the life of the file.

SCOPE — artifact validation only. This module checks that skill metadata is
*well formed and discoverable*. It deliberately does NOT interpret ``permissions:``
semantics, enforce any runtime behavior, or touch gove-zone policy or executor logic.
A skill passing this gate is parseable, not trusted.

No third-party parser is used on purpose: PyYAML is not a dependency of this workspace,
and adding one to run a syntax check would be a worse trade than the deliberately small
strict reader below. The reader accepts the subset of YAML that skill frontmatter
actually uses and refuses anything else, so an unrecognised construct fails the gate
rather than being silently skipped.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

SKILL_TREES = (".agents/skills", ".claude/skills")

# Frontmatter keys whose type is contractual. Unknown keys are allowed — the format is
# expected to grow (license, metadata, permissions) — but they must still parse.
REQUIRED_STR_FIELDS = ("name", "description")
OPTIONAL_TYPED_FIELDS = {"disable-model-invocation": bool}

# Fail closed if discovery itself breaks: a glob that silently matches nothing would
# make every assertion below vacuously true.
MIN_EXPECTED_SKILLS = 5


class FrontmatterError(ValueError):
    """Raised with an actionable message: what is wrong and where."""


def _split_frontmatter(text: str, path: str) -> str:
    """Return the raw frontmatter block, or raise with a specific reason."""
    if not text.startswith("---\n"):
        first = text.split("\n", 1)[0][:60]
        raise FrontmatterError(
            f"{path}: does not start with a '---' frontmatter fence "
            f"(first line is {first!r}). A leading '```markdown' fence is the known "
            f"failure: agents cannot parse a name and skip the skill entirely."
        )
    rest = text[len("---\n") :]
    end = rest.find("\n---")
    if end == -1:
        raise FrontmatterError(
            f"{path}: frontmatter fence is opened but never closed — no terminating "
            f"'---' line was found."
        )
    # The closing fence must be a line of its own.
    after = rest[end + len("\n---") :]
    if after and not after.startswith(("\n", "\r")):
        raise FrontmatterError(
            f"{path}: the closing '---' is not on a line of its own "
            f"(trailing text {after.splitlines()[0][:40]!r})."
        )
    return rest[:end]


def _parse_scalar(raw: str) -> object:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    if value in ("true", "True"):
        return True
    if value in ("false", "False"):
        return False
    return value


def _parse_frontmatter(block: str, path: str) -> dict[str, object]:
    """Strict reader for the YAML subset skill frontmatter uses.

    Supports ``key: scalar``, block scalars (``|``, ``|-``, ``>``, ``>-``), and nested
    mappings or sequences (recorded as present, not deep-parsed). Anything else raises.
    """
    data: dict[str, object] = {}
    lines = block.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip() or line.lstrip().startswith("#"):
            i += 1
            continue
        if line[:1].isspace():
            raise FrontmatterError(
                f"{path}: line {i + 1} of the frontmatter is indented but does not "
                f"belong to a recognised block: {line[:60]!r}"
            )
        if ":" not in line:
            raise FrontmatterError(
                f"{path}: line {i + 1} of the frontmatter is not a 'key: value' pair: {line[:60]!r}"
            )
        key, _, raw = line.partition(":")
        key = key.strip()
        if not key:
            raise FrontmatterError(f"{path}: line {i + 1} has an empty frontmatter key.")
        if key in data:
            raise FrontmatterError(f"{path}: duplicate frontmatter key {key!r}.")
        marker = raw.strip()
        if marker in ("|", "|-", "|+", ">", ">-", ">+"):
            # Block scalar: consume the indented continuation lines.
            i += 1
            chunk: list[str] = []
            while i < len(lines) and (not lines[i].strip() or lines[i][:1].isspace()):
                chunk.append(lines[i].strip())
                i += 1
            data[key] = " ".join(part for part in chunk if part).strip()
            continue
        if marker == "":
            # Nested mapping or sequence. Consume it; record presence without
            # interpreting it — this gate does not read structured fields.
            i += 1
            seen_child = False
            while i < len(lines) and (not lines[i].strip() or lines[i][:1].isspace()):
                if lines[i].strip():
                    seen_child = True
                i += 1
            if not seen_child:
                raise FrontmatterError(
                    f"{path}: key {key!r} has no value and no indented block beneath it."
                )
            data[key] = {}
            continue
        data[key] = _parse_scalar(raw)
        i += 1
    return data


def _discover() -> list[Path]:
    found: list[Path] = []
    for tree in SKILL_TREES:
        base = ROOT / tree
        if base.is_dir():
            found.extend(sorted(base.rglob("SKILL.md")))
    return found


SKILL_FILES = _discover()


def test_skill_discovery_is_not_vacuous() -> None:
    """A broken glob must fail loudly, not pass every other test by finding nothing."""
    assert len(SKILL_FILES) >= MIN_EXPECTED_SKILLS, (
        f"Expected at least {MIN_EXPECTED_SKILLS} SKILL.md files under "
        f"{list(SKILL_TREES)}, found {len(SKILL_FILES)}. Skill discovery is broken, or "
        f"the trees moved — update SKILL_TREES rather than lowering the floor."
    )


@pytest.mark.parametrize(
    "skill_path",
    SKILL_FILES,
    ids=[str(p.relative_to(ROOT)) for p in SKILL_FILES],
)
def test_skill_frontmatter_is_valid(skill_path: Path) -> None:
    rel = str(skill_path.relative_to(ROOT))
    text = skill_path.read_text(encoding="utf-8")

    block = _split_frontmatter(text, rel)
    data = _parse_frontmatter(block, rel)

    for field in REQUIRED_STR_FIELDS:
        assert field in data, (
            f"{rel}: frontmatter is missing the required field {field!r}. "
            f"Agents key skill discovery on it; without it the skill loads as unknown "
            f"or not at all."
        )
        value = data[field]
        assert isinstance(value, str), (
            f"{rel}: frontmatter field {field!r} must be a string, got {type(value).__name__}."
        )
        assert value.strip(), f"{rel}: frontmatter field {field!r} is empty."

    for field, expected_type in OPTIONAL_TYPED_FIELDS.items():
        if field in data:
            assert isinstance(data[field], expected_type), (
                f"{rel}: frontmatter field {field!r} must be "
                f"{expected_type.__name__}, got {type(data[field]).__name__}."
            )

    directory = skill_path.parent.name
    assert data["name"] == directory, (
        f"{rel}: frontmatter name {data['name']!r} does not match its directory "
        f"{directory!r}. Agents resolve skills by directory; a mismatch makes the skill "
        f"unaddressable under the name it advertises."
    )


# --------------------------------------------------------------------------------
# Negative paths. A gate that has never been observed to fail is not a gate — these
# pin the fail-closed behavior so a later "simplification" of the reader cannot make
# it silently permissive.
# --------------------------------------------------------------------------------

# The exact shape of the defect this module was written for: both govern-zone copies
# opened with a fenced code block instead of frontmatter.
REGRESSION_FENCED = "```markdown\n# govern-zone Development Patterns\n\nbody\n```\n"

MALFORMED_CASES = {
    "leading-code-fence": REGRESSION_FENCED,
    "no-frontmatter-at-all": "# Just a heading\n\nbody\n",
    "unterminated-fence": "---\nname: x\ndescription: y\n\nbody with no closing fence\n",
    "closing-fence-not-alone": "---\nname: x\n--- trailing\nbody\n",
    "bare-line-in-block": "---\nname: x\nthis line has no colon\n---\nbody\n",
    "empty-key": "---\n: value\n---\nbody\n",
    "duplicate-key": "---\nname: x\nname: y\n---\nbody\n",
    "dangling-key": "---\nname: x\nmetadata:\n---\nbody\n",
    "stray-indent": "---\n  name: x\n---\nbody\n",
}


@pytest.mark.parametrize("case", sorted(MALFORMED_CASES), ids=sorted(MALFORMED_CASES))
def test_malformed_frontmatter_is_rejected(case: str) -> None:
    text = MALFORMED_CASES[case]
    with pytest.raises(FrontmatterError):
        _parse_frontmatter(_split_frontmatter(text, f"<{case}>"), f"<{case}>")


def test_regression_message_names_the_fence() -> None:
    """The failure message must tell the author what to fix, not just that it failed."""
    with pytest.raises(FrontmatterError) as excinfo:
        _split_frontmatter(REGRESSION_FENCED, "<regression>")
    message = str(excinfo.value)
    assert "<regression>" in message
    assert "```markdown" in message


def test_well_formed_frontmatter_is_accepted() -> None:
    """Guard against the inverse failure: a reader so strict it rejects valid files."""
    text = (
        "---\n"
        "name: example\n"
        'description: "A quoted description."\n'
        "disable-model-invocation: true\n"
        "metadata:\n"
        "  author: someone\n"
        "folded: >-\n"
        "  first line\n"
        "  second line\n"
        "---\n\nbody\n"
    )
    data = _parse_frontmatter(_split_frontmatter(text, "<ok>"), "<ok>")
    assert data["name"] == "example"
    assert data["description"] == "A quoted description."
    assert data["disable-model-invocation"] is True
    assert data["folded"] == "first line second line"
    assert data["metadata"] == {}
