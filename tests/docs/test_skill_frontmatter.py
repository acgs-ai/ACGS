"""Artifact-integrity gate for agent skill files.

Every ``SKILL.md`` under ``.agents/skills/**`` and ``.claude/skills/**`` must carry
parseable ``---``-delimited YAML frontmatter declaring at least a ``name`` and a
``description``.

Why this exists: ``.agents/skills/govern-zone/SKILL.md`` and its mirrored twin under
``.claude/skills/`` both opened with a literal ```` ```markdown ```` fence instead of
frontmatter. Codex logged ``missing YAML frontmatter delimited by ---`` and the skill
was never loadable at all — so the ``allow_implicit_invocation: true`` in its
``agents/openai.yaml``, which makes it eligible for model-initiated invocation without
the user naming it, could never take effect either. NVIDIA's SkillSpector surfaced the
same file as ``Skill: unknown``. Nothing in CI noticed, in either copy, for the life of
the file.

SCOPE — artifact validation only. This module checks that skill metadata is
*well formed and discoverable*. It deliberately does NOT interpret ``permissions:``
semantics, enforce any runtime behavior, or touch gove-zone policy or executor logic.
A skill passing this gate is parseable, not trusted.

The docs workflow installs ``acgs-lite``, whose core dependencies include PyYAML. Use
its safe loader here so this gate accepts and rejects the same YAML syntax as runtime
consumers. The loader is tightened to reject duplicate keys rather than silently keeping
the last value.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver

ROOT = Path(__file__).resolve().parents[2]

SKILL_TREES = (".agents/skills", ".claude/skills")
GOVERN_ZONE_SKILL_PATHS = (
    Path(".agents/skills/govern-zone/SKILL.md"),
    Path(".claude/skills/govern-zone/SKILL.md"),
)

# Frontmatter keys whose type is contractual. Unknown keys are allowed — the format is
# expected to grow (license, metadata, permissions) — but they must still parse.
REQUIRED_STR_FIELDS = ("name", "description")
OPTIONAL_TYPED_FIELDS = {"disable-model-invocation": bool}

# Fail closed if discovery itself breaks: a glob that silently matches nothing would
# make every assertion below vacuously true.
MIN_EXPECTED_SKILLS = 5


class FrontmatterError(ValueError):
    """Raised with an actionable message: what is wrong and where."""


class UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that fails closed when a mapping repeats a key."""


def _construct_unique_mapping(
    loader: UniqueKeySafeLoader, node: MappingNode, deep: bool = False
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeySafeLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


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


def _parse_frontmatter(block: str, path: str) -> dict[str, object]:
    """Parse a frontmatter mapping with safe, standards-compliant YAML semantics."""
    try:
        data = yaml.load(block, Loader=UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        raise FrontmatterError(f"{path}: invalid YAML frontmatter: {exc}") from exc
    if not isinstance(data, dict):
        raise FrontmatterError(
            f"{path}: frontmatter must be a YAML mapping, got {type(data).__name__}."
        )
    if any(not isinstance(key, str) for key in data):
        raise FrontmatterError(f"{path}: every frontmatter key must be a string.")
    return data


def _assert_schema(data: dict[str, object], path: str, directory: str) -> None:
    """Enforce the skill-discovery fields and their contractual types."""
    for field in REQUIRED_STR_FIELDS:
        assert field in data, (
            f"{path}: frontmatter is missing the required field {field!r}. "
            f"Agents key skill discovery on it; without it the skill loads as unknown "
            f"or not at all."
        )
        value = data[field]
        assert isinstance(value, str), (
            f"{path}: frontmatter field {field!r} must be a string, got {type(value).__name__}."
        )
        assert value.strip(), f"{path}: frontmatter field {field!r} is empty."

    for field, expected_type in OPTIONAL_TYPED_FIELDS.items():
        if field in data:
            assert isinstance(data[field], expected_type), (
                f"{path}: frontmatter field {field!r} must be "
                f"{expected_type.__name__}, got {type(data[field]).__name__}."
            )

    assert data["name"] == directory, (
        f"{path}: frontmatter name {data['name']!r} does not match its directory "
        f"{directory!r}. Agents resolve skills by directory; a mismatch makes the skill "
        f"unaddressable under the name it advertises."
    )


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
    "relative_path",
    GOVERN_ZONE_SKILL_PATHS,
    ids=[str(path) for path in GOVERN_ZONE_SKILL_PATHS],
)
def test_required_govern_zone_skill_exists(relative_path: Path) -> None:
    assert (ROOT / relative_path).is_file(), (
        f"Required govern-zone skill mirror is missing: {relative_path}"
    )


def test_govern_zone_skill_mirrors_are_byte_identical() -> None:
    primary, mirror = (ROOT / path for path in GOVERN_ZONE_SKILL_PATHS)
    assert primary.read_bytes() == mirror.read_bytes(), (
        f"Govern-zone skill mirrors differ: {GOVERN_ZONE_SKILL_PATHS[0]} and "
        f"{GOVERN_ZONE_SKILL_PATHS[1]} must remain byte-identical."
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
    _assert_schema(data, rel, skill_path.parent.name)


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
    # Raised in review of this gate: the first reader kept these as literal strings,
    # so it passed artifacts a real YAML parser rejects — exactly the undiscoverable
    # class the gate claims to prevent.
    "unterminated-quote": '---\nname: x\ndescription: "unterminated\n---\nbody\n',
    "undefined-alias": "---\nname: x\ndescription: y\nmetadata: *missing\n---\nbody\n",
    "tab-indent": "---\nname: x\ndescription: y\nmeta:\n\t- a\n---\nbody\n",
    "colon-space-scalar": "---\nname: x\ndescription: value: broken\n---\nbody\n",
    "invalid-escape": '---\nname: x\ndescription: "bad\\q"\n---\nbody\n',
    "unclosed-flow": "---\nname: x\ndescription: y\nmetadata: [unclosed\n---\nbody\n",
}


@pytest.mark.parametrize("case", sorted(MALFORMED_CASES), ids=sorted(MALFORMED_CASES))
def test_malformed_frontmatter_is_rejected(case: str) -> None:
    text = MALFORMED_CASES[case]
    with pytest.raises(FrontmatterError):
        _parse_frontmatter(_split_frontmatter(text, f"<{case}>"), f"<{case}>")


@pytest.mark.parametrize(
    ("case", "text"),
    [
        ("null-description", "---\nname: x\ndescription: null\n---\nbody\n"),
        ("tilde-name", "---\nname: ~\ndescription: y\n---\nbody\n"),
    ],
)
def test_required_string_fields_reject_yaml_null(case: str, text: str) -> None:
    path = f"<{case}>"
    data = _parse_frontmatter(_split_frontmatter(text, path), path)
    with pytest.raises(AssertionError, match="must be a string"):
        _assert_schema(data, path, "x")


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
    assert data["metadata"] == {"author": "someone"}
