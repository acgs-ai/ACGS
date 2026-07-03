"""YAML-backed declarative policy loader.

Extends the RuleSetPolicy implementation to allow policy definition in standard,
easy-to-read YAML syntax.

PyYAML is an *optional* dependency: importing this module (and the top-level
``gove_zone`` package) never requires it. It is imported lazily, only when a
YAML method is actually called, so the core runtime stays dependency-free.
Install it with the ``yaml`` extra: ``pip install 'gove-zone[yaml]'``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from gove_zone.policy import RuleSetPolicy


def _require_yaml() -> Any:
    """Return the PyYAML module, or raise a clear, actionable error if absent."""
    try:
        import yaml  # type: ignore[import-untyped]
    except ModuleNotFoundError as exc:  # pragma: no cover - trivial import guard
        raise ModuleNotFoundError(
            "YAMLPolicy requires PyYAML, which is not installed. Install the "
            "optional 'yaml' extra: pip install 'gove-zone[yaml]'"
        ) from exc
    return yaml


class YAMLPolicy(RuleSetPolicy):
    """YAML-backed declarative policy bundle.

    Loads rules from a YAML file/string that defines an agent boundary schema.
    """

    @classmethod
    def from_yaml(cls, text: str) -> YAMLPolicy:
        """Parse a YAML string into a YAMLPolicy instance."""
        yaml = _require_yaml()
        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML content: {exc}") from exc

        if not isinstance(raw, dict):
            raise ValueError("YAMLPolicy must define a dictionary/object at the root level")

        # Let RuleSetPolicy's dictionary parsing handle the rest
        # (uses Python's class polymorphism to return a YAMLPolicy instance).
        return cast(YAMLPolicy, cls.from_dict(raw))

    @classmethod
    def load_yaml(cls, path: str | Path) -> YAMLPolicy:
        """Load and parse a YAML policy file from disk."""
        text = Path(path).read_text(encoding="utf-8")
        return cls.from_yaml(text)

    def to_yaml(self) -> str:
        """Dump the policy ruleset back to a YAML formatted string."""
        yaml = _require_yaml()
        return cast(
            str,
            yaml.dump(self.to_dict(), sort_keys=True, indent=2, allow_unicode=True),
        )

    def dump_yaml(self, path: str | Path) -> None:
        """Serialize and save the policy to a YAML file on disk."""
        Path(path).write_text(self.to_yaml(), encoding="utf-8")
