"""YAML-backed declarative policy loader.

Extends the RuleSetPolicy implementation to allow policy definition in standard,
easy-to-read YAML syntax.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import yaml  # type: ignore[import-untyped]

from gove_zone.policy import RuleSetPolicy


class YAMLPolicy(RuleSetPolicy):
    """YAML-backed declarative policy bundle.

    Loads rules from a YAML file/string that defines an agent boundary schema.
    """

    @classmethod
    def from_yaml(cls, text: str) -> YAMLPolicy:
        """Parse a YAML string into a YAMLPolicy instance."""
        try:
            raw = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"Invalid YAML content: {exc}") from exc

        if not isinstance(raw, dict):
            raise ValueError("YAMLPolicy must define a dictionary/object at the root level")

        # Let RuleSetPolicy's dictionary parsing handle the rest
        # (uses python's class polymorphism to return a YAMLPolicy instance)
        return cast(YAMLPolicy, cls.from_dict(raw))

    @classmethod
    def load_yaml(cls, path: str | Path) -> YAMLPolicy:
        """Load and parse a YAML policy file from disk."""
        text = Path(path).read_text(encoding="utf-8")
        return cls.from_yaml(text)

    def to_yaml(self) -> str:
        """Dump the policy ruleset back to a YAML formatted string."""
        return cast(
            str,
            yaml.dump(self.to_dict(), sort_keys=True, indent=2, allow_unicode=True),
        )

    def dump_yaml(self, path: str | Path) -> None:
        """Serialize and save the policy to a YAML file on disk."""
        Path(path).write_text(self.to_yaml(), encoding="utf-8")
