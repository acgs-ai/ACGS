#!/usr/bin/env python3
"""Render the three SaaS-beta dependency inputs and the closed scope map.

This generator deliberately uses only Python 3.11's standard library.  Product
manifests remain the authority for runtime, test, extra, and PEP 517 inputs;
the lock model selects the declared groups and adds the explicit PEP 660 helper
that editable builds need after build isolation and resolution are disabled.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
import tomllib
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

CONFIG_VERSION = "acgs-saas-beta-lock-config/v1"
EVIDENCE_INPUTS = (
    "rfc8785==0.1.4",
    "cryptography>=42",
    "jsonschema>=4.23,<5",
    "pytest>=9.0.3,<10",
)
PRODUCT_CODES = ("CP", "GZ")
ALLOWED_ASSIGNMENTS = {
    "EVID",
    "EVID+CP",
    "EVID+CP+GZ",
    "EVID+CP+UI",
    "EVID+UI",
    "EVID+CP+GZ+UI",
}
NODE_COUNTS = {"P0": 4, "P1": 4, "P2": 4, "P3": 5, "P4": 3, "P5": 3, "P6": 3, "P7": 4}
EXPECTED_BOOTSTRAP_MAP = {
    "P0-EVIDENCE-000": "EVID+CP+GZ",
    "P0-MEMBRANE-001": "EVID+CP",
    "P0-CLAIMS-002": "EVID+CP+GZ",
    "P0-GATES-003": "EVID+CP+GZ+UI",
    "P1-MIGRATION-001": "EVID+CP",
    "P1-SCOPE-002": "EVID+CP",
    "P1-LEDGER-003": "EVID+CP",
    "P1-TRUST-004": "EVID+CP+GZ",
    "P2-TENANT-BOOTSTRAP-000": "EVID+CP+GZ",
    "P2-REGISTER-001": "EVID+CP+GZ",
    "P2-IDEMPOTENCY-002": "EVID+CP",
    "P2-VERTICAL-GATE-003": "EVID+CP+GZ",
    "P3-POLICY-001": "EVID+CP",
    "P3-MUTATIONS-002": "EVID+CP",
    "P3-APPROVAL-003": "EVID+CP+GZ",
    "P3-APPROVAL-003B": "EVID+CP+GZ",
    "P3-APPROVAL-003C": "EVID+CP+GZ",
    "P4-ENROLLMENT-001": "EVID+CP+GZ",
    "P4-POLICY-SYNC-002": "EVID+CP+GZ",
    "P4-OUTAGE-003": "EVID+CP+GZ",
    "P5-INGEST-001": "EVID+CP+GZ",
    "P5-STORE-002": "EVID+CP",
    "P5-WITNESS-003": "EVID+CP+GZ",
    "P6-BFF-001": "EVID+CP+UI",
    "P6-CONSOLE-002": "EVID+UI",
    "P6-E2E-003": "EVID+CP+GZ+UI",
    "P7-USAGE-001": "EVID+CP",
    "P7-RELIABILITY-002": "EVID+CP+GZ+UI",
    "P7-PROOFPACK-003": "EVID+CP+GZ+UI",
    "P7-BETA-GATE-004": "EVID+CP+GZ+UI",
}
EXPECTED_OUTPUTS = {
    "EVID": Path("requirements/saas-beta/evidence-test.in"),
    "CP": Path("requirements/saas-beta/cp-test.in"),
    "GZ": Path("requirements/saas-beta/gz-test.in"),
    "MAP": Path("requirements/saas-beta/bootstrap-by-scope.json"),
}
REQ_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
EXTRA_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
REGISTRY_REQUIREMENT_RE = re.compile(
    r"""
    ^
    [A-Za-z0-9][A-Za-z0-9._-]*
    (?:\[[A-Za-z0-9][A-Za-z0-9._-]*(?:\s*,\s*[A-Za-z0-9][A-Za-z0-9._-]*)*\])?
    \s*
    (?:
      (?:~=|==|!=|<=|>=|<|>|===)
      \s*
      [A-Za-z0-9][A-Za-z0-9._!*+~-]*
      (?:\s*,\s*(?:~=|==|!=|<=|>=|<|>|===)\s*[A-Za-z0-9][A-Za-z0-9._!*+~-]*)*
    )?
    (?:\s*;\s*[A-Za-z0-9_.\"' <>=!~(),-]+)?
    $
    """,
    re.VERBOSE,
)
WORKSPACE_REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[(?P<extras>[A-Za-z0-9][A-Za-z0-9._-]*"
    r"(?:\s*,\s*[A-Za-z0-9][A-Za-z0-9._-]*)*)\])?$"
)
UNSAFE_REQUIREMENT_TOKENS = re.compile(
    r"(?i)(?:^|[^\w.+-])(?:https?|file|ssh|git)://|(?:^|[^\w.+-])(?:git|ssh|file)\+"
)


class ConfigError(ValueError):
    """The committed generator model or a selected manifest is invalid."""


def _load_toml(path: Path) -> dict[str, Any]:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"cannot read TOML {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"TOML root must be a table: {path}")
    return data


def _closed_keys(table: Mapping[str, Any], allowed: set[str], where: str) -> None:
    extra = set(table) - allowed
    missing = allowed - set(table)
    if extra or missing:
        raise ConfigError(f"{where} keys mismatch; missing={sorted(missing)} extra={sorted(extra)}")


def _string_list(value: Any, where: str, *, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ConfigError(f"{where} must be a{' non-empty' if nonempty else ''} string list")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ConfigError(f"{where} contains a non-string or blank entry")
    if len(value) != len(set(value)):
        raise ConfigError(f"{where} contains duplicates")
    return list(value)


def _canonical_name(requirement: str) -> str:
    match = REQ_NAME_RE.match(requirement.strip())
    if match is None:
        raise ConfigError(f"unsupported or dynamic requirement: {requirement!r}")
    return re.sub(r"[-_.]+", "-", match.group(0)).lower()


def _canonical_extra(extra: str) -> str:
    return re.sub(r"[-_.]+", "-", extra).lower()


def _validate_requirement_source(
    requirement: str,
    where: str,
    *,
    allowed_workspace_names: set[str] | None = None,
) -> None:
    candidate = requirement.strip()
    allowed_workspace_names = allowed_workspace_names or set()
    if (
        "@" in candidate
        or "://" in candidate
        or candidate.startswith((".", "/", "~"))
        or UNSAFE_REQUIREMENT_TOKENS.search(candidate)
    ):
        raise ConfigError(f"{where}: direct URL/path requirement is not allowed: {requirement!r}")
    if not REGISTRY_REQUIREMENT_RE.fullmatch(candidate):
        raise ConfigError(f"{where}: unsupported or ambiguous requirement source: {requirement!r}")
    name = _canonical_name(candidate)
    if name in allowed_workspace_names:
        return


def _project_name(manifest: Mapping[str, Any], path: Path) -> str:
    project = manifest.get("project")
    if not isinstance(project, dict) or not isinstance(project.get("name"), str):
        raise ConfigError(f"{path}: static [project].name is required")
    return _canonical_name(project["name"])


def _selected_group(manifest: Mapping[str, Any], group: str, path: Path) -> list[str]:
    dependency_groups = manifest.get("dependency-groups", {})
    optional = manifest.get("project", {}).get("optional-dependencies", {})
    candidates: list[Any] = []
    if isinstance(dependency_groups, dict) and group in dependency_groups:
        candidates.append(dependency_groups[group])
    if isinstance(optional, dict) and group in optional:
        candidates.append(optional[group])
    if len(candidates) != 1:
        raise ConfigError(
            f"{path}: group {group!r} must be declared exactly once in "
            "[dependency-groups] or [project.optional-dependencies]"
        )
    return _string_list(candidates[0], f"{path}:{group}")


def _resolve_selected_extra(
    manifest: Mapping[str, Any], extra: str, path: Path
) -> tuple[str, list[str]]:
    optional = manifest.get("project", {}).get("optional-dependencies", {})
    if not isinstance(optional, dict):
        raise ConfigError(f"{path}: selected extra {extra!r} is not declared")

    canonical_keys: dict[str, str] = {}
    for key in optional:
        if not isinstance(key, str) or EXTRA_NAME_RE.fullmatch(key) is None:
            raise ConfigError(f"{path}: optional-dependencies contains an invalid key: {key!r}")
        canonical = _canonical_extra(key)
        if canonical in canonical_keys:
            raise ConfigError(
                f"{path}: optional-dependencies keys collide after normalization: "
                f"{canonical_keys[canonical]!r} and {key!r}"
            )
        canonical_keys[canonical] = key

    selected_key = canonical_keys.get(_canonical_extra(extra))
    if selected_key is None:
        raise ConfigError(f"{path}: selected extra {extra!r} is not declared")
    return selected_key, _string_list(optional[selected_key], f"{path}:extra:{selected_key}")


def _selected_extra(manifest: Mapping[str, Any], extra: str, path: Path) -> list[str]:
    return _resolve_selected_extra(manifest, extra, path)[1]


def _workspace_requirement_extras(
    requirement: str,
    expected_name: str,
    where: str,
) -> tuple[str, ...]:
    match = WORKSPACE_REQUIREMENT_RE.fullmatch(requirement.strip())
    if match is None or _canonical_name(match.group("name")) != expected_name:
        raise ConfigError(
            f"{where}: workspace dependency must be a bare name with optional extras: "
            f"{requirement!r}"
        )
    raw_extras = match.group("extras")
    if raw_extras is None:
        return ()
    extras = tuple(item.strip() for item in raw_extras.split(","))
    if len(extras) != len(set(extras)):
        raise ConfigError(
            f"{where}: workspace dependency extras contain duplicates: {requirement!r}"
        )
    canonical_extras = tuple(_canonical_extra(extra) for extra in extras)
    if len(canonical_extras) != len(set(canonical_extras)):
        raise ConfigError(
            f"{where}: requested extras contain canonical duplicates: {requirement!r}"
        )
    return extras


def _expand_workspace_requirements(
    requirements: Iterable[str],
    *,
    where: str,
    workspace_manifests: Mapping[str, tuple[Path, Path, Mapping[str, Any]]],
    stack: tuple[str, ...],
) -> tuple[list[str], list[str]]:
    expanded: list[str] = []
    sources: list[str] = []

    def add_source(source: str) -> None:
        if source not in sources:
            sources.append(source)

    workspace_names = set(workspace_manifests)
    for requirement in requirements:
        _validate_requirement_source(
            requirement,
            where,
            allowed_workspace_names=workspace_names,
        )
        name = _canonical_name(requirement)
        if name not in workspace_manifests:
            expanded.append(requirement)
            continue

        extras = _workspace_requirement_extras(requirement, name, where)
        if name in stack:
            cycle = " -> ".join((*stack, name))
            raise ConfigError(f"{where}: workspace dependency expansion cycle: {cycle}")

        manifest_rel, manifest_path, manifest = workspace_manifests[name]
        project = manifest.get("project")
        if not isinstance(project, dict):
            raise ConfigError(f"{manifest_rel}: [project] is required")
        nested = _string_list(
            project.get("dependencies", []),
            f"{manifest_rel}:dependencies",
            nonempty=False,
        )
        add_source(f"{manifest_rel}:[project].dependencies")
        for extra in extras:
            selected_extra, extra_requirements = _resolve_selected_extra(
                manifest, extra, manifest_path
            )
            nested.extend(extra_requirements)
            add_source(f"{manifest_rel}:extra:{selected_extra}")

        nested_requirements, nested_sources = _expand_workspace_requirements(
            nested,
            where=f"{manifest_rel}:workspace-expansion",
            workspace_manifests=workspace_manifests,
            stack=(*stack, name),
        )
        expanded.extend(nested_requirements)
        for source in nested_sources:
            add_source(source)

    return expanded, sources


def _unique_requirements(requirements: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for requirement in requirements:
        name = _canonical_name(requirement)
        if name in seen:
            # The manifests may expose the same direct input through a dev group
            # and a selected extra.  Identical text is harmless; conflicting
            # direct constraints would make the input model ambiguous.
            prior = next(item for item in result if _canonical_name(item) == name)
            if prior != requirement:
                raise ConfigError(
                    f"conflicting direct requirements for {name}: {prior!r} and {requirement!r}"
                )
            continue
        seen.add(name)
        result.append(requirement)
    return result


def _render_input(code: str, requirements: list[str], sources: list[str]) -> str:
    lines = [
        "# Generated by scripts/evidence/render_lock_inputs.py; DO NOT EDIT.",
        f"# Target: {code}",
        "# Sources:",
        *[f"#   - {source}" for source in sources],
        "",
        *requirements,
        "",
    ]
    return "\n".join(lines)


def _validate_bootstrap_map(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        raise ConfigError("bootstrap_by_scope must be a table")
    mapping: dict[str, str] = {}
    for node, assignment in raw.items():
        if not isinstance(node, str) or not re.fullmatch(r"P[0-7]-[A-Z0-9-]+", node):
            raise ConfigError(f"invalid node id in bootstrap map: {node!r}")
        if not isinstance(assignment, str) or assignment not in ALLOWED_ASSIGNMENTS:
            raise ConfigError(f"invalid bootstrap assignment for {node}: {assignment!r}")
        tokens = assignment.split("+")
        if tokens[0] != "EVID" or tokens.count("EVID") != 1 or len(tokens) != len(set(tokens)):
            raise ConfigError(f"assignment must start with exactly one EVID: {node}={assignment}")
        mapping[node] = assignment
    if mapping != EXPECTED_BOOTSTRAP_MAP:
        expected_count = len(EXPECTED_BOOTSTRAP_MAP)
        missing = sorted(set(EXPECTED_BOOTSTRAP_MAP) - set(mapping))
        extra = sorted(set(mapping) - set(EXPECTED_BOOTSTRAP_MAP))
        changed = sorted(
            node
            for node in set(mapping) & set(EXPECTED_BOOTSTRAP_MAP)
            if mapping[node] != EXPECTED_BOOTSTRAP_MAP[node]
        )
        raise ConfigError(
            f"bootstrap map differs from exact reviewed {expected_count}-node map; "
            f"missing={missing} extra={extra} changed={changed}"
        )
    return mapping


def _exact_output(value: Any, code: str) -> Path:
    expected = EXPECTED_OUTPUTS[code]
    if not isinstance(value, str) or Path(value) != expected or value != expected.as_posix():
        raise ConfigError(f"{code}.output must be exactly {expected.as_posix()!r}")
    return expected


def _safe_parent_chain(root: Path, destination: Path) -> None:
    if destination == root or not destination.is_relative_to(root):
        raise ConfigError(f"renderer destination escaped output root: {destination}")
    current = root
    for part in destination.relative_to(root).parent.parts:
        current /= part
        if os.path.lexists(current) and (current.is_symlink() or not current.is_dir()):
            raise ConfigError(f"renderer parent is symlinked or not a directory: {current}")
    if os.path.lexists(destination) and (destination.is_symlink() or not destination.is_file()):
        raise ConfigError(f"renderer destination is symlinked or not a regular file: {destination}")


def _atomic_publish(output_root: Path, writes: Mapping[Path, str]) -> list[Path]:
    if not output_root.is_absolute() or output_root != output_root.resolve(strict=False):
        raise ConfigError("output root must be an absolute canonical path")
    if os.path.lexists(output_root) and (output_root.is_symlink() or not output_root.is_dir()):
        raise ConfigError("output root must be a non-symlink directory")
    expected = {output_root / relative for relative in EXPECTED_OUTPUTS.values()}
    if set(writes) != expected or len(writes) != len(EXPECTED_OUTPUTS):
        raise ConfigError("renderer destination set must be the exact four closed outputs")
    for destination in writes:
        _safe_parent_chain(output_root, destination)

    snapshots: dict[Path, tuple[bytes, int] | None] = {}
    for destination in writes:
        snapshots[destination] = (
            (destination.read_bytes(), destination.stat().st_mode & 0o777)
            if destination.exists()
            else None
        )

    created_dirs: list[Path] = []
    staged: dict[Path, tuple[Path, tuple[int, int]]] = {}
    committed: list[Path] = []
    token = f"{os.getpid()}-{secrets.token_hex(8)}"
    try:
        for directory in sorted(
            {output_root, *(destination.parent for destination in writes)},
            key=lambda item: len(item.parts),
        ):
            missing: list[Path] = []
            cursor = directory
            while not cursor.exists():
                missing.append(cursor)
                cursor = cursor.parent
            for candidate in reversed(missing):
                candidate.mkdir()
                created_dirs.append(candidate)
            if directory.is_symlink() or not directory.is_dir():
                raise ConfigError(f"renderer parent changed during publication: {directory}")

        for destination, content in writes.items():
            _safe_parent_chain(output_root, destination)
            temporary = destination.with_name(f".{destination.name}.{token}.tmp")
            if os.path.lexists(temporary):
                raise ConfigError(f"renderer temporary path already exists: {temporary}")
            payload = content.encode("utf-8")
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            fd = os.open(temporary, flags, 0o644)
            try:
                if os.write(fd, payload) != len(payload):
                    raise ConfigError(f"short renderer write: {temporary}")
                os.fsync(fd)
                metadata = os.fstat(fd)
                staged[destination] = (temporary, (metadata.st_dev, metadata.st_ino))
            finally:
                os.close(fd)

        for destination in sorted(writes, key=str):
            temporary, _ = staged[destination]
            _safe_parent_chain(output_root, destination)
            os.replace(temporary, destination)
            committed.append(destination)
        return sorted(writes, key=str)
    except BaseException as exc:
        rollback_errors: list[str] = []
        for destination in reversed(committed):
            snapshot = snapshots[destination]
            try:
                if snapshot is None:
                    current = destination.lstat()
                    expected_inode = staged[destination][1]
                    if (current.st_dev, current.st_ino) != expected_inode:
                        raise ConfigError(f"refusing to unlink changed output: {destination}")
                    destination.unlink()
                else:
                    payload, mode = snapshot
                    rollback = destination.with_name(f".{destination.name}.{token}.rollback")
                    fd = os.open(rollback, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
                    try:
                        if os.write(fd, payload) != len(payload):
                            raise ConfigError(f"short renderer rollback write: {rollback}")
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    os.replace(rollback, destination)
            except BaseException as rollback_exc:
                rollback_errors.append(f"{destination}: {rollback_exc}")
        if rollback_errors:
            raise ConfigError(
                f"renderer publication failed ({exc}); rollback also failed: {rollback_errors}"
            ) from exc
        if isinstance(exc, ConfigError):
            raise
        raise ConfigError(f"renderer publication failed: {exc}") from exc
    finally:
        for temporary, _ in staged.values():
            temporary.unlink(missing_ok=True)
        for directory in reversed(created_dirs):
            try:
                directory.rmdir()
            except OSError:
                pass


def render(config_path: Path, output_root: Path) -> list[Path]:
    config_path = config_path.resolve(strict=True)
    repo_root = config_path.parents[2]
    config = _load_toml(config_path)
    _closed_keys(
        config,
        {"schema_version", "meta", "EVID", "CP", "GZ", "bootstrap_by_scope"},
        "lock config",
    )
    if config["schema_version"] != CONFIG_VERSION:
        raise ConfigError(f"unsupported config schema: {config['schema_version']!r}")
    meta = config["meta"]
    if not isinstance(meta, dict):
        raise ConfigError("meta must be a table")
    _closed_keys(meta, {"uv_version", "python_version", "python_platform", "exclude_newer"}, "meta")
    if meta != {
        "uv_version": "0.11.19",
        "python_version": "3.11",
        "python_platform": "x86_64-manylinux_2_28",
        "exclude_newer": "2026-07-10T00:00:00Z",
    }:
        raise ConfigError("tool/platform/cutoff identities drifted from the reviewed contract")

    evid = config["EVID"]
    if not isinstance(evid, dict):
        raise ConfigError("EVID must be a table")
    _closed_keys(evid, {"output", "evidence_test"}, "EVID")
    evidence_inputs = _string_list(evid["evidence_test"], "EVID.evidence_test")
    if tuple(evidence_inputs) != EVIDENCE_INPUTS:
        raise ConfigError(f"EVID.evidence_test must be exactly {list(EVIDENCE_INPUTS)!r}")

    writes: dict[Path, str] = {}
    evidence_output = output_root / _exact_output(evid["output"], "EVID")
    writes[evidence_output] = _render_input(
        "EVID",
        evidence_inputs,
        ["requirements/saas-beta/locks.toml:EVID.evidence_test"],
    )

    for code in PRODUCT_CODES:
        section = config[code]
        if not isinstance(section, dict):
            raise ConfigError(f"{code} must be a table")
        _closed_keys(
            section,
            {
                "manifest",
                "output",
                "dependency_groups",
                "extras",
                "editable_no_deps",
                "pep517_backend",
                "pep660_editable_build",
            },
            code,
        )
        manifest_rel = Path(str(section["manifest"]))
        if manifest_rel.is_absolute() or ".." in manifest_rel.parts:
            raise ConfigError(f"{code}.manifest must be a repository-relative safe path")
        manifest_path = (repo_root / manifest_rel).resolve(strict=True)
        if not manifest_path.is_relative_to(repo_root):
            raise ConfigError(f"{code}.manifest escaped the repository")
        manifest = _load_toml(manifest_path)

        editable_paths = _string_list(section["editable_no_deps"], f"{code}.editable_no_deps")
        workspace_manifests: dict[str, tuple[Path, Path, Mapping[str, Any]]] = {}
        for editable in editable_paths:
            editable_path = Path(editable)
            if editable_path.is_absolute() or ".." in editable_path.parts:
                raise ConfigError(f"{code} editable path is unsafe: {editable!r}")
            editable_manifest_path = (repo_root / editable_path / "pyproject.toml").resolve(
                strict=True
            )
            if not editable_manifest_path.is_relative_to(repo_root):
                raise ConfigError(f"{code} editable path escaped the repository: {editable!r}")
            editable_manifest = _load_toml(editable_manifest_path)
            editable_name = _project_name(editable_manifest, editable_manifest_path)
            if editable_name in workspace_manifests:
                raise ConfigError(f"{code}: duplicate editable workspace name: {editable_name}")
            workspace_manifests[editable_name] = (
                editable_path / "pyproject.toml",
                editable_manifest_path,
                editable_manifest,
            )

        project = manifest.get("project")
        if not isinstance(project, dict):
            raise ConfigError(f"{manifest_rel}: [project] is required")
        base = _string_list(
            project.get("dependencies", []), f"{manifest_rel}:dependencies", nonempty=False
        )
        groups = _string_list(section["dependency_groups"], f"{code}.dependency_groups")
        extras = _string_list(section["extras"], f"{code}.extras")
        selected: list[str] = list(base)
        for group in groups:
            selected.extend(_selected_group(manifest, group, manifest_path))
        for extra in extras:
            selected.extend(_selected_extra(manifest, extra, manifest_path))

        project_name = _project_name(manifest, manifest_path)
        selected, expanded_sources = _expand_workspace_requirements(
            selected,
            where=f"{manifest_rel}:selected",
            workspace_manifests=workspace_manifests,
            stack=(project_name,),
        )

        build_system = manifest.get("build-system")
        if not isinstance(build_system, dict):
            raise ConfigError(f"{manifest_rel}: a static [build-system] is required")
        backend = build_system.get("build-backend")
        if backend != section["pep517_backend"] or not isinstance(backend, str):
            raise ConfigError(f"{code}: PEP 517 backend declaration drifted or is dynamic")
        build_requires = _string_list(
            build_system.get("requires"), f"{manifest_rel}:[build-system].requires"
        )
        if not any(_canonical_name(item) == "hatchling" for item in build_requires):
            raise ConfigError(f"{code}: Hatchling must be an explicit PEP 517 backend input")

        pep660 = _string_list(section["pep660_editable_build"], f"{code}.pep660_editable_build")
        if pep660 != ["editables==0.6"]:
            raise ConfigError(f"{code}: pep660_editable_build must be exactly editables==0.6")

        for requirement in build_requires:
            _validate_requirement_source(requirement, f"{manifest_rel}:[build-system].requires")
            if _canonical_name(requirement) in workspace_manifests:
                raise ConfigError(f"{code}: build-system workspace dependencies are not allowed")
        for requirement in pep660:
            _validate_requirement_source(
                requirement, f"requirements/saas-beta/locks.toml:{code}.pep660_editable_build"
            )
            if _canonical_name(requirement) in workspace_manifests:
                raise ConfigError(f"{code}: PEP 660 workspace dependencies are not allowed")

        requirements = _unique_requirements([*selected, *build_requires, *pep660])
        if "editables==0.6" not in requirements:
            raise ConfigError(f"{code}: explicit PEP 660 helper was not rendered")
        output = output_root / _exact_output(section["output"], code)
        sources = [
            str(manifest_rel),
            *expanded_sources,
            f"{manifest_rel}:[build-system].requires",
            f"requirements/saas-beta/locks.toml:{code}.pep660_editable_build",
        ]
        writes[output] = _render_input(code, requirements, sources)

    bootstrap = _validate_bootstrap_map(config["bootstrap_by_scope"])
    bootstrap_output = output_root / EXPECTED_OUTPUTS["MAP"]
    writes[bootstrap_output] = json.dumps(bootstrap, indent=2, ensure_ascii=False) + "\n"

    return _atomic_publish(output_root, writes)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="requirements/saas-beta/locks.toml", type=Path)
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path.cwd(),
        help="repository-shaped output root (primarily for negative tests)",
    )
    args = parser.parse_args(argv)
    try:
        written = render(args.config, args.output_root)
    except (ConfigError, OSError) as exc:
        print(f"lock input generation failed: {exc}", file=sys.stderr)
        return 2
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
