"""Tests for the fail-closed Cloud Run manifest renderer used by the deploy
workflow (.github/workflows/deploy-agent-bus-analyzer.yml).

The renderer is the last code between CI secrets and `gcloud run services
replace`, so every failure mode must abort before a manifest is written:
missing values, unsafe characters, lost placeholders, and — critically —
any drift in the maxScale=1 / Secret-Manager-signing invariants.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "render_service", PACKAGE_ROOT / "deploy" / "render_service.py"
)
assert _SPEC is not None and _SPEC.loader is not None
render_service = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(render_service)

VALID_VALUES = {
    "RENDER_IMAGE": "us-central1-docker.pkg.dev/proj/acgi/agent-bus-analyzer:abc123def456",
    "RENDER_PROJECT_NUMBER": "123456789012",
    "RENDER_RUNTIME_SA": "analyzer-runtime@proj.iam.gserviceaccount.com",
    "RENDER_TRACE_BUCKET": "proj-analyzer-trace-store",
}


def _service_template() -> str:
    return (PACKAGE_ROOT / "deploy" / "cloudrun" / "service.yaml").read_text(encoding="utf-8")


def _live_yaml_lines(rendered: str) -> list[str]:
    """Non-comment lines — the template's header comment mentions REPLACE_*."""
    return [line for line in rendered.splitlines() if not line.lstrip().startswith("#")]


def test_renders_committed_service_manifest_with_all_placeholders_substituted() -> None:
    rendered = render_service.render(_service_template(), VALID_VALUES)

    assert not any("REPLACE_" in line for line in _live_yaml_lines(rendered))
    assert VALID_VALUES["RENDER_IMAGE"] in rendered
    assert VALID_VALUES["RENDER_RUNTIME_SA"] in rendered
    assert VALID_VALUES["RENDER_TRACE_BUCKET"] in rendered
    assert (
        "run.googleapis.com/secrets: evidence-signing-secret:"
        "projects/123456789012/secrets/acgs-evidence-signing-secret" in rendered
    )
    # Deployment invariants survive rendering.
    assert 'autoscaling.knative.dev/maxScale: "1"' in rendered
    assert "secretKeyRef:" in rendered
    assert 'key: "1"' in rendered


@pytest.mark.parametrize("missing", sorted(VALID_VALUES))
def test_fails_closed_when_any_value_is_missing(missing: str) -> None:
    values = {k: v for k, v in VALID_VALUES.items() if k != missing}

    with pytest.raises(render_service.RenderError, match="missing value"):
        render_service.render(_service_template(), values)


@pytest.mark.parametrize("empty", ["", "   "])
def test_fails_closed_when_a_value_is_blank(empty: str) -> None:
    values = dict(VALID_VALUES, RENDER_TRACE_BUCKET=empty)

    with pytest.raises(render_service.RenderError, match="missing value"):
        render_service.render(_service_template(), values)


@pytest.mark.parametrize(
    "unsafe",
    [
        "bucket\nspec: injected",  # newline = YAML structure injection
        'bucket" onerror: x',  # quote breakout
        "bucket name",  # whitespace
    ],
)
def test_fails_closed_on_values_that_could_inject_yaml(unsafe: str) -> None:
    values = dict(VALID_VALUES, RENDER_TRACE_BUCKET=unsafe)

    with pytest.raises(render_service.RenderError, match="unsafe"):
        render_service.render(_service_template(), values)


def test_fails_closed_when_template_lost_a_placeholder() -> None:
    template = _service_template().replace("REPLACE_ANALYZER_TRACE_BUCKET", "hardcoded-bucket")

    with pytest.raises(render_service.RenderError, match="lost placeholder"):
        render_service.render(template, VALID_VALUES)


def test_fails_closed_on_unrendered_extra_placeholder() -> None:
    template = _service_template() + "\nextraField: REPLACE_SOMETHING_NEW\n"

    with pytest.raises(render_service.RenderError, match="unrendered placeholder"):
        render_service.render(template, VALID_VALUES)


def test_comment_mentions_of_replace_do_not_fail_the_render() -> None:
    # The committed template's header comment documents the REPLACE_* contract;
    # only live YAML lines count as unrendered placeholders.
    template = _service_template() + "\n# note: REPLACE_ tokens are rendered in CI\n"

    rendered = render_service.render(template, VALID_VALUES)

    assert "note: REPLACE_ tokens" in rendered


def test_fails_closed_when_max_scale_invariant_drifts() -> None:
    template = _service_template().replace(
        'autoscaling.knative.dev/maxScale: "1"',
        'autoscaling.knative.dev/maxScale: "5"',
    )

    with pytest.raises(render_service.RenderError, match="invariant"):
        render_service.render(template, VALID_VALUES)


def test_fails_closed_when_signing_secret_is_inlined_instead_of_secret_manager() -> None:
    template = _service_template().replace("secretKeyRef:", "inlineRef:")

    with pytest.raises(render_service.RenderError, match="invariant"):
        render_service.render(template, VALID_VALUES)


def test_cli_writes_rendered_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    for name, value in VALID_VALUES.items():
        monkeypatch.setenv(name, value)
    out = tmp_path / "service.rendered.yaml"

    exit_code = render_service.main(
        [
            "--template",
            str(PACKAGE_ROOT / "deploy" / "cloudrun" / "service.yaml"),
            "--out",
            str(out),
        ]
    )

    assert exit_code == 0
    rendered = out.read_text(encoding="utf-8")
    assert not any("REPLACE_" in line for line in _live_yaml_lines(rendered))
    assert 'autoscaling.knative.dev/maxScale: "1"' in rendered


def test_cli_fails_closed_and_writes_nothing_without_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    for name in VALID_VALUES:
        monkeypatch.delenv(name, raising=False)
    out = tmp_path / "service.rendered.yaml"

    exit_code = render_service.main(
        [
            "--template",
            str(PACKAGE_ROOT / "deploy" / "cloudrun" / "service.yaml"),
            "--out",
            str(out),
        ]
    )

    assert exit_code == 1
    assert not out.exists()
    assert "fail-closed" in capsys.readouterr().err
