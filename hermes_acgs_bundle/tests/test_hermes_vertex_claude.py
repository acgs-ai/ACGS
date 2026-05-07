from hermes_acgs_middleware import HermesACGSMiddleware
from hermes_vertex_claude import (
    build_payload,
    generate_governed_response,
    raw_predict_url,
    vertex_endpoint,
)


def test_vertex_endpoint_for_global_and_region():
    assert vertex_endpoint("global") == "https://aiplatform.googleapis.com"
    assert vertex_endpoint("us") == "https://aiplatform.us.rep.googleapis.com"
    assert vertex_endpoint("us-east5") == "https://us-east5-aiplatform.googleapis.com"


def test_payload_matches_anthropic_vertex_raw_predict_shape():
    payload = build_payload("Hello Hermes", max_tokens=128)

    assert payload == {
        "anthropic_version": "vertex-2023-10-16",
        "stream": False,
        "max_tokens": 128,
        "messages": [{"role": "user", "content": "Hello Hermes"}],
    }


def test_raw_predict_url_targets_anthropic_publisher_model():
    assert raw_predict_url(
        project_id="project-123",
        location="global",
        model="claude-opus-4-7",
    ) == (
        "https://aiplatform.googleapis.com/v1/projects/project-123/locations/global"
        "/publishers/anthropic/models/claude-opus-4-7:rawPredict"
    )


def test_governed_response_applies_final_policy_to_vertex_output():
    def fake_request(url, payload):
        assert url.endswith("/publishers/anthropic/models/claude-opus-4-7:rawPredict")
        assert payload["messages"][0]["content"] == "Use for Hermes"
        return {"content": [{"type": "text", "text": "Use sk-proj-1234567890abcdef"}]}

    response = generate_governed_response(
        "Use for Hermes",
        project_id="project-123",
        acgs=HermesACGSMiddleware(),
        request_func=fake_request,
    )

    assert "I cannot release this answer as written." in response
    assert "sk-proj-1234567890abcdef" not in response
