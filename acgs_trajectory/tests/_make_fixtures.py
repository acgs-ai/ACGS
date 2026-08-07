"""Generate deterministic Claude Code transcript fixtures.

Shapes mirror a live version-2.1.170 session (ADR 0002 D1-D5). Run:
    python tests/_make_fixtures.py
Fixture files are committed; regenerate only when the source format changes.
"""

from __future__ import annotations

import json
from pathlib import Path

FX = Path(__file__).parent / "fixtures"
FX.mkdir(parents=True, exist_ok=True)

V = "2.1.170"
SID = "sess-0001"
BASE = {"sessionId": SID, "version": V, "entrypoint": "cli", "cwd": "/repo", "gitBranch": "master", "userType": "external", "isSidechain": False}


def rec(**kw):
    d = dict(BASE)
    d.update(kw)
    return d


def user_text(uuid, parent, text, ts):
    return rec(type="user", uuid=uuid, parentUuid=parent, timestamp=ts,
               message={"role": "user", "content": [{"type": "text", "text": text}]})


def asst(uuid, parent, block, ts, model="claude-opus-4-8"):
    return rec(type="assistant", uuid=uuid, parentUuid=parent, timestamp=ts,
               requestId=f"req-{uuid}",
               message={"role": "assistant", "model": model, "content": [block],
                        "usage": {"input_tokens": 100, "output_tokens": 20,
                                  "cache_read_input_tokens": 0, "cache_creation_input_tokens": 50}})


def thinking(text):
    return {"type": "thinking", "thinking": text}


def text_block(text):
    return {"type": "text", "text": text}


def tool_use(tid, name, inp, caller=None):
    b = {"type": "tool_use", "id": tid, "name": name, "input": inp}
    if caller is not None:
        b["caller"] = caller
    return b


def tool_result(uuid, parent, tid, content, ts, is_error=False, sidechain=False):
    r = rec(type="user", uuid=uuid, parentUuid=parent, timestamp=ts, isSidechain=sidechain,
            message={"role": "user", "content": [{"type": "tool_result", "tool_use_id": tid,
                                                   "content": content, "is_error": is_error}]})
    return r


def system_hook(uuid, parent, ts, subtype="PreToolUse", prevented=False, errors=None, tool_use_id=None, names=("scope-gate",)):
    return rec(type="system", uuid=uuid, parentUuid=parent, timestamp=ts, subtype=subtype,
               hookInfos=[{"name": n} for n in names], hookErrors=list(errors or []),
               preventedContinuation=prevented, stopReason=("policy" if prevented else None),
               toolUseID=tool_use_id, level="info", hasOutput=True)


def attachment(uuid, parent, ts):
    return rec(type="attachment", uuid=uuid, parentUuid=parent, timestamp=ts,
               attachment={"type": "context", "note": "injected file"})


def last_prompt(leaf):
    return {"type": "last-prompt", "sessionId": SID, "lastPrompt": "continue", "leafUuid": leaf}


def write(name, records):
    path = FX / name
    path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in records) + "\n", encoding="utf-8")
    return path


def complete_session():
    T1 = "toolu_A1"
    recs = [
        user_text("u1", None, "Fix the auth token expiry check.", "2026-08-06T10:00:00Z"),
        asst("a1", "u1", thinking("Need to inspect middleware first."), "2026-08-06T10:00:01Z"),
        asst("a2", "a1", tool_use(T1, "Bash", {"command": "rg token_expiry"}), "2026-08-06T10:00:02Z"),
        tool_result("r1", "a2", T1, "src/auth.py:42: if now < exp", "2026-08-06T10:00:03Z", is_error=False),
        asst("a3", "r1", text_block("Found it; the check uses < not <=."), "2026-08-06T10:00:04Z"),
        system_hook("s1", "a3", "2026-08-06T10:00:05Z", tool_use_id=T1),
        attachment("at1", "a3", "2026-08-06T10:00:06Z"),
        {"type": "queue-operation", "operation": "flush", "sessionId": SID, "timestamp": "2026-08-06T10:00:07Z"},
        last_prompt("a3"),
    ]
    write("complete_session.jsonl", recs)


def subagent_session():
    """Main issues a Task tool_use; a sidechain trajectory runs under it."""
    T1 = "toolu_TASK1"
    recs = [
        user_text("u1", None, "Investigate the failing test.", "2026-08-06T11:00:00Z"),
        asst("a1", "u1", tool_use(T1, "Task", {"prompt": "explore"}, caller="main"), "2026-08-06T11:00:01Z"),
        # sidechain root attaches to spawning tool_use a1
        rec(type="assistant", uuid="sc1", parentUuid="a1", isSidechain=True, timestamp="2026-08-06T11:00:02Z",
            message={"role": "assistant", "model": "claude-opus-4-8",
                     "content": [tool_use("toolu_SC", "Grep", {"pattern": "def test_"}, caller="sub")],
                     "usage": {"input_tokens": 10, "output_tokens": 5, "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}}),
        tool_result("sc2", "sc1", "toolu_SC", "tests/test_x.py:10", "2026-08-06T11:00:03Z", sidechain=True),
        tool_result("r1", "a1", T1, "subagent found the test", "2026-08-06T11:00:04Z"),
        asst("a2", "r1", text_block("Subagent located it."), "2026-08-06T11:00:05Z"),
        last_prompt("a2"),
    ]
    write("subagent_session.jsonl", recs)


def hook_prevented_session():
    T1 = "toolu_BLK"
    recs = [
        user_text("u1", None, "Push to main.", "2026-08-06T12:00:00Z"),
        asst("a1", "u1", tool_use(T1, "Bash", {"command": "git push origin main"}), "2026-08-06T12:00:01Z"),
        system_hook("s1", "a1", "2026-08-06T12:00:02Z", subtype="PreToolUse", prevented=True,
                    errors=["blocked-op: human-gated push"], tool_use_id=T1, names=("blocked-op-escalation-guard",)),
        asst("a2", "s1", text_block("Push is human-gated; stopping."), "2026-08-06T12:00:03Z"),
        last_prompt("a2"),
    ]
    write("hook_prevented_session.jsonl", recs)


def missing_parent_session():
    recs = [
        user_text("u1", None, "Do something.", "2026-08-06T13:00:00Z"),
        asst("a1", "ghost-parent", text_block("orphaned node"), "2026-08-06T13:00:01Z"),
        last_prompt("a1"),
    ]
    write("missing_parent_session.jsonl", recs)


def broken_tool_ref_session():
    recs = [
        user_text("u1", None, "Run a tool.", "2026-08-06T14:00:00Z"),
        # tool_result references a tool_use that never occurred
        tool_result("r1", "u1", "toolu_DOES_NOT_EXIST", "orphan result", "2026-08-06T14:00:01Z"),
        last_prompt("r1"),
    ]
    write("broken_tool_ref_session.jsonl", recs)


def secret_session():
    # Generic assigned-secret SHAPE (secret_pattern_match tier -> quarantine).
    # No high-precision key literal committed; a confirmed_secret is tested inline.
    T1 = "toolu_S1"
    leaked = "password=Sup3rSecretValue1234567"
    recs = [
        user_text("u1", None, "Print env.", "2026-08-06T15:00:00Z"),
        asst("a1", "u1", tool_use(T1, "Bash", {"command": "cat .env"}), "2026-08-06T15:00:01Z"),
        tool_result("r1", "a1", T1, leaked, "2026-08-06T15:00:02Z"),
        last_prompt("r1"),
    ]
    write("secret_session.jsonl", recs)


def placeholder_session():
    # AWS canonical EXAMPLE key -> example_placeholder tier -> ALLOWED (noted, not quarantined).
    T1 = "toolu_P1"
    recs = [
        user_text("u1", None, "Show sample config.", "2026-08-06T15:10:00Z"),
        asst("a1", "u1", tool_use(T1, "Bash", {"command": "cat README"}), "2026-08-06T15:10:01Z"),
        tool_result("r1", "a1", T1, "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE", "2026-08-06T15:10:02Z"),
        last_prompt("r1"),
    ]
    write("placeholder_session.jsonl", recs)


# ---- H2 adversarial fixtures ------------------------------------------------


def mixed_session_ids():
    r1 = user_text("u1", None, "one", "2026-08-06T19:00:00Z")
    r2 = user_text("u2", "u1", "two", "2026-08-06T19:00:01Z")
    r2["sessionId"] = "sess-OTHER"  # provenance violation: two identities in one file
    write("mixed_session_ids.jsonl", [r1, r2, last_prompt("u2")])


def cyclic_parent_session():
    a = asst("a1", "a2", text_block("cycle A"), "2026-08-06T19:10:00Z")
    b = asst("a2", "a1", text_block("cycle B"), "2026-08-06T19:10:01Z")
    write("cyclic_parent_session.jsonl", [a, b, last_prompt("a2")])


def dangling_tool_use_session():
    # tool_use with no matching tool_result (session ended mid-call)
    T1 = "toolu_D1"
    recs = [
        user_text("u1", None, "run", "2026-08-06T19:20:00Z"),
        asst("a1", "u1", tool_use(T1, "Bash", {"command": "sleep 999"}), "2026-08-06T19:20:01Z"),
        last_prompt("a1"),
    ]
    write("dangling_tool_use_session.jsonl", recs)


def result_before_use_session():
    # tool_result appears (seq) BEFORE its tool_use — out-of-order integrity violation
    T1 = "toolu_O1"
    recs = [
        user_text("u1", None, "run", "2026-08-06T19:30:00Z"),
        tool_result("r1", "u1", T1, "early result", "2026-08-06T19:30:01Z"),
        asst("a1", "r1", tool_use(T1, "Bash", {"command": "echo"}), "2026-08-06T19:30:02Z"),
        last_prompt("a1"),
    ]
    write("result_before_use_session.jsonl", recs)


def missing_session_id_session():
    r1 = user_text("u1", None, "hi", "2026-08-06T19:40:00Z")
    del r1["sessionId"]
    write("missing_session_id_session.jsonl", [r1])


def missing_version_session():
    r1 = user_text("u1", None, "hi", "2026-08-06T19:50:00Z")
    del r1["version"]
    write("missing_version_session.jsonl", [r1, last_prompt("u1")])


def unsupported_version_session():
    recs = [
        rec(type="user", uuid="u1", parentUuid=None, version="9.9.9", timestamp="2026-08-06T16:00:00Z",
            message={"role": "user", "content": [{"type": "text", "text": "hi"}]}),
        last_prompt("u1"),
    ]
    write("unsupported_version_session.jsonl", recs)


def malformed_session():
    # one valid line, then a broken JSON line
    good = json.dumps(user_text("u1", None, "ok", "2026-08-06T17:00:00Z"), ensure_ascii=False)
    (FX / "malformed_session.jsonl").write_text(good + "\n{ this is not json }\n", encoding="utf-8")


def unknown_type_session():
    recs = [
        user_text("u1", None, "hi", "2026-08-06T18:00:00Z"),
        {"type": "brand-new-record-type", "uuid": "x1", "parentUuid": "u1", "sessionId": SID,
         "version": V, "timestamp": "2026-08-06T18:00:01Z"},
        last_prompt("u1"),
    ]
    write("unknown_type_session.jsonl", recs)


if __name__ == "__main__":
    complete_session()
    subagent_session()
    hook_prevented_session()
    missing_parent_session()
    broken_tool_ref_session()
    secret_session()
    placeholder_session()
    unsupported_version_session()
    malformed_session()
    unknown_type_session()
    # H2 adversarial
    mixed_session_ids()
    cyclic_parent_session()
    dangling_tool_use_session()
    result_before_use_session()
    missing_session_id_session()
    missing_version_session()
    print("fixtures written to", FX)
