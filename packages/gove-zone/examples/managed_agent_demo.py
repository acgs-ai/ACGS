"""End-to-End Demo of the Next-Generation Managed Agent Platform.

Shows how to define a YAML policy, construct a ManagedAgent with sandbox
isolation, and execute governed tools in less than 40 lines of user code.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from gove_zone import DeniedError, LocalProcessSandbox, ManagedAgent, YAMLPolicy

# 1. Define agent boundaries declaratively in YAML
YAML_POLICY = """
id: research-agent-policy/v1
rules:
  - id: block-sensitive-directory
    effect: deny
    tools:
      - write_evidence
    state_contains:
      unsafe_path: true
    reason: Modify operations inside protected directories are blocked.
"""


# 2. Define a standard Python tool function
def write_evidence(path: str, content: str) -> str:
    """A tool to write research evidence to a file."""
    return f"Successfully wrote {len(content)} characters to {path}"


def main() -> None:
    print("=== Next-Generation Managed Agent Platform Demo ===")

    # Use a temporary directory for audit ledger and sandbox
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_path = Path(tmpdir) / "audit.jsonl"

        # 3. Initialize declarative policy & sandbox
        policy = YAMLPolicy.from_yaml(YAML_POLICY)
        sandbox = LocalProcessSandbox(use_bwrap=False)

        # 4. Construct the ManagedAgent
        agent = ManagedAgent(
            name="research-bot",
            policy=policy,
            sandbox=sandbox,
            audit_path=audit_path,
        )

        # 5. Register the tool
        agent.register_tool("write_evidence", write_evidence)

        print("\n[Step 1] Dispatching without a strict receipt dispatcher...")
        try:
            agent.dispatch(
                "write_evidence",
                {"path": "/tmp/evidence.txt", "content": "Proof of correctness"},
                goal="Record verification evidence",
                state={"unsafe_path": False},
            )
        except DeniedError as e:
            print(f"Blocked before side effect: {e}")
            print(f"Decision Record Code: {e.record.matched_rules}")
            print(f"Tamper-Evident Chain Head: {e.audit_hash}")

        print("\n[Step 2] Dispatching a blocked tool call that violates policy...")
        # This call will trigger a DENY policy decision because unsafe_path is true
        try:
            agent.dispatch(
                "write_evidence",
                {"path": "/etc/shadow", "content": "compromised"},
                goal="Attempt privilege escalation",
                state={"unsafe_path": True},
            )
        except DeniedError as e:
            print(f"Governance Membraned blocked execution: {e}")
            print(f"Decision Record Code: {e.record.matched_rules}")
            print(f"Tamper-Evident Chain Head: {e.audit_hash}")

        print("\n[Step 3] Verifying the audit ledger integrity...")
        ledger_content = audit_path.read_text(encoding="utf-8")
        print(f"Total audit events recorded: {len(ledger_content.splitlines())}")
        print("Demo completed successfully!")


if __name__ == "__main__":
    main()
