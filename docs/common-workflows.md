# Common workflows

## 1. Evaluate before a side effect

1. The host normalizes a proposed tool call.
2. ACGS evaluates policy and authority before execution.
3. The host executes only if the decision permits it.
4. A receipt and audit event are retained for replay.

Use this workflow for file writes, shell commands, MCP tool calls, deployment steps, and other actions that cross a trust boundary.

## 2. Wire a hook-capable host

1. Run `gove-zone setup` to produce host guidance.
2. Install the hook command in the host's pre-tool event.
3. Start in report mode until receipts are visible.
4. Move to enforce mode only after deny paths are tested.

## 3. Review an audit trail

1. Locate the audit JSONL path used by the host.
2. Verify each event is chained to the previous event where applicable.
3. Verify the decision receipt against expected actor, action, arguments, and policy context.
4. Preserve the audit path and command output in the review evidence packet.

## 4. Add a new agent framework adapter

1. Identify the framework's tool-call payload shape.
2. Normalize the payload into the ACGS tool-call contract.
3. Add tests for allow, deny, malformed, and batch behavior.
4. Prove the adapter is wired into the actual host path, not only imported in a unit test.

## 5. Make readiness claims safely

Use precise claim classes:

- **local proof**: command output from this checkout;
- **release readiness**: artifact and evidence packet produced locally;
- **deployment proof**: live workflow and post-deploy evidence;
- **compliance proof**: independent review and domain-specific evidence.

Do not collapse these into a single production-ready claim.
