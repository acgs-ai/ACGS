# Error codes

This page defines documentation-level error classes for governed workflows. Exact CLI exception names and exit codes should be checked against the current `gove-zone` implementation.

## Suggested classes

| Class | Meaning | Expected host behavior |
| --- | --- | --- |
| `runtime.malformed_payload` | The event cannot be normalized. | Block before side effect. |
| `runtime.malformed_batch` | A recognized batch includes an unparseable child call. | Block the batch before side effects. |
| `policy.load_failed` | Required policy material cannot be loaded. | Block in enforce mode. |
| `receipt.verification_failed` | Receipt does not match expected action context. | Block before side effect. |
| `audit.write_failed` | Required audit evidence could not be written. | Block in enforce mode. |
| `decision.denied` | Policy denied the action. | Block. |
| `decision.escalated` | Policy requires review. | Block pending review. |

## Evidence to capture

For each failure, capture the input event, command output, audit path, policy reference, and host mode. Do not include secrets in troubleshooting artifacts.
