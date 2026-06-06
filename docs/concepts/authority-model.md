# Authority model

ACGS treats authority as a runtime fact that must be checked before action. A model proposing a step is not automatically authorized to execute it.

## Roles

- **Actor**: the agent, workflow, user, or service proposing an action.
- **Validator**: the governance principal that evaluates the action.
- **Policy bundle**: the reviewed policy context used for the decision.
- **Executor**: the host component that performs the side effect only after authorization.
- **Auditor**: a reviewer or automated process that replays the evidence later.

## Separation principle

The actor that wants to act should not be the sole authority that approves the action. ACGS keeps proposal, validation, execution, and audit evidence distinct so that approvals can be inspected and replayed.

## Boundary inputs

A useful authorization check includes:

- actor identity;
- tool or action name;
- normalized arguments;
- tenant or workspace context;
- policy version or bundle hash;
- expected side effect boundary;
- receipt expiry, if applicable.

## Failure posture

If identity, policy, payload parsing, or receipt verification is missing or malformed, the host should fail closed before the side effect.
