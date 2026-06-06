# Agent Evaluation Checklist

Use before allowing an agent into a new environment or higher autonomy tier.

## Identity and scope

- [ ] Agent purpose is documented.
- [ ] Owner is named.
- [ ] Allowed tools are listed.
- [ ] Forbidden actions are listed.
- [ ] Environment boundaries are clear.

## Data and privacy

- [ ] Data classes are documented.
- [ ] Sensitive data handling is defined.
- [ ] Retention and deletion are defined.
- [ ] Logs do not leak secrets.

## Runtime controls

- [ ] Tool calls are gated.
- [ ] High-risk actions require approval.
- [ ] Denied actions are logged.
- [ ] Rollback/deactivation path exists.

## Quality and safety

- [ ] Task evals exist.
- [ ] Security tests cover prompt injection, output handling, supply chain, sensitive disclosure, and excessive agency.
- [ ] Human oversight is meaningful for consequential tasks.
- [ ] Incident response process exists.

## Evidence

- [ ] Model/provider/version is recorded.
- [ ] Policy/control version is recorded.
- [ ] Evaluation date and results are recorded.
- [ ] Re-check triggers are defined.
