# agent-bus-analyzer

Observer-only analysis layer for the `EnhancedAgentBus` + `gove-zone` audit
chain. Captures dispatch / response events, persists hash-chained traces in
append-only JSONL, surfaces wiring defects and tampering through a privileged
console view.

- **Spec**: `specs/001-enhanced-agent-bus-analysis/spec.md`
- **Plan**: `specs/001-enhanced-agent-bus-analysis/plan.md`
- **Tasks**: `specs/001-enhanced-agent-bus-analysis/tasks.md`

The package is read-only on the bus and the gove-zone audit chain. It is
never on the authorization path.
