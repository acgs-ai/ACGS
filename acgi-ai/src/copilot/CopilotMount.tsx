import { CopilotPanel } from './CopilotPanel'

/**
 * Default-exported entry so the copilot tree (panel + `@ag-ui/client`) is
 * code-split into its own lazy chunk, downloaded only when the panel mounts
 * (`VITE_COPILOT_ENABLED === 'true'`). Note: the chunk is still emitted at build
 * time and counts toward the marketing perf budget — the flag defers download,
 * not bundle cost.
 */
export default function CopilotMount() {
  return <CopilotPanel />
}
