import type { SettingSection } from '../../api/types'

export const SETTING_SECTIONS: SettingSection[] = [
  {
    title: 'Deliberation',
    settings: [
      {
        key: 'deliberation.sla.hours',
        desc: 'Maximum time a high-risk decision may sit in the human-in-the-loop queue before the bus auto-refuses.',
        value: '8',
        source: 'constitution',
      },
      {
        key: 'deliberation.queue.max',
        desc: 'Soft cap on open deliberations; over this, new escalations route to the on-call partner directly.',
        value: '24',
        source: 'operator',
      },
      {
        key: 'deliberation.escalation.chain',
        desc: 'Ordered roles consulted when a deliberation breaches its SLA.',
        value: 'counsel → maintainer → partner',
        source: 'default',
      },
    ],
  },
  {
    title: 'MACI lanes',
    settings: [
      {
        key: 'maci.proposer.parallelism',
        desc: 'Concurrent proposers permitted to draft against the same matter.',
        value: '4',
        source: 'operator',
      },
      {
        key: 'maci.validator.quorum',
        desc: 'Independent validators required before a draft may be promoted to canon.',
        value: '2',
        source: 'constitution',
      },
      {
        key: 'maci.executor.scope.policy',
        desc: 'How tightly the bus checks scope intersection between the executor and its tool.',
        value: 'strict',
        source: 'constitution',
      },
    ],
  },
  {
    title: 'Bus',
    settings: [
      {
        key: 'bus.drift.tolerance.bytes',
        desc: 'Tolerated byte difference between the compiled constitution and the runtime constitution.',
        value: '0',
        source: 'constitution',
      },
      {
        key: 'bus.retry.policy',
        desc: 'Backoff policy on a transient bus refusal (not on a constitutional refusal).',
        value: 'exponential · 3 attempts · 5s base',
        source: 'operator',
      },
      {
        key: 'bus.hash.refresh.seconds',
        desc: 'How often the bus, gateway, and worker recompute and compare the constitutional hash.',
        value: '30',
        source: 'default',
      },
    ],
  },
  {
    title: 'Notifications',
    settings: [
      {
        key: 'notify.event.email',
        desc: 'Where the bus mails a refusal digest at the end of each UTC day.',
        value: 'sec-ops@acgs.ai',
        source: 'operator',
      },
      {
        key: 'notify.webhook.url',
        desc: 'Streaming subscription endpoint for the live ledger.',
        value: 'wss://bus.internal/observe',
        source: 'operator',
      },
      {
        key: 'notify.severity.threshold',
        desc: 'Minimum posture at which a refusal is paged out of band.',
        value: 'partial',
        source: 'operator',
      },
    ],
  },
]
