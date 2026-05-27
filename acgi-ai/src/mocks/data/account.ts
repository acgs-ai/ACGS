import type { AccountView } from '../../api/types'

export const ACCOUNT_VIEW: AccountView = {
  identity: [
    { key: 'name', value: 'M. Custodian', source: 'sso' },
    { key: 'email', value: 'm.custodian@hofstra-lorenz.com', source: 'sso' },
    { key: 'role', value: 'custodian · clerk', source: 'constitution' },
    { key: 'lane.allowed', value: 'Custodian, Validator', source: 'constitution' },
    { key: 'mfa', value: 'WebAuthn · iCloud Keychain', source: 'self' },
    {
      key: 'attestation.cert',
      value: 'CERT-9821 · valid through 2026-12-01',
      source: 'sso',
    },
  ],
  sessions: [
    {
      id: 'S-9421',
      device: 'macOS · Safari 19',
      ip: '203.0.113.41',
      location: 'New York, NY',
      started: '2026-05-04 13:02 UTC',
      current: true,
    },
    {
      id: 'S-9407',
      device: 'iPadOS · Safari',
      ip: '203.0.113.41',
      location: 'New York, NY',
      started: '2026-05-04 09:18 UTC',
      current: false,
    },
    {
      id: 'S-9388',
      device: 'macOS · Chrome 198',
      ip: '198.51.100.7',
      location: 'Brooklyn, NY · vpn',
      started: '2026-05-03 21:54 UTC',
      current: false,
    },
  ],
  recentActions: [
    {
      ts: '2026-05-04 13:32:41',
      posture: 'privileged',
      action: 'Opened deliberation D-2031 on Matter-9821',
      cite: '§164.502(b)',
    },
    {
      ts: '2026-05-04 12:47:55',
      posture: 'confirmed',
      action: 'Approved P-1497 promotion to canon',
      cite: 'SR 11-7 §V',
    },
    {
      ts: '2026-05-04 11:14:08',
      posture: 'partial',
      action: 'Held P-1499 pending validator quorum',
      cite: 'Internal §3.1',
    },
    {
      ts: '2026-05-03 17:08:22',
      posture: 'confirmed',
      action: 'Switched tenancy to Hofstra & Lorenz',
      cite: 'Internal §3.4',
    },
    {
      ts: '2026-05-03 09:18:11',
      posture: 'confirmed',
      action: 'Sign-in via Google Workspace SSO',
      cite: 'auth · attested',
    },
  ],
}
