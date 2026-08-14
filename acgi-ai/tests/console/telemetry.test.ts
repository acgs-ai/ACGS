// Console telemetry emitter gates (docs/POSTHOG_CONSOLE_TELEMETRY_DESIGN.md
// §4 resolution table, §6 gate rows):
//   - route-template resolution never resolves $receiptId (leak regression)
//   - the resolution table covers every route in the console route tree
//     (fails closed when a route is added without a table entry)
//   - flag off ⇒ zero telemetry network calls, exercised through a real
//     rendered user flow, not just the emitter API
//   - flag on ⇒ batches post to same-origin /api/telemetry with only
//     allowlisted shapes

import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { fireEvent, render, screen } from '@testing-library/react'
import React from 'react'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { CONSOLE_SECTIONS, routeTemplateFor } from '../../src/surfaces/console/telemetry'

// Route paths the resolution table explicitly handles. A new route in the
// console route tree must be added here AND to routeTemplateFor's mapping —
// this set is the fails-closed coverage gate.
const HANDLED_ROUTE_PATHS = new Set([
  '/login',
  '/console',
  '/console/overview',
  '/console/$section',
  '/console/audit/$receiptId',
  '$',
])

describe('route-template resolution (design §4)', () => {
  test('receipt ids NEVER resolve — audit route reports the literal template', () => {
    expect(routeTemplateFor('/console/audit/rcpt-2f9a44c1')).toBe('/console/audit/$receiptId')
    expect(routeTemplateFor('/console/audit/../../etc')).toBe('/console/audit/$receiptId')
  })

  test('known sections resolve through the closed enum', () => {
    for (const section of CONSOLE_SECTIONS) {
      expect(routeTemplateFor(`/console/${section}`)).toBe(`/console/${section}`)
    }
  })

  test('unknown sections stay a literal template (default-deny)', () => {
    expect(routeTemplateFor('/console/rcpt-secret-name')).toBe('/console/$section')
    expect(routeTemplateFor('/console')).toBe('/console')
    expect(routeTemplateFor('/login')).toBe('/login')
    expect(routeTemplateFor('/anything-else')).toBe('$')
  })

  test('every route in the console route tree is covered by the table', () => {
    const appSource = readFileSync(resolve(__dirname, '../../src/surfaces/console/App.tsx'), 'utf8')
    const routePaths = [...appSource.matchAll(/path:\s*'([^']+)'/g)].map((m) => m[1])
    expect(routePaths.length).toBeGreaterThanOrEqual(5)
    for (const routePath of routePaths) {
      expect(
        HANDLED_ROUTE_PATHS.has(routePath),
        `route ${routePath} has no entry in the telemetry resolution table — ` +
          'add it to routeTemplateFor and HANDLED_ROUTE_PATHS (design §4)',
      ).toBe(true)
    }
  })

  test('sidebar section paths all resolve without falling to the generic template', () => {
    const consoleSource = readFileSync(resolve(__dirname, '../../src/routes/Console.tsx'), 'utf8')
    const navPaths = [...consoleSource.matchAll(/path:\s*'(\/console[^']*)'/g)].map((m) => m[1])
    expect(navPaths.length).toBeGreaterThanOrEqual(10)
    for (const navPath of navPaths) {
      expect(routeTemplateFor(navPath)).not.toBe('/console/$section')
    }
  })
})

describe('flag off (default test env): zero telemetry network calls', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  test('a real Login flow emits nothing', async () => {
    expect(import.meta.env.VITE_CONSOLE_TELEMETRY).not.toBe('1')
    const beacon = vi.fn(() => true)
    Object.defineProperty(navigator, 'sendBeacon', { value: beacon, configurable: true })
    const fetchSpy = vi.spyOn(globalThis, 'fetch')

    const { Login } = await import('../../src/routes/Login')
    render(React.createElement(Login, {}))
    const providerButton = screen.getAllByRole('button')[0]
    fireEvent.click(providerButton)

    const { __flushForTest } = await import('../../src/surfaces/console/telemetry')
    __flushForTest()

    expect(beacon).not.toHaveBeenCalled()
    const telemetryFetches = fetchSpy.mock.calls.filter(([input]) =>
      String(input).includes('/api/telemetry'),
    )
    expect(telemetryFetches).toHaveLength(0)
  })

  test('track() is a no-op through the emitter API', async () => {
    const beacon = vi.fn(() => true)
    Object.defineProperty(navigator, 'sendBeacon', { value: beacon, configurable: true })
    const { track, __flushForTest } = await import('../../src/surfaces/console/telemetry')
    track('console_signed_out')
    track('console_section_navigated', { route_template: '/console/policies' })
    __flushForTest()
    expect(beacon).not.toHaveBeenCalled()
  })
})

describe('flag on: batches post to same-origin /api/telemetry', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
    vi.resetModules()
    vi.restoreAllMocks()
  })

  async function freshEnabledEmitter() {
    vi.resetModules()
    vi.stubEnv('VITE_CONSOLE_TELEMETRY', '1')
    return import('../../src/surfaces/console/telemetry')
  }

  test('events flush as one schema-tagged batch via sendBeacon', async () => {
    const beacon = vi.fn(() => true)
    Object.defineProperty(navigator, 'sendBeacon', { value: beacon, configurable: true })
    const { track, __flushForTest } = await freshEnabledEmitter()

    track('console_section_navigated', { route_template: '/console/policies' })
    track('deliberation_action_taken', { action_kind: 'approved' })
    __flushForTest()

    expect(beacon).toHaveBeenCalledTimes(1)
    const [endpoint, blob] = beacon.mock.calls[0] as [string, Blob]
    expect(endpoint).toBe('/api/telemetry')
    const body = JSON.parse(await blob.text())
    expect(body.schema).toBe('console-telemetry/1')
    expect(body.events).toHaveLength(2)
    for (const event of body.events) {
      expect(Object.keys(event).sort()).toEqual(['emitted_at', 'event', 'properties'])
    }
    expect(body.events[0].properties).toEqual({ route_template: '/console/policies' })
  })

  test('falls back to keepalive fetch when sendBeacon is unavailable', async () => {
    Object.defineProperty(navigator, 'sendBeacon', { value: undefined, configurable: true })
    const fetchSpy = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(null, { status: 202 }))
    const { track, __flushForTest } = await freshEnabledEmitter()

    track('magic_link_requested')
    __flushForTest()

    const call = fetchSpy.mock.calls.find(([input]) => String(input).includes('/api/telemetry'))
    expect(call).toBeDefined()
    const init = call?.[1]
    expect(init?.keepalive).toBe(true)
    expect(init?.credentials).toBe('same-origin')
  })

  test('the batch cap forces a flush at 20 events', async () => {
    const beacon = vi.fn(() => true)
    Object.defineProperty(navigator, 'sendBeacon', { value: beacon, configurable: true })
    const { track } = await freshEnabledEmitter()
    for (let i = 0; i < 20; i += 1) {
      track('console_signed_out')
    }
    expect(beacon).toHaveBeenCalledTimes(1)
  })
})
