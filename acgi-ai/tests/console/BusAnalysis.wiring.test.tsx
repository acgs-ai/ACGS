// T037 — Defect wiring contract tests.
//
// The defect surface (`/api/bus/defects`) and `useBusDefects` hook are not
// yet implemented. This test pins the *data-fetch contract* so the future
// hook + panel land against the shape the analyzer already speaks.
//
// We assert two things:
//   1. The MSW stack can return a defect list payload at /api/bus/defects.
//   2. The shape parses cleanly (kind, items[], item.id/kind/severity).
//
// The full panel-render assertion is `.skip`-marked until the
// `useBusDefects` hook + DefectPanel component land in src/.

import { describe, expect, test } from 'vitest'
import { HttpResponse, http } from 'msw'
import { screen } from '@testing-library/react'
import { server } from '../../src/mocks/server'
import { BusAnalysis } from '../../src/routes/console/BusAnalysis'
import { renderWithProviders } from './render'

type BusDefect = {
  id: string
  kind: 'unwired-handler' | 'orphan-response' | 'ingest-gap' | 'tampered-chain'
  severity: 'info' | 'warning' | 'critical'
  correlation_id: string
  detected_at: string
  detail: string
}

type BusDefectList = {
  kind: 'defect-list'
  items: BusDefect[]
}

const FIXTURE: BusDefectList = {
  kind: 'defect-list',
  items: [
    {
      id: 'defect-0001',
      kind: 'unwired-handler',
      severity: 'warning',
      correlation_id: '33333333-3333-7333-8333-333333333333',
      detected_at: '2026-05-14T13:32:45.000Z',
      detail: 'Handler reasoner.evaluate was dispatched but never registered.',
    },
  ],
}

describe('BusAnalysis defect wiring (T037)', () => {
  test('a test-local handler can serve /api/bus/defects with a defect payload', async () => {
    server.use(
      http.get('/api/bus/defects', () => HttpResponse.json(FIXTURE)),
    )

    const response = await fetch('/api/bus/defects')
    expect(response.ok).toBe(true)

    const body = (await response.json()) as BusDefectList
    expect(body.kind).toBe('defect-list')
    expect(body.items).toHaveLength(1)

    const defect = body.items[0]
    expect(defect.id).toBe('defect-0001')
    expect(defect.kind).toBe('unwired-handler')
    expect(defect.severity).toBe('warning')
    expect(defect.correlation_id).toMatch(/^[0-9a-f-]{36}$/)
  })

  test('an empty defect list still parses', async () => {
    server.use(
      http.get('/api/bus/defects', () =>
        HttpResponse.json({ kind: 'defect-list', items: [] }),
      ),
    )

    const response = await fetch('/api/bus/defects')
    const body = (await response.json()) as BusDefectList
    expect(body.kind).toBe('defect-list')
    expect(body.items).toEqual([])
  })

  test('DefectPanel renders the defect list when useBusDefects returns data', async () => {
    server.use(
      http.get('/api/bus/defects', () => HttpResponse.json(FIXTURE)),
    )
    renderWithProviders(<BusAnalysis />)
    await screen.findByText(/wiring defects/i)
    expect(await screen.findByText(/reasoner\.evaluate/i)).toBeInTheDocument()
  })
})
