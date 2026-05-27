import '@testing-library/jest-dom/vitest'
import { afterAll, afterEach, beforeAll } from 'vitest'
import { resetMswNodeServer, startMswNodeServer, stopMswNodeServer } from '../src/mocks/server'

beforeAll(() => {
  startMswNodeServer()
})

afterEach(() => {
  resetMswNodeServer()
})

afterAll(() => {
  stopMswNodeServer()
})
