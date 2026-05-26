import path from 'node:path'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vitest/config'

// Vitest config for acgi-ai unit tests.
//
// Notes:
// - Tests live in `tests/**` (outside `src/`) so `tsconfig.app.json` (which
//   only `include`s `src`) keeps production type-checking clean.
// - `define` injects VITE_USE_MOCKS=true: `src/mocks/handlers.ts` throws at
//   import time when this flag is not 'true'.
// - Alias `@/*` mirrors `vite.config.ts`.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  define: {
    'import.meta.env.VITE_USE_MOCKS': JSON.stringify('true'),
  },
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['tests/**/*.test.{ts,tsx}'],
    exclude: ['tests/e2e/**', 'node_modules/**', 'dist/**'],
    setupFiles: ['./tests/setup.ts'],
  },
})
