import { readdirSync, rmSync } from 'node:fs'
import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import type { Plugin } from 'vite'
import { defineConfig, loadEnv } from 'vite'

const BUILD_EXCLUDED_FILENAMES = new Set([
  'AGENTS.md',
  'CLAUDE.md',
  'DESIGN.md',
  'DEPLOY.md',
  'mockServiceWorker.js',
])
const SURFACES = new Set(['console', 'marketing'])
const SURFACE_APPS = {
  console: path.resolve(__dirname, './src/surfaces/console/App.tsx'),
  marketing: path.resolve(__dirname, './src/surfaces/marketing/App.tsx'),
}

function resolveSurface(mode: string, env: Record<string, string>): 'console' | 'marketing' {
  const requested =
    process.env.VITE_ACGI_SURFACE ||
    env.VITE_ACGI_SURFACE ||
    (mode === 'marketing' ? 'marketing' : 'console')
  if (!SURFACES.has(requested)) {
    throw new Error(`Unsupported VITE_ACGI_SURFACE "${requested}". Use "console" or "marketing".`)
  }
  return requested as 'console' | 'marketing'
}

function removeInternalDocs(dir: string) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const filePath = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      removeInternalDocs(filePath)
      continue
    }
    if (BUILD_EXCLUDED_FILENAMES.has(entry.name)) rmSync(filePath, { force: true })
  }
}

function stripInternalDocs(): Plugin {
  let outDir = path.resolve(__dirname, 'dist')
  return {
    name: 'strip-internal-docs',
    apply: 'build',
    configResolved(config) {
      outDir = path.resolve(config.root, config.build.outDir)
    },
    closeBundle() {
      removeInternalDocs(outDir)
    },
  }
}

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const proxyTarget = env.VITE_API_PROXY_TARGET || 'http://localhost:8080'
  const surface = resolveSurface(mode, env)
  const outDir = process.env.ACGI_OUT_DIR || env.ACGI_OUT_DIR || 'dist'

  return {
    plugins: [react(), tailwindcss(), stripInternalDocs()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
        '@surface/App': SURFACE_APPS[surface],
      },
    },
    build: {
      outDir,
    },
    server: {
      proxy: {
        // /api/* in dev. Bypassed entirely when VITE_USE_MOCKS=true (MSW
        // intercepts before fetch reaches the network).
        '/api': {
          target: proxyTarget,
          changeOrigin: true,
        },
      },
    },
  }
})
