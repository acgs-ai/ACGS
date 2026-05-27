import { readdirSync, rmSync } from 'node:fs'
import path from 'node:path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import type { Plugin } from 'vite'
import { defineConfig, loadEnv } from 'vite'

const INTERNAL_DOC_NAMES = new Set(['AGENTS.md', 'CLAUDE.md', 'DESIGN.md', 'DEPLOY.md'])

function removeInternalDocs(dir: string) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const filePath = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      removeInternalDocs(filePath)
      continue
    }
    if (INTERNAL_DOC_NAMES.has(entry.name)) rmSync(filePath, { force: true })
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
  return {
    plugins: [react(), tailwindcss(), stripInternalDocs()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
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
