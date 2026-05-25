/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_USE_MOCKS?: 'true' | 'false'
  readonly VITE_BYPASS_SESSION?: 'true' | 'false'
  readonly VITE_API_PROXY_TARGET?: string
  readonly VITE_EVAL_MODE?: 'true' | 'false'
  readonly VITE_LOG_LEVEL?: 'debug' | 'info' | 'warn' | 'error'
  readonly VITE_DISABLE_REFRESH_INTERVAL?: 'true' | 'false'
  readonly VITE_FIXTURE_FALLBACK_VISIBLE?: 'true' | 'false'
  readonly VITE_PRIVILEGE_BANNER_AUDIT?: 'true' | 'false'
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
