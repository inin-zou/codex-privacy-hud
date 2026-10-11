import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

// Relative base so the built `dist/` can be served from any path, including
// straight out of `local_ui_server.py`'s static routes later on.
// Dev server stays on localhost only (CLAUDE.md I2: nothing beyond 127.0.0.1).
// `/api/*` is proxied to the local audit server when VITE_API_TARGET is set,
// e.g. VITE_API_TARGET=http://127.0.0.1:51234 (the URL `$privacy` prints).
export default defineConfig(({ mode }) => {
  const target = loadEnv(mode, '.', 'VITE_').VITE_API_TARGET
  return {
    plugins: [react()],
    base: './',
    server: {
      port: 5173,
      proxy: target ? { '/api': { target, changeOrigin: false } } : undefined,
    },
  }
})
