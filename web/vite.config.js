import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// Relative base ('./') so the built assets work when the backend serves
// the panel under a secret path prefix (the `path` env variable).
export default defineConfig({
  base: './',
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:3000',
      '/download': 'http://localhost:3000',
      '/share': 'http://localhost:3000',
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
})
