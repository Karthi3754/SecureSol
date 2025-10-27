import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:5000',
        changeOrigin: true,
      },
      '/ai-engine': {
      target: 'http://localhost:8001', // analyzer service
      changeOrigin: true,
      rewrite: (path) => path.replace(/^\/analyzer/, ''),
    },
    },
  },
  optimizeDeps: {
    include: ['react-dropzone'], // <-- explicitly pre-bundle react-dropzone
  },
})
