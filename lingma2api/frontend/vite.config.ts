import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../frontend-dist',
    emptyOutDir: true,
  },
  server: {
    port: 3000,
    proxy: {
      '/v1': 'http://127.0.0.1:8080',
      '/admin': 'http://127.0.0.1:8080',
    },
  },
});
