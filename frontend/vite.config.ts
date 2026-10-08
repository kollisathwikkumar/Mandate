import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', 'VITE_');
  const apiTarget = env.VITE_API_PROXY_TARGET || 'http://127.0.0.1:3000';
  const mcpTarget = env.VITE_MCP_PROXY_TARGET || 'http://127.0.0.1:3100';
  return {
  plugins: [react()],
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            { name: 'react-vendor', test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/, priority: 20 },
            { name: 'three-vendor', test: /node_modules[\\/](@react-three|three)[\\/]/, maxSize: 420_000, priority: 15 },
          ],
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': { target: apiTarget, changeOrigin: false },
      '/health': { target: apiTarget, changeOrigin: false },
      '/auth': { target: apiTarget, changeOrigin: false },
      '/mcp': { target: mcpTarget, changeOrigin: false },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./tests/setup.ts'],
  },
  };
});
