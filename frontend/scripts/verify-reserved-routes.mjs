const base = process.env.MANDATE_FRONTEND_URL ?? 'http://127.0.0.1:5173';
for (const path of ['/api/v1/no-such-route', '/auth/no-such-route', '/mcp/no-such-route', '/health/no-such-route']) {
  const response = await fetch(new URL(path, base), { headers: { accept: 'text/html' }, redirect: 'manual' });
  const body = await response.text();
  if (response.ok || body.includes('<!doctype html>') || body.includes('<div id="root">')) {
    throw new Error(`${path} was swallowed by the frontend shell (${response.status})`);
  }
  console.log(`${path}: ${response.status}; no frontend shell`);
}
