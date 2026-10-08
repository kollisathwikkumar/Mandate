const apiValue = process.env.MANDATE_STAGING_API_URL;
const originValue = process.env.MANDATE_STAGING_ORIGIN;
const token = process.env.MANDATE_STAGING_TOKEN;

function fail(message) {
  console.error(`FAIL ${message}`);
  process.exitCode = 1;
}

function exactUrl(value, name) {
  if (value === undefined || value.trim() === '') throw new Error(`${name} is required`);
  const url = new URL(value);
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if ((url.protocol !== 'https:' && !(loopback && url.protocol === 'http:'))
    || url.pathname !== '/' || url.search !== '' || url.hash !== '' || url.username !== '' || url.password !== '') {
    throw new Error(`${name} must be an HTTPS origin (HTTP loopback only for local checks)`);
  }
  return url.origin;
}

if (apiValue === undefined || originValue === undefined || token === undefined || token.trim() === '') {
  console.error('Set MANDATE_STAGING_API_URL, MANDATE_STAGING_ORIGIN, and MANDATE_STAGING_TOKEN; the token is read from the environment and never printed.');
  process.exit(2);
}

let api;
let origin;
try {
  api = exactUrl(apiValue, 'MANDATE_STAGING_API_URL');
  origin = exactUrl(originValue, 'MANDATE_STAGING_ORIGIN');
} catch (error) {
  console.error(error instanceof Error ? error.message : 'Invalid staging configuration');
  process.exit(2);
}

async function request(path, options = {}) {
  return fetch(new URL(path, `${api}/`), { ...options, signal: AbortSignal.timeout(8000) });
}

async function check(name, action) {
  try {
    const result = await action();
    if (!result) fail(name);
    else console.log(`PASS ${name}`);
  } catch (error) {
    fail(`${name}: ${error instanceof Error ? error.message : 'request failed'}`);
  }
}

await check('liveness endpoint', async () => {
  const response = await request('/health/live');
  return response.status === 200 && (await response.json()).status === 'live';
});

await check('readiness endpoint and PostgreSQL', async () => {
  const response = await request('/health/ready');
  return response.status === 200 && (await response.json()).status === 'ready';
});

await check('OpenAPI contract is published', async () => {
  const response = await request('/api/v1/openapi.json');
  const document = await response.json();
  return response.status === 200 && document.openapi === '3.1.0'
    && typeof document.paths === 'object' && Object.keys(document.paths).length > 0;
});

await check('configured CORS preflight is exact and bearer-compatible', async () => {
  const response = await request('/api/v1/me', {
    method: 'OPTIONS',
    headers: {
      Origin: origin,
      'Access-Control-Request-Method': 'GET',
      'Access-Control-Request-Headers': 'authorization',
    },
  });
  return response.status === 204
    && response.headers.get('access-control-allow-origin') === origin
    && response.headers.get('access-control-allow-methods')?.includes('GET') === true
    && response.headers.get('access-control-allow-headers')?.toLowerCase().includes('authorization') === true
    && response.headers.get('access-control-allow-credentials') === null;
});

await check('staging OIDC bearer authentication and /me contract', async () => {
  const response = await request('/api/v1/me', {
    headers: { Authorization: `Bearer ${token}`, Origin: origin },
  });
  return response.status === 200 && response.headers.get('access-control-allow-origin') === origin;
});

if (process.exitCode === 1) process.exit(1);
