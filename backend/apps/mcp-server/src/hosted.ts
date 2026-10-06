import {
  OAuthError,
  OAuthErrorCode,
  createMcpHandler,
  getOAuthProtectedResourceMetadataUrl,
  hostHeaderValidationResponse,
  originValidationResponse,
  requireBearerAuth,
} from '@modelcontextprotocol/server';
import { z } from 'zod';
import { createMandateMcpServer, MandateRestMcpClient } from './server.js';

export interface HostedMcpConfiguration {
  readonly apiUrl: string;
  readonly resourceUrl: string;
  readonly issuer: string;
  readonly organizationId: string | null;
  readonly allowedOrigins: readonly string[];
}

function parseUrl(value: string, label: string, allowLoopbackHttp: boolean): URL {
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error(`${label} must be an absolute URL`); }
  const loopback = new Set(['127.0.0.1', 'localhost', '[::1]']);
  if (parsed.username || parsed.password || parsed.search || parsed.hash
    || (parsed.protocol !== 'https:' && !(allowLoopbackHttp && parsed.protocol === 'http:' && loopback.has(parsed.hostname)))) {
    throw new Error(`${label} must use HTTPS (HTTP only for loopback development), without credentials, query, or fragment`);
  }
  return parsed;
}

function parseOrigins(values: readonly string[]): string[] {
  return values.map((value) => {
    let origin: URL;
    try { origin = new URL(value); } catch { throw new Error('MANDATE_MCP_ALLOWED_ORIGINS must contain absolute origins'); }
    const loopback = new Set(['127.0.0.1', 'localhost', '[::1]']);
    if ((origin.protocol !== 'https:' && !(origin.protocol === 'http:' && loopback.has(origin.hostname)))
      || origin.origin !== value || origin.username || origin.password) {
      throw new Error('MANDATE_MCP_ALLOWED_ORIGINS must contain canonical HTTPS origins (HTTP only for loopback development)');
    }
    return origin.origin;
  });
}

export function parseHostedMcpConfiguration(environment: NodeJS.ProcessEnv): HostedMcpConfiguration {
  const apiUrl = z.string().url().parse(environment.MANDATE_API_URL);
  const resourceUrl = z.string().url().parse(environment.MANDATE_MCP_RESOURCE_URL);
  const issuer = z.string().url().parse(environment.MANDATE_JWT_ISSUER);
  parseUrl(apiUrl, 'MANDATE_API_URL', true);
  const resource = parseUrl(resourceUrl, 'MANDATE_MCP_RESOURCE_URL', true);
  parseUrl(issuer, 'MANDATE_JWT_ISSUER', false);
  if (resource.pathname !== '/mcp' || resource.href !== resourceUrl || !resourceUrl.endsWith('/mcp')) {
    throw new Error('MANDATE_MCP_RESOURCE_URL must be a canonical URL ending in /mcp');
  }
  const organizationId = environment.MANDATE_ORGANIZATION_ID ?? null;
  const allowedOrigins = environment.MANDATE_MCP_ALLOWED_ORIGINS === undefined
    ? [] : parseOrigins(environment.MANDATE_MCP_ALLOWED_ORIGINS.split(',').map((item) => item.trim()).filter(Boolean));
  return { apiUrl, resourceUrl, issuer, organizationId, allowedOrigins };
}

function metadataResponse(configuration: HostedMcpConfiguration, request: Request): Response | undefined {
  const resourceUrl = new URL(configuration.resourceUrl);
  const metadataPath = new URL(getOAuthProtectedResourceMetadataUrl(resourceUrl)).pathname;
  if (new URL(request.url).pathname !== metadataPath) return undefined;
  const corsHeaders = {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, OPTIONS',
    'access-control-allow-headers': 'content-type',
    'content-type': 'application/json',
  };
  if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders });
  if (request.method !== 'GET') return new Response(JSON.stringify({ error: 'method_not_allowed' }), { status: 405, headers: { ...corsHeaders, allow: 'GET, OPTIONS' } });
  const metadata = {
    resource: resourceUrl.href,
    authorization_servers: [configuration.issuer],
    bearer_methods_supported: ['header'],
  };
  return new Response(JSON.stringify(metadata), { status: 200, headers: corsHeaders });
}

function withCors(response: Response, origin: string | null): Response {
  if (origin === null) return response;
  const headers = new Headers(response.headers);
  headers.set('access-control-allow-origin', origin);
  headers.set('access-control-expose-headers', 'mcp-protocol-version, mcp-session-id, www-authenticate');
  const vary = headers.get('vary');
  headers.set('vary', vary === null ? 'Origin' : `${vary}, Origin`);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function validateRequestOrigin(request: Request, allowedOrigins: readonly string[]): Response | undefined {
  const value = request.headers.get('origin');
  if (value === null) return undefined;
  let origin: URL;
  try { origin = new URL(value); } catch { return new Response('Invalid Origin', { status: 403 }); }
  if (origin.origin !== value || origin.username || origin.password || !allowedOrigins.includes(origin.origin)) {
    return new Response('Invalid Origin', { status: 403 });
  }
  const allowedHostnames = allowedOrigins.map((allowed) => new URL(allowed).hostname);
  return originValidationResponse(request, allowedHostnames);
}

function isInvalidCredential(error: unknown): boolean {
  return error instanceof Error && /MANDATE_API_(UNAUTHENTICATED|INVALID_TOKEN|TOKEN_EXPIRED)\b/.test(error.message);
}

function tokenHasResourceAudience(token: string, resourceUrl: URL): boolean {
  if (token.startsWith('mnd_agent_')) return true;
  const segments = token.split('.');
  const payloadSegment = segments[1];
  if (segments.length !== 3 || payloadSegment === undefined) return false;
  try {
    const payload: unknown = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8'));
    const parsed = z.object({ aud: z.union([z.string(), z.array(z.string())]) }).passthrough().safeParse(payload);
    if (!parsed.success) return false;
    const audiences = typeof parsed.data.aud === 'string' ? [parsed.data.aud] : parsed.data.aud;
    return audiences.includes(resourceUrl.href);
  } catch {
    return false;
  }
}

/** Creates the stateless Streamable HTTP MCP endpoint used by hosted deployments. */
export function createHostedMcpFetchHandler(configuration: HostedMcpConfiguration, fetcher: typeof fetch = fetch): (request: Request) => Promise<Response> {
  const apiUrl = parseUrl(configuration.apiUrl, 'MANDATE_API_URL', true);
  const resourceUrl = parseUrl(configuration.resourceUrl, 'MANDATE_MCP_RESOURCE_URL', true);
  parseUrl(configuration.issuer, 'MANDATE_JWT_ISSUER', false);
  if (resourceUrl.pathname !== '/mcp' || resourceUrl.href !== configuration.resourceUrl) throw new Error('MANDATE_MCP_RESOURCE_URL must be a canonical URL ending in /mcp');
  const allowedOrigins = parseOrigins(configuration.allowedOrigins);
  const resourceMetadataUrl = getOAuthProtectedResourceMetadataUrl(resourceUrl);
  const verifier = {
    async verifyAccessToken(token: string) {
      try {
        const client = await MandateRestMcpClient.connect(apiUrl.href, token, configuration.organizationId, fetcher);
        if (!tokenHasResourceAudience(token, resourceUrl)) throw new OAuthError(OAuthErrorCode.InvalidToken, 'Access token is not issued for this MCP resource');
        return {
          token,
          clientId: `mandate-${client.context.principalType.toLowerCase()}`,
          scopes: [],
          resource: resourceUrl,
          // Mandate's API revalidates the bearer token on every tool call. This
          // short auth-info lifetime bounds middleware state for opaque agent tokens.
          expiresAt: Math.floor(Date.now() / 1000) + 30,
          extra: { mandateApi: client },
        };
      } catch (error: unknown) {
        if (isInvalidCredential(error)) throw new OAuthError(OAuthErrorCode.InvalidToken, 'Invalid access token');
        throw error;
      }
    },
  };
  const gate = requireBearerAuth({ verifier, resourceMetadataUrl, expectedResource: resourceUrl });
  const handler = createMcpHandler(async (context) => {
    const client = context.authInfo?.extra?.mandateApi;
    if (!(client instanceof MandateRestMcpClient)) throw new OAuthError(OAuthErrorCode.InvalidToken, 'Missing verified Mandate identity');
    return createMandateMcpServer(client);
  });

  return async (request: Request): Promise<Response> => {
    const url = new URL(request.url);
    if (url.origin !== resourceUrl.origin) return new Response('Not found', { status: 404 });
    const metadata = metadataResponse(configuration, request);
    if (metadata !== undefined) return metadata;
    if (url.pathname !== resourceUrl.pathname) return new Response('Not found', { status: 404 });
    const hostError = hostHeaderValidationResponse(request, [resourceUrl.hostname]);
    if (hostError !== undefined) return hostError;
    const originError = validateRequestOrigin(request, allowedOrigins);
    if (originError !== undefined) return originError;
    const requestOrigin = request.headers.get('origin');
    if (request.method === 'OPTIONS') {
      return withCors(new Response(null, {
        status: 204,
        headers: {
          'access-control-allow-methods': 'GET, POST, DELETE, OPTIONS',
          'access-control-allow-headers': 'authorization, content-type, accept, mcp-protocol-version, last-event-id',
          'access-control-max-age': '600',
        },
      }), requestOrigin);
    }
    const authInfo = await gate(request);
    if (authInfo instanceof Response) return withCors(authInfo, requestOrigin);
    return withCors(await handler.fetch(request, { authInfo }), requestOrigin);
  };
}

export async function startHostedMcpFromEnvironment(environment: NodeJS.ProcessEnv = process.env): Promise<void> {
  const configuration = parseHostedMcpConfiguration(environment);
  const host = environment.HOST ?? '127.0.0.1';
  const port = Number(environment.MCP_PORT ?? '3100');
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('MCP_PORT must be a valid TCP port');
  const handler = createHostedMcpFetchHandler(configuration);
  const { createServer } = await import('node:http');
  const server = createServer(async (incoming, outgoing) => {
    try {
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of incoming) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buffer.length;
        if (size > 4 * 1024 * 1024) {
          outgoing.writeHead(413, { 'content-type': 'application/json' });
          outgoing.end(JSON.stringify({ error: 'request_too_large' }));
          return;
        }
        chunks.push(buffer);
      }
      const protocol = incoming.headers['x-forwarded-proto'] === 'https' ? 'https:' : 'http:';
      const hostHeader = incoming.headers.host;
      if (hostHeader === undefined) {
        outgoing.writeHead(400); outgoing.end(); return;
      }
      const requestUrl = `${protocol}//${hostHeader}${incoming.url ?? '/'}`;
      const headers = new Headers();
      for (const [name, value] of Object.entries(incoming.headers)) {
        if (value !== undefined) headers.set(name, Array.isArray(value) ? value.join(', ') : value);
      }
      const body = chunks.length === 0 ? undefined : Buffer.concat(chunks);
      const request = new Request(requestUrl, { method: incoming.method ?? 'GET', headers, ...(body === undefined ? {} : { body, duplex: 'half' }) });
      const response = await handler(request);
      const responseHeaders = Object.fromEntries(response.headers.entries());
      outgoing.writeHead(response.status, responseHeaders);
      if (response.body === null) {
        outgoing.end();
      } else {
        for await (const chunk of response.body) {
          if (!outgoing.write(Buffer.from(chunk))) await new Promise<void>((resolve, reject) => {
            outgoing.once('drain', resolve);
            outgoing.once('error', reject);
          });
        }
        outgoing.end();
      }
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : 'MCP request failed';
      console.error(`Hosted MCP request failed: ${message}`);
      if (!outgoing.headersSent) outgoing.writeHead(500, { 'content-type': 'application/json' });
      outgoing.end(JSON.stringify({ error: 'internal_server_error' }));
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 15_000;
  server.keepAliveTimeout = 5_000;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  console.info(`Mandate hosted MCP listening on ${host}:${port}; authorization server ${configuration.issuer}`);
  const shutdown = (): void => { server.close(); };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
}
