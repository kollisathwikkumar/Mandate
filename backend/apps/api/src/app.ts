import { createHash, createHmac, randomBytes, randomUUID } from 'node:crypto';
import Fastify, { type FastifyError, type FastifyInstance, type FastifyReply, type FastifyRequest } from 'fastify';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import type { Pool } from 'pg';
import { z } from 'zod';
import { ACTION_STATES } from '../../../packages/domain/src/action-state.js';
import { createFastifyLoggerOptions } from '../../../packages/observability/src/config.js';
import { PostgresRateLimitStore } from '../../../packages/adapters/src/postgres/rate-limit-store.js';
import { AgentApplicationService, ApplicationAccessError } from '../../../packages/application/src/agent-service.js';
import { ActionApplicationService } from '../../../packages/application/src/action-service.js';
import { ActionAuthorizationApplicationService, ActionAuthorizationConflictError } from '../../../packages/application/src/action-authorization-service.js';
import { ActionExecutionApplicationService, ActionExecutionRequestError } from '../../../packages/application/src/action-execution-service.js';
import { ApprovalApplicationService } from '../../../packages/application/src/approval-service.js';
import { ExecutionReorgResolutionService } from '../../../packages/application/src/execution-reorg-resolution-service.js';
import { ActivityApplicationService } from '../../../packages/application/src/activity-service.js';
import { AuditExportService, type AuditExportSigner } from '../../../packages/application/src/audit-export-service.js';
import { PolicyApplicationService } from '../../../packages/application/src/policy-service.js';
import { AgentCreateSchema, type ApiErrorCode } from '../../../packages/api-contracts/src/schemas.js';
import { PolicyConflictError, PolicyStore } from '../../../packages/adapters/src/postgres/policy-store.js';
import { ActionConflictError, ActionStore } from '../../../packages/adapters/src/postgres/action-store.js';
import { ApprovalStore } from '../../../packages/adapters/src/postgres/approval-store.js';
import { ExecutionReorgResolutionStore, ExecutionReorgResolutionConflictError } from '../../../packages/adapters/src/postgres/execution-reorg-resolution-store.js';
import { ActivityStore } from '../../../packages/adapters/src/postgres/activity-store.js';
import type { Principal } from '../../../packages/domain/src/principal.js';
import { AgentConflictError, AgentStore } from '../../../packages/adapters/src/postgres/agent-store.js';
import { ActionIntentSchema, PolicyRevisionSchema } from '../../../packages/policy/src/schema.js';
import { openApiDocument } from './openapi.js';
import { parseCorsAllowedOrigins } from './cors-config.js';
import { ModelCredentialStore } from '../../../packages/adapters/src/postgres/model-credential-store.js';
import type { ModelProviderTester, ModelSecretStore } from '../../../packages/ports/src/model-secret-store.js';
import { AwsModelSecretStore } from '../../../packages/adapters/src/aws/secrets-manager.js';
import { HttpModelProviderTester } from '../../../packages/adapters/src/model-provider-tester.js';
import { AccountApplicationService } from '../../../packages/application/src/account-service.js';
import { AccountConflictError, AccountStore } from '../../../packages/adapters/src/postgres/account-store.js';
import { AccountCreateSchema } from '../../../packages/api-contracts/src/schemas.js';
import type { AccountEnrollmentVerifier } from '../../../packages/ports/src/account-enrollment-verifier.js';
import { EvmAccountEnrollmentVerifier, ChainVerificationError } from '../../../packages/adapters/src/chain/evm-account-enrollment-verifier.js';
import { PolicyActivationStore } from '../../../packages/adapters/src/postgres/policy-activation-store.js';
import { EvmSafePolicyActivationReader, PolicyActivationChainError } from '../../../packages/adapters/src/chain/evm-safe-policy-activation-reader.js';
import type { SafePolicyActivationReader } from '../../../packages/ports/src/safe-policy-activation-reader.js';
import { PolicyActivationApplicationService, PolicyActivationConflictError } from '../../../packages/application/src/policy-activation-service.js';
import { SafePolicyActivationError } from '../../../packages/chain/src/safe-policy-activation-plan.js';
import { EvmPolicyCompileError } from '../../../packages/chain/src/evm-safe-policy-compiler.js';
import { EvmSafePolicyActivationFinalizer } from '../../../packages/adapters/src/chain/evm-safe-policy-activation-finalizer.js';
import { PolicyActivationFinalizationError, type PolicyActivationFinalizer } from '../../../packages/ports/src/policy-activation-finalizer.js';
import { PolicyRevocationStore } from '../../../packages/adapters/src/postgres/policy-revocation-store.js';
import { EvmSafePolicyRevocationFinalizer } from '../../../packages/adapters/src/chain/evm-safe-policy-revocation-finalizer.js';
import { PolicyRevocationApplicationService, PolicyRevocationConflictError } from '../../../packages/application/src/policy-revocation-service.js';
import { PolicyRevocationFinalizationError, type PolicyRevocationFinalizer } from '../../../packages/ports/src/policy-revocation-finalizer.js';
import type { ActionExecutionStateReader } from '../../../packages/ports/src/action-execution-state-reader.js';
import { EvmActionExecutionStateReader, ActionExecutionChainReadError } from '../../../packages/adapters/src/chain/evm-action-execution-state-reader.js';
import { ActionAuthorizationStore } from '../../../packages/adapters/src/postgres/action-authorization-store.js';
import { ActionTransactionSubmissionError, type ActionTransactionSubmitter } from '../../../packages/ports/src/action-transaction-submitter.js';
import { ActionExecutionSubmissionConflictError } from '../../../packages/ports/src/action-execution-submission-repository.js';
import { ActionExecutionSubmissionStore } from '../../../packages/adapters/src/postgres/action-execution-submission-store.js';
import { EvmActionTransactionSubmitter } from '../../../packages/adapters/src/chain/evm-action-transaction-submitter.js';
import { RepositoryAccessError } from '../../../packages/ports/src/repository-errors.js';
import { WebhookEndpointStore, WebhookConflictError } from '../../../packages/adapters/src/postgres/webhook-endpoint-store.js';
import { OrganizationMembershipStore, OrganizationMembershipConflictError } from '../../../packages/adapters/src/postgres/organization-membership-store.js';
import { OrganizationOnboardingStore, OrganizationOnboardingConflictError } from '../../../packages/adapters/src/postgres/organization-onboarding-store.js';
import { OrganizationInvitationStore, OrganizationInvitationConflictError } from '../../../packages/adapters/src/postgres/organization-invitation-store.js';
import type { OrganizationRole } from '../../../packages/domain/src/principal.js';
import { AwsWebhookSecretStore } from '../../../packages/adapters/src/aws/secrets-manager.js';
import { PublicHttpsWebhookUrlValidator } from '../../../packages/adapters/src/webhooks/https-webhook-transport.js';
import { WEBHOOK_EVENT_TYPES, type WebhookSecretStore, type WebhookUrlValidator } from '../../../packages/ports/src/webhook.js';
import type { InvitationTokenCipher } from '../../../packages/ports/src/invitation-email.js';

declare module 'fastify' {
  interface FastifyRequest {
    principal: Principal | null;
  }
}

const OrganizationIdSchema = z.string().min(1).max(128).regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/);
const IdempotencyKeySchema = z.string().min(1).max(200);

export interface ApiServerConfig {
  readonly pool: Pool;
  readonly jwksUrl: string;
  readonly issuer: string;
  readonly audience: string | string[];
  readonly logger?: boolean;
  readonly rateLimit?: { readonly maxRequests: number; readonly windowSeconds: number };
  readonly rateLimitHmacKey?: string;
  readonly trustedProxyCidrs?: readonly string[];
  readonly corsAllowedOrigins?: readonly string[];
  readonly modelSecretStore?: ModelSecretStore;
  readonly modelProviderTester?: ModelProviderTester;
  readonly webhookSecretStore?: WebhookSecretStore;
  readonly webhookUrlValidator?: WebhookUrlValidator;
  readonly accountEnrollmentVerifier?: AccountEnrollmentVerifier;
  readonly chainRpcUrls?: Readonly<Record<number, string>>;
  readonly chainRpcFallbackUrls?: Readonly<Record<number, readonly string[]>>;
  readonly trustedSafeSingletons?: Readonly<Record<number, string>>;
  readonly policyActivationReader?: SafePolicyActivationReader;
  readonly policyActivationFinalizer?: PolicyActivationFinalizer;
  readonly policyRevocationFinalizer?: PolicyRevocationFinalizer;
  readonly actionExecutionStateReader?: ActionExecutionStateReader;
  readonly actionTransactionSubmitter?: ActionTransactionSubmitter;
  readonly chainConfirmations?: Readonly<Record<number, number>>;
  readonly auditExportSigner?: AuditExportSigner;
  readonly invitationTokenCipher?: InvitationTokenCipher;
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function bearerToken(request: FastifyRequest): string | null {
  const authorization = request.headers.authorization;
  if (typeof authorization !== 'string') return null;
  const match = /^Bearer ([A-Za-z0-9._~-]{16,4096})$/.exec(authorization);
  return match?.[1] ?? null;
}

function errorBody(code: ApiErrorCode, message: string, requestId: string): { error: { code: ApiErrorCode; message: string; requestId: string } } {
  return { error: { code, message, requestId } };
}

const transientDependencyCodes = new Set([
  'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'EHOSTUNREACH', 'ENETUNREACH', 'ENOTFOUND', 'EAI_AGAIN',
  '08000', '08001', '08003', '08004', '08006', '08007', '08P01', '53300', '57P03',
]);

function webhookErrorResponse(error: unknown, request: FastifyRequest, reply: FastifyReply): FastifyReply | null {
  if (error instanceof RepositoryAccessError) {
    return reply.code(error.statusCode).send(errorBody(error.statusCode === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Webhook endpoint access was denied', request.id));
  }
  if (error instanceof WebhookConflictError) {
    return reply.code(409).send(errorBody(error.code, error.message, request.id));
  }
  if (error instanceof Error && error.message.startsWith('WEBHOOK_URL_')) {
    return reply.code(400).send(errorBody('INVALID_REQUEST', 'Webhook destination must be a valid public HTTPS URL', request.id));
  }
  return null;
}

async function authenticateToken(token: string, jwks: ReturnType<typeof createRemoteJWKSet>, config: ApiServerConfig, store: AgentStore): Promise<Principal | null> {
  if (token.startsWith('mnd_agent_')) {
    const credential = await store.findAgentByCredentialHash(sha256(token));
    return credential === null
      ? null
      : { type: 'AGENT', organizationId: credential.organizationId, agentId: credential.agentId, keyVersion: credential.keyVersion, credentialId: credential.credentialId };
  }

  try {
    const verified = await jwtVerify(token, jwks, {
      algorithms: ['RS256'],
      issuer: config.issuer,
      audience: config.audience,
      requiredClaims: ['exp', 'sub'],
    });
    const subject = verified.payload.sub;
    if (typeof subject !== 'string' || subject.length === 0) return null;
    const verifiedEmail = verified.payload.email_verified === true && typeof verified.payload.email === 'string'
      ? z.string().trim().email().max(254).safeParse(verified.payload.email)
      : null;
    return { type: 'HUMAN', subject, ...(verifiedEmail?.success === true ? { verifiedEmail: verifiedEmail.data.toLowerCase() } : {}) };
  } catch {
    return null;
  }
}

async function authorizeOrganization(
  service: AgentApplicationService,
  principal: Principal,
  organizationIdValue: string,
): Promise<readonly { readonly organizationId: string; readonly role: string }[] | null> {
  if (principal.type === 'AGENT') return principal.organizationId === organizationIdValue ? [] : null;
  const memberships = await service.humanOrganizations(principal.subject);
  return memberships.some((membership) => membership.organizationId === organizationIdValue) ? memberships : null;
}

function mapApplicationError(error: unknown, request: FastifyRequest): { statusCode: number; body: ReturnType<typeof errorBody> } | null {
  if (error instanceof RepositoryAccessError) {
    return { statusCode: error.statusCode, body: errorBody(error.statusCode === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'The principal is not authorized for this organization resource', request.id) };
  }
  if (error instanceof ApplicationAccessError) {
    return { statusCode: error.statusCode, body: errorBody(error.code, error.message, request.id) };
  }
  if (error instanceof OrganizationMembershipConflictError) {
    return { statusCode: error.code === 'IDEMPOTENCY_CONFLICT' || error.code === 'LAST_OWNER' ? 409 : error.code === 'OWNER_ROLE_REQUIRED' ? 403 : 404, body: errorBody(error.code === 'OWNER_ROLE_REQUIRED' ? 'FORBIDDEN' : error.code === 'MEMBER_NOT_FOUND' ? 'RESOURCE_NOT_FOUND' : 'RESOURCE_CONFLICT', error.message, request.id) };
  }
  if (error instanceof AgentConflictError) {
    return { statusCode: 409, body: errorBody(error.code, error.message, request.id) };
  }
  if (error instanceof PolicyConflictError) {
    return { statusCode: 409, body: errorBody(error.code, error.message, request.id) };
  }
  if (error instanceof PolicyActivationConflictError) {
    return { statusCode: 409, body: errorBody('RESOURCE_CONFLICT', error.message, request.id) };
  }
  if (error instanceof PolicyRevocationConflictError) {
    return { statusCode: 409, body: errorBody('RESOURCE_CONFLICT', error.message, request.id) };
  }
  if (error instanceof ActionConflictError) {
    return { statusCode: 409, body: errorBody(error.code, error.message, request.id) };
  }
  if (error instanceof ActionAuthorizationConflictError) {
    return { statusCode: 409, body: errorBody(error.code, error.message, request.id) };
  }
  if (error instanceof ActionExecutionSubmissionConflictError) {
    return { statusCode: 409, body: errorBody(error.code, error.message, request.id) };
  }
  if (error instanceof ExecutionReorgResolutionConflictError) {
    return { statusCode: 409, body: errorBody(error.code, error.message, request.id) };
  }
  if (error instanceof ActionExecutionRequestError) {
    return { statusCode: error.statusCode, body: errorBody(error.code, error.message, request.id) };
  }
  if (error instanceof ActionTransactionSubmissionError) {
    return error.code === 'RPC_UNAVAILABLE' || error.code === 'UNSUPPORTED_CHAIN'
      ? { statusCode: 503, body: errorBody('DEPENDENCY_UNAVAILABLE', 'Configured transaction submission RPC is unavailable', request.id) }
      : { statusCode: 409, body: errorBody('RESOURCE_CONFLICT', 'Signed transaction does not match the configured execution chain', request.id) };
  }
  if (error instanceof ActionExecutionChainReadError) {
    return error.code === 'RPC_UNAVAILABLE' || error.code === 'UNSUPPORTED_CHAIN'
      ? { statusCode: 503, body: errorBody('DEPENDENCY_UNAVAILABLE', 'Configured action execution chain reader is unavailable', request.id) }
      : { statusCode: 409, body: errorBody('RESOURCE_CONFLICT', 'Current Safe execution state does not match the enrolled account', request.id) };
  }
  if (error instanceof AccountConflictError) {
    return { statusCode: 409, body: errorBody(error.code, error.message, request.id) };
  }
  if (error instanceof EvmPolicyCompileError || error instanceof SafePolicyActivationError) {
    return { statusCode: 409, body: errorBody('RESOURCE_CONFLICT', error.message, request.id) };
  }
  if (error instanceof PolicyActivationChainError) {
    return error.code === 'RPC_UNAVAILABLE' || error.code === 'UNSUPPORTED_CHAIN'
      ? { statusCode: 503, body: errorBody('DEPENDENCY_UNAVAILABLE', 'Configured chain activation reader is unavailable', request.id) }
      : { statusCode: 409, body: errorBody('RESOURCE_CONFLICT', 'Current Safe state does not match the enrolled account', request.id) };
  }
  if (error instanceof PolicyActivationFinalizationError) {
    return ['RPC_UNAVAILABLE', 'UNSUPPORTED_CHAIN', 'INVALID_CONFIRMATION_CONFIGURATION'].includes(error.code)
      ? { statusCode: 503, body: errorBody('DEPENDENCY_UNAVAILABLE', 'Configured activation finality verification is unavailable', request.id) }
      : { statusCode: 409, body: errorBody('RESOURCE_CONFLICT', 'Safe activation transaction is missing, unsuccessful, unfinalized, or no longer matches current chain state', request.id) };
  }
  if (error instanceof PolicyRevocationFinalizationError) {
    return ['RPC_UNAVAILABLE', 'UNSUPPORTED_CHAIN', 'INVALID_CONFIRMATION_CONFIGURATION'].includes(error.code)
      ? { statusCode: 503, body: errorBody('DEPENDENCY_UNAVAILABLE', 'Configured revocation finality verification is unavailable', request.id) }
      : { statusCode: 409, body: errorBody('RESOURCE_CONFLICT', 'Safe revocation transaction is missing, unsuccessful, unfinalized, or no longer matches current chain state', request.id) };
  }
  if (error instanceof ChainVerificationError) {
    return error.code === 'RPC_UNAVAILABLE' || error.code === 'UNSUPPORTED_CHAIN' || error.code === 'CHAIN_STATE_CHANGED'
      ? { statusCode: 503, body: errorBody('DEPENDENCY_UNAVAILABLE', 'Configured chain verification is unavailable', request.id) }
      : { statusCode: 409, body: errorBody('RESOURCE_CONFLICT', 'The registered account does not meet on-chain enrollment requirements', request.id) };
  }
  return null;
}

export async function createApiServer(config: ApiServerConfig): Promise<FastifyInstance> {
  const rateLimitHmacKey = config.rateLimitHmacKey ?? process.env.MANDATE_RATE_LIMIT_HMAC_KEY;
  if (rateLimitHmacKey === undefined && process.env.NODE_ENV === 'production') {
    throw new Error('MANDATE_RATE_LIMIT_HMAC_KEY is required in production');
  }
  const rateLimitHmacSecret = rateLimitHmacKey ?? randomBytes(32);
  if (typeof rateLimitHmacSecret === 'string' && Buffer.byteLength(rateLimitHmacSecret, 'utf8') < 32) {
    throw new Error('MANDATE_RATE_LIMIT_HMAC_KEY must contain at least 32 UTF-8 bytes');
  }
  const rateLimitMaxRequests = config.rateLimit?.maxRequests ?? 120;
  const rateLimitWindowSeconds = config.rateLimit?.windowSeconds ?? 60;
  if (!Number.isSafeInteger(rateLimitMaxRequests) || rateLimitMaxRequests < 1 || rateLimitMaxRequests > 1_000_000
    || !Number.isSafeInteger(rateLimitWindowSeconds) || rateLimitWindowSeconds < 1 || rateLimitWindowSeconds > 86_400) {
    throw new Error('Rate-limit settings are outside the supported range');
  }
  const jwksUrl = new URL(config.jwksUrl);
  if (jwksUrl.protocol !== 'https:' && !(jwksUrl.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(jwksUrl.hostname))) {
    throw new Error('JWKS URL must use HTTPS except for loopback development');
  }
  const jwks = createRemoteJWKSet(jwksUrl);
  const corsAllowedOrigins = config.corsAllowedOrigins === undefined
    ? undefined
    : config.corsAllowedOrigins.map((origin) => {
      const parsedOrigins = parseCorsAllowedOrigins(origin);
      const [parsedOrigin] = parsedOrigins ?? [];
      if (parsedOrigins?.length !== 1 || parsedOrigin === undefined) {
        throw new Error('Each configured CORS origin must be exactly one canonical origin');
      }
      return parsedOrigin;
    });
  if (corsAllowedOrigins !== undefined && new Set(corsAllowedOrigins).size !== corsAllowedOrigins.length) {
    throw new Error('CORS origin allowlist contains duplicate origins');
  }
  const store = new AgentStore(config.pool);
  const service = new AgentApplicationService(store);
  const policyService = new PolicyApplicationService(new PolicyStore(config.pool));
  const actionService = new ActionApplicationService(new ActionStore(config.pool));
  const actionAuthorizationStore = new ActionAuthorizationStore(config.pool);
  const actionAuthorizationService = new ActionAuthorizationApplicationService(
    actionAuthorizationStore,
    config.actionExecutionStateReader ?? new EvmActionExecutionStateReader(config.chainRpcUrls ?? {}),
  );
  const actionExecutionService = new ActionExecutionApplicationService(
    actionAuthorizationStore,
    new ActionExecutionSubmissionStore(config.pool),
    config.actionTransactionSubmitter ?? new EvmActionTransactionSubmitter(config.chainRpcUrls ?? {}, config.chainRpcFallbackUrls ?? {}),
  );
  const approvalService = new ApprovalApplicationService(new ApprovalStore(config.pool));
  const executionReorgResolutionService = new ExecutionReorgResolutionService(new ExecutionReorgResolutionStore(config.pool));
  const activityService = new ActivityApplicationService(new ActivityStore(config.pool));
  const auditExportService = config.auditExportSigner === undefined
    ? null
    : new AuditExportService(new ActivityStore(config.pool), config.auditExportSigner);
  const accountEnrollmentVerifier = config.accountEnrollmentVerifier ?? new EvmAccountEnrollmentVerifier(config.chainRpcUrls ?? {}, config.trustedSafeSingletons ?? {});
  const accountService = new AccountApplicationService(new AccountStore(config.pool), accountEnrollmentVerifier);
  const policyActivationService = new PolicyActivationApplicationService(
    new PolicyActivationStore(config.pool),
    accountEnrollmentVerifier,
    config.policyActivationReader ?? new EvmSafePolicyActivationReader(config.chainRpcUrls ?? {}),
    config.policyActivationFinalizer ?? new EvmSafePolicyActivationFinalizer(config.chainRpcUrls ?? {}, config.chainConfirmations ?? {}),
    config.chainConfirmations ?? {},
  );
  const policyRevocationService = new PolicyRevocationApplicationService(
    new PolicyRevocationStore(config.pool), accountEnrollmentVerifier,
    config.policyActivationReader ?? new EvmSafePolicyActivationReader(config.chainRpcUrls ?? {}),
    config.policyRevocationFinalizer ?? new EvmSafePolicyRevocationFinalizer(config.chainRpcUrls ?? {}, config.chainConfirmations ?? {}),
    config.chainConfirmations ?? {},
  );
  const modelCredentialStore = new ModelCredentialStore(config.pool);
  const modelSecretStore = config.modelSecretStore ?? new AwsModelSecretStore();
  const modelProviderTester = config.modelProviderTester ?? new HttpModelProviderTester();
  const webhookEndpointStore = new WebhookEndpointStore(config.pool);
  const organizationMembershipStore = new OrganizationMembershipStore(config.pool);
  const organizationOnboardingStore = new OrganizationOnboardingStore(config.pool);
  const organizationInvitationStore = new OrganizationInvitationStore(config.pool, config.invitationTokenCipher);
  const webhookSecretStore = config.webhookSecretStore ?? new AwsWebhookSecretStore();
  const webhookUrlValidator = config.webhookUrlValidator ?? new PublicHttpsWebhookUrlValidator();
  const app = Fastify({
    logger: config.logger === true ? createFastifyLoggerOptions() : config.logger ?? false,
    bodyLimit: 300_000,
    trustProxy: config.trustedProxyCidrs === undefined ? false : [...config.trustedProxyCidrs],
  });
  const rateLimitStore = new PostgresRateLimitStore(config.pool);
  app.decorateRequest('principal', null);

  app.addHook('onSend', async (request, reply, payload) => {
    reply.header('x-request-id', request.id);
    reply.header('x-content-type-options', 'nosniff');
    reply.header('x-frame-options', 'DENY');
    reply.header('cache-control', 'no-store');
    return payload;
  });

  app.addHook('onRequest', async (request, reply) => {
    if (request.url.startsWith('/api/v1/') && corsAllowedOrigins !== undefined && request.headers.origin !== undefined) {
      const origin = request.headers.origin;
      if (!corsAllowedOrigins.includes(origin)) {
        await reply.code(403).send(errorBody('FORBIDDEN', 'Browser origin is not allowed', request.id));
        return;
      }
      reply.header('vary', 'Origin');
      reply.header('access-control-allow-origin', origin);
      reply.header('access-control-expose-headers', 'x-request-id, retry-after, ratelimit-limit, ratelimit-remaining, ratelimit-reset');

      const requestedMethod = request.headers['access-control-request-method'];
      if (request.method === 'OPTIONS' && typeof requestedMethod === 'string') {
        const allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
        const requestedHeaders = request.headers['access-control-request-headers'];
        const allowedHeaders = new Set(['authorization', 'content-type', 'idempotency-key']);
        const headerNames = typeof requestedHeaders === 'string' && requestedHeaders.length > 0
          ? requestedHeaders.split(',').map((header) => header.trim().toLowerCase())
          : [];
        if (!allowedMethods.includes(requestedMethod.toUpperCase())
          || headerNames.some((header) => !allowedHeaders.has(header))) {
          await reply.code(403).send(errorBody('FORBIDDEN', 'Browser preflight requested a method or header that is not allowed', request.id));
          return;
        }
        reply.header('access-control-allow-methods', allowedMethods.join(', '));
        reply.header('access-control-allow-headers', 'Authorization, Content-Type, Idempotency-Key');
        reply.header('access-control-max-age', '600');
        await reply.code(204).send();
        return;
      }
    }
    if (!request.url.startsWith('/api/v1/') || request.routeOptions.url === '/api/v1/openapi.json') return;
    const source = createHmac('sha256', rateLimitHmacSecret).update(`ip:${request.ip}`, 'utf8').digest('hex');
    const maximum = rateLimitMaxRequests;
    const windowSeconds = rateLimitWindowSeconds;
    const decision = await rateLimitStore.consume(source, maximum, windowSeconds).catch(() => null);
    if (decision === null) {
      request.log.error({ requestId: request.id, code: 'RATE_LIMIT_STORAGE_UNAVAILABLE' }, 'Shared rate limiter unavailable');
      await reply.code(503).send(errorBody('DEPENDENCY_UNAVAILABLE', 'Request admission is temporarily unavailable', request.id));
      return;
    }
    reply.header('ratelimit-limit', maximum);
    reply.header('ratelimit-remaining', decision.remainingRequests);
    reply.header('ratelimit-reset', decision.retryAfterSeconds);
    if (!decision.allowed) {
      reply.header('retry-after', decision.retryAfterSeconds);
      await reply.code(429).send(errorBody('RATE_LIMITED', 'Request limit exceeded; retry after the current window', request.id));
    }
  });

  app.addHook('preHandler', async (request, reply) => {
    if (!request.url.startsWith('/api/v1/')) return;
    if (request.routeOptions.url === '/api/v1/openapi.json') return;
    if (request.routeOptions.url === undefined || request.routeOptions.url.length === 0) return;
    const token = bearerToken(request);
    if (token === null) {
      await reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
      return;
    }
    try {
      const principal = await authenticateToken(token, jwks, config, store);
      if (principal === null) {
        await reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
        return;
      }
      request.principal = principal;
    } catch {
      await reply.code(503).send(errorBody('DEPENDENCY_UNAVAILABLE', 'Identity service is temporarily unavailable', request.id));
    }
  });

  app.setErrorHandler((error: FastifyError, request, reply) => {
    if (error.code === 'FST_ERR_CTP_BODY_TOO_LARGE') return reply.code(413).send(errorBody('INVALID_REQUEST', 'Request body exceeds the supported size', request.id));
    if (error.code === 'FST_ERR_CTP_INVALID_MEDIA_TYPE') return reply.code(415).send(errorBody('INVALID_REQUEST', 'Request content type is not supported', request.id));
    if (error.validation !== undefined || error.statusCode === 400) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'Request data is invalid', request.id));
    }
    const dependencyCode = typeof error.code === 'string' && transientDependencyCodes.has(error.code) ? error.code : null;
    const dependencyUnavailable = dependencyCode !== null || error.statusCode === 502 || error.statusCode === 503;
    request.log.error({
      requestId: request.id,
      method: request.method,
      route: request.routeOptions.url ?? 'unmatched',
      category: dependencyUnavailable ? 'DEPENDENCY' : 'INTERNAL',
      failureCode: dependencyCode ?? (error.statusCode === 502 ? 'UPSTREAM_502' : error.statusCode === 503 ? 'UPSTREAM_503' : 'UNEXPECTED'),
    }, 'Request failed');
    if (error.statusCode === 502) return reply.code(502).send(errorBody('DEPENDENCY_UNAVAILABLE', 'An upstream service failed', request.id));
    return dependencyUnavailable
      ? reply.code(503).send(errorBody('DEPENDENCY_UNAVAILABLE', 'A required service is temporarily unavailable', request.id))
      : reply.code(500).send(errorBody('INTERNAL_ERROR', 'The request could not be completed', request.id));
  });

  app.setNotFoundHandler((request, reply) => reply.code(404).send(errorBody('RESOURCE_NOT_FOUND', 'The requested route was not found', request.id)));

  app.get('/health/live', async (_request, reply) => reply.code(200).send({ status: 'live' }));
  app.get('/health/ready', async (request, reply) => {
    try {
      await config.pool.query('SELECT 1');
      return reply.code(200).send({ status: 'ready', dependencies: { postgres: 'ready' } });
    } catch {
      return reply.code(503).send({ status: 'not_ready', dependencies: { postgres: 'unavailable' }, requestId: request.id });
    }
  });

  app.get('/api/v1/openapi.json', async (_request, reply) => reply.code(200).send(openApiDocument));

  const providerSchema = z.enum(['DEEPSEEK', 'OPENAI', 'ANTHROPIC', 'OTHER']);
  // oxlint-disable-next-line no-control-regex -- Control-character rejection is intentional.
  const modelKeySchema = z.string().min(16).max(4096).refine((value) => !/[\u0000-\u001f\u007f]/.test(value), 'API key contains control characters');
  const organizationProviderPath = '/api/v1/orgs/:orgId/integrations/model-providers';
  const authorizeModelAdmin = async (orgId: string, principal: Principal): Promise<number | null> => {
    if (principal.type !== 'HUMAN') return 403;
    const role = await modelCredentialStore.getHumanRole(orgId, principal.subject);
    return role === null ? 404 : role === 'OWNER' || role === 'ADMIN' ? null : 403;
  };
  app.get<{ Params: { orgId: string } }>(organizationProviderPath, async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    if (!organization.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Organization identifier is invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeModelAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Model provider integrations require organization administrator access', request.id));
    return reply.code(200).send({ credentials: await modelCredentialStore.listCredentials(organization.data) });
  });

  app.put<{ Params: { orgId: string; provider: string }; Body: { apiKey: string } }>(`${organizationProviderPath}/:provider`, async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const provider = providerSchema.safeParse(request.params.provider.toUpperCase());
    const body = z.object({ apiKey: modelKeySchema }).strict().safeParse(request.body);
    const rawIdempotencyKey = request.headers['idempotency-key'];
    const idempotencyKey = typeof rawIdempotencyKey === 'string' ? IdempotencyKeySchema.safeParse(rawIdempotencyKey) : null;
    if (!organization.success || !provider.success || !body.success || idempotencyKey === null || !idempotencyKey.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid provider, API key, and Idempotency-Key are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeModelAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Model provider integrations require organization administrator access', request.id));
    const apiKey = body.data.apiKey;
    const fingerprint = sha256(`${provider.data}|${sha256(apiKey)}`);
    let secretReference: string | null = null;
    let committed = false;
    let replacedSecretReference: string | null = null;
    try {
      secretReference = await modelSecretStore.put(organization.data, provider.data, apiKey);
      const result = await modelCredentialStore.writeCredential({ organizationId: organization.data, principalId: principal.type === 'HUMAN' ? principal.subject : '', idempotencyKey: idempotencyKey.data, requestHash: `0x${fingerprint}`, provider: provider.data, secretReference, maskedSuffix: apiKey.slice(-4) });
      committed = true;
      if (result.kind === 'REPLAY') await modelSecretStore.delete(secretReference).catch(() => undefined);
      if (result.kind === 'CREATED') replacedSecretReference = result.replacedSecretReference;
      const credential = result.credential;
      const replayed = result.kind === 'REPLAY';
      if (replayed) return reply.code(200).send({ credential, replayed: true });
      if (replacedSecretReference !== null && replacedSecretReference !== secretReference) await modelSecretStore.delete(replacedSecretReference).catch(() => undefined);
      return reply.code(201).send({ credential });
    } catch (error: unknown) {
      if (!committed && secretReference !== null) await modelSecretStore.delete(secretReference).catch(() => undefined);
      if (error instanceof Error && error.message === 'IDEMPOTENCY_CONFLICT') return reply.code(409).send(errorBody('IDEMPOTENCY_CONFLICT', 'Idempotency key was already used for a different request', request.id));
      throw error;
    }
  });

  app.post<{ Params: { orgId: string; provider: string } }>(`${organizationProviderPath}/:provider/test`, async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const provider = providerSchema.safeParse(request.params.provider.toUpperCase());
    if (!organization.success || !provider.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid organization and provider are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeModelAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Model provider integrations require organization administrator access', request.id));
    const credential = await modelCredentialStore.getCredential(organization.data, provider.data);
    if (credential === null) return reply.code(404).send(errorBody('RESOURCE_NOT_FOUND', 'Model provider credential was not found', request.id));
    if (credential.state === 'DISABLED') return reply.code(409).send(errorBody('RESOURCE_CONFLICT', 'Disabled credentials must be replaced before testing', request.id));
    const outcome = await modelProviderTester.test(provider.data, await modelSecretStore.get(credential.secretReference));
    const state = outcome.ok ? 'ACTIVE' : 'ERROR';
    const record = await modelCredentialStore.markVerified(organization.data, principal.type === 'HUMAN' ? principal.subject : '', provider.data, credential.secretReference, state);
    if (record === null) return reply.code(409).send(errorBody('RESOURCE_CONFLICT', 'Credential changed while verification was in progress', request.id));
    return reply.code(200).send({ ok: outcome.ok, reason: outcome.reason, credential: { provider: record.provider, maskedSuffix: record.maskedSuffix, state: record.state, verifiedAt: record.verifiedAt } });
  });

  app.post<{ Params: { orgId: string; provider: string } }>(`${organizationProviderPath}/:provider/disable`, async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const provider = providerSchema.safeParse(request.params.provider.toUpperCase());
    if (!organization.success || !provider.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid organization and provider are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeModelAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Model provider integrations require organization administrator access', request.id));
    const disabled = await modelCredentialStore.updateCredentialState(organization.data, principal.type === 'HUMAN' ? principal.subject : '', provider.data, 'DISABLED');
    return disabled === null ? reply.code(404).send(errorBody('RESOURCE_NOT_FOUND', 'Model provider credential was not found', request.id)) : reply.code(200).send({ credential: { provider: disabled.provider, maskedSuffix: disabled.maskedSuffix, state: disabled.state, disabledAt: disabled.disabledAt } });
  });

  app.delete<{ Params: { orgId: string; provider: string } }>(`${organizationProviderPath}/:provider`, async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const provider = providerSchema.safeParse(request.params.provider.toUpperCase());
    if (!organization.success || !provider.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid organization and provider are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeModelAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Model provider integrations require organization administrator access', request.id));
    const subject = principal.type === 'HUMAN' ? principal.subject : '';
    const disabled = await modelCredentialStore.updateCredentialState(organization.data, subject, provider.data, 'DISABLED');
    if (disabled === null) return reply.code(204).send();
    await modelSecretStore.delete(disabled.secretReference);
    await modelCredentialStore.deleteCredential(organization.data, subject, provider.data);
    return reply.code(204).send();
  });

  const memberPath = '/api/v1/orgs/:orgId/members';
  // oxlint-disable-next-line no-control-regex -- Control-character rejection is intentional.
  const memberSubjectSchema = z.string().min(1).max(255).refine((value) => !/[\u0000-\u001f\u007f]/.test(value));
  const memberRoleSchema = z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']);
  const authorizeMemberAdmin = async (orgId: string, principal: Principal): Promise<number | null> => {
    if (principal.type !== 'HUMAN') return 403;
    const role = await organizationMembershipStore.getHumanRole(orgId, principal.subject);
    return role === null ? 404 : role === 'OWNER' || role === 'ADMIN' ? null : 403;
  };
  app.get<{ Params: { orgId: string } }>(memberPath, async (request, reply) => {
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const principal = request.principal;
    if (!organization.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Organization identifier is invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    if (principal.type !== 'HUMAN') return reply.code(403).send(errorBody('FORBIDDEN', 'Member management requires a human principal', request.id));
    try { return reply.code(200).send({ members: await organizationMembershipStore.listMembers(organization.data, principal.subject) }); }
    catch (error: unknown) { const mapped = mapApplicationError(error, request); if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body); throw error; }
  });
  app.put<{ Params: { orgId: string; subject: string } }>(`${memberPath}/:subject`, async (request, reply) => {
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const subject = memberSubjectSchema.safeParse(request.params.subject);
    const body = z.object({ role: memberRoleSchema }).strict().safeParse(request.body);
    const idempotencyKey = readIdempotencyKey(request);
    const principal = request.principal;
    if (!organization.success || !subject.success || !body.success || idempotencyKey === null) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid member subject, role, and Idempotency-Key are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeMemberAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Member management requires organization administrator access', request.id));
    try {
      const input = { organizationId: organization.data, principalId: principal.type === 'HUMAN' ? principal.subject : '', subject: subject.data, role: body.data.role as OrganizationRole, idempotencyKey, requestHash: `0x${sha256(JSON.stringify({ subject: subject.data, role: body.data.role }))}` };
      const result = await organizationMembershipStore.setMemberRole(input);
      return reply.code(result.kind === 'CREATED' ? 201 : 200).send({ member: result.member, ...(result.kind === 'REPLAY' ? { replayed: true as const } : {}) });
    } catch (error: unknown) { const mapped = mapApplicationError(error, request); if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body); throw error; }
  });
  app.delete<{ Params: { orgId: string; subject: string } }>(`${memberPath}/:subject`, async (request, reply) => {
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const subject = memberSubjectSchema.safeParse(request.params.subject);
    const idempotencyKey = readIdempotencyKey(request);
    const principal = request.principal;
    if (!organization.success || !subject.success || idempotencyKey === null) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid member subject and Idempotency-Key are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeMemberAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Member management requires organization administrator access', request.id));
    try {
      const input = { organizationId: organization.data, principalId: principal.type === 'HUMAN' ? principal.subject : '', subject: subject.data, idempotencyKey, requestHash: `0x${sha256(JSON.stringify({ subject: subject.data, operation: 'remove' }))}` };
      await organizationMembershipStore.removeMember(input);
      return reply.code(204).send();
    } catch (error: unknown) { const mapped = mapApplicationError(error, request); if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body); throw error; }
  });

  const webhookPath = '/api/v1/orgs/:orgId/webhooks';
  const webhookEndpointIdSchema = z.string().uuid();
  const webhookCreateSchema = z.object({
    url: z.string().trim().min(1).max(2048),
    eventTypes: z.array(z.enum(WEBHOOK_EVENT_TYPES)).min(1).max(30).refine((items) => new Set(items).size === items.length, 'eventTypes must be unique'),
  }).strict();
  const webhookEnabledSchema = z.object({ enabled: z.boolean() }).strict();
  const authorizeWebhookAdmin = async (orgId: string, principal: Principal): Promise<number | null> => {
    if (principal.type !== 'HUMAN') return 403;
    const role = await webhookEndpointStore.getHumanRole(orgId, principal.subject);
    return role === null ? 404 : role === 'OWNER' || role === 'ADMIN' ? null : 403;
  };
  const webhookPrincipalSubject = (principal: Principal): string => principal.type === 'HUMAN' ? principal.subject : '';
  const readIdempotencyKey = (request: FastifyRequest): string | null => {
    const raw = request.headers['idempotency-key'];
    if (typeof raw !== 'string') return null;
    const parsed = IdempotencyKeySchema.safeParse(raw);
    return parsed.success ? parsed.data : null;
  };

  app.post('/api/v1/orgs', async (request, reply) => {
    // oxlint-disable-next-line no-control-regex -- Control-character rejection is intentional.
    const body = z.object({ displayName: z.string().trim().min(1).max(160).refine((value) => !/[\u0000-\u001f\u007f]/.test(value)) }).strict().safeParse(request.body);
    const idempotencyKey = readIdempotencyKey(request);
    const principal = request.principal;
    if (!body.success || idempotencyKey === null) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid organization display name and Idempotency-Key are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    if (principal.type !== 'HUMAN') return reply.code(403).send(errorBody('FORBIDDEN', 'Only a human principal can create an organization', request.id));
    const requestHash = `0x${sha256(JSON.stringify({ displayName: body.data.displayName }))}`;
    try {
      const result = await organizationOnboardingStore.create({ principalId: principal.subject, displayName: body.data.displayName, idempotencyKey, requestHash });
      return reply.code(result.kind === 'CREATED' ? 201 : 200).send({ organization: result.organization, ...(result.kind === 'REPLAY' ? { replayed: true as const } : {}) });
    } catch (error: unknown) {
      if (error instanceof OrganizationOnboardingConflictError) return reply.code(409).send(errorBody('IDEMPOTENCY_CONFLICT', 'The Idempotency-Key was already used for a different organization request', request.id));
      throw error;
    }
  });

  const invitationEmailSchema = z.string().trim().email().max(254);
  app.post<{ Params: { orgId: string } }>('/api/v1/orgs/:orgId/invitations', async (request, reply) => {
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const body = z.object({ email: invitationEmailSchema, role: z.enum(['OWNER', 'ADMIN', 'APPROVER', 'VIEWER']) }).strict().safeParse(request.body);
    const idempotencyKey = readIdempotencyKey(request);
    const principal = request.principal;
    if (!organization.success || !body.success || idempotencyKey === null) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid organization, invitation email, role, and Idempotency-Key are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    if (principal.type !== 'HUMAN') return reply.code(403).send(errorBody('FORBIDDEN', 'Organization invitations require a human principal', request.id));
    const email = body.data.email.toLowerCase();
    const requestHash = `0x${sha256(JSON.stringify({ email, role: body.data.role }))}`;
    try {
      const result = await organizationInvitationStore.create({ organizationId: organization.data, principalId: principal.subject, email, role: body.data.role, idempotencyKey, requestHash });
      return reply.code(result.kind === 'CREATED' ? 201 : 200).send({
        invitation: result.invitation,
        ...(result.kind === 'CREATED' && result.token !== null ? { invitationToken: result.token, shownOnce: true as const } : {}),
        ...(result.kind === 'CREATED' && config.invitationTokenCipher !== undefined ? { emailDeliveryQueued: true as const } : {}),
        ...(result.kind === 'REPLAY' ? { replayed: true as const } : {}),
      });
    } catch (error: unknown) {
      if (error instanceof OrganizationInvitationConflictError) {
        const ownerRoleRequired = error.code === 'OWNER_ROLE_REQUIRED';
        return reply.code(ownerRoleRequired ? 403 : 409).send(errorBody(ownerRoleRequired ? 'FORBIDDEN' : 'IDEMPOTENCY_CONFLICT', error.message, request.id));
      }
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.get<{ Params: { orgId: string } }>('/api/v1/orgs/:orgId/invitations', async (request, reply) => {
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const principal = request.principal;
    if (!organization.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Organization identifier is invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    if (principal.type !== 'HUMAN') return reply.code(403).send(errorBody('FORBIDDEN', 'Invitation management requires a human principal', request.id));
    try { return reply.code(200).send({ invitations: await organizationInvitationStore.list({ organizationId: organization.data, principalId: principal.subject }) }); }
    catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.delete<{ Params: { orgId: string; invitationId: string } }>('/api/v1/orgs/:orgId/invitations/:invitationId', async (request, reply) => {
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const invitationId = z.string().uuid().safeParse(request.params.invitationId);
    const idempotencyKey = readIdempotencyKey(request);
    const principal = request.principal;
    if (!organization.success || !invitationId.success || idempotencyKey === null) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid organization invitation and Idempotency-Key are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    if (principal.type !== 'HUMAN') return reply.code(403).send(errorBody('FORBIDDEN', 'Invitation management requires a human principal', request.id));
    try {
      await organizationInvitationStore.revoke({ organizationId: organization.data, principalId: principal.subject, invitationId: invitationId.data, idempotencyKey, requestHash: `0x${sha256(JSON.stringify({ invitationId: invitationId.data, operation: 'revoke' }))}` });
      return reply.code(204).send();
    } catch (error: unknown) {
      if (error instanceof OrganizationInvitationConflictError) return reply.code(409).send(errorBody(error.code === 'IDEMPOTENCY_CONFLICT' ? 'IDEMPOTENCY_CONFLICT' : 'RESOURCE_CONFLICT', error.message, request.id));
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post('/api/v1/invitations/accept', async (request, reply) => {
    const body = z.object({ token: z.string().min(40).max(128).regex(/^[A-Za-z0-9_-]+$/) }).strict().safeParse(request.body);
    const principal = request.principal;
    if (!body.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid invitation token is required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    if (principal.type !== 'HUMAN' || principal.verifiedEmail === undefined) return reply.code(403).send(errorBody('FORBIDDEN', 'Invitation acceptance requires a human identity with a verified email claim', request.id));
    try {
      const result = await organizationInvitationStore.accept({ token: body.data.token, principalId: principal.subject, verifiedEmail: principal.verifiedEmail });
      return reply.code(200).send({ organizationId: result.organizationId, role: result.role, accepted: true, ...(result.kind === 'REPLAY' ? { replayed: true as const } : {}) });
    } catch (error: unknown) {
      if (error instanceof OrganizationInvitationConflictError) return reply.code(409).send(errorBody('RESOURCE_CONFLICT', error.message, request.id));
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.get<{ Params: { orgId: string } }>(webhookPath, async (request, reply) => {
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const principal = request.principal;
    if (!organization.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Organization identifier is invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeWebhookAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Webhook integrations require organization administrator access', request.id));
    return reply.code(200).send({ endpoints: await webhookEndpointStore.list(organization.data, webhookPrincipalSubject(principal)) });
  });

  app.post<{ Params: { orgId: string } }>(webhookPath, async (request, reply) => {
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const principal = request.principal;
    const body = webhookCreateSchema.safeParse(request.body);
    const idempotencyKey = readIdempotencyKey(request);
    if (!organization.success || !body.success || idempotencyKey === null) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid HTTPS endpoint, event list, and Idempotency-Key are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeWebhookAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Webhook integrations require organization administrator access', request.id));
    const eventTypes = [...body.data.eventTypes].sort();
    const requestHash = `0x${sha256(JSON.stringify({ url: body.data.url, eventTypes }))}`;
    let secretReference: string | null = null;
    let committed = false;
    const endpointId = randomUUID();
    const signingSecret = randomBytes(32).toString('base64url');
    try {
      await webhookUrlValidator.validate(body.data.url);
      secretReference = await webhookSecretStore.put(organization.data, endpointId, signingSecret);
      const result = await webhookEndpointStore.create({
        organizationId: organization.data, principalId: webhookPrincipalSubject(principal), endpointId, idempotencyKey,
        requestHash, url: body.data.url, eventTypes, secretReference,
      });
      committed = true;
      if (result.kind === 'REPLAY') {
        await webhookSecretStore.delete(secretReference).catch(() => undefined);
        return reply.code(200).send({ endpoint: result.endpoint, replayed: true });
      }
      return reply.code(201).send({ endpoint: result.endpoint, signingSecret, shownOnce: true });
    } catch (error: unknown) {
      if (!committed && secretReference !== null) await webhookSecretStore.delete(secretReference).catch(() => undefined);
      const mapped = webhookErrorResponse(error, request, reply);
      if (mapped !== null) return mapped;
      throw error;
    }
  });

  app.post<{ Params: { orgId: string; endpointId: string } }>(`${webhookPath}/:endpointId/rotate-secret`, async (request, reply) => {
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const endpointId = webhookEndpointIdSchema.safeParse(request.params.endpointId);
    const principal = request.principal;
    const idempotencyKey = readIdempotencyKey(request);
    if (!organization.success || !endpointId.success || idempotencyKey === null) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid endpoint identifier and Idempotency-Key are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeWebhookAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Webhook integrations require organization administrator access', request.id));
    const requestHash = `0x${sha256(JSON.stringify({ endpointId: endpointId.data, operation: 'rotate-secret' }))}`;
    const signingSecret = randomBytes(32).toString('base64url');
    let secretReference: string | null = null;
    let committed = false;
    try {
      secretReference = await webhookSecretStore.put(organization.data, endpointId.data, signingSecret);
      const outcome = await webhookEndpointStore.rotateSecret({
        organizationId: organization.data, principalId: webhookPrincipalSubject(principal), endpointId: endpointId.data,
        idempotencyKey, requestHash, secretReference,
      });
      committed = true;
      if (outcome.kind === 'REPLAY') {
        await webhookSecretStore.delete(secretReference).catch(() => undefined);
        if (outcome.priorSecretReference !== null) {
          await webhookSecretStore.delete(outcome.priorSecretReference);
          await webhookEndpointStore.clearPriorSecretReference({ organizationId: organization.data, endpointId: endpointId.data, secretReference: outcome.priorSecretReference });
        }
        return reply.code(200).send({ endpointId: endpointId.data, replayed: true });
      }
      let cleanupPending = false;
      if (outcome.priorSecretReference !== null) {
        try {
          await webhookSecretStore.delete(outcome.priorSecretReference);
          await webhookEndpointStore.clearPriorSecretReference({ organizationId: organization.data, endpointId: endpointId.data, secretReference: outcome.priorSecretReference });
        } catch { cleanupPending = true; }
      }
      return reply.code(200).send({ endpointId: endpointId.data, signingSecret, shownOnce: true, cleanupPending });
    } catch (error: unknown) {
      if (!committed && secretReference !== null) await webhookSecretStore.delete(secretReference).catch(() => undefined);
      const mapped = webhookErrorResponse(error, request, reply);
      if (mapped !== null) return mapped;
      throw error;
    }
  });

  app.patch<{ Params: { orgId: string; endpointId: string } }>(`${webhookPath}/:endpointId`, async (request, reply) => {
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const endpointId = webhookEndpointIdSchema.safeParse(request.params.endpointId);
    const principal = request.principal;
    const body = webhookEnabledSchema.safeParse(request.body);
    const idempotencyKey = readIdempotencyKey(request);
    if (!organization.success || !endpointId.success || !body.success || idempotencyKey === null) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid endpoint, enabled flag, and Idempotency-Key are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeWebhookAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Webhook integrations require organization administrator access', request.id));
    try {
      const requestHash = `0x${sha256(JSON.stringify({ endpointId: endpointId.data, enabled: body.data.enabled }))}`;
      const result = await webhookEndpointStore.setEnabled({
        organizationId: organization.data, principalId: webhookPrincipalSubject(principal), endpointId: endpointId.data,
        idempotencyKey, requestHash, enabled: body.data.enabled,
      });
      return reply.code(200).send({ endpoint: result.endpoint, ...(result.kind === 'REPLAY' ? { replayed: true as const } : {}) });
    } catch (error: unknown) {
      const mapped = webhookErrorResponse(error, request, reply);
      if (mapped !== null) return mapped;
      throw error;
    }
  });

  app.delete<{ Params: { orgId: string; endpointId: string } }>(`${webhookPath}/:endpointId`, async (request, reply) => {
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const endpointId = webhookEndpointIdSchema.safeParse(request.params.endpointId);
    const principal = request.principal;
    const idempotencyKey = readIdempotencyKey(request);
    if (!organization.success || !endpointId.success || idempotencyKey === null) return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid endpoint and Idempotency-Key are required', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeWebhookAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Webhook integrations require organization administrator access', request.id));
    try {
      const requestHash = `0x${sha256(JSON.stringify({ endpointId: endpointId.data, operation: 'delete' }))}`;
      const result = await webhookEndpointStore.disableAndRemove({
        organizationId: organization.data, principalId: webhookPrincipalSubject(principal), endpointId: endpointId.data,
        idempotencyKey, requestHash,
      });
      if (result.secretReference !== null) {
        await webhookSecretStore.delete(result.secretReference);
        await webhookEndpointStore.clearSecretReference({ organizationId: organization.data, endpointId: endpointId.data, secretReference: result.secretReference });
      }
      return reply.code(204).send();
    } catch (error: unknown) {
      const mapped = webhookErrorResponse(error, request, reply);
      if (mapped !== null) return mapped;
      return reply.code(503).send(errorBody('DEPENDENCY_UNAVAILABLE', 'Webhook deletion is pending secret cleanup; retry with the same idempotency key', request.id));
    }
  });

  app.get<{ Params: { orgId: string; endpointId: string }; Querystring: { limit?: string } }>(`${webhookPath}/:endpointId/deliveries`, async (request, reply) => {
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const endpointId = webhookEndpointIdSchema.safeParse(request.params.endpointId);
    const principal = request.principal;
    const query = z.object({ limit: z.coerce.number().int().min(1).max(100).default(25) }).strict().safeParse(request.query);
    if (!organization.success || !endpointId.success || !query.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Webhook delivery query is invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    const denied = await authorizeWebhookAdmin(organization.data, principal);
    if (denied !== null) return reply.code(denied).send(errorBody(denied === 404 ? 'RESOURCE_NOT_FOUND' : 'FORBIDDEN', 'Webhook integrations require organization administrator access', request.id));
    try {
      const deliveries = await webhookEndpointStore.listDeliveries({ organizationId: organization.data, principalId: webhookPrincipalSubject(principal), endpointId: endpointId.data, limit: query.data.limit });
      return reply.code(200).send({ deliveries });
    } catch (error: unknown) {
      const mapped = webhookErrorResponse(error, request, reply);
      if (mapped !== null) return mapped;
      throw error;
    }
  });


  app.get('/api/v1/me', async (request, reply) => {
    const principal = request.principal;
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    if (principal.type === 'AGENT') {
      return reply.code(200).send({ principal: { type: principal.type, organizationId: principal.organizationId, agentId: principal.agentId, keyVersion: principal.keyVersion } });
    }
    const memberships = await service.humanOrganizations(principal.subject);
    return reply.code(200).send({ principal: { type: principal.type, subject: principal.subject }, organizations: memberships });
  });

  app.get<{ Params: { orgId: string } }>('/api/v1/orgs/:orgId/agents', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    if (!organization.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Organization identifier is invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const memberships = await authorizeOrganization(service, principal, organization.data);
      if (memberships === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
      const agents = await service.listAgents(principal, organization.data);
      return reply.code(200).send({ agents });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.get<{ Params: { orgId: string } }>('/api/v1/orgs/:orgId/policies', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    if (!organization.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Organization identifier is invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const policies = await policyService.listPolicies(principal, organization.data);
      return reply.code(200).send({ policies });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.get<{ Params: { orgId: string; policyId: string; revision: string } }>('/api/v1/orgs/:orgId/policies/:policyId/revisions/:revision', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const policyId = OrganizationIdSchema.safeParse(request.params.policyId);
    const revision = z.coerce.number().int().positive().safe().safeParse(request.params.revision);
    if (!organization.success || !policyId.success || !revision.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Policy revision identifiers are invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const policy = await policyService.getRevision(principal, organization.data, policyId.data, revision.data);
      return reply.code(200).send(policy);
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string } }>('/api/v1/orgs/:orgId/policies', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const revision = PolicyRevisionSchema.safeParse(request.body);
    const idempotencyHeader = request.headers['idempotency-key'];
    const idempotencyKey = typeof idempotencyHeader === 'string' ? IdempotencyKeySchema.safeParse(idempotencyHeader) : null;
    if (!organization.success || !revision.success || revision.data.revision !== 1 || revision.data.organizationId !== organization.data || idempotencyKey === null || !idempotencyKey.success) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid organization, revision-1 policy body, and Idempotency-Key are required', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const result = await policyService.createDraft(principal, organization.data, idempotencyKey.data, revision.data);
      return reply.code(result.kind === 'CREATED' ? 201 : 200).send({ ...result.policy, ...(result.kind === 'REPLAY' ? { replayed: true } : {}) });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string; policyId: string } }>('/api/v1/orgs/:orgId/policies/:policyId/revisions', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const revision = PolicyRevisionSchema.safeParse(request.body);
    const idempotencyHeader = request.headers['idempotency-key'];
    const idempotencyKey = typeof idempotencyHeader === 'string' ? IdempotencyKeySchema.safeParse(idempotencyHeader) : null;
    if (!organization.success || !revision.success || revision.data.revision < 2 || revision.data.organizationId !== organization.data || revision.data.policyId !== request.params.policyId || idempotencyKey === null || !idempotencyKey.success) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid policy revision and Idempotency-Key are required', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const result = await policyService.createRevision(principal, organization.data, idempotencyKey.data, revision.data);
      return reply.code(result.kind === 'CREATED' ? 201 : 200).send({ ...result.policy, ...(result.kind === 'REPLAY' ? { replayed: true } : {}) });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string; policyId: string } }>('/api/v1/orgs/:orgId/policies/:policyId/activate', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const policyId = OrganizationIdSchema.safeParse(request.params.policyId);
    const idempotencyHeader = request.headers['idempotency-key'];
    const idempotencyKey = typeof idempotencyHeader === 'string' ? IdempotencyKeySchema.safeParse(idempotencyHeader) : null;
    if (!organization.success || !policyId.success || idempotencyKey === null || !idempotencyKey.success) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid organization, policy, and Idempotency-Key are required', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const result = await policyActivationService.prepare(principal, organization.data, policyId.data, idempotencyKey.data);
      return reply.code(result.kind === 'CREATED' ? 201 : 200).send({
        planId: result.planId,
        state: result.plan.status,
        plan: result.plan,
        ...(result.kind === 'REPLAY' ? { replayed: true } : {}),
      });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string; policyId: string }; Body: { planId: string; transactionHashes: string[] } }>(
    '/api/v1/orgs/:orgId/policies/:policyId/activate/finalize', async (request, reply) => {
      const principal = request.principal;
      const organization = OrganizationIdSchema.safeParse(request.params.orgId);
      const policyId = OrganizationIdSchema.safeParse(request.params.policyId);
      const body = z.object({
        planId: z.string().uuid(),
        transactionHashes: z.array(z.string().regex(/^0x[0-9a-fA-F]{64}$/)).min(1).max(32),
      }).strict().safeParse(request.body);
      const idempotencyHeader = request.headers['idempotency-key'];
      const idempotencyKey = typeof idempotencyHeader === 'string' ? IdempotencyKeySchema.safeParse(idempotencyHeader) : null;
      if (!organization.success || !policyId.success || !body.success || idempotencyKey === null || !idempotencyKey.success) {
        return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid activation plan, transaction hashes, and Idempotency-Key are required', request.id));
      }
      if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
      try {
        const outcome = await policyActivationService.finalize(
          principal, organization.data, policyId.data, body.data.planId, idempotencyKey.data, body.data.transactionHashes,
        );
        return reply.code(200).send({
          ...outcome.result,
          ...(outcome.kind === 'REPLAY' ? { replayed: true } : {}),
        });
      } catch (error: unknown) {
        const mapped = mapApplicationError(error, request);
        if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
        throw error;
      }
    },
  );

  app.post<{ Params: { orgId: string; policyId: string } }>('/api/v1/orgs/:orgId/policies/:policyId/revoke', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const policyId = OrganizationIdSchema.safeParse(request.params.policyId);
    const idempotencyHeader = request.headers['idempotency-key'];
    const idempotencyKey = typeof idempotencyHeader === 'string' ? IdempotencyKeySchema.safeParse(idempotencyHeader) : null;
    if (!organization.success || !policyId.success || idempotencyKey === null || !idempotencyKey.success) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid organization, policy, and Idempotency-Key are required', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const result = await policyRevocationService.prepare(principal, organization.data, policyId.data, idempotencyKey.data);
      return reply.code(result.kind === 'CREATED' ? 201 : 200).send({
        planId: result.planId, state: result.plan.status, plan: result.plan,
        ...(result.kind === 'REPLAY' ? { replayed: true } : {}),
      });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string; policyId: string }; Body: { planId: string; transactionHash: string } }>(
    '/api/v1/orgs/:orgId/policies/:policyId/revoke/finalize', async (request, reply) => {
      const principal = request.principal;
      const organization = OrganizationIdSchema.safeParse(request.params.orgId);
      const policyId = OrganizationIdSchema.safeParse(request.params.policyId);
      const body = z.object({ planId: z.string().uuid(), transactionHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/) }).strict().safeParse(request.body);
      const idempotencyHeader = request.headers['idempotency-key'];
      const idempotencyKey = typeof idempotencyHeader === 'string' ? IdempotencyKeySchema.safeParse(idempotencyHeader) : null;
      if (!organization.success || !policyId.success || !body.success || idempotencyKey === null || !idempotencyKey.success) {
        return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid revocation plan, transaction hash, and Idempotency-Key are required', request.id));
      }
      if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
      try {
        const outcome = await policyRevocationService.finalize(
          principal, organization.data, policyId.data, body.data.planId, idempotencyKey.data, body.data.transactionHash,
        );
        return reply.code(200).send({ ...outcome.result, ...(outcome.kind === 'REPLAY' ? { replayed: true } : {}) });
      } catch (error: unknown) {
        const mapped = mapApplicationError(error, request);
        if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
        throw error;
      }
    },
  );

  app.post<{ Params: { orgId: string; policyId: string } }>('/api/v1/orgs/:orgId/policies/:policyId/simulate', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const policyId = OrganizationIdSchema.safeParse(request.params.policyId);
    const action = ActionIntentSchema.safeParse(request.body);
    if (!organization.success || !policyId.success || !action.success
      || action.data.organizationId !== organization.data || action.data.policyId !== policyId.data) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid action intent matching the organization and policy is required', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const result = await policyService.simulateAction(principal, organization.data, policyId.data, action.data);
      return reply.code(200).send(result);
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string } }>('/api/v1/orgs/:orgId/actions', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const action = ActionIntentSchema.safeParse(request.body);
    const idempotencyHeader = request.headers['idempotency-key'];
    const idempotencyKey = typeof idempotencyHeader === 'string' ? IdempotencyKeySchema.safeParse(idempotencyHeader) : null;
    if (!organization.success || !action.success || idempotencyKey === null || !idempotencyKey.success || action.data.idempotencyKey !== idempotencyKey.data || action.data.organizationId !== organization.data) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid action, matching organization, and Idempotency-Key are required', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const result = await actionService.submitAction(principal, organization.data, idempotencyKey.data, action.data);
      return reply.code(result.kind === 'CREATED' ? 201 : 200).send({ ...result.action, ...(result.kind === 'REPLAY' ? { replayed: true } : {}) });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string; actionId: string } }>('/api/v1/orgs/:orgId/actions/:actionId/authorize', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const actionId = OrganizationIdSchema.safeParse(request.params.actionId);
    const idempotencyHeader = request.headers['idempotency-key'];
    const idempotencyKey = typeof idempotencyHeader === 'string' ? IdempotencyKeySchema.safeParse(idempotencyHeader) : null;
    if (!organization.success || !actionId.success || idempotencyKey === null || !idempotencyKey.success || request.body !== undefined) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid action identifier and Idempotency-Key are required; this operation has no request body', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const outcome = await actionAuthorizationService.authorizeAction(principal, organization.data, actionId.data, idempotencyKey.data);
      return reply.code(outcome.kind === 'CREATED' ? 201 : 200).send({
        ...outcome.result,
        ...(outcome.kind === 'REPLAY' ? { replayed: true } : {}),
      });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string; actionId: string } }>('/api/v1/orgs/:orgId/actions/:actionId/execute', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const actionId = OrganizationIdSchema.safeParse(request.params.actionId);
    const body = z.object({
      signature: z.string().regex(/^0x(?:[0-9a-fA-F]{2}){65}$/),
      rawTransaction: z.string().max(262146).regex(/^0x(?:[0-9a-fA-F]{2})+$/),
    }).strict().safeParse(request.body);
    const idempotencyHeader = request.headers['idempotency-key'];
    const idempotencyKey = typeof idempotencyHeader === 'string' ? IdempotencyKeySchema.safeParse(idempotencyHeader) : null;
    if (!organization.success || !actionId.success || !body.success || idempotencyKey === null || !idempotencyKey.success) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid action, signature, signed transaction, and Idempotency-Key are required', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const outcome = await actionExecutionService.executeAction(
        principal, organization.data, actionId.data, idempotencyKey.data, body.data.signature, body.data.rawTransaction,
      );
      return reply.code(outcome.kind === 'CREATED' ? 201 : 200).send({
        ...outcome.result, ...(outcome.kind === 'REPLAY' ? { replayed: true } : {}),
      });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string; actionId: string } }>('/api/v1/orgs/:orgId/actions/:actionId/approval', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const actionId = OrganizationIdSchema.safeParse(request.params.actionId);
    const body = z.object({ outcome: z.enum(['APPROVED', 'DENIED']), actionHash: z.string().regex(/^0x[0-9a-f]{64}$/) }).strict().safeParse(request.body);
    const idempotencyHeader = request.headers['idempotency-key'];
    const idempotencyKey = typeof idempotencyHeader === 'string' ? IdempotencyKeySchema.safeParse(idempotencyHeader) : null;
    if (!organization.success || !actionId.success || !body.success || idempotencyKey === null || !idempotencyKey.success) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid action approval and Idempotency-Key are required', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const result = await approvalService.decide(principal, organization.data, actionId.data, idempotencyKey.data, body.data.actionHash, body.data.outcome);
      return reply.code(result.kind === 'CREATED' ? 201 : 200).send({ ...result.approval, ...(result.kind === 'REPLAY' ? { replayed: true } : {}) });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string; actionId: string } }>('/api/v1/orgs/:orgId/actions/:actionId/reorg-resolution', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const actionId = OrganizationIdSchema.safeParse(request.params.actionId);
    const body = z.object({
      disposition: z.enum(['CONSUMED', 'RELEASED']),
      // oxlint-disable-next-line no-control-regex -- Control-character rejection is intentional.
      reason: z.string().trim().min(1).max(1000).refine((value) => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)),
      evidenceHash: z.string().regex(/^0x[0-9a-fA-F]{64}$/).optional(),
    }).strict().safeParse(request.body);
    const idempotencyHeader = request.headers['idempotency-key'];
    const idempotencyKey = typeof idempotencyHeader === 'string' ? IdempotencyKeySchema.safeParse(idempotencyHeader) : null;
    if (!organization.success || !actionId.success || !body.success || idempotencyKey === null || !idempotencyKey.success) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid deep-reorg disposition, reason, and Idempotency-Key are required', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const result = await executionReorgResolutionService.resolve(principal, {
        organizationId: organization.data,
        actionId: actionId.data,
        idempotencyKey: idempotencyKey.data,
        disposition: body.data.disposition,
        reason: body.data.reason,
        evidenceHash: body.data.evidenceHash?.toLowerCase() ?? null,
      });
      const { kind, ...resolution } = result;
      return reply.code(kind === 'CREATED' ? 201 : 200).send({
        ...resolution, ...(kind === 'REPLAY' ? { replayed: true } : {}),
      });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.get<{ Params: { orgId: string }; Querystring: { state?: string; limit?: string } }>('/api/v1/orgs/:orgId/actions', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const query = z.object({ state: z.enum(ACTION_STATES).optional(), limit: z.coerce.number().int().min(1).max(100).default(50) }).strict().safeParse(request.query);
    if (!organization.success || !query.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Action list filters are invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const actions = await activityService.listActions(principal, organization.data, query.data.state ?? null, query.data.limit);
      return reply.code(200).send({ actions });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.get<{ Params: { orgId: string; actionId: string } }>('/api/v1/orgs/:orgId/actions/:actionId', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const actionId = OrganizationIdSchema.safeParse(request.params.actionId);
    if (!organization.success || !actionId.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Organization and action identifiers are invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const action = await activityService.getAction(principal, organization.data, actionId.data);
      return reply.code(200).send(action);
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.get<{ Params: { orgId: string }; Querystring: { limit?: string; beforeSequence?: string } }>('/api/v1/orgs/:orgId/audit-events', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const query = z.object({
      limit: z.coerce.number().int().min(1).max(100).default(50),
      beforeSequence: z.string().regex(/^[1-9][0-9]{0,18}$/).refine((value) => BigInt(value) <= 9223372036854775807n).optional(),
    }).strict().safeParse(request.query);
    if (!organization.success || !query.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Audit pagination parameters are invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const events = await activityService.listAuditEvents(principal, organization.data, query.data.limit, query.data.beforeSequence ?? null);
      return reply.code(200).send({ events });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.get<{ Params: { orgId: string }; Querystring: { limit?: string; beforeSequence?: string } }>('/api/v1/orgs/:orgId/audit-exports', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const query = z.object({
      limit: z.coerce.number().int().min(1).max(10_000).default(1_000),
      beforeSequence: z.string().regex(/^[1-9][0-9]{0,18}$/).refine((value) => BigInt(value) <= 9223372036854775807n).optional(),
    }).strict().safeParse(request.query);
    if (!organization.success || !query.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Audit export parameters are invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    if (auditExportService === null) return reply.code(503).send(errorBody('DEPENDENCY_UNAVAILABLE', 'Signed audit exports are not configured', request.id));
    try {
      const result = await auditExportService.create(principal, organization.data, query.data.limit, query.data.beforeSequence ?? null);
      return reply.code(200).send(result);
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      return reply.code(503).send(errorBody('DEPENDENCY_UNAVAILABLE', 'Audit export could not be produced', request.id));
    }
  });

  app.get<{ Params: { orgId: string }; Querystring: { limit?: string; actionId?: string } }>('/api/v1/orgs/:orgId/receipts', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const query = z.object({
      limit: z.coerce.number().int().min(1).max(100).default(50),
      actionId: z.string().min(1).max(128).regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]*$/).optional(),
    }).strict().safeParse(request.query);
    if (!organization.success || !query.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Receipt pagination parameters are invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const receipts = await activityService.listReceipts(principal, organization.data, query.data.limit, query.data.actionId ?? null);
      return reply.code(200).send({ receipts });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.get<{ Params: { orgId: string }; Querystring: { limit?: string } }>('/api/v1/orgs/:orgId/alerts', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const query = z.object({ limit: z.coerce.number().int().min(1).max(100).default(50) }).strict().safeParse(request.query);
    if (!organization.success || !query.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Alert pagination parameters are invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const alerts = await activityService.listAlerts(principal, organization.data, query.data.limit);
      return reply.code(200).send({ alerts });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string } }>('/api/v1/orgs/:orgId/agents', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const body = AgentCreateSchema.safeParse(request.body);
    const idempotencyHeader = request.headers['idempotency-key'];
    const idempotencyKey = typeof idempotencyHeader === 'string' ? IdempotencyKeySchema.safeParse(idempotencyHeader) : null;
    if (!organization.success || !body.success || idempotencyKey === null || !idempotencyKey.success) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid organization, agent body, and Idempotency-Key are required', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const result = await service.registerAgent(principal, organization.data, idempotencyKey.data, body.data);
      if (result.kind === 'REPLAY') return reply.code(200).send({ agent: result.agent, replayed: true });
      return reply.code(201).send({ agent: result.agent, credential: { token: result.token, shownOnce: true } });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.get<{ Params: { orgId: string } }>('/api/v1/orgs/:orgId/accounts', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    if (!organization.success) return reply.code(400).send(errorBody('INVALID_REQUEST', 'Organization identifier is invalid', request.id));
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const accounts = await accountService.listAccounts(principal, organization.data);
      return reply.code(200).send({ accounts });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string } }>('/api/v1/orgs/:orgId/accounts', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const account = AccountCreateSchema.safeParse(request.body);
    const rawIdempotencyKey = request.headers['idempotency-key'];
    const idempotencyKey = typeof rawIdempotencyKey === 'string' ? IdempotencyKeySchema.safeParse(rawIdempotencyKey) : null;
    if (!organization.success || !account.success || idempotencyKey === null || !idempotencyKey.success) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'A valid account and Idempotency-Key are required', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const outcome = await accountService.registerAccount(principal, organization.data, idempotencyKey.data, account.data);
      return reply.code(outcome.kind === 'CREATED' ? 201 : 200).send({ account: outcome.account, ...(outcome.kind === 'REPLAY' ? { replayed: true } : {}) });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  app.post<{ Params: { orgId: string; accountId: string } }>('/api/v1/orgs/:orgId/accounts/:accountId/verify', async (request, reply) => {
    const principal = request.principal;
    const organization = OrganizationIdSchema.safeParse(request.params.orgId);
    const accountId = OrganizationIdSchema.safeParse(request.params.accountId);
    const rawIdempotencyKey = request.headers['idempotency-key'];
    const idempotencyKey = typeof rawIdempotencyKey === 'string' ? IdempotencyKeySchema.safeParse(rawIdempotencyKey) : null;
    if (!organization.success || !accountId.success || idempotencyKey === null || !idempotencyKey.success) {
      return reply.code(400).send(errorBody('INVALID_REQUEST', 'Valid organization, account, and Idempotency-Key are required', request.id));
    }
    if (principal === null) return reply.code(401).send(errorBody('UNAUTHENTICATED', 'A valid bearer credential is required', request.id));
    try {
      const outcome = await accountService.verifyAccount(principal, organization.data, accountId.data, idempotencyKey.data);
      return reply.code(200).send({ account: outcome.account, ...(outcome.kind === 'REPLAY' ? { replayed: true } : {}) });
    } catch (error: unknown) {
      const mapped = mapApplicationError(error, request);
      if (mapped !== null) return reply.code(mapped.statusCode).send(mapped.body);
      throw error;
    }
  });

  return app;
}
