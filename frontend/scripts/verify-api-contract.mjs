const origin = process.env.MANDATE_API_BASE_URL ?? 'http://127.0.0.1:3000';
let base;
try {
  base = new URL(origin);
} catch {
  console.error('MANDATE_API_BASE_URL must be an absolute local URL.');
  process.exit(2);
}
if (base.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname)) {
  console.error('This development checker only accepts an HTTP loopback API URL.');
  process.exit(2);
}

const operations = [
  ['get', '/health/ready'],
  ['get', '/api/v1/me'],
  ['post', '/api/v1/orgs'],
  ['get', '/api/v1/orgs/{orgId}/agents'],
  ['post', '/api/v1/orgs/{orgId}/agents'],
  ['get', '/api/v1/orgs/{orgId}/policies'],
  ['post', '/api/v1/orgs/{orgId}/policies'],
  ['get', '/api/v1/orgs/{orgId}/policies/{policyId}/revisions/{revision}'],
  ['post', '/api/v1/orgs/{orgId}/policies/{policyId}/revisions'],
  ['post', '/api/v1/orgs/{orgId}/policies/{policyId}/activate'],
  ['post', '/api/v1/orgs/{orgId}/policies/{policyId}/activate/finalize'],
  ['post', '/api/v1/orgs/{orgId}/policies/{policyId}/revoke'],
  ['post', '/api/v1/orgs/{orgId}/policies/{policyId}/revoke/finalize'],
  ['post', '/api/v1/orgs/{orgId}/policies/{policyId}/simulate'],
  ['get', '/api/v1/orgs/{orgId}/actions'],
  ['get', '/api/v1/orgs/{orgId}/actions/{actionId}'],
  ['post', '/api/v1/orgs/{orgId}/actions/{actionId}/approval'],
  ['get', '/api/v1/orgs/{orgId}/audit-events'],
  ['get', '/api/v1/orgs/{orgId}/receipts'],
  ['get', '/api/v1/orgs/{orgId}/alerts'],
  ['get', '/api/v1/orgs/{orgId}/members'],
  ['get', '/api/v1/orgs/{orgId}/invitations'],
  ['post', '/api/v1/orgs/{orgId}/invitations'],
  ['delete', '/api/v1/orgs/{orgId}/invitations/{invitationId}'],
  ['get', '/api/v1/orgs/{orgId}/accounts'],
  ['post', '/api/v1/orgs/{orgId}/accounts'],
  ['post', '/api/v1/orgs/{orgId}/accounts/{accountId}/verify'],
  ['get', '/api/v1/orgs/{orgId}/integrations/model-providers'],
  ['put', '/api/v1/orgs/{orgId}/integrations/model-providers/{provider}'],
  ['post', '/api/v1/orgs/{orgId}/integrations/model-providers/{provider}/test'],
  ['post', '/api/v1/orgs/{orgId}/integrations/model-providers/{provider}/disable'],
  ['delete', '/api/v1/orgs/{orgId}/integrations/model-providers/{provider}'],
  ['get', '/api/v1/orgs/{orgId}/webhooks'],
  ['post', '/api/v1/orgs/{orgId}/webhooks'],
  ['patch', '/api/v1/orgs/{orgId}/webhooks/{endpointId}'],
  ['delete', '/api/v1/orgs/{orgId}/webhooks/{endpointId}'],
  ['post', '/api/v1/orgs/{orgId}/webhooks/{endpointId}/rotate-secret'],
  ['get', '/api/v1/orgs/{orgId}/webhooks/{endpointId}/deliveries'],
];

let response;
try {
  response = await fetch(new URL('/api/v1/openapi.json', base));
} catch (error) {
  console.error(`Could not reach local API at ${base.origin}: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}
if (!response.ok) {
  console.error(`OpenAPI returned HTTP ${response.status}. Start the local API and retry.`);
  process.exit(1);
}

let document;
try {
  document = await response.json();
} catch {
  console.error('The OpenAPI endpoint did not return valid JSON.');
  process.exit(1);
}
if (document === null || typeof document !== 'object' || document.paths === null || typeof document.paths !== 'object') {
  console.error('The API response is missing an OpenAPI paths object.');
  process.exit(1);
}

const missing = operations.filter(([method, path]) => {
  const item = document.paths[path];
  return item === null || typeof item !== 'object' || !(method in item);
});
if (missing.length > 0) {
  console.error(`API contract is missing ${missing.length}/${operations.length} frontend operations:`);
  for (const [method, path] of missing) console.error(`  ${method.toUpperCase()} ${path}`);
  process.exit(1);
}
console.log(`PASS: ${operations.length}/${operations.length} frontend API operations are present in the local OpenAPI contract (${document.openapi ?? 'OpenAPI version unknown'}).`);
console.log('This check validates route/method availability only; authenticated payload and state-transition flows require OIDC-backed integration tests.');
