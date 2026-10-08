import { expect, it } from 'vitest';
import { safeReturnTo } from '../src/auth/returnTo';
it.each(['/app/policies/policy-1/edit', '/app/activity/action-1?view=receipt#evidence', '/app/settings/accounts'])('preserves known local deep links: %s', (path) => {
  expect(safeReturnTo(path)).toBe(path);
});
it.each([undefined, null, {}, '', 'https://evil.com', '//evil.com', '/app/../login', '/app/%2e%2e/login', '/app/%252e%252e/login', '/app/agents/%2f', '/app/agents/a\\b', '/app/agents/a\nb', '/app/unknown', '/login', '/api/v1/me'])('rejects invalid return destinations: %s', (path) => {
  expect(safeReturnTo(path)).toBe('/app/overview');
});
