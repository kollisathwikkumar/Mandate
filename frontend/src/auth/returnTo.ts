import { type JSONType } from 'zod';
import { matchRoute } from '../app/routeManifest';

export function safeReturnTo(value: JSONType | undefined): string {
  const fallback = '/app/overview';
  // oxlint-disable-next-line no-control-regex -- Control-character rejection is intentional.
  if (typeof value !== 'string' || !value.startsWith('/app/') || /[\\\u0000-\u0020\u007f]/.test(value)) return fallback;
  const pathname = value.split(/[?#]/, 1)[0];
  if (pathname === undefined || pathname.split('/').some((segment) => segment === '.' || segment === '..')) return fallback;
  const route = matchRoute(pathname);
  return route?.definition.audience === 'app' ? value : fallback;
}
