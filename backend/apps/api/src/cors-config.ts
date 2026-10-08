const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

export function parseCorsAllowedOrigins(value: string | undefined): readonly string[] | undefined {
  if (value === undefined || value.trim() === '') return undefined;
  const entries = value.split(',').map((entry) => entry.trim());
  if (entries.some((entry) => entry.length === 0)) throw new Error('MANDATE_CORS_ALLOWED_ORIGINS contains an empty origin');

  const origins: string[] = [];
  for (const entry of entries) {
    if (entry === '*' || entry === 'null') throw new Error('MANDATE_CORS_ALLOWED_ORIGINS must contain exact origins, not wildcard or null');
    let parsed: URL;
    try {
      parsed = new URL(entry);
    } catch {
      throw new Error('MANDATE_CORS_ALLOWED_ORIGINS contains an invalid origin');
    }
    const secure = parsed.protocol === 'https:';
    const localDevelopment = parsed.protocol === 'http:' && LOOPBACK_HOSTS.has(parsed.hostname);
    if ((!secure && !localDevelopment) || parsed.origin !== entry || parsed.username !== '' || parsed.password !== '') {
      throw new Error('MANDATE_CORS_ALLOWED_ORIGINS must contain canonical HTTPS origins (HTTP loopback is for development only)');
    }
    if (origins.includes(parsed.origin)) throw new Error('MANDATE_CORS_ALLOWED_ORIGINS contains a duplicate origin');
    origins.push(parsed.origin);
  }
  return origins;
}
