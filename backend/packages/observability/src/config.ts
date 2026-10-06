export interface ObservabilityConfig {
  readonly enabled: boolean;
  readonly serviceName: string;
  readonly sampleRatio: number;
  readonly tracesEndpoint: string | null;
  readonly metricsEndpoint: string | null;
}

function endpoint(value: string, signal: 'traces' | 'metrics'): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`OTEL ${signal} endpoint must be a valid URL`);
  }
  const loopback = url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]';
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && loopback)) {
    throw new Error('OTEL endpoint must use HTTPS except for loopback development');
  }
  if (url.username || url.password || url.search || url.hash) throw new Error(`OTEL ${signal} endpoint cannot contain credentials, query, or fragment`);
  return url.toString();
}

function parseRatio(value: string | undefined): number {
  if (value === undefined || value === '') return 0.1;
  const ratio = Number(value);
  if (!Number.isFinite(ratio) || ratio < 0 || ratio > 1) throw new Error('MANDATE_OTEL_SAMPLE_RATIO must be between 0 and 1');
  return ratio;
}

export function parseObservabilityConfig(env: Readonly<Record<string, string | undefined>>): ObservabilityConfig {
  const enabledValue = env.MANDATE_OTEL_ENABLED ?? 'false';
  if (enabledValue !== 'true' && enabledValue !== 'false') throw new Error('MANDATE_OTEL_ENABLED must be true or false');
  const enabled = enabledValue === 'true';
  const serviceName = env.OTEL_SERVICE_NAME ?? env.MANDATE_SERVICE_NAME ?? 'mandate-backend';
  if (serviceName.trim() === '' || serviceName.length > 128) throw new Error('OTEL_SERVICE_NAME must contain 1 to 128 characters');
  const sampleRatio = parseRatio(env.MANDATE_OTEL_SAMPLE_RATIO);
  if (!enabled) return { enabled, serviceName, sampleRatio, tracesEndpoint: null, metricsEndpoint: null };

  const generic = env.OTEL_EXPORTER_OTLP_ENDPOINT;
  const trace = env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT;
  const metric = env.OTEL_EXPORTER_OTLP_METRICS_ENDPOINT;
  if (generic === undefined && (trace === undefined || metric === undefined)) {
    throw new Error('OTEL requires OTEL_EXPORTER_OTLP_ENDPOINT or both signal-specific endpoints');
  }
  const base = generic === undefined ? null : endpoint(generic, 'traces').replace(/\/$/, '');
  const tracesEndpoint = endpoint(trace ?? `${base}/v1/traces`, 'traces');
  const metricsEndpoint = endpoint(metric ?? `${base}/v1/metrics`, 'metrics');
  return { enabled, serviceName, sampleRatio, tracesEndpoint, metricsEndpoint };
}

export function createFastifyLoggerOptions(): {
  readonly level: string;
  readonly redact: { paths: string[]; censor: string };
} {
  return {
    level: process.env.LOG_LEVEL ?? 'info',
    redact: {
      paths: [
        'req.headers.authorization', 'req.headers.cookie', 'req.headers.set-cookie',
        'req.body.apiKey', 'req.body.modelApiKey', 'req.body.token', 'req.body.invitationToken',
        'req.body.secret', 'req.body.privateKey', 'req.body.rawTransaction',
      ],
      censor: '[REDACTED]',
    },
  };
}
