import { PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { ParentBasedSampler, TraceIdRatioBasedSampler } from '@opentelemetry/sdk-trace-base';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { HttpInstrumentation } from '@opentelemetry/instrumentation-http';
import { PgInstrumentation } from '@opentelemetry/instrumentation-pg';
import fastifyOtel from '@fastify/otel';
import { parseObservabilityConfig } from './config.js';

let sdk: NodeSDK | null = null;
let shutdownPromise: Promise<void> | null = null;

export function startObservability(env: Readonly<Record<string, string | undefined>> = process.env): boolean {
  const config = parseObservabilityConfig(env);
  if (!config.enabled) return false;
  if (sdk !== null) return true;

  const traceEndpoint = config.tracesEndpoint;
  const metricEndpoint = config.metricsEndpoint;
  if (traceEndpoint === null || metricEndpoint === null) throw new Error('Enabled observability config requires trace and metric endpoints');

  const traceExporter = new OTLPTraceExporter({ url: traceEndpoint });
  const metricExporter = new OTLPMetricExporter({ url: metricEndpoint });
  sdk = new NodeSDK({
    autoDetectResources: false,
    resource: resourceFromAttributes({ 'service.name': config.serviceName }),
    sampler: new ParentBasedSampler({ root: new TraceIdRatioBasedSampler(config.sampleRatio) }),
    traceExporter,
    metricReaders: [new PeriodicExportingMetricReader({ exporter: metricExporter, exportIntervalMillis: 30_000 })],
    instrumentations: [
      new HttpInstrumentation({
        disableOutgoingRequestInstrumentation: true,
        headersToSpanAttributes: {},
        applyCustomAttributesOnSpan(span, request) {
          if (!('url' in request)) return;
          const rawUrl = request.url;
          if (typeof rawUrl !== 'string') return;
          try {
            const parsed = new URL(rawUrl, `http://${request.headers.host ?? 'localhost'}`);
            const pathOnly = `${parsed.origin}${parsed.pathname}`;
            span.setAttribute('url.full', pathOnly);
            span.setAttribute('http.url', pathOnly);
            span.setAttribute('http.target', parsed.pathname);
            if (parsed.search.length > 0) span.setAttribute('url.query', '[REDACTED]');
          } catch {
            span.setAttribute('url.full', '[REDACTED]');
            span.setAttribute('http.url', '[REDACTED]');
            span.setAttribute('http.target', '[REDACTED]');
          }
        },
      }),
      new PgInstrumentation({ enhancedDatabaseReporting: false, addSqlCommenterCommentToQueries: false }),
      new fastifyOtel.FastifyOtelInstrumentation({
        registerOnInitialization: true,
        instrumentHooks: false,
        requestHook(span, request) {
          const route = request.routeOptions.url;
          span.setAttribute('url.path', route ?? request.url.split('?', 1)[0] ?? '/');
        },
      }),
    ],
  });
  sdk.start();
  return true;
}

export async function shutdownObservability(): Promise<void> {
  if (sdk === null) return;
  shutdownPromise ??= sdk.shutdown().then(() => { sdk = null; shutdownPromise = null; });
  await shutdownPromise;
}
