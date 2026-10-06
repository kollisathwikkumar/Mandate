import { describe, expect, it } from 'vitest';
import { createFastifyLoggerOptions, parseObservabilityConfig } from '../src/config.js';

describe('observability configuration', () => {
  it('disables exporters by default and uses a stable service identity', () => {
    expect(parseObservabilityConfig({})).toEqual({
      enabled: false,
      serviceName: 'mandate-backend',
      sampleRatio: 0.1,
      tracesEndpoint: null,
      metricsEndpoint: null,
    });
  });

  it('derives trace and metric OTLP endpoints from a local collector endpoint', () => {
    expect(parseObservabilityConfig({
      MANDATE_OTEL_ENABLED: 'true',
      OTEL_SERVICE_NAME: 'mandate-api',
      OTEL_EXPORTER_OTLP_ENDPOINT: 'http://127.0.0.1:4318',
      MANDATE_OTEL_SAMPLE_RATIO: '1',
    })).toEqual({
      enabled: true,
      serviceName: 'mandate-api',
      sampleRatio: 1,
      tracesEndpoint: 'http://127.0.0.1:4318/v1/traces',
      metricsEndpoint: 'http://127.0.0.1:4318/v1/metrics',
    });
  });

  it('rejects public plaintext OTLP endpoints and invalid sampling configuration', () => {
    expect(() => parseObservabilityConfig({
      MANDATE_OTEL_ENABLED: 'true', OTEL_EXPORTER_OTLP_ENDPOINT: 'http://collector.example.test:4318',
    })).toThrow('OTEL endpoint must use HTTPS except for loopback development');
    expect(() => parseObservabilityConfig({ MANDATE_OTEL_SAMPLE_RATIO: '1.1' })).toThrow('MANDATE_OTEL_SAMPLE_RATIO must be between 0 and 1');
    expect(() => parseObservabilityConfig({ MANDATE_OTEL_ENABLED: 'yes' })).toThrow('MANDATE_OTEL_ENABLED must be true or false');
    expect(() => parseObservabilityConfig({ MANDATE_OTEL_ENABLED: 'true', OTEL_EXPORTER_OTLP_ENDPOINT: 'https://user:pass@collector.example.test' })).toThrow('cannot contain credentials');
    expect(() => parseObservabilityConfig({ MANDATE_OTEL_ENABLED: 'true', OTEL_EXPORTER_OTLP_TRACES_ENDPOINT: 'https://trace.example.test' })).toThrow('requires OTEL_EXPORTER_OTLP_ENDPOINT or both signal-specific endpoints');
  });

  it('redacts authorization, cookies, API keys, invitation tokens, and wallet material in structured logs', () => {
    const options = createFastifyLoggerOptions();
    expect(options.redact.paths).toEqual(expect.arrayContaining([
      'req.headers.authorization', 'req.headers.cookie', 'req.body.apiKey', 'req.body.invitationToken', 'req.body.privateKey',
    ]));
    expect(options.redact.censor).toBe('[REDACTED]');
  });
});
