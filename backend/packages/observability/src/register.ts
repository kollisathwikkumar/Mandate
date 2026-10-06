import { shutdownObservability, startObservability } from './sdk.js';

startObservability();
process.once('beforeExit', () => {
  void shutdownObservability().catch(() => {
    process.stderr.write('OpenTelemetry shutdown failed\n');
  });
});
