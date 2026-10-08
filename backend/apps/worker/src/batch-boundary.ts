export type WorkerComponent =
  | 'audit-anchor-worker'
  | 'outbox-worker'
  | 'webhook-delivery-worker'
  | 'invitation-email-worker'
  | 'execution-reconciler';

export async function runBatchWithIsolation<T>(
  component: WorkerComponent,
  batch: () => Promise<T>,
  onFailure: (component: WorkerComponent) => void,
): Promise<T | null> {
  try {
    return await batch();
  } catch {
    onFailure(component);
    return null;
  }
}
