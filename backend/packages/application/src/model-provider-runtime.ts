import type { ModelProvider, ModelCredentialRepository } from '../../ports/src/model-credential-repository.js';
import type { ModelSecretStore } from '../../ports/src/model-secret-store.js';

export class ModelProviderRuntime {
  public constructor(private readonly credentials: ModelCredentialRepository, private readonly secrets: ModelSecretStore) {}

  public async resolveActiveCredential(organizationId: string, provider: ModelProvider): Promise<string | null> {
    const credential = await this.credentials.getCredential(organizationId, provider);
    if (credential === null || credential.state !== 'ACTIVE') return null;
    return this.secrets.get(credential.secretReference);
  }
}
