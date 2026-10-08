export type PolicyEditorState = 'ready' | 'loading' | 'missing' | 'error';

export interface PolicyEditorResources {
  readonly isRevision: boolean;
  readonly policiesLoading: boolean;
  readonly policiesLoaded: boolean;
  readonly policiesFailed: boolean;
  readonly policyExists: boolean;
  readonly revisionLoading: boolean;
  readonly revisionLoaded: boolean;
  readonly revisionFailed: boolean;
}

export function getPolicyEditorState(resources: PolicyEditorResources): PolicyEditorState {
  if (!resources.isRevision) return 'ready';
  if (resources.policiesFailed) return 'error';
  if (resources.policiesLoading || !resources.policiesLoaded) return 'loading';
  if (!resources.policyExists) return 'missing';
  if (resources.revisionFailed) return 'error';
  if (resources.revisionLoading || !resources.revisionLoaded) return 'loading';
  return 'ready';
}
