import { describe, expect, it } from 'vitest';
import { getPolicyEditorState, type PolicyEditorResources } from '../src/app/policyEditorState';

const resolved: PolicyEditorResources = {
  isRevision: true, policiesLoading: false, policiesLoaded: true, policiesFailed: false,
  policyExists: true, revisionLoading: false, revisionLoaded: true, revisionFailed: false,
};

describe('policy revision editor loading state', () => {
  it('opens a new draft without waiting for the policy-list query', () => {
    expect(getPolicyEditorState({ ...resolved, isRevision: false, policiesLoaded: false, policiesLoading: true, policyExists: false, revisionLoaded: false })).toBe('ready');
  });

  it('shows loading until the policy list resolves', () => {
    expect(getPolicyEditorState({ ...resolved, policiesLoaded: false, policiesLoading: true })).toBe('loading');
  });

  it('surfaces a policy-list request failure rather than a permanent spinner', () => {
    expect(getPolicyEditorState({ ...resolved, policiesLoaded: false, policiesLoading: false, policiesFailed: true, policyExists: false })).toBe('error');
  });

  it('reports a missing policy after a successful list load', () => {
    expect(getPolicyEditorState({ ...resolved, policyExists: false, revisionLoaded: false })).toBe('missing');
  });

  it('waits for the canonical revision body after locating the policy', () => {
    expect(getPolicyEditorState({ ...resolved, revisionLoading: true, revisionLoaded: false })).toBe('loading');
  });

  it('surfaces a canonical revision fetch failure', () => {
    expect(getPolicyEditorState({ ...resolved, revisionLoading: false, revisionLoaded: false, revisionFailed: true })).toBe('error');
  });

  it('opens editing only after the canonical revision has loaded', () => {
    expect(getPolicyEditorState(resolved)).toBe('ready');
  });
});
