import { describe, expect, it } from 'vitest';
import { getActivityDetailHref } from '../src/app/activityLinks';

describe('activity detail links', () => {
  it('links action audit events to the action detail route', () => {
    expect(getActivityDetailHref('ACTION', 'action/with space')).toBe('/app/activity/action%2Fwith%20space');
  });

  it.each(['AGENT', 'POLICY', 'ORGANIZATION', 'ACCOUNT'])('does not treat %s subject IDs as action IDs', (subjectType) => {
    expect(getActivityDetailHref(subjectType, 'subject-123')).toBeNull();
  });
});
