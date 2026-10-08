import { describe, expect, it } from 'vitest';
import { canSwitchOrganization } from '../src/app/organizationPicker';

describe('organization picker interaction state', () => {
  it('disables switching when there are zero or one memberships', () => {
    expect(canSwitchOrganization(0)).toBe(false);
    expect(canSwitchOrganization(1)).toBe(false);
  });

  it('enables switching only when another membership is available', () => {
    expect(canSwitchOrganization(2)).toBe(true);
    expect(canSwitchOrganization(4)).toBe(true);
  });
});
