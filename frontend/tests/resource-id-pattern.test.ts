import { describe, expect, it } from 'vitest';
import { RESOURCE_ID_PATTERN } from '../src/app/inputPatterns';

describe('resource ID HTML pattern', () => {
  const pattern = new RegExp(`^(?:${RESOURCE_ID_PATTERN})$`, 'v');

  it.each(['agent-01', 'Agent_v2.foo', '1'])('accepts supported IDs such as %s', (value) => {
    expect(pattern.test(value)).toBe(true);
  });

  it.each(['', '-starts-with-hyphen', 'space name', 'bad/name'])('rejects unsupported IDs such as %s', (value) => {
    expect(pattern.test(value)).toBe(false);
  });
});
