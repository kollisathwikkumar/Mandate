import { describe, expect, it } from 'vitest';
import { canTransitionAction, type ActionState } from '../src/action-state.js';

const allowedTransitions: ReadonlyArray<readonly [ActionState, ActionState]> = [
  ['RECEIVED', 'VALIDATED'],
  ['VALIDATED', 'QUOTED'],
  ['QUOTED', 'EVALUATED'],
  ['EVALUATED', 'BLOCKED'],
  ['EVALUATED', 'HELD'],
  ['EVALUATED', 'ALLOWED'],
  ['HELD', 'APPROVED'],
  ['HELD', 'DENIED'],
  ['HELD', 'EXPIRED'],
  ['ALLOWED', 'RESERVED'],
  ['APPROVED', 'RESERVED'],
  ['RESERVED', 'AUTHORIZED'],
  ['AUTHORIZED', 'SUBMITTED'],
  ['SUBMITTED', 'CONFIRMED'],
  ['SUBMITTED', 'REVERTED'],
  ['SUBMITTED', 'DROPPED'],
  ['CONFIRMED', 'RECONCILED'],
  ['REVERTED', 'RECONCILED'],
  ['DROPPED', 'RECONCILED'],
  ['RECONCILED', 'REORGED'],
];

describe('action lifecycle state machine', () => {
  it.each(allowedTransitions)('allows %s → %s', (from, to) => {
    expect(canTransitionAction(from, to)).toBe(true);
  });

  it.each([
    ['RECEIVED', 'EVALUATED'],
    ['EVALUATED', 'AUTHORIZED'],
    ['HELD', 'SUBMITTED'],
    ['BLOCKED', 'RESERVED'],
    ['DENIED', 'APPROVED'],
    ['EXPIRED', 'RESERVED'],
    ['SUBMITTED', 'RECONCILED'],
    ['RECONCILED', 'SUBMITTED'],
    ['REORGED', 'SUBMITTED'],
  ] as const)('rejects invalid transition %s → %s', (from, to) => {
    expect(canTransitionAction(from, to)).toBe(false);
  });
});
