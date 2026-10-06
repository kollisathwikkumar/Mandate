export const ACTION_STATES = [
  'RECEIVED',
  'VALIDATED',
  'QUOTED',
  'EVALUATED',
  'BLOCKED',
  'HELD',
  'APPROVED',
  'DENIED',
  'EXPIRED',
  'ALLOWED',
  'RESERVED',
  'AUTHORIZED',
  'SUBMITTED',
  'CONFIRMED',
  'REVERTED',
  'DROPPED',
  'REORGED',
  'RECONCILED',
] as const;

export type ActionState = (typeof ACTION_STATES)[number];

const ALLOWED_TRANSITIONS: Readonly<Record<ActionState, readonly ActionState[]>> = {
  RECEIVED: ['VALIDATED'],
  VALIDATED: ['QUOTED'],
  QUOTED: ['EVALUATED'],
  EVALUATED: ['BLOCKED', 'HELD', 'ALLOWED'],
  BLOCKED: [],
  HELD: ['APPROVED', 'DENIED', 'EXPIRED'],
  APPROVED: ['RESERVED'],
  DENIED: [],
  EXPIRED: [],
  ALLOWED: ['RESERVED'],
  RESERVED: ['AUTHORIZED'],
  AUTHORIZED: ['SUBMITTED'],
  SUBMITTED: ['CONFIRMED', 'REVERTED', 'DROPPED'],
  CONFIRMED: ['RECONCILED'],
  REVERTED: ['RECONCILED'],
  DROPPED: ['RECONCILED'],
  RECONCILED: ['REORGED'],
  REORGED: [],
};

export function canTransitionAction(from: ActionState, to: ActionState): boolean {
  return ALLOWED_TRANSITIONS[from].includes(to);
}
