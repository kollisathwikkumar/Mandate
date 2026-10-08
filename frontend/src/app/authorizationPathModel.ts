import type { AccountList, AgentList, PolicyList, Receipts } from '../api/schemas';

export type AuthorizationPathStep = {
  readonly key: 'agents' | 'policies' | 'accounts' | 'evidence';
  readonly index: string;
  readonly title: string;
  readonly count: number;
  readonly status: 'ready' | 'attention' | 'evidence' | 'pending';
  readonly statusLabel: string;
  readonly note: string;
  readonly href: string;
};

type AuthorizationPathInput = {
  readonly agents: readonly Pick<AgentList['agents'][number], 'status'>[];
  readonly policies: readonly Pick<PolicyList['policies'][number], 'state'>[];
  readonly accounts: readonly Pick<AccountList['accounts'][number], 'status' | 'verifiedAt'>[];
  readonly receipts: readonly Pick<Receipts['receipts'][number], 'status'>[];
};

export function buildAuthorizationPath(input: AuthorizationPathInput): readonly AuthorizationPathStep[] {
  const activeAgents = input.agents.filter((agent) => agent.status === 'ACTIVE').length;
  const activePolicies = input.policies.filter((policy) => policy.state === 'ACTIVE').length;
  const verifiedAccounts = input.accounts.filter((account) => account.status === 'ACTIVE' && account.verifiedAt !== null).length;
  const finalReceipts = input.receipts.filter((receipt) => receipt.status === 'FINAL').length;

  return [
    {
      key: 'agents', index: '01', title: 'Agent identity', count: activeAgents,
      status: activeAgents > 0 ? 'ready' : 'attention',
      statusLabel: activeAgents > 0 ? 'Identity active' : 'Register an agent',
      note: activeAgents > 0 ? 'Active identities are listed; credentials identify callers, not permissions.' : 'No active agent identity is registered in this workspace.',
      href: '/app/agents',
    },
    {
      key: 'policies', index: '02', title: 'Policy boundary', count: activePolicies,
      status: activePolicies > 0 ? 'ready' : 'attention',
      statusLabel: activePolicies > 0 ? 'Active rules' : 'Actions remain blocked',
      note: activePolicies > 0 ? 'Matching rules still apply to each exact action; this count grants no blanket access.' : 'Actions remain blocked without an active policy. Draft, revoked, and expired policies do not authorize actions.',
      href: '/app/policies',
    },
    {
      key: 'accounts', index: '03', title: 'Verified account', count: verifiedAccounts,
      status: verifiedAccounts > 0 ? 'ready' : 'attention',
      statusLabel: verifiedAccounts > 0 ? 'Supported & verified' : 'Verify supported account',
      note: verifiedAccounts > 0 ? 'Active supported accounts with recorded verification; policy/account matching is still required.' : 'No active supported account has a verification record.',
      href: '/app/settings/accounts',
    },
    {
      key: 'evidence', index: '04', title: 'Final evidence', count: finalReceipts,
      status: finalReceipts > 0 ? 'evidence' : 'pending',
      statusLabel: finalReceipts > 0 ? 'Reconciled receipts' : 'No final receipts',
      note: finalReceipts > 0 ? `${finalReceipts} final receipt${finalReceipts === 1 ? '' : 's'} in the latest 5; evidence is not an authorization grant.` : 'No final receipts in the latest 5; tentative or reorged receipts are not final.',
      href: '/app/activity',
    },
  ];
}
