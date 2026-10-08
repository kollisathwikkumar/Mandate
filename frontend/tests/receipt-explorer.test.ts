import { describe, expect, it } from 'vitest';
import { receiptExplorerUrl } from '../src/app/receiptExplorer';

describe('receipt explorer links', () => {
  it('links Monad testnet receipts to the testnet explorer', () => {
    expect(receiptExplorerUrl(10143, '0x123abc')).toBe('https://testnet.monadexplorer.com/tx/0x123abc');
  });

  it('does not send unrecognized chains to a Monad explorer', () => {
    expect(receiptExplorerUrl(1, '0x123abc')).toBeNull();
    expect(receiptExplorerUrl(999999, '0x123abc')).toBeNull();
  });

  it('encodes the transaction hash as one URL path segment', () => {
    expect(receiptExplorerUrl(10143, '0xabc?redirect=https://attacker.example')).toBe('https://testnet.monadexplorer.com/tx/0xabc%3Fredirect%3Dhttps%3A%2F%2Fattacker.example');
  });
});
