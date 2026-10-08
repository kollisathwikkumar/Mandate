const transactionExplorers: Readonly<Record<number, string>> = {
  10143: 'https://testnet.monadexplorer.com/tx/',
};

export function receiptExplorerUrl(chainId: number, transactionHash: string): string | null {
  const explorer = transactionExplorers[chainId];
  if (explorer === undefined) return null;
  return `${explorer}${encodeURIComponent(transactionHash)}`;
}
