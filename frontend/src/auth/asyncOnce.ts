/** Shares a single asynchronous operation across repeated effects in one document. */
export function createAsyncOnce<T>(): (operation: () => Promise<T>) => Promise<T> {
  let result: Promise<T> | null = null;
  return (operation) => {
    if (result === null) result = operation();
    return result;
  };
}
