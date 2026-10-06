export class RepositoryAccessError extends Error {
  public constructor(public readonly statusCode: 403 | 404) {
    super(statusCode === 403 ? 'Repository access denied' : 'Repository resource not found');
    this.name = 'RepositoryAccessError';
  }
}
