import type { Pool } from 'pg';

export interface RateLimitDecision {
  readonly allowed: boolean;
  readonly remainingRequests: number;
  readonly retryAfterSeconds: number;
}

interface RateWindowRow {
  readonly request_count: number;
  readonly retry_after_seconds: number;
}

export class PostgresRateLimitStore {
  private operationsSinceCleanup = 0;

  constructor(private readonly pool: Pool) {}

  async consume(subjectHash: string, maxRequests: number, windowSeconds: number): Promise<RateLimitDecision> {
    if (!/^[0-9a-f]{64}$/.test(subjectHash)) throw new Error('Rate-limit subject hash must be a SHA-256 hex digest');
    if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > 1_000_000) throw new Error('Rate-limit max requests is invalid');
    if (!Number.isSafeInteger(windowSeconds) || windowSeconds < 1 || windowSeconds > 86_400) throw new Error('Rate-limit window is invalid');

    const result = await this.pool.query<RateWindowRow>(
      `WITH active_window AS (
         SELECT to_timestamp(floor(extract(epoch FROM statement_timestamp()) / $3::double precision) * $3::double precision) AS starts_at
       )
       INSERT INTO api_rate_limit_windows (subject_hash, window_start, request_count)
       SELECT $1, active_window.starts_at, 1 FROM active_window
       ON CONFLICT (subject_hash, window_start) DO UPDATE
         SET request_count = LEAST(api_rate_limit_windows.request_count + 1, $2::integer + 1)
       RETURNING request_count,
         GREATEST(1, CEIL(extract(epoch FROM (window_start + make_interval(secs => $3::double precision) - statement_timestamp()))))::integer AS retry_after_seconds`,
      [subjectHash, maxRequests, windowSeconds],
    );
    const row = result.rows[0];
    if (row === undefined) throw new Error('PostgreSQL did not return a rate-limit decision');
    this.operationsSinceCleanup += 1;
    if (this.operationsSinceCleanup >= 1000) {
      this.operationsSinceCleanup = 0;
      try {
        await this.pool.query("DELETE FROM api_rate_limit_windows WHERE window_start < statement_timestamp() - interval '1 day'");
      } catch {
        // Cleanup is opportunistic; the decision query above remains authoritative.
      }
    }
    const allowed = row.request_count <= maxRequests;
    return { allowed, remainingRequests: Math.max(0, maxRequests - row.request_count), retryAfterSeconds: row.retry_after_seconds };
  }
}
