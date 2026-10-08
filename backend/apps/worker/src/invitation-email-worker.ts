import type { Pool, PoolClient } from 'pg';
import type { InvitationEmailMessage, InvitationEmailTransport, InvitationTokenCipher } from '../../../packages/ports/src/invitation-email.js';

interface ClaimedInvitationEmail {
  readonly invitation_id: string;
  readonly organization_id: string;
  readonly email: string;
  readonly role: string;
  readonly organization_name: string;
  readonly expires_at: Date;
  readonly token_ciphertext: string;
  readonly attempts: number;
}

export interface InvitationEmailBatchResult {
  readonly claimed: number;
  readonly sent: number;
  readonly retried: number;
  readonly failed: number;
}

export interface InvitationEmailWorkerConfig {
  readonly from: string;
  readonly acceptUrl: string;
}

const MAX_ATTEMPTS = 12;
const MAX_BATCH_SIZE = 50;

async function cancelClosedInvitations(client: PoolClient): Promise<void> {
  await client.query(`UPDATE invitation_email_deliveries AS delivery
    SET status = 'CANCELLED', token_ciphertext = NULL, locked_at = NULL, updated_at = now()
    FROM organization_invitations AS invitation
    WHERE delivery.invitation_id = invitation.id AND delivery.status = 'PENDING'
      AND (invitation.state <> 'PENDING' OR invitation.expires_at <= now())`);
}

async function claim(client: PoolClient, limit: number): Promise<readonly ClaimedInvitationEmail[]> {
  await cancelClosedInvitations(client);
  const result = await client.query<ClaimedInvitationEmail>(
    `WITH ready AS (
       SELECT delivery.invitation_id
       FROM invitation_email_deliveries AS delivery
       JOIN organization_invitations AS invitation ON invitation.id = delivery.invitation_id
       WHERE delivery.status = 'PENDING' AND delivery.available_at <= now()
         AND (delivery.locked_at IS NULL OR delivery.locked_at < now() - interval '60 seconds')
         AND invitation.state = 'PENDING' AND invitation.expires_at > now()
       ORDER BY delivery.available_at, delivery.created_at
       FOR UPDATE OF delivery SKIP LOCKED
       LIMIT $1
     )
     UPDATE invitation_email_deliveries AS delivery
     SET locked_at = now(), attempts = delivery.attempts + 1, updated_at = now()
     FROM ready, organization_invitations AS invitation, organizations AS organization
     WHERE delivery.invitation_id = ready.invitation_id AND invitation.id = delivery.invitation_id
       AND organization.id = invitation.organization_id
     RETURNING delivery.invitation_id::text, invitation.organization_id, invitation.email,
       invitation.role, organization.display_name AS organization_name, invitation.expires_at,
       delivery.token_ciphertext, delivery.attempts`,
    [limit],
  );
  return result.rows;
}

async function markSent(pool: Pool, invitationId: string): Promise<void> {
  await pool.query(`UPDATE invitation_email_deliveries
    SET status = 'DELIVERED', token_ciphertext = NULL, locked_at = NULL, sent_at = now(),
      last_error_code = NULL, updated_at = now()
    WHERE invitation_id = $1 AND status = 'PENDING' AND locked_at IS NOT NULL`, [invitationId]);
}

async function markFailed(pool: Pool, delivery: ClaimedInvitationEmail): Promise<'RETRIED' | 'FAILED'> {
  const final = delivery.attempts >= MAX_ATTEMPTS;
  const delaySeconds = Math.min(3600, 2 ** Math.min(delivery.attempts, 10));
  await pool.query(`UPDATE invitation_email_deliveries SET status = $2,
    token_ciphertext = CASE WHEN $2 = 'FAILED' THEN NULL ELSE token_ciphertext END,
    locked_at = NULL,
    available_at = CASE WHEN $2 = 'PENDING' THEN now() + ($3 * interval '1 second') ELSE available_at END,
    last_error_code = 'EMAIL_DELIVERY_FAILED', updated_at = now()
    WHERE invitation_id = $1 AND status = 'PENDING' AND locked_at IS NOT NULL`,
  [delivery.invitation_id, final ? 'FAILED' : 'PENDING', delaySeconds]);
  return final ? 'FAILED' : 'RETRIED';
}

function invitationLink(baseUrl: string, token: string): string {
  return `${baseUrl}#token=${encodeURIComponent(token)}`;
}

function buildMessage(config: InvitationEmailWorkerConfig, invitation: ClaimedInvitationEmail, token: string): InvitationEmailMessage {
  // oxlint-disable-next-line no-control-regex -- Control-character rejection is intentional.
  const organizationName = invitation.organization_name.replace(/[\r\n\u0000-\u001f\u007f]/g, ' ').slice(0, 160);
  return {
    from: config.from,
    to: invitation.email,
    subject: 'You have been invited to Mandate',
    text: `You have been invited to join ${organizationName} as ${invitation.role}.\n\nAccept the invitation: ${invitationLink(config.acceptUrl, token)}\n\nThis invitation expires at ${invitation.expires_at.toISOString()}. If you were not expecting this email, you can ignore it.`,
  };
}

export class InvitationEmailDeliveryWorker {
  public constructor(
    private readonly pool: Pool,
    private readonly cipher: InvitationTokenCipher,
    private readonly transport: InvitationEmailTransport,
    private readonly config: InvitationEmailWorkerConfig,
  ) {}

  public async runBatch(batchSize = 25): Promise<InvitationEmailBatchResult> {
    if (!Number.isInteger(batchSize) || batchSize < 1 || batchSize > MAX_BATCH_SIZE) {
      throw new RangeError(`batchSize must be an integer from 1 to ${MAX_BATCH_SIZE}`);
    }
    const client = await this.pool.connect();
    let deliveries: readonly ClaimedInvitationEmail[];
    try {
      await client.query('BEGIN');
      deliveries = await claim(client, batchSize);
      await client.query('COMMIT');
    } catch (error: unknown) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

    let sent = 0;
    let retried = 0;
    let failed = 0;
    for (const delivery of deliveries) {
      try {
        const token = this.cipher.decrypt(delivery.token_ciphertext, delivery.organization_id, delivery.invitation_id);
        await this.transport.send(buildMessage(this.config, delivery, token));
        await markSent(this.pool, delivery.invitation_id);
        sent += 1;
      } catch {
        const outcome = await markFailed(this.pool, delivery);
        if (outcome === 'RETRIED') retried += 1;
        else failed += 1;
      }
    }
    return { claimed: deliveries.length, sent, retried, failed };
  }
}
