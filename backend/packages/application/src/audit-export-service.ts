import { createHash, createPrivateKey, createPublicKey, sign, verify, type KeyObject } from 'node:crypto';
import type { AuditEventRecord, ActivityRepository } from '../../ports/src/activity-repository.js';
import type { Principal } from '../../domain/src/principal.js';
import { ApplicationAccessError } from './agent-service.js';

export interface AuditExportPayload {
  readonly schemaVersion: 1;
  readonly organizationId: string;
  readonly exportedAt: string;
  readonly fromSequence: string | null;
  readonly throughSequence: string | null;
  readonly events: readonly AuditEventRecord[];
  readonly integrityNotice: 'Signatures and hash links provide tamper evidence, not proof of source truth or completeness.';
}

export interface SignedAuditExport {
  readonly payload: AuditExportPayload;
  readonly canonicalPayload: string;
  readonly algorithm: 'Ed25519';
  readonly keyId: string;
  readonly publicKeyPem: string;
  readonly keyFingerprint: string;
  readonly signature: string;
}

export interface AuditExportVerification {
  readonly valid: boolean;
  readonly reason: 'SIGNATURE_INVALID' | 'KEY_FINGERPRINT_MISMATCH' | 'PAYLOAD_MISMATCH' | 'HASH_CHAIN_INVALID' | null;
}

export interface AuditExportSigner {
  sign(value: string, context?: AuditSignatureContext): Omit<SignedAuditExport, 'payload' | 'canonicalPayload'>;
}

export type AuditSignatureContext = 'MANDATE_AUDIT_EXPORT_V1' | 'MANDATE_AUDIT_ANCHOR_V1';

function signatureInput(keyId: string, canonicalPayload: string, context: AuditSignatureContext): Buffer {
  return Buffer.from(`${context}\n${keyId}\n${canonicalPayload}`, 'utf8');
}

export function canonicalizeAuditExportJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('Audit export contains a non-finite number');
    return Object.is(value, -0) ? '0' : JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((entry) => canonicalizeAuditExportJson(entry)).join(',')}]`;
  if (typeof value === 'object') {
    const objectValue = value as Record<string, unknown>;
    const keys = Object.keys(objectValue).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalizeAuditExportJson(objectValue[key])}`).join(',')}}`;
  }
  throw new Error('Audit export contains a value that is not JSON serializable');
}

function eventOrderAndLinksAreValid(events: readonly AuditEventRecord[]): boolean {
  let previousSequence: bigint | null = null;
  let previousEventHash: string | null = null;
  for (const event of events) {
    if (!/^[1-9][0-9]{0,18}$/.test(event.sequence)) return false;
    const sequence = BigInt(event.sequence);
    if (previousSequence !== null && sequence <= previousSequence) return false;
    if (previousSequence !== null && event.previousHash !== previousEventHash) return false;
    if (!/^0x[0-9a-f]{64}$/.test(event.eventHash)) return false;
    if (event.previousHash !== null && !/^0x[0-9a-f]{64}$/.test(event.previousHash)) return false;
    previousSequence = sequence;
    previousEventHash = event.eventHash;
  }
  return true;
}

export class Ed25519AuditExportSigner implements AuditExportSigner {
  private readonly privateKey: KeyObject;
  private readonly publicKey: KeyObject;
  private readonly publicKeyPem: string;
  private readonly keyFingerprint: string;

  public constructor(private readonly keyId: string, privateKeyPem: string) {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(keyId)) throw new Error('Audit signing key ID is invalid');
    this.privateKey = createPrivateKey(privateKeyPem);
    if (this.privateKey.asymmetricKeyType !== 'ed25519') throw new Error('Audit signing key must be Ed25519');
    this.publicKey = createPublicKey(this.privateKey);
    this.publicKeyPem = this.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const publicKeyDer = this.publicKey.export({ type: 'spki', format: 'der' });
    this.keyFingerprint = createHash('sha256').update(publicKeyDer).digest('hex');
  }

  public sign(value: string, context: AuditSignatureContext = 'MANDATE_AUDIT_EXPORT_V1'): Omit<SignedAuditExport, 'payload' | 'canonicalPayload'> {
    const signature = sign(null, signatureInput(this.keyId, value, context), this.privateKey).toString('base64');
    return {
      algorithm: 'Ed25519',
      keyId: this.keyId,
      publicKeyPem: this.publicKeyPem,
      keyFingerprint: this.keyFingerprint,
      signature,
    };
  }
}

export class AuditExportService {
  public constructor(
    private readonly repository: ActivityRepository,
    private readonly signer: AuditExportSigner,
    private readonly now: () => Date = () => new Date(),
  ) {}

  public async create(principal: Principal, organizationId: string, limit: number, beforeSequence: string | null): Promise<SignedAuditExport> {
    if (principal.type !== 'HUMAN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    const role = await this.repository.getHumanRole(organizationId, principal.subject);
    if (role === null) throw new ApplicationAccessError(404, 'RESOURCE_NOT_FOUND');
    if (role !== 'OWNER' && role !== 'ADMIN') throw new ApplicationAccessError(403, 'FORBIDDEN');
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw new Error('Audit export limit must be an integer from 1 to 10000');
    if (beforeSequence !== null && !/^[1-9][0-9]{0,18}$/.test(beforeSequence)) throw new Error('Audit export cursor is invalid');

    const descendingEvents = await this.repository.listAuditEvents(organizationId, null, limit, beforeSequence);
    const events = [...descendingEvents].reverse();
    if (!eventOrderAndLinksAreValid(events)) throw new Error('Audit event hash chain is inconsistent');
    const payload: AuditExportPayload = {
      schemaVersion: 1,
      organizationId,
      exportedAt: this.now().toISOString(),
      fromSequence: events[0]?.sequence ?? null,
      throughSequence: events.at(-1)?.sequence ?? null,
      events,
      integrityNotice: 'Signatures and hash links provide tamper evidence, not proof of source truth or completeness.',
    };
    const canonicalPayload = canonicalizeAuditExportJson(payload);
    return { payload, canonicalPayload, ...this.signer.sign(canonicalPayload) };
  }
}

export function verifyAuditExport(exportValue: SignedAuditExport, trustedKeyFingerprint: string): AuditExportVerification {
  try {
    const publicKey = createPublicKey(exportValue.publicKeyPem);
    const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
    const fingerprint = createHash('sha256').update(publicKeyDer).digest('hex');
    if (!/^[0-9a-f]{64}$/.test(trustedKeyFingerprint)
      || fingerprint !== trustedKeyFingerprint || fingerprint !== exportValue.keyFingerprint
      || publicKey.asymmetricKeyType !== 'ed25519') {
      return { valid: false, reason: 'KEY_FINGERPRINT_MISMATCH' };
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(exportValue.keyId)
      || !verify(null, signatureInput(exportValue.keyId, exportValue.canonicalPayload, 'MANDATE_AUDIT_EXPORT_V1'), publicKey, Buffer.from(exportValue.signature, 'base64'))) {
      return { valid: false, reason: 'SIGNATURE_INVALID' };
    }
    const canonicalPayload = canonicalizeAuditExportJson(exportValue.payload);
    if (canonicalPayload !== exportValue.canonicalPayload) return { valid: false, reason: 'PAYLOAD_MISMATCH' };
    if (!eventOrderAndLinksAreValid(exportValue.payload.events)) return { valid: false, reason: 'HASH_CHAIN_INVALID' };
    return { valid: true, reason: null };
  } catch {
    return { valid: false, reason: 'SIGNATURE_INVALID' };
  }
}
