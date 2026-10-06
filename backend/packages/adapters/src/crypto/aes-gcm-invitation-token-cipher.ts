import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import type { InvitationTokenCipher } from '../../../ports/src/invitation-email.js';

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{40,128}$/;
const CONTEXT_LIMIT = 128;

function aad(organizationId: string, invitationId: string): Buffer {
  if (organizationId.length < 1 || organizationId.length > CONTEXT_LIMIT
    || invitationId.length < 1 || invitationId.length > CONTEXT_LIMIT) {
    throw new Error('Invitation encryption context is invalid');
  }
  return Buffer.from(JSON.stringify([organizationId, invitationId]), 'utf8');
}

export class AesGcmInvitationTokenCipher implements InvitationTokenCipher {
  private readonly key: Buffer;

  public constructor(keyHex: string) {
    if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) throw new Error('Invitation token encryption key must be 32 bytes encoded as hex');
    this.key = Buffer.from(keyHex, 'hex');
  }

  public encrypt(token: string, organizationId: string, invitationId: string): string {
    if (!TOKEN_PATTERN.test(token)) throw new Error('Invitation token format is invalid');
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(aad(organizationId, invitationId));
    const encrypted = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
    return `v1.${iv.toString('base64url')}.${cipher.getAuthTag().toString('base64url')}.${encrypted.toString('base64url')}`;
  }

  public decrypt(ciphertext: string, organizationId: string, invitationId: string): string {
    const parts = ciphertext.split('.');
    if (parts.length !== 4 || parts[0] !== 'v1' || parts[1] === undefined || parts[2] === undefined || parts[3] === undefined
      || !/^[A-Za-z0-9_-]{16}$/.test(parts[1]) || !/^[A-Za-z0-9_-]{22}$/.test(parts[2])
      || !/^[A-Za-z0-9_-]{1,172}$/.test(parts[3])) {
      throw new Error('Invitation ciphertext format is invalid');
    }
    const iv = Buffer.from(parts[1], 'base64url');
    const authTag = Buffer.from(parts[2], 'base64url');
    if (iv.length !== 12 || authTag.length !== 16) throw new Error('Invitation ciphertext format is invalid');
    const decipher = createDecipheriv('aes-256-gcm', this.key, iv);
    decipher.setAAD(aad(organizationId, invitationId));
    decipher.setAuthTag(authTag);
    const token = Buffer.concat([decipher.update(Buffer.from(parts[3], 'base64url')), decipher.final()]).toString('utf8');
    if (!TOKEN_PATTERN.test(token)) throw new Error('Decrypted invitation token is invalid');
    return token;
  }
}
