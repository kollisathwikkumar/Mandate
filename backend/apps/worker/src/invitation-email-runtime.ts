import { z } from 'zod';

export interface InvitationEmailRuntimeConfig {
  readonly encryptionKeyHex: string;
  readonly from: string;
  readonly acceptUrl: string;
}

const EmailSchema = z.string().trim().email().max(254);

function validateAcceptUrl(value: string): string {
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error('MANDATE_INVITATION_ACCEPT_URL must be an absolute HTTPS URL'); }
  const localHost = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
  if ((parsed.protocol !== 'https:' && !(localHost && parsed.protocol === 'http:'))
    || parsed.username !== '' || parsed.password !== '' || parsed.search !== '' || parsed.hash !== '') {
    throw new Error('MANDATE_INVITATION_ACCEPT_URL must be HTTPS without credentials, query, or fragment');
  }
  return parsed.toString().replace(/\/$/, '');
}

export function readInvitationEmailRuntimeConfig(environment: Readonly<Record<string, string | undefined>>): InvitationEmailRuntimeConfig | null {
  const encryptionKeyHex = environment.MANDATE_INVITATION_TOKEN_ENCRYPTION_KEY_HEX?.trim() ?? '';
  const fromValue = environment.MANDATE_INVITATION_EMAIL_FROM?.trim() ?? '';
  const acceptUrlValue = environment.MANDATE_INVITATION_ACCEPT_URL?.trim() ?? '';
  if (encryptionKeyHex === '' && fromValue === '' && acceptUrlValue === '') return null;
  if (encryptionKeyHex === '') throw new Error('MANDATE_INVITATION_TOKEN_ENCRYPTION_KEY_HEX is required for invitation email delivery');
  if (!/^[0-9a-fA-F]{64}$/.test(encryptionKeyHex)) throw new Error('MANDATE_INVITATION_TOKEN_ENCRYPTION_KEY_HEX must contain 32 bytes encoded as hex');
  const from = EmailSchema.safeParse(fromValue);
  if (!from.success) throw new Error('MANDATE_INVITATION_EMAIL_FROM must be a valid email address');
  if (acceptUrlValue === '') throw new Error('MANDATE_INVITATION_ACCEPT_URL is required for invitation email delivery');
  return { encryptionKeyHex, from: from.data, acceptUrl: validateAcceptUrl(acceptUrlValue) };
}
