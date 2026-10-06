import { describe, expect, it } from 'vitest';
import { readInvitationEmailRuntimeConfig } from '../src/invitation-email-runtime.js';

describe('readInvitationEmailRuntimeConfig', () => {
  it('disables delivery only when all three settings are absent', () => {
    expect(readInvitationEmailRuntimeConfig({})).toBeNull();
  });

  it('requires a complete encryption, sender, and acceptance URL configuration', () => {
    expect(() => readInvitationEmailRuntimeConfig({ MANDATE_INVITATION_EMAIL_FROM: 'mandate@example.com' })).toThrow('ENCRYPTION_KEY_HEX');
    expect(() => readInvitationEmailRuntimeConfig({ MANDATE_INVITATION_TOKEN_ENCRYPTION_KEY_HEX: 'a'.repeat(64) })).toThrow('EMAIL_FROM');
    expect(() => readInvitationEmailRuntimeConfig({
      MANDATE_INVITATION_TOKEN_ENCRYPTION_KEY_HEX: 'a'.repeat(64), MANDATE_INVITATION_EMAIL_FROM: 'mandate@example.com',
    })).toThrow('ACCEPT_URL');
  });

  it('accepts a valid HTTPS sender/link tuple and normalizes a trailing slash', () => {
    expect(readInvitationEmailRuntimeConfig({
      MANDATE_INVITATION_TOKEN_ENCRYPTION_KEY_HEX: 'a'.repeat(64),
      MANDATE_INVITATION_EMAIL_FROM: 'mandate@example.com',
      MANDATE_INVITATION_ACCEPT_URL: 'https://console.example.com/invitations/accept/',
    })).toEqual({
      encryptionKeyHex: 'a'.repeat(64), from: 'mandate@example.com',
      acceptUrl: 'https://console.example.com/invitations/accept',
    });
  });

  it('rejects invalid keys, sender addresses, and unsafe URLs', () => {
    const base = {
      MANDATE_INVITATION_TOKEN_ENCRYPTION_KEY_HEX: 'a'.repeat(64),
      MANDATE_INVITATION_EMAIL_FROM: 'mandate@example.com',
      MANDATE_INVITATION_ACCEPT_URL: 'https://console.example.com/accept',
    };
    expect(() => readInvitationEmailRuntimeConfig({ ...base, MANDATE_INVITATION_TOKEN_ENCRYPTION_KEY_HEX: 'short' })).toThrow('32 bytes');
    expect(() => readInvitationEmailRuntimeConfig({ ...base, MANDATE_INVITATION_EMAIL_FROM: 'bad email' })).toThrow('valid email');
    expect(() => readInvitationEmailRuntimeConfig({ ...base, MANDATE_INVITATION_ACCEPT_URL: 'not an absolute URL' }))
      .toThrow('must be an absolute HTTPS URL');
    for (const url of ['http://console.example.com/accept', 'https://user:pass@example.com/accept', 'https://console.example.com/accept?token=x', 'https://console.example.com/accept#token']) {
      expect(() => readInvitationEmailRuntimeConfig({ ...base, MANDATE_INVITATION_ACCEPT_URL: url })).toThrow('HTTPS');
    }
    expect(readInvitationEmailRuntimeConfig({ ...base, MANDATE_INVITATION_ACCEPT_URL: 'http://localhost:3000/accept' })?.acceptUrl)
      .toBe('http://localhost:3000/accept');
  });
});
