export interface InvitationTokenCipher {
  encrypt(token: string, organizationId: string, invitationId: string): string;
  decrypt(ciphertext: string, organizationId: string, invitationId: string): string;
}

export interface InvitationEmailMessage {
  readonly from: string;
  readonly to: string;
  readonly subject: string;
  readonly text: string;
}

export interface InvitationEmailTransport {
  send(message: InvitationEmailMessage): Promise<void>;
}
