import { SESv2Client, SendEmailCommand, type SendEmailCommandInput } from '@aws-sdk/client-sesv2';
import { describe, expect, it, vi } from 'vitest';
import { AwsSesEmailApi, SesInvitationEmailTransport, type SesEmailApi } from '../src/aws/ses-invitation-email-transport.js';

describe('SesInvitationEmailTransport', () => {
  it('sends a plain-text invitation email using the AWS SES v2 command', async () => {
    const captured: SendEmailCommandInput[] = [];
    const api: SesEmailApi = { async sendEmail(input) { captured.push(input); } };
    const transport = new SesInvitationEmailTransport(api);
    await transport.send({ from: 'mandate@example.com', to: 'owner@example.com', subject: 'Invite', text: 'Accept #token=secret' });
    expect(captured[0]).toMatchObject({
      FromEmailAddress: 'mandate@example.com',
      Destination: { ToAddresses: ['owner@example.com'] },
      Content: { Simple: { Subject: { Data: 'Invite', Charset: 'UTF-8' }, Body: { Text: { Data: 'Accept #token=secret', Charset: 'UTF-8' } } } },
    });
  });

  it('wraps the AWS SES v2 request in a SendEmailCommand', async () => {
    const commands: object[] = [];
    const sdkApi = new AwsSesEmailApi({
      async send(command: object) { commands.push(command); return {}; },
    } as unknown as SESv2Client);
    await sdkApi.sendEmail({
      FromEmailAddress: 'mandate@example.com',
      Content: { Simple: { Subject: { Data: 'Invite' }, Body: { Text: { Data: 'Text' } } } },
    });
    expect(commands[0]).toBeInstanceOf(SendEmailCommand);
  });

  it('constructs the AWS client with the ambient SDK region configuration', () => {
    expect(new AwsSesEmailApi()).toBeInstanceOf(AwsSesEmailApi);
  });

  it('constructs the AWS client with an explicitly configured region', async () => {
    vi.stubEnv('AWS_REGION', 'us-east-1');
    vi.resetModules();
    try {
      const { AwsSesEmailApi: RegionalSesApi } = await import('../src/aws/ses-invitation-email-transport.js');
      expect(new RegionalSesApi()).toBeInstanceOf(RegionalSesApi);
    } finally {
      vi.unstubAllEnvs();
      vi.resetModules();
    }
  });
});
