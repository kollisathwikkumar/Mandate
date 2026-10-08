import { SESv2Client, SendEmailCommand, type SendEmailCommandInput } from '@aws-sdk/client-sesv2';
import type { InvitationEmailMessage, InvitationEmailTransport } from '../../../ports/src/invitation-email.js';
import { resolveAwsRegion } from './region.js';

const configuredRegion = resolveAwsRegion(process.env.AWS_REGION, process.env.AWS_DEFAULT_REGION);

export interface SesEmailApi {
  sendEmail(input: SendEmailCommandInput): Promise<void>;
}

export class AwsSesEmailApi implements SesEmailApi {
  public constructor(private readonly client = new SESv2Client(
    configuredRegion === undefined ? {} : { region: configuredRegion },
  )) {}

  public async sendEmail(input: SendEmailCommandInput): Promise<void> {
    await this.client.send(new SendEmailCommand(input));
  }
}

export class SesInvitationEmailTransport implements InvitationEmailTransport {
  public constructor(private readonly api: SesEmailApi = new AwsSesEmailApi()) {}

  public async send(message: InvitationEmailMessage): Promise<void> {
    await this.api.sendEmail({
      FromEmailAddress: message.from,
      Destination: { ToAddresses: [message.to] },
      Content: {
        Simple: {
          Subject: { Data: message.subject, Charset: 'UTF-8' },
          Body: { Text: { Data: message.text, Charset: 'UTF-8' } },
        },
      },
    });
  }
}
