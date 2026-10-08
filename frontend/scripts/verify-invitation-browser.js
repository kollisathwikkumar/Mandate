/**
 * Complete a local-only invitation lifecycle in a real authenticated browser.
 * Uses a reserved .invalid address and never reads or emits the one-time token.
 * @param {import('playwright').Page} page
 */
async (page) => {
  const origin = 'http://127.0.0.1:5173';
  const email = `codex-ui-${Date.now()}@mandate.invalid`;
  const failures = [];
  const assert = (condition, label) => { if (!condition) { failures.push(label); throw new Error(label); } };
  await page.getByRole('link', { name: 'Team', exact: true }).click();
  await page.waitForURL(`${origin}/app/settings/team`);
  await page.getByLabel('Email address').fill(email);
  await page.getByLabel('Role').selectOption('VIEWER');

  const createResponseWait = page.waitForResponse((response) => response.request().method() === 'POST' && new URL(response.url()).pathname.endsWith('/invitations'));
  await page.getByRole('button', { name: 'Send invitation', exact: false }).click();
  const createResponse = await createResponseWait;
  assert(createResponse.status() === 201, `Invitation create returned HTTP ${createResponse.status()}`);
  const createPayload = await createResponse.json();
  const invitationRecord = typeof createPayload === 'object' && createPayload !== null && 'invitation' in createPayload ? createPayload.invitation : null;
  const invitationId = typeof invitationRecord === 'object' && invitationRecord !== null && 'id' in invitationRecord && typeof invitationRecord.id === 'string' ? invitationRecord.id : '';
  assert(invitationId.length > 0, 'Invitation create returned its record identifier');
  const tokenDialog = page.getByRole('dialog', { name: 'Invitation token — shown once' });
  await tokenDialog.waitFor({ state: 'visible' });
  assert(await tokenDialog.locator('.secret-value').count() === 1, 'The one-time token dialog is displayed; the secret value is not read or logged');
  await tokenDialog.getByRole('button', { name: 'Close dialog' }).click();
  await tokenDialog.waitFor({ state: 'hidden' });
  await page.getByText('Invitation created.', { exact: false }).waitFor();

  const row = page.locator('.panel').filter({ hasText: 'Pending access' }).getByRole('row').filter({ hasText: invitationId });
  await row.waitFor({ state: 'visible' });
  const revokeResponseWait = page.waitForResponse((response) => response.request().method() === 'DELETE' && new URL(response.url()).pathname.endsWith(`/invitations/${invitationId}`));
  page.once('dialog', (dialog) => dialog.accept());
  await row.getByRole('button', { name: 'Revoke', exact: true }).click();
  const revokeResponse = await revokeResponseWait;
  assert(revokeResponse.status() === 204, `Invitation revoke returned HTTP ${revokeResponse.status()}`);
  await page.getByText('Pending invitation revoked.', { exact: true }).waitFor();
  await row.getByText('REVOKED', { exact: true }).waitFor();
  assert(await row.getByRole('button', { name: 'Revoke', exact: true }).count() === 0, 'Revoked row no longer offers the pending-only action');

  return { result: 'PASS', email, invitationId, createStatus: createResponse.status(), revokeStatus: revokeResponse.status(), tokenRead: false, failures };
}
