/**
 * Verifies the authenticated policy editor preflight against the live local API.
 * Requires an existing website SSO session; does not inject identity tokens.
 * @param {import('playwright').Page} page
 */
async (page) => {
  const origin = 'http://127.0.0.1:5173';
  const posts = [];
  const pageErrors = [];
  page.on('request', (request) => {
    if (request.method() === 'POST' && request.url().includes('/policies')) posts.push(request.url());
  });
  page.on('pageerror', (error) => pageErrors.push(error.message));
  await page.goto(`${origin}/app/policies/new`);
  await page.getByRole('heading', { name: 'Draft a policy' }).waitFor();
  await page.getByRole('status').filter({ hasText: 'A draft must reference an active organization agent' }).waitFor();
  const disabled = await page.getByRole('button', { name: 'Create draft' }).isDisabled();
  const guidance = await page.getByRole('status').innerText();
  const links = await page.getByRole('status').getByRole('link').evaluateAll((items) => items.map((item) => item.getAttribute('href')));
  await page.screenshot({ path: 'output/playwright/policy-draft-prerequisites.png' });
  return { result: disabled && posts.length === 0 && pageErrors.length === 0 ? 'PASS' : 'FAIL', disabled, guidance, links, policyPostRequests: posts.length, pageErrors };
}
