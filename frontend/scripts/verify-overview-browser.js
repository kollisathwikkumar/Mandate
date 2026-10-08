/**
 * Playwright CLI browser audit. Requires an already authenticated local session
 * established through the website's SSO flow; never injects tokens or credentials.
 * Run with: playwright-cli --session <session> run-code --filename scripts/verify-overview-browser.js
 * @param {import('playwright').Page} page
 */
async (page) => {
  const origin = 'http://127.0.0.1:5173';
  const overview = `${origin}/app/overview`;
  const checks = [];
  const failures = [];
  const pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  const assert = (condition, label) => {
    if (!condition) { failures.push(label); throw new Error(label); }
    checks.push(label);
  };
  const waitLive = async () => {
    await page.getByRole('heading', { name: 'Overview', exact: true }).waitFor();
    await page.locator('.authorization-step').first().waitFor();
    await page.locator('.metric-card').filter({ hasText: 'Recent signals' }).locator('small').filter({ hasText: 'Latest 5 alert records' }).waitFor();
  };
  const revealAll = async () => {
    for (const panel of await page.locator('.authorization-path-panel, .recent-panel, .console-grid').all()) {
      await panel.scrollIntoViewIfNeeded();
      await page.waitForFunction((selector) => {
        const element = document.querySelector(selector);
        return element !== null && Number.parseFloat(getComputedStyle(element).opacity) >= 0.99;
      }, await panel.evaluate((element) => `.${Array.from(element.classList).join('.')}`));
    }
    await page.evaluate(() => window.scrollTo(0, 0));
  };
  try {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(overview);
    await waitLive();
    assert(await page.locator('.avatar-button').getAttribute('aria-label') === 'Sign out', 'Topbar action is accurately labeled Sign out');
    assert(await page.locator('.metric-card').count() === 4, 'Four metrics are navigable console links');
    assert((await page.locator('.metric-card').allTextContents()).some((text) => text.includes('Recent signals') && text.includes('Latest 5 alert records')), 'Signals are recent records, not invented open-alert state');
    assert(await page.locator('.console-ambient canvas').count() === 1, 'One shared ambient 3D canvas');
    await revealAll();
    await page.screenshot({ path: 'output/playwright/overview-authorization-path-desktop.png', fullPage: true });

    const nodes = [
      { href: '/app/agents', heading: 'Agents' },
      { href: '/app/policies', heading: 'Policies' },
      { href: '/app/settings/accounts', heading: 'Accounts' },
      { href: '/app/activity', heading: 'Activity' },
    ];
    for (const node of nodes) {
      await page.locator(`.authorization-step[href="${node.href}"]`).click();
      await page.waitForURL(`${origin}${node.href}`);
      await page.getByRole('heading', { name: node.heading, exact: true }).waitFor();
      assert(new URL(page.url()).pathname === node.href, `Authorization node opens ${node.heading}`);
      await page.getByRole('link', { name: 'Overview', exact: true }).click();
      await waitLive();
    }

    await page.setViewportSize({ width: 390, height: 844 });
    await revealAll();
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), '390px overview has no horizontal document overflow');
    await page.screenshot({ path: 'output/playwright/overview-authorization-path-mobile.png', fullPage: true });
    await page.getByRole('button', { name: 'Open navigation', exact: true }).click();
    assert(await page.locator('.console-sidebar').evaluate((element) => element.classList.contains('sidebar-open')), 'Mobile navigation opens');
    await page.getByRole('link', { name: 'Accounts', exact: true }).click();
    await page.waitForURL(`${origin}/app/settings/accounts`);
    assert(!(await page.locator('.console-sidebar').evaluate((element) => element.classList.contains('sidebar-open'))), 'Mobile navigation closes after a section selection');
    await page.goto(overview);
    await waitLive();

    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.reload();
    await waitLive();
    assert(await page.locator('.page-scroll-progress').evaluate((element) => getComputedStyle(element).display === 'none'), 'Reduced motion hides the animated scroll progress');
    assert(await page.locator('.recent-panel').evaluate((element) => Number.parseFloat(getComputedStyle(element).opacity) >= 0.99), 'Reduced motion reveals offscreen content immediately');
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.setViewportSize({ width: 1440, height: 1000 });

    let releaseReceipts;
    const gate = new Promise((resolve) => { releaseReceipts = resolve; });
    const receiptsPattern = '**/receipts?limit=5';
    await page.route(receiptsPattern, async (route) => { await gate; await route.continue(); });
    await page.reload();
    const receiptMetric = page.locator('.metric-card').filter({ hasText: 'Recent receipts' });
    await receiptMetric.locator('small').filter({ hasText: 'Loading live data' }).waitFor();
    assert(await receiptMetric.locator('strong').innerText() === '—', 'Pending receipts never display a fabricated zero');
    releaseReceipts();
    await waitLive();
    await page.unroute(receiptsPattern);

    await page.route(receiptsPattern, (route) => route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: { code: 'TEST_UNAVAILABLE', message: 'Simulated receipt outage', requestId: 'browser-audit' } }) }));
    await page.reload();
    await receiptMetric.locator('strong').filter({ hasText: 'Unavailable' }).waitFor();
    assert(await receiptMetric.locator('small').innerText() === 'API request failed', 'Simulated receipt outage remains visible, not zero');
    await page.unroute(receiptsPattern);
    await page.reload();
    await waitLive();
    assert(await receiptMetric.locator('strong').innerText() !== 'Unavailable', 'Receipt metric recovers using the real local API');
    assert(pageErrors.length === 0, 'No browser page errors during the audit');
    await revealAll();
    await page.screenshot({ path: 'output/playwright/overview-authorization-path-desktop.png', fullPage: true });
    return { result: 'PASS', checks, failures, pageErrors };
  } finally {
    await page.unroute('**/receipts?limit=5');
    await page.emulateMedia({ reducedMotion: null });
    await page.setViewportSize({ width: 1440, height: 1000 });
  }
}
