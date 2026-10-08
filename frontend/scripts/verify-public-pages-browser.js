/**
 * Browser audit for the public product, editorial, developer, and SSO-entry pages.
 * Run from frontend/ with playwright-cli run-code --filename scripts/verify-public-pages-browser.js
 * @param {import('playwright').Page} page
 */
async (page) => {
  const origin = 'http://127.0.0.1:5173';
  const pages = [
    { path: '/', heading: 'Give agents', reveal: '.workflow-row' },
    { path: '/how-it-works', heading: 'From a rule', reveal: '.lifecycle-step' },
    { path: '/security', heading: 'Secure by', reveal: '.security-card' },
    { path: '/integrations', heading: 'One policy', reveal: '.integration-row' },
    { path: '/developers', heading: 'Build on the', reveal: '.developer-code-reveal' },
    { path: '/login', heading: 'Sign in to', reveal: '.login-card' },
  ];
  const checks = [];
  const failures = [];
  const pageErrors = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  const assert = (condition, label) => {
    if (!condition) { failures.push(label); throw new Error(label); }
    checks.push(label);
  };
  try {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto(origin);
    const publicLinks = [
      ['How it works', '/how-it-works'],
      ['Security', '/security'],
      ['Integrations', '/integrations'],
      ['Developers', '/developers'],
    ];
    for (const [label, path] of publicLinks) {
      await page.getByRole('navigation', { name: 'Main navigation' }).getByRole('link', { name: label, exact: true }).click();
      await page.waitForURL(`${origin}${path}`);
      assert(new URL(page.url()).pathname === path, `Navigation link opens ${path}`);
      await page.goto(origin);
    }
    await page.goto(`${origin}/login`);
    const signInExplanation = await page.locator('.login-card').innerText();
    assert(signInExplanation.includes('That prompt belongs to your identity provider—not Mandate.'), 'Sign-in page explains that credential prompts belong to the identity provider, not a Mandate-local password');
    assert(await page.locator('.login-card input[type="password"], .login-card input[autocomplete="username"]').count() === 0, 'Mandate website does not collect identity-provider credentials');
    await page.getByRole('button', { name: 'Continue with SSO' }).click();
    await page.waitForURL((url) => url.pathname.includes('/protocol/openid-connect/auth'));
    assert((await page.title()).includes('Mandate Local Test Identity Provider'), 'SSO opens the configured local test identity provider');
    await page.goto(origin);
    await page.getByRole('link', { name: 'See how it works' }).click();
    await page.waitForURL(`${origin}/how-it-works`);
    assert(new URL(page.url()).pathname === '/how-it-works', 'Home hero action opens How it works');
    await page.goto(origin);
    await page.getByRole('link', { name: 'Enter the control plane' }).click();
    await page.waitForURL(`${origin}/login`);
    assert(new URL(page.url()).pathname === '/login', 'Home primary action opens the website SSO entry');
    await page.getByRole('button', { name: 'Continue with SSO' }).click();
    await page.waitForURL((url) => url.pathname.includes('/protocol/openid-connect/auth'));
    const authorizationUrl = new URL(page.url());
    assert(authorizationUrl.searchParams.get('response_type') === 'code', 'Website sign-in initiates OIDC authorization-code flow');
    assert(authorizationUrl.searchParams.get('code_challenge_method') === 'S256', 'Website sign-in uses PKCE S256');
    assert(authorizationUrl.searchParams.get('redirect_uri') === `${origin}/login/callback`, 'OIDC returns to the Mandate website callback');
    await page.goto(origin);
    for (const item of pages) {
      await page.setViewportSize({ width: 1440, height: 1000 });
      await page.goto(`${origin}${item.path}`);
      const heading = page.locator('h1').first();
      await heading.waitFor();
      assert((await heading.innerText()).includes(item.heading), `${item.path} renders its page heading`);
      await page.locator('.public-ambient canvas').waitFor({ timeout: 10000 });
      assert(await page.locator('.public-ambient canvas').count() === 1, `${item.path} has the shared animated 3D background`);
      const motionReveals = page.locator('main div[style*="opacity"]');
      for (const node of await motionReveals.all()) {
        await node.scrollIntoViewIfNeeded();
        await page.waitForFunction((element) => Number.parseFloat(getComputedStyle(element).opacity) >= 0.99, await node.elementHandle());
      }
      assert(await motionReveals.evaluateAll((nodes) => nodes.every((element) => Number.parseFloat(getComputedStyle(element).opacity) >= 0.99)), `${item.path} reveals all scroll-triggered content`);
      const revealNodes = page.locator(item.reveal);
      assert(await revealNodes.count() > 0, `${item.path} has its expected reveal content`);
      for (const node of await revealNodes.all()) {
        await node.scrollIntoViewIfNeeded();
        await page.waitForFunction((element) => Number.parseFloat(getComputedStyle(element).opacity) >= 0.99, await node.elementHandle());
      }
      assert(true, `${item.path} reveal content becomes visible while scrolling`);
      await page.evaluate(() => window.scrollTo(0, 0));
      await page.screenshot({ path: `output/playwright/public-${item.path === '/' ? 'home' : item.path.slice(1)}-desktop.png`, fullPage: true });
      await page.setViewportSize({ width: 390, height: 844 });
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), `${item.path} has no horizontal overflow at 390px`);
      await page.screenshot({ path: `output/playwright/public-${item.path === '/' ? 'home' : item.path.slice(1)}-mobile.png`, fullPage: true });
    }
    await page.goto(`${origin}/developers`);
    await page.context().grantPermissions(['clipboard-read', 'clipboard-write'], { origin });
    await page.getByRole('button', { name: 'Copy example' }).click();
    await page.getByRole('button', { name: 'Copied' }).waitFor();
    assert(await page.evaluate(() => navigator.clipboard.readText()).then((text) => text.includes('MandateClient.connect') && text.includes('simulateAction')), 'Developer copy action writes the SDK example to clipboard');
    const contractTabPromise = page.context().waitForEvent('page');
    await page.getByRole('link', { name: 'Open local API contract' }).click();
    const contractTab = await contractTabPromise;
    await contractTab.waitForLoadState('domcontentloaded');
    assert((await contractTab.locator('body').innerText()).includes('openapi'), 'Developer API-contract action opens the live local backend OpenAPI document');
    await contractTab.close();
    await page.goto(origin);
    const magneticAction = page.getByRole('link', { name: 'Enter the control plane' });
    const actionBounds = await magneticAction.boundingBox();
    if (actionBounds === null) throw new Error('Primary action is not visible for the magnetic interaction check');
    await page.mouse.move(actionBounds.x + actionBounds.width * 0.85, actionBounds.y + actionBounds.height * 0.85);
    const magneticHandle = await magneticAction.elementHandle();
    await page.waitForFunction((element) => {
      const value = getComputedStyle(element).translate;
      return value !== 'none' && value !== '0px 0px';
    }, magneticHandle);
    assert(true, 'Primary CTA responds with a restrained magnetic pointer movement');
    await page.mouse.move(0, 0);
    await page.waitForFunction((element) => ['0px', '0px 0px'].includes(getComputedStyle(element).translate), magneticHandle);
    assert(true, 'Magnetic CTA recenters when the pointer leaves');
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto(`${origin}/`);
    await page.locator('h1').first().waitFor();
    assert(await page.locator('.page-scroll-progress').evaluate((element) => getComputedStyle(element).display === 'none'), 'Reduced motion disables the animated scroll progress');
    assert(await page.locator('.public-ambient canvas').count() === 0, 'Reduced motion uses the static background instead of the animated canvas');
    assert(await page.locator('.magnetic-action').first().evaluate((element) => getComputedStyle(element).translate === 'none'), 'Reduced motion disables magnetic CTA movement');
    assert(pageErrors.length === 0, 'No browser page errors across public pages');
    return { result: 'PASS', checks, failures, pageErrors };
  } finally {
    await page.emulateMedia({ reducedMotion: null });
    await page.setViewportSize({ width: 1440, height: 1000 });
  }
}
