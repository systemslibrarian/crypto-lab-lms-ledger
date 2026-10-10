import { expect, test } from '@playwright/test';

for (const width of [1280, 380, 320]) {
  test(`HSS adaptation is disclosed and ordinary rollover still verifies at ${width}px`, async ({ page }) => {
    test.setTimeout(120_000);
    await page.setViewportSize({ width, height: 900 });
    await page.goto('.');
    const scope = page.locator('#hss-transcript-scope');
    await expect(scope).toContainText('non-interoperable teaching adaptation');
    await expect(scope).toContainText('60-byte custom child-key message');
    await expect(scope).toContainText('56-byte child public key');
    await expect(scope).toContainText('h1=h2=3 is not an RFC parameter set');
    await page.locator('#hss-sign-8').click();
    await expect(page.locator('#hss-state-line')).toContainText('8/64', { timeout: 90_000 });
    await page.locator('#hss-sign-1').click();
    await expect(page.locator('#hss-state-line')).toContainText('9/64', { timeout: 90_000 });
    await expect(page.locator('#hss-state-line')).toContainText('verified end-to-end');
    await expect(page.locator('#hss-rollover')).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth)).toBeLessThanOrEqual(width);
  });
}
