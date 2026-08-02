import { expect, test } from '@playwright/test';

test('signature-size claims are derived from the material the verifier consumes', async ({ page }) => {
  await page.goto('.');

  await expect(page.locator('#hss-size-example')).toContainText(
    'two h=10, w=8 LMS signature components total 2,904 bytes (~2.9 KB)',
  );
  await expect(page.locator('#hss-size-example')).toContainText(
    'the RFC 8554 HSS signature is 2,964 bytes (~3.0 KB)',
  );

  await page.getByRole('button', { name: 'Sign Message' }).click();
  const liveSize = page.locator('#live-signature-size');
  await expect(liveSize).toContainText('2336 bytes');
  await expect(liveSize).toContainText('32-byte C randomizer + 67×32 OTS + 5×32 auth path');
});
