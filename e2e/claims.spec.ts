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

test('cited standards and parameter sets match the documents they name', async ({ page }) => {
  await page.goto('.');

  // RFC 8554 §4.3: the public key is the chain iterated 2^w - 1 times, so a
  // w=4 chain is 15 hash steps across 16 positions, not 16 steps.
  await expect(page.locator('#section-a .chain-primer-caption')).toContainText(
    '15 hash steps (16 positions, 0 to 15)',
  );

  // HSS is RFC 8554 §6. NIST SP 800-208 §6 is random number generation.
  await expect(page.getByRole('heading', { name: 'D2 \u2014 HSS structure (RFC 8554 \u00a76)' })).toBeVisible();

  // RFC 8554 Appendix F Test Case 1 is LMOTS_SHA256_N32_W8; the page signs W4.
  await expect(page.locator('#hss-transcript-scope')).toContainText(
    'Test Case 1 is the W8 parameter set (LMOTS_SHA256_N32_W8, p=34), not the W4 set this page signs with',
  );

  // CNSA 2.0 approves validated ML-DSA for firmware signing too; LMS and XMSS
  // are the ones available now. NSA CNSA 2.0 and Quantum Computing FAQ,
  // Ver. 2.2, October 2026.
  const cnsa = page.locator('#section-e');
  await expect(cnsa).toContainText('Ver. 2.2, October 2026');
  await expect(cnsa).toContainText(
    'Validated ML-DSA is approved for all signing use cases',
  );
  await expect(cnsa).not.toContainText('only approved post-quantum signature schemes');
});
