import { expect, test } from '@playwright/test';

test('deployment research retains its conditions and separates the live attack', async ({ page }) => {
  await page.goto('.');
  const note = page.locator('#hash-research-note');
  await expect(note).toBeVisible();
  for (const condition of ['hash variant', 'message length and format', 'across keys', 'hash-block', 'hash-call', 'classical', 'SHAKE256', 'preprints', 'not a practical break', 'leaf-reuse']) {
    await expect(note).toContainText(condition);
  }
  await expect(note.locator('a[href="https://eprint.iacr.org/2026/2624"]')).toBeVisible();
  await expect(note.locator('a[href="https://eprint.iacr.org/2026/2635"]')).toBeVisible();
});
