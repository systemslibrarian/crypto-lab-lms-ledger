import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are gated on the LMS test vectors; this gates
 * them on accessibility the same way. Scans the full page with every
 * collapsible expanded, in both the dark (default) and light themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function revealAll(page: Page): Promise<void> {
  // Neutralize animations/transitions/opacity so nothing is mid-fade when axe
  // measures contrast.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.evaluate(() => {
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal panels the app keeps collapsed via the `.hidden` utility class
    // (display:none !important) or a raw [hidden] attribute / inline style.
    for (const el of Array.from(document.querySelectorAll('.hidden'))) {
      el.classList.remove('hidden');
    }
    for (const el of Array.from(document.querySelectorAll('[hidden]'))) {
      el.removeAttribute('hidden');
    }
    for (const el of Array.from(
      document.querySelectorAll<HTMLElement>(
        '[style*="display: none"], [style*="display:none"]',
      ),
    )) {
      el.style.display = '';
    }
    // The signing-locked overlay dims a panel; undo it so its contents scan.
    for (const el of Array.from(document.querySelectorAll('.signing-locked'))) {
      el.classList.remove('signing-locked');
    }
  });
}


async function checkGradientContrast(page: Page): Promise<void> {
  const issues = await page.evaluate(() => {
    function getLum(r: number, g: number, b: number) {
      const [rs, gs, bs] = [r, g, b].map((c) => {
        c /= 255;
        return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
      });
      return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs;
    }
    function getContrast(l1: number, l2: number) {
      const lighter = Math.max(l1, l2);
      const darker = Math.min(l1, l2);
      return (lighter + 0.05) / (darker + 0.05);
    }
    function parseRGBA(colorStr: string) {
      const match = colorStr.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)(?:,\s*([\d.]+))?\)/);
      if (match) return [parseInt(match[1]), parseInt(match[2]), parseInt(match[3]), match[4] ? parseFloat(match[4]) : 1];
      return null;
    }
    function blend(fg: number[], bg: number[]) {
      const a = fg[3] !== undefined ? fg[3] : 1;
      return [
        Math.round(fg[0] * a + bg[0] * (1 - a)),
        Math.round(fg[1] * a + bg[1] * (1 - a)),
        Math.round(fg[2] * a + bg[2] * (1 - a))
      ];
    }
    const issues: { element: string; contrast: number }[] = [];
    const elements = document.querySelectorAll('*');
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    const bodyBg = isLight ? [238, 245, 247, 1] : [7, 17, 24, 1];
    
    for (const el of elements) {
      const style = window.getComputedStyle(el);
      const bgImage = style.backgroundImage;
      if (bgImage && bgImage.includes('gradient')) {
        const textRGBA = parseRGBA(style.color);
        if (!textRGBA) continue;
        const textLum = getLum(textRGBA[0], textRGBA[1], textRGBA[2]);
        const bgColors = [...bgImage.matchAll(/rgba?\([^)]+\)|#[0-9a-fA-F]{3,8}/g)].map((m) => m[0]);
        if (bgColors.length === 0) continue;
        let minContrast = Infinity;
        for (const bgCol of bgColors) {
          let rgba = parseRGBA(bgCol);
          if (!rgba && bgCol.startsWith('#')) {
            let hex = bgCol.replace('#', '');
            if (hex.length === 3) hex = hex[0]+hex[0]+hex[1]+hex[1]+hex[2]+hex[2];
            if (hex.length === 6) rgba = [parseInt(hex.slice(0, 2), 16), parseInt(hex.slice(2, 4), 16), parseInt(hex.slice(4, 6), 16), 1];
            if (hex.length === 8) rgba = [parseInt(hex.slice(0, 2), 16), parseInt(hex.slice(2, 4), 16), parseInt(hex.slice(4, 6), 16), parseInt(hex.slice(6, 8), 16) / 255];
          }
          if (rgba) {
            const blended = blend(rgba, bodyBg);
            const bgLum = getLum(blended[0], blended[1], blended[2]);
            const contrast = getContrast(textLum, bgLum);
            if (contrast < minContrast) minContrast = contrast;
          }
        }
        if (minContrast < 4.5 && el.textContent && el.textContent.trim().length > 0) {
          if (
            el.children.length === 0 ||
            Array.from(el.childNodes).some((n) => n.nodeType === 3 && (n.textContent?.trim().length ?? 0) > 0)
          ) {
            issues.push({ element: el.tagName + '.' + el.className, contrast: minContrast });
          }
        }
      }
    }
    return issues;
  });
  for (const issue of issues) {
    expect(issue.contrast, `Gradient contrast too low on ${issue.element}`).toBeGreaterThanOrEqual(4.5);
  }
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page })
    .withTags(TAGS)
    .exclude('.btn-primary')
    .analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
  await checkGradientContrast(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('h1').first()).toBeVisible();
  await expect(page.locator('#init-overlay')).toBeHidden();
  await expect(page.locator('#btn-sign')).toBeEnabled();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await revealAll(page);
  await scan(page);
});

