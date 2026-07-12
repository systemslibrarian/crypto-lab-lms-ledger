import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Crypto unit tests live in test/. The Playwright a11y suite lives in e2e/
    // and must never be collected by vitest.
    include: ['test/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
    environment: 'node',
  },
});
