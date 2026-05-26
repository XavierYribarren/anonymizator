import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        include: ['tests/unit/js/**/*.test.js'],
        environmentMatchGlobs: [
            ['tests/unit/js/i18n.test.js', 'jsdom'],
        ],
        environment: 'node',
        globals: true,
    },
});
