import { defineConfig, devices } from '@playwright/test';
import * as path from 'path';

const projectRoot = path.resolve('.');

export default defineConfig({
    testDir: '.',
    timeout: 30_000,
    retries: process.env.CI ? 2 : 0,
    workers: 1, // sequential — shared SQLite DB
    use: {
        baseURL: 'http://localhost:8000',
        trace: 'on-first-retry',
        screenshot: 'only-on-failure',
    },
    projects: [
        { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    ],
    webServer: {
        command: 'uvicorn web.main:app --host 0.0.0.0 --port 8000',
        cwd: projectRoot,
        port: 8000,
        reuseExistingServer: !process.env.CI,
        env: {
            DATABASE_PATH: '/tmp/anonymizator_e2e_test.db',
            UPLOAD_DIR: '/tmp/anonymizator_e2e_uploads',
            BASE_URL: 'http://localhost:8000',
            MAX_FILE_SIZE_MB: '10',
            SMTP_HOST: '',
        },
    },
});
