import { test, expect } from './fixtures';

test.describe('Upload page (collector)', () => {
    test('shows upload zone for a valid token', async ({ page, uploadUrl }) => {
        await page.goto(uploadUrl);
        await expect(page.locator('[data-testid="upload-drop-zone"]')).toBeVisible({ timeout: 10_000 });
        await expect(page.locator('[data-testid="upload-title"]')).toBeVisible();
    });

    test('does not expose RSA or key terminology to collector', async ({ page, uploadUrl }) => {
        await page.goto(uploadUrl);
        await page.waitForSelector('[data-testid="upload-drop-zone"]');
        const body = await page.locator('body').textContent();
        expect(body?.toLowerCase()).not.toContain('rsa');
        expect(body?.toLowerCase()).not.toContain('public key');
        expect(body?.toLowerCase()).not.toContain('clé publique');
    });

    test('shows invalid-token state for unknown token', async ({ page }) => {
        await page.goto('/upload/00000000-0000-0000-0000-000000000000');
        await expect(page.locator('[data-testid="error-invalid-token"]')).toBeVisible({ timeout: 10_000 });
    });

    test('uploads a file successfully', async ({ page, uploadUrl, testFile }) => {
        await page.goto(uploadUrl);
        await page.waitForSelector('[data-testid="upload-drop-zone"]');

        const input = await page.evaluateHandle(() => {
            const i = document.createElement('input');
            i.type = 'file';
            return i;
        });
        await page.setInputFiles('[data-testid="upload-drop-zone"]', testFile);
        await expect(page.locator('[data-testid="upload-success"]')).toBeVisible({ timeout: 30_000 });
    });

    test('shows already-used state on second visit', async ({ page, uploadUrl, testFile }) => {
        // First upload
        await page.goto(uploadUrl);
        await page.waitForSelector('[data-testid="upload-drop-zone"]');
        await page.setInputFiles('[data-testid="upload-drop-zone"]', testFile);
        await page.waitForSelector('[data-testid="upload-success"]', { timeout: 30_000 });

        // Second visit to same URL
        await page.goto(uploadUrl);
        await expect(page.locator('[data-testid="error-already-used"]')).toBeVisible({ timeout: 10_000 });
    });

    test('shows error for file exceeding MAX_FILE_SIZE_MB', async ({ page, uploadUrl }) => {
        await page.goto(uploadUrl);
        await page.waitForSelector('[data-testid="upload-drop-zone"]');

        // Simulate dropping an oversized file via JS
        await page.evaluate((maxMB) => {
            const bigFile = new File(
                [new ArrayBuffer((maxMB + 1) * 1024 * 1024)],
                'too_big.csv',
                { type: 'text/csv' }
            );
            const dt = new DataTransfer();
            dt.items.add(bigFile);
            const zone = document.querySelector('[data-testid="upload-drop-zone"]')!;
            zone.dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true }));
        }, 10);

        await expect(page.locator('[data-testid="upload-drop-zone"]')).toContainText(/too large|trop volumineux/, { timeout: 5_000 });
    });
});
