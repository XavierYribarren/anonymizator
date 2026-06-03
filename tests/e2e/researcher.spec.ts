import { test, expect } from './fixtures';

test.describe('Researcher page', () => {
    test.beforeEach(async ({ page }) => {
        // Clear localStorage between tests
        await page.goto('/');
        await page.evaluate(() => localStorage.clear());
    });

    test('shows no-key section on first visit', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('[data-testid="no-key-section"]')).toBeVisible();
        await expect(page.locator('[data-testid="generate-key-btn"]')).toBeVisible();
    });

    test('hides invite form when no key is loaded', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('[data-testid="send-invite-btn"]')).not.toBeVisible();
    });

    test('opens key generation modal on button click', async ({ page }) => {
        await page.goto('/');
        await page.click('[data-testid="generate-key-btn"]');
        await expect(page.locator('[data-testid="keygen-modal"]')).toBeVisible();
    });

    test('modal shows private key download after generation', async ({ page }) => {
        await page.goto('/');
        await page.click('[data-testid="generate-key-btn"]');
        await expect(page.locator('[data-testid="private-key-download"]')).toBeVisible({ timeout: 20_000 });
        await expect(page.locator('[data-testid="key-warning"]')).toBeVisible();
    });

    test('saves public key in localStorage after save-pubkey click', async ({ page }) => {
        await page.goto('/');
        await page.click('[data-testid="generate-key-btn"]');
        await page.waitForSelector('[data-testid="save-pubkey-btn"]', { timeout: 20_000 });
        await page.click('[data-testid="save-pubkey-btn"]');
        const stored = await page.evaluate(() => localStorage.getItem('anonymizator_public_key'));
        expect(stored).toContain('BEGIN PUBLIC KEY');
    });

    test('shows key-loaded indicator after key is saved', async ({ page }) => {
        await page.goto('/');
        await page.click('[data-testid="generate-key-btn"]');
        await page.waitForSelector('[data-testid="save-pubkey-btn"]', { timeout: 20_000 });
        await page.click('[data-testid="save-pubkey-btn"]');
        await expect(page.locator('[data-testid="key-loaded-indicator"]')).toBeVisible();
    });

    test('fingerprint is 16 hex characters', async ({ page }) => {
        await page.goto('/');
        await page.click('[data-testid="generate-key-btn"]');
        await page.waitForSelector('[data-testid="save-pubkey-btn"]', { timeout: 20_000 });
        await page.click('[data-testid="save-pubkey-btn"]');
        const fp = await page.locator('[data-testid="key-fingerprint"]').textContent();
        expect(fp?.trim()).toMatch(/^[0-9a-f]{16}$/);
    });

    test('reloads key from localStorage on return visit', async ({ page }) => {
        // First visit: generate and save
        await page.goto('/');
        await page.click('[data-testid="generate-key-btn"]');
        await page.waitForSelector('[data-testid="save-pubkey-btn"]', { timeout: 20_000 });
        await page.click('[data-testid="save-pubkey-btn"]');
        await page.waitForSelector('[data-testid="key-loaded-indicator"]');

        // Return visit
        await page.goto('/');
        await expect(page.locator('[data-testid="key-loaded-indicator"]')).toBeVisible();
        await expect(page.locator('[data-testid="no-key-section"]')).not.toBeVisible();
    });

    test('generates invite link with collector email', async ({ page }) => {
        await page.goto('/');
        await page.click('[data-testid="generate-key-btn"]');
        await page.waitForSelector('[data-testid="save-pubkey-btn"]', { timeout: 20_000 });
        await page.click('[data-testid="save-pubkey-btn"]');
        await page.waitForSelector('[data-testid="send-invite-btn"]');

        await page.fill('[data-testid="collector-email"]', 'collector@test.com');
        await page.click('[data-testid="send-invite-btn"]');

        await expect(page.locator('[data-testid="invite-success"]')).toBeVisible({ timeout: 10_000 });
        const link = await page.locator('[data-testid="invite-link"]').inputValue();
        expect(link).toContain('/upload/');
    });
});
