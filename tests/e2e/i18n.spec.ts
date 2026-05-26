import { test, expect } from '@playwright/test';

test.describe('Internationalisation', () => {
    test('researcher page shows French UI with fr-FR browser', async ({ browser }) => {
        const ctx = await browser.newContext({ locale: 'fr-FR' });
        const page = await ctx.newPage();
        await page.goto('/');
        // data-i18n attributes should be replaced with French text
        const generateBtn = page.locator('[data-testid="generate-key-btn"]');
        await expect(generateBtn).toContainText(/Générer|paire|clés/i, { timeout: 5_000 });
        await ctx.close();
    });

    test('upload page shows French UI with fr-FR browser', async ({ browser }) => {
        const ctx = await browser.newContext({ locale: 'fr-FR' });
        const page = await ctx.newPage();
        // Create a token for the upload page
        const kp = await ctx.request.post('/api/tokens', {
            data: {
                public_key: require('crypto').generateKeyPairSync('rsa', {
                    modulusLength: 2048,
                    publicKeyEncoding: { type: 'spki', format: 'pem' },
                    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
                }).publicKey,
                collector_email: 'c@test.com',
            },
        });
        const { upload_url } = await kp.json();
        await page.goto(upload_url);
        await page.waitForSelector('[data-testid="upload-title"]');
        const title = await page.locator('[data-testid="upload-title"]').textContent();
        expect(title).toContain('Envoi');
        await ctx.close();
    });

    test('falls back to English for unsupported locale (de)', async ({ browser }) => {
        const ctx = await browser.newContext({ locale: 'de-DE' });
        const page = await ctx.newPage();
        await page.goto('/');
        const generateBtn = page.locator('[data-testid="generate-key-btn"]');
        // Should show English text (fallback)
        await expect(generateBtn).toContainText(/Generate|key|pair/i, { timeout: 5_000 });
        await ctx.close();
    });

    test('English UI with en-US browser', async ({ browser }) => {
        const ctx = await browser.newContext({ locale: 'en-US' });
        const page = await ctx.newPage();
        await page.goto('/');
        const generateBtn = page.locator('[data-testid="generate-key-btn"]');
        await expect(generateBtn).toContainText(/Generate/i, { timeout: 5_000 });
        await ctx.close();
    });

    test('decrypt page key label translated for fr-FR', async ({ browser }) => {
        const ctx = await browser.newContext({ locale: 'fr-FR' });
        const page = await ctx.newPage();
        await page.goto('/decrypt');
        // The decrypt button should show French
        const btn = page.locator('[data-testid="decrypt-btn"]');
        await expect(btn).toContainText(/Déchiffrer/i, { timeout: 5_000 });
        await ctx.close();
    });
});
