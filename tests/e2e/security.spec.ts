import { test, expect } from '@playwright/test';
import { getTestKeyPair } from './fixtures';

test.describe('API security', () => {
    test('GET /api/files/{id} without fingerprint → 422', async ({ request }) => {
        const resp = await request.get('/api/files/any-file-id');
        expect(resp.status()).toBe(422);
    });

    test('GET /api/files/{id} with wrong fingerprint → 403 or 404', async ({ request }) => {
        const resp = await request.get('/api/files/any-file-id?fingerprint=wrong');
        expect([403, 404]).toContain(resp.status());
    });

    test('DELETE /api/files/{id} without fingerprint → 422', async ({ request }) => {
        const resp = await request.delete('/api/files/any-file-id');
        expect(resp.status()).toBe(422);
    });

    test('DELETE /api/files/{id} with wrong fingerprint → 403 or 404', async ({ request }) => {
        const resp = await request.delete('/api/files/any-file-id?fingerprint=wrong');
        expect([403, 404]).toContain(resp.status());
    });

    test('POST /api/tokens with invalid key → 422', async ({ request }) => {
        const resp = await request.post('/api/tokens', {
            data: {
                public_key: 'not-a-pem-key',
                collector_email: 'c@test.com',
            },
        });
        expect(resp.status()).toBe(422);
    });

    test('POST /api/tokens missing collector_email → 422', async ({ request }) => {
        const { publicKey } = getTestKeyPair();
        const resp = await request.post('/api/tokens', {
            data: { public_key: publicKey },
        });
        expect(resp.status()).toBe(422);
    });

    test('security headers present on HTML pages', async ({ request }) => {
        const resp = await request.get('/');
        const h = resp.headers();
        expect(h['x-content-type-options']).toBe('nosniff');
        expect(h['x-frame-options']).toBe('DENY');
        expect(h['referrer-policy']).toBe('same-origin');
        expect(h['permissions-policy']).toBeDefined();
    });

    test('upload exceeding MAX_FILE_SIZE_MB → 413', async ({ request }) => {
        const { publicKey } = getTestKeyPair();
        const tokenResp = await request.post('/api/tokens', {
            data: { public_key: publicKey, collector_email: 'c@test.com' },
        });
        const { token_id } = await tokenResp.json();

        const tooBig = Buffer.alloc(11 * 1024 * 1024);
        const resp = await request.post(`/api/upload/${token_id}`, {
            multipart: {
                file: {
                    name: 'big.enc',
                    mimeType: 'application/octet-stream',
                    buffer: tooBig,
                },
            },
        });
        expect(resp.status()).toBe(413);
    });

    test('/api/tokens/{id} always returns 200 (anti-enumeration)', async ({ request }) => {
        const resp = await request.get('/api/tokens/00000000-0000-0000-0000-000000000000');
        expect(resp.status()).toBe(200);
        const data = await resp.json();
        expect(data.valid).toBe(false);
    });
});
