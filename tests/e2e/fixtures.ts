import { test as base } from '@playwright/test';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

// ── Static test key pair (generated once per test run) ────────────────────────

let _keyPair: { publicKey: string; privateKey: string } | null = null;

export function getTestKeyPair(): { publicKey: string; privateKey: string } {
    if (!_keyPair) {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });
        _keyPair = { publicKey, privateKey };
    }
    return _keyPair;
}

// ── Custom fixtures ───────────────────────────────────────────────────────────

type Fixtures = {
    testFile: string;
    uploadUrl: string;
    uploadUrlWithKey: { url: string; fingerprint: string };
};

export const test = base.extend<Fixtures>({
    testFile: async ({}, use) => {
        const filePath = path.join('/tmp', `anon_test_${Date.now()}.csv`);
        fs.writeFileSync(filePath, 'id,name,value\n1,Alice,42\n2,Bob,99\n');
        await use(filePath);
        try { fs.unlinkSync(filePath); } catch { /* already gone */ }
    },

    uploadUrl: async ({ request }, use) => {
        const { publicKey } = getTestKeyPair();
        const resp = await request.post('/api/tokens', {
            data: {
                public_key: publicKey,
                researcher_email: null,
                collector_email: 'collector@test.com',
            },
        });
        const data = await resp.json();
        await use(data.upload_url as string);
    },

    uploadUrlWithKey: async ({ request }, use) => {
        const { publicKey } = getTestKeyPair();
        const resp = await request.post('/api/tokens', {
            data: {
                public_key: publicKey,
                researcher_email: null,
                collector_email: 'collector@test.com',
            },
        });
        const data = await resp.json();
        // Extract fingerprint from the upload URL token then list files — or compute inline
        const fp = data.token_id ? await _fingerprint(publicKey) : '';
        await use({ url: data.upload_url as string, fingerprint: fp });
    },
});

async function _fingerprint(publicKeyPem: string): Promise<string> {
    const b64 = publicKeyPem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
    const der = Buffer.from(b64, 'base64');
    const hash = crypto.createHash('sha256').update(der).digest('hex');
    return hash.slice(0, 16);
}

export { expect } from '@playwright/test';
