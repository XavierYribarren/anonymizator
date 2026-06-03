/**
 * Tests for the Web Crypto primitives used in crypto.js.
 *
 * Functions are replicated here (not imported) because crypto.js is a
 * browser script, not an ES module. The test validates the same algorithm
 * and binary format that the browser and Python server share.
 */
import { describe, it, expect, beforeAll } from 'vitest';

// ── Helpers (mirrors crypto.js) ───────────────────────────────────────────────

function pemToBuffer(pem) {
    const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
    const binary = atob(b64);
    const buf = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
    return buf.buffer;
}

function bufferToPem(buffer, label) {
    const b64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    const lines = b64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

async function generateKeyPair() {
    const kp = await crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true, ['encrypt', 'decrypt']
    );
    const pubBuf = await crypto.subtle.exportKey('spki', kp.publicKey);
    const privBuf = await crypto.subtle.exportKey('pkcs8', kp.privateKey);
    return {
        publicKeyPem: bufferToPem(pubBuf, 'PUBLIC KEY'),
        privateKeyPem: bufferToPem(privBuf, 'PRIVATE KEY'),
        publicKey: kp.publicKey,
        privateKey: kp.privateKey,
    };
}

async function encryptFile(fileBytes, publicKeyPem) {
    const publicKey = await crypto.subtle.importKey(
        'spki', pemToBuffer(publicKeyPem),
        { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']
    );
    const aesKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 }, true, ['encrypt']
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv }, aesKey, fileBytes
    );
    const rawAes = await crypto.subtle.exportKey('raw', aesKey);
    const encAesKey = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' }, publicKey, rawAes
    );
    // Layout: [encAesKey 256 B][iv 12 B][ciphertext+tag]
    const out = new Uint8Array(256 + 12 + ciphertext.byteLength);
    out.set(new Uint8Array(encAesKey), 0);
    out.set(iv, 256);
    out.set(new Uint8Array(ciphertext), 268);
    return out;
}

async function decryptFile(encBytes, privateKeyPem) {
    const privateKey = await crypto.subtle.importKey(
        'pkcs8', pemToBuffer(privateKeyPem),
        { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']
    );
    const encAesKey = encBytes.slice(0, 256);
    const iv = encBytes.slice(256, 268);
    const ciphertext = encBytes.slice(268);
    const rawAes = await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' }, privateKey, encAesKey
    );
    const aesKey = await crypto.subtle.importKey(
        'raw', rawAes, { name: 'AES-GCM' }, false, ['decrypt']
    );
    return new Uint8Array(
        await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ciphertext)
    );
}

async function getFingerprint(publicKeyPem) {
    const key = await crypto.subtle.importKey(
        'spki', pemToBuffer(publicKeyPem),
        { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']
    );
    const exported = await crypto.subtle.exportKey('spki', key);
    const hash = await crypto.subtle.digest('SHA-256', exported);
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
        .slice(0, 16);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Key generation', () => {
    let kp;
    beforeAll(async () => { kp = await generateKeyPair(); });

    it('public key is SPKI PEM (not RSA PUBLIC KEY)', () => {
        expect(kp.publicKeyPem).toContain('BEGIN PUBLIC KEY');
        expect(kp.publicKeyPem).not.toContain('RSA PUBLIC KEY');
    });

    it('private key is PKCS8 PEM (not RSA PRIVATE KEY)', () => {
        expect(kp.privateKeyPem).toContain('BEGIN PRIVATE KEY');
        expect(kp.privateKeyPem).not.toContain('RSA PRIVATE KEY');
    });
});

describe('Encrypt / Decrypt', () => {
    let kp;
    beforeAll(async () => { kp = await generateKeyPair(); });

    it('decrypts to original plaintext', async () => {
        const original = new TextEncoder().encode('Hello Anonymizator!');
        const enc = await encryptFile(original, kp.publicKeyPem);
        const dec = await decryptFile(enc, kp.privateKeyPem);
        expect(dec).toEqual(original);
    });

    it('ciphertext differs from plaintext', async () => {
        const data = new TextEncoder().encode('plaintext');
        const enc = await encryptFile(data, kp.publicKeyPem);
        expect(enc).not.toEqual(data);
    });

    it('two encryptions of same data differ (random IV)', async () => {
        const data = new TextEncoder().encode('same data');
        const enc1 = await encryptFile(data, kp.publicKeyPem);
        const enc2 = await encryptFile(data, kp.publicKeyPem);
        expect(enc1).not.toEqual(enc2);
    });

    it('wrong private key causes decryption failure', async () => {
        const other = await generateKeyPair();
        const enc = await encryptFile(new TextEncoder().encode('secret'), kp.publicKeyPem);
        await expect(decryptFile(enc, other.privateKeyPem)).rejects.toThrow();
    });

    it('corrupted ciphertext causes decryption failure', async () => {
        const enc = await encryptFile(new TextEncoder().encode('secret'), kp.publicKeyPem);
        const corrupted = new Uint8Array(enc);
        corrupted[corrupted.length - 1] ^= 0xFF; // flip last byte of AES-GCM tag
        await expect(decryptFile(corrupted, kp.privateKeyPem)).rejects.toThrow();
    });

    it('handles empty file', async () => {
        const empty = new Uint8Array(0);
        const enc = await encryptFile(empty, kp.publicKeyPem);
        const dec = await decryptFile(enc, kp.privateKeyPem);
        expect(dec).toEqual(empty);
    });

    it('binary format: [256 B RSA key][12 B IV][ciphertext+16 B tag]', async () => {
        const data = new TextEncoder().encode('test');
        const enc = await encryptFile(data, kp.publicKeyPem);
        expect(enc.byteLength).toBe(256 + 12 + data.length + 16);
    });
});

describe('Fingerprint', () => {
    let kp;
    beforeAll(async () => { kp = await generateKeyPair(); });

    it('is 16 lowercase hex characters', async () => {
        const fp = await getFingerprint(kp.publicKeyPem);
        expect(fp).toHaveLength(16);
        expect(fp).toMatch(/^[0-9a-f]{16}$/);
    });

    it('is deterministic for the same key', async () => {
        const fp1 = await getFingerprint(kp.publicKeyPem);
        const fp2 = await getFingerprint(kp.publicKeyPem);
        expect(fp1).toBe(fp2);
    });

    it('differs for different keys', async () => {
        const other = await generateKeyPair();
        const fp1 = await getFingerprint(kp.publicKeyPem);
        const fp2 = await getFingerprint(other.publicKeyPem);
        expect(fp1).not.toBe(fp2);
    });
});
