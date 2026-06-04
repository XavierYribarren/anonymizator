/**
 * Cryptographic primitives using the Web Crypto API.
 *
 * File format produced by encryptFile():
 *   [encrypted_aes_key : 512 bytes]  RSA-4096 OAEP-encrypted AES-256 key
 *   [iv                : 12 bytes]   AES-GCM nonce
 *   [ciphertext + tag  : N+16 bytes] AES-GCM payload (16-byte tag appended by the API)
 *
 * This layout is identical to what crypto_utils.py produces and expects.
 */

// ── PEM / Buffer helpers ──────────────────────────────────────────────────────

function pemToBuffer(pem) {
    const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
    const binary = atob(b64);
    const buf = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
    return buf.buffer;
}

function bufferToPem(buffer, label) {
    const bytes = new Uint8Array(buffer);
    let b64 = "";
    // btoa in chunks to avoid call-stack overflow on large keys
    const chunkSize = 8192;
    for (let i = 0; i < bytes.length; i += chunkSize) {
        b64 += btoa(String.fromCharCode(...bytes.subarray(i, i + chunkSize)));
    }
    const lines = b64.match(/.{1,64}/g).join("\n");
    return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

async function getFingerprint(publicKeyPem) {
    const buffer = pemToBuffer(publicKeyPem);
    const hash = await crypto.subtle.digest("SHA-256", buffer);
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
}

// ── Key generation ────────────────────────────────────────────────────────────

async function generateKeyPair() {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 4096,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    const publicKeyBuffer = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    const privateKeyBuffer = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

    return {
        publicKeyPem: bufferToPem(publicKeyBuffer, "PUBLIC KEY"),
        privateKeyPem: bufferToPem(privateKeyBuffer, "PRIVATE KEY"),
    };
}

// ── Encryption ────────────────────────────────────────────────────────────────

async function encryptFile(fileBytes, publicKeyPem) {
    const publicKey = await crypto.subtle.importKey(
        "spki",
        pemToBuffer(publicKeyPem),
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["encrypt"]
    );

    const aesKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt"]
    );

    const iv = crypto.getRandomValues(new Uint8Array(12));

    // AES-GCM produces ciphertext with the 16-byte authentication tag appended
    const encryptedPayload = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        aesKey,
        fileBytes
    );

    const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
    const encryptedAesKey = await crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        rawAesKey
    );

    // Layout: [512 B RSA key] [12 B IV] [N+16 B ciphertext+tag]
    const result = new Uint8Array(512 + 12 + encryptedPayload.byteLength);
    result.set(new Uint8Array(encryptedAesKey), 0);
    result.set(iv, 512);
    result.set(new Uint8Array(encryptedPayload), 524);
    return result;
}

// ── Decryption ────────────────────────────────────────────────────────────────

async function decryptFile(encBytes, privateKeyPem) {
    // Web Crypto only supports PKCS#8 (-----BEGIN PRIVATE KEY-----)
    if (
        privateKeyPem.includes("BEGIN RSA PRIVATE KEY") ||
        privateKeyPem.includes("BEGIN OPENSSH PRIVATE KEY")
    ) {
        throw new Error(
            "Format de clé non supporté dans le navigateur.\n" +
            "Convertissez votre clé avec la commande :\n" +
            "openssl pkcs8 -topk8 -nocrypt -in ancienne_cle.pem -out nouvelle_cle.pem"
        );
    }

    const privateKey = await crypto.subtle.importKey(
        "pkcs8",
        pemToBuffer(privateKeyPem),
        { name: "RSA-OAEP", hash: "SHA-256" },
        false,
        ["decrypt"]
    );

    const encryptedAesKey = encBytes.slice(0, 512);   // Uint8Array
    const iv = encBytes.slice(512, 524);              // 12-byte nonce
    const ciphertextWithTag = encBytes.slice(524);    // ciphertext + 16-byte tag

    const rawAesKey = await crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedAesKey
    );

    const aesKey = await crypto.subtle.importKey(
        "raw",
        rawAesKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv },
        aesKey,
        ciphertextWithTag
    );

    return new Uint8Array(decrypted);
}
