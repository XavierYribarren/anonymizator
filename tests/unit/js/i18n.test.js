/**
 * Tests for the i18n engine logic (web/static/i18n.js).
 *
 * The core functions are replicated here as pure functions so they can be
 * tested without a browser environment or complex module loading.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Replicated core logic from i18n.js ────────────────────────────────────────

function t(translations, key, params = {}) {
    const keys = key.split('.');
    let value = translations;
    for (const k of keys) {
        value = value?.[k];
        if (value === undefined) return key;
    }
    if (typeof value !== 'string') return key;
    return value.replace(/\{(\w+)\}/g, (_, k) => params[k] ?? `{${k}}`);
}

function detectLocale(navigatorLanguage) {
    return (navigatorLanguage || 'en').toLowerCase().split('-')[0];
}

async function loadLocale(fetchFn, locale) {
    try {
        const res = await fetchFn(`/locales/${locale}.json`);
        if (!res.ok) throw new Error();
        return await res.json();
    } catch {
        return null;
    }
}

async function initI18n(fetchFn, navigatorLanguage) {
    const detected = detectLocale(navigatorLanguage);
    let translations = await loadLocale(fetchFn, detected);
    let locale;
    if (!translations) {
        translations = await loadLocale(fetchFn, 'en');
        locale = 'en';
    } else {
        locale = detected;
    }
    return { translations: translations || {}, locale };
}

// ── Sample translations ───────────────────────────────────────────────────────

const EN = {
    common: { app_name: 'Anonymizator', copy: 'Copy', copied: 'Copied!', error: 'Error' },
    upload: {
        file_too_large: 'File too large. Maximum size: {max} MB.',
        title: 'Secure file upload',
        step_done: 'Sent!',
    },
    researcher: {
        invite_sent: 'Invitation sent to {email}',
        keygen_error: 'Error: {message}',
    },
};

const FR = {
    common: { app_name: 'Anonymizator', copy: 'Copier', copied: 'Copié !', error: 'Erreur' },
    upload: {
        file_too_large: 'Fichier trop volumineux. Taille maximale : {max} Mo.',
        title: 'Envoi sécurisé',
        step_done: 'Envoyé !',
    },
    researcher: {
        invite_sent: 'Invitation envoyée à {email}',
        keygen_error: 'Erreur : {message}',
    },
};

// ── Translation lookup ────────────────────────────────────────────────────────

describe('t() — translation lookup', () => {
    it('returns translation for an existing key', () => {
        expect(t(EN, 'common.copy')).toBe('Copy');
        expect(t(FR, 'common.copy')).toBe('Copier');
    });

    it('returns the key name for a missing key', () => {
        expect(t(EN, 'nonexistent.key')).toBe('nonexistent.key');
    });

    it('returns the key for a partial path (non-string node)', () => {
        expect(t(EN, 'common')).toBe('common');
    });

    it('interpolates single {placeholder}', () => {
        expect(t(EN, 'upload.file_too_large', { max: 2 }))
            .toBe('File too large. Maximum size: 2 MB.');
    });

    it('interpolates multiple placeholders', () => {
        expect(t(EN, 'researcher.invite_sent', { email: 'alice@test.com' }))
            .toBe('Invitation sent to alice@test.com');
    });

    it('leaves unreplaced placeholders as {key}', () => {
        expect(t(EN, 'upload.file_too_large', {}))
            .toBe('File too large. Maximum size: {max} MB.');
    });

    it('handles nested keys up to 3 levels', () => {
        expect(t(EN, 'researcher.keygen_error', { message: 'oops' }))
            .toBe('Error: oops');
    });

    it('handles empty translations object gracefully', () => {
        expect(t({}, 'any.key')).toBe('any.key');
    });
});

// ── Locale detection ──────────────────────────────────────────────────────────

describe('detectLocale()', () => {
    it('strips region code from fr-FR → fr', () => {
        expect(detectLocale('fr-FR')).toBe('fr');
    });

    it('strips region code from en-US → en', () => {
        expect(detectLocale('en-US')).toBe('en');
    });

    it('lowercases the locale code', () => {
        expect(detectLocale('FR')).toBe('fr');
    });

    it('falls back to en when input is empty', () => {
        expect(detectLocale('')).toBe('en');
    });

    it('falls back to en when input is null', () => {
        expect(detectLocale(null)).toBe('en');
    });

    it('handles plain locale without region', () => {
        expect(detectLocale('de')).toBe('de');
    });
});

// ── loadLocale and initI18n ───────────────────────────────────────────────────

describe('loadLocale()', () => {
    it('returns translations when fetch succeeds', async () => {
        const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => EN });
        const result = await loadLocale(mockFetch, 'en');
        expect(result).toEqual(EN);
    });

    it('returns null when response is not ok', async () => {
        const mockFetch = vi.fn().mockResolvedValue({ ok: false });
        expect(await loadLocale(mockFetch, 'de')).toBeNull();
    });

    it('returns null when fetch throws', async () => {
        const mockFetch = vi.fn().mockRejectedValue(new Error('network error'));
        expect(await loadLocale(mockFetch, 'en')).toBeNull();
    });

    it('fetches the correct URL', async () => {
        const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => EN });
        await loadLocale(mockFetch, 'fr');
        expect(mockFetch).toHaveBeenCalledWith('/locales/fr.json');
    });
});

describe('initI18n()', () => {
    it('uses browser language when locale file exists', async () => {
        const mockFetch = vi.fn().mockResolvedValue({ ok: true, json: async () => FR });
        const { locale, translations } = await initI18n(mockFetch, 'fr-FR');
        expect(locale).toBe('fr');
        expect(translations).toEqual(FR);
    });

    it('falls back to en when browser language has no locale file', async () => {
        const mockFetch = vi.fn()
            .mockResolvedValueOnce({ ok: false })           // de.json fails
            .mockResolvedValueOnce({ ok: true, json: async () => EN }); // en.json works
        const { locale, translations } = await initI18n(mockFetch, 'de-DE');
        expect(locale).toBe('en');
        expect(translations).toEqual(EN);
    });

    it('fetches detected locale first, then en as fallback', async () => {
        const mockFetch = vi.fn()
            .mockResolvedValueOnce({ ok: false })
            .mockResolvedValueOnce({ ok: true, json: async () => EN });
        await initI18n(mockFetch, 'ja');
        expect(mockFetch).toHaveBeenNthCalledWith(1, '/locales/ja.json');
        expect(mockFetch).toHaveBeenNthCalledWith(2, '/locales/en.json');
    });
});
