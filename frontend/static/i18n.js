const I18n = (() => {
    let _translations = {};
    let _locale = 'en';
    let _initPromise = null;

    function detectLocale() {
        return (navigator.language || 'en').toLowerCase().split('-')[0];
    }

    async function loadLocale(locale) {
        try {
            const res = await fetch(`/locales/${locale}.json`);
            if (!res.ok) throw new Error();
            return await res.json();
        } catch {
            return null;
        }
    }

    function init() {
        if (!_initPromise) {
            _initPromise = (async () => {
                const detected = detectLocale();
                let translations = await loadLocale(detected);
                if (!translations) {
                    translations = await loadLocale('en');
                    _locale = 'en';
                } else {
                    _locale = detected;
                }
                _translations = translations || {};
                applyTranslations();
                return _locale;
            })();
        }
        return _initPromise;
    }

    function t(key, params = {}) {
        const keys = key.split('.');
        let value = _translations;
        for (const k of keys) {
            value = value?.[k];
            if (value === undefined) return key;
        }
        if (typeof value !== 'string') return key;
        return value.replace(/\{(\w+)\}/g, (_, k) => params[k] ?? `{${k}}`);
    }

    function applyTranslations() {
        document.querySelectorAll('[data-i18n]').forEach(el => {
            el.textContent = t(el.getAttribute('data-i18n'));
        });
        document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
            el.placeholder = t(el.getAttribute('data-i18n-placeholder'));
        });
        document.querySelectorAll('[data-i18n-title]').forEach(el => {
            el.title = t(el.getAttribute('data-i18n-title'));
        });
    }

    return { init, t, applyTranslations, getLocale: () => _locale };
})();

document.addEventListener('DOMContentLoaded', () => I18n.init());
