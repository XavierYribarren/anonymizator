# Locales

Translation files for Anonymizator's i18n engine.

## File format

Each locale is a JSON file named `{locale}.json` (e.g. `en.json`, `fr.json`).

```json
{
  "_meta": {
    "language": "English",
    "locale": "en",
    "author": "...",
    "version": "1.0"
  },
  "section": {
    "key": "Translated string"
  }
}
```

Strings can contain `{placeholder}` tokens that are replaced at runtime:

```json
"invite_sent": "Invitation sent to {email}"
```

## Adding a language

1. Copy `en.json` to `{locale}.json` (use the ISO 639-1 code, e.g. `de`, `es`, `it`).
2. Translate every value. **Do not change the keys.**
3. Update `_meta.language` and `_meta.locale` to match the new locale.
4. The i18n engine will pick it up automatically via browser language detection.

## Key structure

| Section | Description |
|---------|-------------|
| `common` | Shared UI labels (copy, cancel, close…) |
| `nav` | Sidebar navigation links |
| `researcher` | Researcher dashboard (key management, invitations, files) |
| `upload` | Collector upload page (states, progress steps, errors) |
| `decrypt` | Decrypt page |

## Fallback behaviour

If the browser language has no matching locale file, the engine falls back to `en.json`.
