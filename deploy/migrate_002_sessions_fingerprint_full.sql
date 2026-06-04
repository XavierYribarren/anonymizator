-- Migration 002 — public_key_fingerprint : passage de 16 à 64 caractères hex (SHA-256 complet)
--
-- Contexte : _public_key_fingerprint() tronquait à 16 chars (64 bits).
-- Après correction, les nouvelles empreintes font 64 chars (256 bits).
-- Les deux formats sont incompatibles : les sessions existantes (16-char fingerprint)
-- ne peuvent pas être converties sans les clés publiques d'origine.
-- => Les sessions actives sont invalidées ; les utilisateurs devront se ré-authentifier.
--
-- Les tables tokens et uploaded_files sont également concernées :
--   - tokens    : contient public_key (PEM), une migration applicative peut recalculer
--                 l'empreinte si nécessaire (les tokens non consommés ont encore leur clé).
--   - uploaded_files : la clé publique n'est pas stockée ; les fichiers existants resteront
--                 accessibles uniquement si le chercheur possède encore une session avec
--                 l'ancien fingerprint (impossible après cette migration) — ils expirent
--                 naturellement selon FILE_EXPIRY_DAYS.
--
-- Exécuter avec : sqlite3 anonymizator.db < migrate_002_sessions_fingerprint_full.sql

PRAGMA foreign_keys = OFF;

BEGIN;

-- Recrée la table sessions à l'identique (TEXT n'a pas de contrainte de longueur en SQLite).
-- Les lignes existantes ne sont PAS copiées : leurs fingerprints 16-char sont obsolètes.
CREATE TABLE sessions_new (
    token                  TEXT PRIMARY KEY,
    public_key_fingerprint TEXT NOT NULL,
    created_at             TEXT NOT NULL,
    last_seen_at           TEXT NOT NULL,
    expires_at             TEXT NOT NULL
);

DROP TABLE sessions;

ALTER TABLE sessions_new RENAME TO sessions;

CREATE INDEX IF NOT EXISTS idx_sessions_fingerprint ON sessions(public_key_fingerprint);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at  ON sessions(expires_at);

COMMIT;

PRAGMA foreign_keys = ON;
