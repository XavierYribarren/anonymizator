-- Migration 001 — tokens.collector_email : retrait de la contrainte NOT NULL
--
-- SQLite ne supporte pas ALTER COLUMN ; on recrée la table.
-- Exécuter avec : sqlite3 anonymizator.db < migrate_001_tokens_collector_email_nullable.sql

PRAGMA foreign_keys = OFF;

BEGIN;

CREATE TABLE tokens_new (
    id                     TEXT PRIMARY KEY,
    public_key             TEXT NOT NULL,
    public_key_fingerprint TEXT NOT NULL,
    researcher_email       TEXT,
    collector_email        TEXT,
    created_at             TEXT NOT NULL,
    expires_at             TEXT NOT NULL,
    used_at                TEXT,
    file_id                TEXT
);

INSERT INTO tokens_new
    SELECT id, public_key, public_key_fingerprint, researcher_email,
           collector_email, created_at, expires_at, used_at, file_id
    FROM tokens;

DROP TABLE tokens;

ALTER TABLE tokens_new RENAME TO tokens;

CREATE INDEX IF NOT EXISTS idx_tokens_expires_at ON tokens(expires_at);

COMMIT;

PRAGMA foreign_keys = ON;
