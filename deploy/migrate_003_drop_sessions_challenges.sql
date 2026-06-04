-- migrate_003_drop_sessions_challenges.sql
-- Drops the sessions and challenges tables no longer used after switching
-- from challenge-response auth to opaque researcher_token (public_keys.researcher_token).
-- Safe to run multiple times: DROP TABLE IF EXISTS is idempotent.

DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS challenges;
