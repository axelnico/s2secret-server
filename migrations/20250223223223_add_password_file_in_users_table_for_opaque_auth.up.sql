-- Add up migration script here
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE s2secret_user
ADD COLUMN password_file bytea NOT NULL DEFAULT gen_random_bytes(32);