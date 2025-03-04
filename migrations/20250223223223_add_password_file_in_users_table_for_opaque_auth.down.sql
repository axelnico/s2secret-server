-- Add down migration script here
ALTER TABLE s2secret_user
DROP COLUMN password_file;

DROP EXTENSION IF EXISTS pgcrypto;

