-- Add up migration script here
ALTER TABLE s2secret_user
DROP COLUMN server_key_file;

ALTER TABLE s2secret_user
ADD COLUMN server_key_file bytea NOT NULL DEFAULT gen_random_bytes(32);