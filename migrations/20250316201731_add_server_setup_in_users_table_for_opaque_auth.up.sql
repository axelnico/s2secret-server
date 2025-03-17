-- Add up migration script here
ALTER TABLE s2secret_user
ADD COLUMN server_auth_setup bytea NOT NULL DEFAULT gen_random_bytes(32);