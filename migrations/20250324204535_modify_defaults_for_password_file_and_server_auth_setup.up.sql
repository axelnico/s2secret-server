-- Add up migration script here
ALTER TABLE s2secret_user
ALTER COLUMN password_file SET DEFAULT gen_random_bytes(192),
ALTER COLUMN server_auth_setup SET DEFAULT gen_random_bytes(128);