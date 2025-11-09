-- Add down migration script here
ALTER TABLE s2secret_user
    ADD COLUMN server_key_file bytea NOT NULL DEFAULT gen_random_bytes(32);

ALTER TABLE emergency_contact
    ADD COLUMN server_key_file bytea NOT NULL DEFAULT gen_random_bytes(32);