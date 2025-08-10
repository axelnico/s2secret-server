-- Add up migration script here
ALTER TABLE emergency_contact
ALTER COLUMN server_key_file SET DEFAULT gen_random_bytes(32);