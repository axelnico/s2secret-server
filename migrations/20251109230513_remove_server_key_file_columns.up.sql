-- Add up migration script here
ALTER TABLE s2secret_user
    DROP COLUMN server_key_file;

ALTER TABLE emergency_contact
    DROP COLUMN server_key_file;