-- Add down migration script here
ALTER TABLE emergency_contact
ALTER COLUMN server_key_file DROP DEFAULT;
