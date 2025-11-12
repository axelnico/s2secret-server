-- Add up migration script here
ALTER TABLE emergency_contact_secret_access
    ADD COLUMN email_enabled boolean NOT NULL DEFAULT false;