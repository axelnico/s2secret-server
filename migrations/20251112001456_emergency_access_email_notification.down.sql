-- Add down migration script here
ALTER TABLE emergency_contact_secret_access
    DROP COLUMN email_enabled;