-- Add down migration script here
ALTER TABLE s2secret_user
DROP COLUMN server_auth_setup;