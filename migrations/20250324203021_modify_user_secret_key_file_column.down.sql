-- Add down migration script here
ALTER TABLE s2secret_user
DROP COLUMN server_key_file;

ALTER TABLE s2secret_user
ADD COLUMN server_key_file char(64);