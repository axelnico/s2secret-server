-- Add down migration script here
ALTER TABLE secret
DROP COLUMN user_id;