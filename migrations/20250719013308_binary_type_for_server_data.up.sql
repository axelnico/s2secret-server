-- Add up migration script here
ALTER TABLE secret
    ALTER COLUMN title TYPE bytea USING decode(title,'base64'),
    ALTER COLUMN user_name TYPE bytea USING decode(user_name,'base64'),
    ALTER COLUMN site TYPE bytea USING decode(site,'base64'),
    ALTER COLUMN notes TYPE bytea USING decode(notes,'base64');

ALTER TABLE secret_share
    ALTER COLUMN server_share TYPE bytea USING decode(server_share, 'base64');