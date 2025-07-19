-- Add down migration script here
ALTER TABLE secret
    ALTER COLUMN title TYPE TEXT USING encode(title,'base64'),
    ALTER COLUMN user_name TYPE TEXT USING encode(user_name,'base64'),
    ALTER COLUMN site TYPE TEXT USING encode(site,'base64'),
    ALTER COLUMN notes TYPE TEXT USING encode(notes,'base64');

ALTER TABLE secret_share
    ALTER COLUMN server_share TYPE TEXT USING encode(server_share,'base64');