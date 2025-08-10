-- Add down migration script here
ALTER TABLE emergency_contact
    ALTER COLUMN server_key_file TYPE TEXT USING encode(server_key_file,'base64'),
    ALTER COLUMN server_share TYPE TEXT USING encode(server_share,'base64');

ALTER TABLE emergency_contact_secret_access
    ALTER COLUMN server_ticket TYPE TEXT USING encode(server_ticket,'base64'),
    ALTER COLUMN server_v TYPE TEXT USING encode(server_v,'base64'),
    ALTER COLUMN server_a TYPE TEXT USING encode(server_a,'base64');