-- Add up migration script here
ALTER TABLE emergency_contact
    ALTER COLUMN server_key_file TYPE bytea USING decode(server_key_file,'base64'),
    ALTER COLUMN server_share TYPE bytea USING decode(server_share,'base64');

ALTER TABLE emergency_contact_secret_access
    ALTER COLUMN server_ticket TYPE bytea USING decode(server_ticket, 'base64'),
    ALTER COLUMN server_v TYPE bytea USING decode(server_v, 'base64'),
    ALTER COLUMN server_a TYPE bytea USING decode(server_a, 'base64');