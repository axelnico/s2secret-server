-- Add up migration script here
ALTER TABLE secret_share
ADD COLUMN id_secret UUID REFERENCES secret (id_secret);

ALTER TABLE secret
DROP COLUMN share_id;