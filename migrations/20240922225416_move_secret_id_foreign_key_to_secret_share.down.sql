-- Add down migration script here
ALTER TABLE secret
ADD COLUMN share_id UUID REFERENCES secret_share (id_secret_share);

ALTER TABLE secret_share
DROP COLUMN secret_id;
