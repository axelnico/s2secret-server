-- Add up migration script here
ALTER TABLE secret
ADD COLUMN user_id UUID REFERENCES s2secret_user(id_user);