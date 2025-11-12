-- Add down migration script here
alter table secret_share
    drop constraint secret_share_id_secret_key;