-- Add up migration script here
alter table secret_share
    add unique (id_secret);
