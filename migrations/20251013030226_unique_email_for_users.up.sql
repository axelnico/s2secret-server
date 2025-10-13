-- Add up migration script here
alter table s2secret_user
    add unique (email);