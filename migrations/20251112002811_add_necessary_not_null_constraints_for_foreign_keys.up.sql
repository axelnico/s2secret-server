-- Add up migration script here
alter table secret
    alter column user_id set not null;

alter table emergency_contact
    alter column user_id set not null;

alter table secret_share
    alter column id_secret set not null;