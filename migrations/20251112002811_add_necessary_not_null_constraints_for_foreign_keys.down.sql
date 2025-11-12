-- Add down migration script here
alter table secret
    alter column user_id drop not null;

alter table emergency_contact
    alter column user_id drop not null;

alter table secret_share
    alter column id_secret drop not null;