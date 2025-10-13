-- Add down migration script here
alter table s2secret_user
    drop constraint s2secret_user_email_key;