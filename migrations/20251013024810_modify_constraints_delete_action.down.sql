-- Add down migration script here
alter table secret_share
    drop constraint secret_share_id_secret_fkey;

alter table secret_share
    add constraint secret_share_id_secret_fkey
        foreign key (id_secret)
            references secret(id_secret)
            on delete no action;

alter table emergency_contact_secret_access
    drop constraint emergency_contact_secret_access_id_secret_fkey,
    drop constraint emergency_contact_secret_access_id_emergency_contact_fkey;

alter table emergency_contact_secret_access
    add constraint emergency_contact_secret_access_id_secret_fkey
        foreign key (id_secret)
            references secret(id_secret)
            on delete no action,
    add constraint emergency_contact_secret_access_id_emergency_contact_fkey
        foreign key (id_emergency_contact)
            references emergency_contact(id_emergency_contact)
            on delete no action;