-- Add up migration script here
insert into proactive_protection (id_proactive_protection, description,protection_interval)
values(gen_random_uuid(), 'Extreme', interval '1 day');
insert into proactive_protection (id_proactive_protection, description,protection_interval)
values(gen_random_uuid(), 'High', interval '1 week');
insert into proactive_protection (id_proactive_protection, description,protection_interval)
values(gen_random_uuid(), 'Medium', interval '1 month');
