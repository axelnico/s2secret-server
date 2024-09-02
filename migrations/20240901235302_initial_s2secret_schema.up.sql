CREATE TABLE s2secret_user (
   id_user UUID NOT NULL,
   email VARCHAR(128) NOT NULL,
   name VARCHAR(64) NOT NULL,
   server_key_file CHAR(64) NOT NULL,
   created_at TIMESTAMP NOT NULL,
   last_login TIMESTAMP,
   PRIMARY KEY (id_user)
);

CREATE TABLE emergency_contact (
   id_emergency_contact UUID NOT NULL,
   email VARCHAR(128) NOT NULL,
   description VARCHAR(128),
   server_key_file CHAR(64) NOT NULL,
   server_share BYTEA NOT NULL,
   user_id UUID REFERENCES s2secret_user (id_user),
   PRIMARY KEY (id_emergency_contact)
);

CREATE TABLE proactive_protection (
  id_proactive_protection UUID NOT NULL,
  description VARCHAR(64) NOT NULL,
  protection_interval INTERVAL NOT NULL,
  PRIMARY KEY (id_proactive_protection)
);

CREATE TABLE secret_share (
  id_secret_share UUID NOT NULL,
  server_share BYTEA NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  proactive_protection_id UUID REFERENCES proactive_protection (id_proactive_protection),
  PRIMARY KEY (id_secret_share)
);

CREATE TABLE secret (
  id_secret UUID NOT NULL,
  title bytea NOT NULL,
  user_name BYTEA,
  site BYTEA,
  notes BYTEA,
  share_id UUID REFERENCES secret_share (id_secret_share),
  PRIMARY KEY (id_secret)
);

CREATE TABLE emergency_contact_secret_access (
  id_emergency_contact UUID REFERENCES emergency_contact (id_emergency_contact),
  id_secret UUID REFERENCES secret (id_secret),
  server_ticket BYTEA NOT NULL,
  server_v BYTEA NOT NULL,
  server_a BYTEA NOT NULL,
  PRIMARY KEY (id_emergency_contact,id_secret)
);