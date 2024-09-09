CREATE TABLE IF NOT EXISTS s2secret_user (
   id_user UUID NOT NULL,
   email VARCHAR(128) NOT NULL,
   name VARCHAR(64) NOT NULL,
   server_key_file CHAR(64) NOT NULL,
   created_at TIMESTAMP NOT NULL,
   last_login TIMESTAMP,
   PRIMARY KEY (id_user)
);

CREATE TABLE IF NOT EXISTS emergency_contact (
   id_emergency_contact UUID NOT NULL,
   email VARCHAR(128) NOT NULL,
   description VARCHAR(128),
   server_key_file CHAR(64) NOT NULL,
   server_share TEXT NOT NULL,
   user_id UUID REFERENCES s2secret_user (id_user),
   PRIMARY KEY (id_emergency_contact)
);

CREATE TABLE IF NOT EXISTS proactive_protection (
  id_proactive_protection UUID NOT NULL,
  description VARCHAR(64) NOT NULL,
  protection_interval INTERVAL NOT NULL,
  PRIMARY KEY (id_proactive_protection)
);

CREATE TABLE IF NOT EXISTS secret_share (
  id_secret_share UUID NOT NULL,
  server_share TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  updated_at TIMESTAMP NOT NULL,
  proactive_protection_id UUID REFERENCES proactive_protection (id_proactive_protection),
  PRIMARY KEY (id_secret_share)
);

CREATE TABLE IF NOT EXISTS secret (
  id_secret UUID NOT NULL,
  title TEXT NOT NULL,
  user_name TEXT,
  site TEXT,
  notes TEXT,
  share_id UUID REFERENCES secret_share (id_secret_share),
  PRIMARY KEY (id_secret)
);

CREATE TABLE IF NOT EXISTS emergency_contact_secret_access (
  id_emergency_contact UUID REFERENCES emergency_contact (id_emergency_contact),
  id_secret UUID REFERENCES secret (id_secret),
  server_ticket TEXT NOT NULL,
  server_v TEXT NOT NULL,
  server_a TEXT NOT NULL,
  PRIMARY KEY (id_emergency_contact,id_secret)
);