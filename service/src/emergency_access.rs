use std::env;
use std::fs::File;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
use bincode::{Decode, Encode};
use lettre::{Address, Message, SmtpTransport, Transport};
use lettre::message::header::ContentType;
use lettre::message::{Attachment, Body, Mailbox, MultiPart, SinglePart, SinglePartBuilder};
use lettre::transport::smtp::authentication::Credentials;
use crate::EmergencyContact;

#[derive(Deserialize, Serialize)]
pub struct EmergencyContactSecretAccess {
    id_emergency_contact: Uuid,
    id_secret: Uuid,
    pub server_ticket: Vec<u8>,
    pub server_v: Vec<u8>,
    pub server_a: Vec<u8>,
}

#[derive(Deserialize, Serialize, Encode, Decode)]
pub struct Ticket {
    pub password_hash: String,
    pub encrypted_secret: Vec<u8>,
}

#[derive(Deserialize,Serialize)]
struct EmergencyAccessClientFileContent {
    id_emergency_contact: Uuid,
    id_secret: Uuid,
    password_salt: String,
    data_encryption_key: Vec<u8>,
    ticket_share: Vec<u8>,
    v_share: Vec<u8>,
    a_share: Vec<u8>,
    a : Vec<u8>
}

impl EmergencyContactSecretAccess {
    pub async fn emergency_access_for_contact_and_secret(secret_id: &Uuid, contact_id: &Uuid, database: &PgPool) -> Option<Self> {
        sqlx::query_as!(Self, "SELECT id_emergency_contact, id_secret, server_ticket, server_v, server_a from emergency_contact_secret_access sa where sa.id_secret = $1 and sa.id_emergency_contact = $2", secret_id, contact_id).fetch_optional(database).await.unwrap()
    }

    pub async fn add_emergency_contact_to_secret(secret_id: &Uuid, emergency_contact_id: &Uuid, user_id: &Uuid, server_ticket: &Vec<u8>, server_v: &Vec<u8>, server_a: &Vec<u8>, database: &PgPool) -> Option<Uuid> {
        let mut transaction = database.begin().await.unwrap();
        let emergency_contact_uuid = sqlx::query_scalar!("SELECT id_emergency_contact from emergency_contact where id_emergency_contact=$1 and user_id=$2",emergency_contact_id, user_id).fetch_optional(&mut *transaction).await.unwrap();
        match emergency_contact_uuid {
            None => None,
            Some(emergency_contact_uuid) => {
                let emergency_contact_secret_access_uuid = sqlx::query_scalar!("SELECT id_emergency_contact from emergency_contact_secret_access where id_emergency_contact=$1 and id_secret=$2",emergency_contact_id,secret_id).fetch_optional(&mut *transaction).await.unwrap();
                match emergency_contact_secret_access_uuid {
                    Some(_) => None, // This means that the emergency contact has already been associated to the secret. Do nothing
                    None => {
                        sqlx::query!("INSERT INTO emergency_contact_secret_access(id_emergency_contact, id_secret, server_ticket, server_v, server_a) VALUES ($1, $2, $3, $4, $5)",
                                emergency_contact_id, secret_id, server_ticket, server_v, server_a).execute(&mut *transaction).await.unwrap();
                        transaction.commit().await.unwrap();
                        Some(emergency_contact_uuid)
                    }
                }
            }
        }
    }

    pub async fn send_emergency_access_data_to_emergency_contact(secret_id: &Uuid, emergency_contact_id: &Uuid, user_id: &Uuid, password_salt: String, encrypted_data_encryption_key: Vec<u8>, encrypted_ticket_share: Vec<u8>, encrypted_v_share: Vec<u8>, encrypted_a_share: Vec<u8>, encrypted_a: Vec<u8>, database: &PgPool) {
        let emergency_contact = EmergencyContact::emergency_contact_of_user(emergency_contact_id, user_id, database).await.unwrap();
        dotenvy::dotenv().ok();
        let mut buffer = Vec::new();
        let emergency_access_file_content = EmergencyAccessClientFileContent {
            id_emergency_contact: *emergency_contact_id,
            id_secret: *secret_id,
            data_encryption_key: encrypted_data_encryption_key,
            password_salt,
            ticket_share: encrypted_ticket_share,
            v_share: encrypted_v_share,
            a_share: encrypted_a_share,
            a: encrypted_a
        };
        let email_from = env::var("EMAIL_FROM").expect("EMAIL_FROM is not set in .env file");
        let smtp_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME is not set in .env file");
        let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set in .env file");
        ciborium::ser::into_writer(&emergency_access_file_content, &mut buffer).unwrap();
        let filename = String::from("content.cbor");
        let content_type = ContentType::parse("application/cbor").unwrap(); // Adjust ContentType based on file type
        let attachment = Attachment::new(filename).body(Body::new(buffer), content_type);
        let email_from = Address::try_from(email_from).unwrap();
        let email_to = Address::try_from(emergency_contact.email).unwrap();
        let email = Message::builder()
            .from(Mailbox::new(None,email_from))
            .to(Mailbox::new(None, email_to))
            .subject("S2Secret - Emergency Access Data")
            .multipart(
                MultiPart::mixed()
                    .singlepart(SinglePart::builder().header(ContentType::TEXT_PLAIN).body(String::from("Access data")))
                    .singlepart(attachment)
            )
            .unwrap();

        let creds = Credentials::new(smtp_username, smtp_password);

        // Open a remote connection to gmail
        let mailer = SmtpTransport::relay("smtp.gmail.com")
            .unwrap()
            .credentials(creds)
            .build();

        // Send the email
        match mailer.send(&email) {
            Ok(_) => println!("Email sent successfully!"),
            Err(e) => panic!("Could not send email: {e:?}"),
        }
    }
}