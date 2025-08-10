use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
#[derive(Deserialize, Serialize)]
pub struct EmergencyContactSecretAccess {
    id_emergency_contact: Uuid,
    id_secret: Uuid,
    pub server_ticket: Vec<u8>,
    pub server_v: Vec<u8>,
    pub server_a: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
pub struct Ticket {
    pub password_hash: Vec<u8>,
    pub encrypted_secret: Vec<u8>,
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
                        Some(emergency_contact_uuid)
                    }
                }
            }
        }
    }
}