use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
#[derive(Deserialize, Serialize)]
pub struct EmergencyContact {
    id_emergency_contact: Uuid,
    email: String,
    description: Option<String>
}

impl EmergencyContact {
    pub async fn emergency_contacts_of_secret(secret_id: &Uuid, user_id: &Uuid, database: &PgPool) -> Vec<Self> {
        sqlx::query_as!(Self, "SELECT ec.id_emergency_contact,ec.email,ec.description from emergency_contact ec \
                                inner join emergency_contact_secret_access eca on ec.id_emergency_contact = eca.id_emergency_contact where eca.id_secret = $1 and ec.user_id = $2",secret_id, user_id)
            .fetch_all(database).await.unwrap()
    }
    pub async fn add_emergency_contact_to_secret(secret_id: &Uuid, emergency_contact_id: &Uuid, user_id: &Uuid, server_ticket: &String, server_v: &String, server_a: &String, database: &PgPool) -> Option<Uuid> {
        let emergency_contact_uuid = sqlx::query_scalar!("SELECT id_emergency_contact from emergency_contact where id_emergency_contact=$1 and user_id=$2",emergency_contact_id, user_id).fetch_optional(database).await.unwrap();
        match emergency_contact_uuid {
            None => None,
            Some(emergency_contact_uuid) => {
                let emergency_contact_secret_access_uuid = sqlx::query_scalar!("SELECT id_emergency_contact from emergency_contact_secret_access where id_emergency_contact=$1 and id_secret=$2",emergency_contact_id,secret_id).fetch_optional(database).await.unwrap();
                match emergency_contact_secret_access_uuid {
                    Some(_) => None, // This means that the emergency contact has already been associated to the secret. Do nothing
                    None => {
                        sqlx::query!("INSERT INTO emergency_contact_secret_access(id_emergency_contact, id_secret, server_ticket, server_v, server_a) VALUES ($1, $2, $3, $4, $5)",
                                emergency_contact_id, secret_id, server_ticket, server_v, server_a).execute(database).await.unwrap();
                        Some(emergency_contact_uuid)
                    }
                }
            }
        }
    }
    pub async fn remove_emergency_contact_from_secret(secret_id: &Uuid, emergency_contact_id: &Uuid, database: &PgPool) {
        sqlx::query!("DELETE from emergency_contact_secret_access where id_emergency_contact = $1 and id_secret = $2",emergency_contact_id,secret_id).execute(database).await.unwrap();
    }
    pub async fn emergency_contacts(database: &PgPool, user_id: &Uuid) -> Vec<Self> {
        sqlx::query_as!(Self, "SELECT id_emergency_contact,email,description from emergency_contact where user_id = $1",user_id).fetch_all(database).await.unwrap()
    }
}