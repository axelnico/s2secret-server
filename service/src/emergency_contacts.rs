use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
#[derive(Deserialize, Serialize)]
pub struct EmergencyContact {
    id_emergency_contact: Uuid,
    email: String,
    description: Option<String>,
    pub server_key_file : Vec<u8>,
    server_share: Vec<u8>,
}

impl EmergencyContact {
    
    pub async fn add_emergency_contact_for_user(email: &String, description: Option<&String>, server_key_file: &Vec<u8>, server_share: &Vec<u8> ,user_id: &Uuid, database: &PgPool) -> Uuid {
        let new_emergency_contact_id = Uuid::new_v4();
        sqlx::query!("INSERT INTO emergency_contact(id_emergency_contact, email, description, server_key_file, server_share, user_id) VALUES ($1,$2,$3,$4,$5,$6)",new_emergency_contact_id, email, description, server_key_file, server_share, user_id ).execute(database).await.unwrap();
        new_emergency_contact_id
    }
    
    pub async fn emergency_contacts_of_secret(secret_id: &Uuid, user_id: &Uuid, database: &PgPool) -> Vec<Self> {
        sqlx::query_as!(Self, "SELECT ec.id_emergency_contact,ec.email,ec.description, ec.server_key_file, ec.server_share from emergency_contact ec \
                                inner join emergency_contact_secret_access eca on ec.id_emergency_contact = eca.id_emergency_contact where eca.id_secret = $1 and ec.user_id = $2",secret_id, user_id)
            .fetch_all(database).await.unwrap()
    }
    
    pub async fn remove_emergency_contact_from_secret(secret_id: &Uuid, emergency_contact_id: &Uuid, database: &PgPool) {
        sqlx::query!("DELETE from emergency_contact_secret_access where id_emergency_contact = $1 and id_secret = $2",emergency_contact_id,secret_id).execute(database).await.unwrap();
    }
    pub async fn emergency_contacts(database: &PgPool, user_id: &Uuid) -> Vec<Self> {
        sqlx::query_as!(Self, "SELECT id_emergency_contact,email,description, server_key_file, server_share from emergency_contact where user_id = $1",user_id).fetch_all(database).await.unwrap()
    }
    
    pub async fn emergency_contact_of_user(emergency_contact_id: &Uuid, user_id: &Uuid ,database: &PgPool) -> Option<Self> {
        sqlx::query_as!(Self, "SELECT id_emergency_contact,email,description, server_key_file, server_share from emergency_contact where id_emergency_contact = $1 and user_id = $2",emergency_contact_id, user_id).fetch_optional(database).await.unwrap()
    }
    
    pub async fn emergency_contact_data(emergency_contact_id: &Uuid,database: &PgPool) -> Option<Self> {
        sqlx::query_as!(Self, "SELECT id_emergency_contact,email,description, server_key_file, server_share from emergency_contact where id_emergency_contact = $1",emergency_contact_id).fetch_optional(database).await.unwrap()
    }
    
    pub async fn delete_emergency_contact(emergency_contact_id: &Uuid, user_id: &Uuid, database: &PgPool) -> Option<Uuid> {
        let emergency_contact = Self::emergency_contact_of_user(emergency_contact_id, user_id, database).await;
        match emergency_contact            {
            Some(emergency_contact) => {
                let mut transaction = database.begin().await.unwrap();
                sqlx::query!("DELETE from emergency_contact_secret_access where id_emergency_contact = $1", emergency_contact_id).execute(&mut *transaction).await.unwrap();
                sqlx::query!("DELETE from emergency_contact where id_emergency_contact = $1", emergency_contact_id).execute(&mut *transaction).await.unwrap();
                transaction.commit().await.unwrap();
                Some(emergency_contact.id_emergency_contact)
            },
            None => None
        }
    }
}