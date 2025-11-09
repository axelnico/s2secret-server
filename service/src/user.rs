use chrono::Utc;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
#[derive(Deserialize, Serialize)]
pub struct User {
    pub id_user: Uuid,
    pub email: String,
    pub name: String,
}

#[derive(Deserialize, Serialize)]
pub struct UserRegistrationData {
    pub password_file: Vec<u8>,
    pub server_auth_setup: Vec<u8>
}

impl User {
    pub async fn data(database: &PgPool, id: &Uuid) -> Option<Self> {
        sqlx::query_as!(Self, "SELECT id_user, email, name from s2secret_user WHERE id_user = $1", id).fetch_optional(database).await.unwrap()
    }

    pub async fn create_new_user(database: &PgPool, email: &String, name: &String, password_file: &[u8], server_auth_setup:&[u8]) -> Uuid {
        let new_user_id = Uuid::new_v4();
        let now = Utc::now().naive_utc();
        sqlx::query!("INSERT INTO s2secret_user(id_user, email, name, created_at, password_file, server_auth_setup) VALUES ($1, $2, $3, $4, $5, $6)",
                                new_user_id, email, name ,now, password_file, server_auth_setup).execute(database).await.unwrap();
        new_user_id
    }

    pub async fn registration_data(database: &PgPool, email: &String) -> Option<UserRegistrationData> {
        sqlx::query_as!(UserRegistrationData, "SELECT password_file, server_auth_setup from s2secret_user WHERE email = $1", email).fetch_optional(database).await.unwrap()
    }

    pub async fn user_id(database: &PgPool, email: &String) -> Option<Uuid> {
        sqlx::query_scalar!("SELECT id_user from s2secret_user WHERE email = $1", email).fetch_optional(database).await.unwrap()
    }
}