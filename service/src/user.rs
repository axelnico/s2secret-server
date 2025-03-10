use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
#[derive(Deserialize, Serialize)]
pub struct User {
    pub id_user: Uuid,
    pub email: String,
    name: String,
    server_key_file: String
}

impl User {
    pub async fn data(database: &PgPool, id: Uuid) -> Option<Self> {
        sqlx::query_as!(Self, "SELECT id_user, email, name, server_key_file from s2secret_user WHERE id_user = $1", id).fetch_optional(database).await.unwrap()
    }

    pub async fn create_new_user(database: &PgPool, email: &String, name: &String, password_file: &[u8]) -> Uuid {
        let new_user_id = Uuid::new_v4();
        let now = Utc::now().naive_utc();
        let dummy_server_key_file = "dummy server key file";
        sqlx::query!("INSERT INTO s2secret_user(id_user, email, name, server_key_file, created_at, password_file) VALUES ($1, $2, $3, $4, $5, $6)",
                                new_user_id, email, name, dummy_server_key_file ,now, password_file).execute(database).await.unwrap();
        new_user_id
    }

    pub async fn password_file_bytes(database: &PgPool, email: &String) -> Option<Vec<u8>> {
        sqlx::query_scalar!("SELECT password_file from s2secret_user WHERE email = $1", email).fetch_optional(database).await.unwrap()
    }

    pub async fn user_id(database: &PgPool, email: &String) -> Option<Uuid> {
        sqlx::query_scalar!("SELECT id_user from s2secret_user WHERE email = $1", email).fetch_optional(database).await.unwrap()
    }
}