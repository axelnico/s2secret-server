use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;
#[derive(Deserialize, Serialize)]
pub struct User {
    id_user: Uuid,
    email: String,
    name: String,
    server_key_file: String
}

impl User {
    pub async fn data(database: &PgPool) -> Self {
        sqlx::query_as!(Self, "SELECT id_user, email, name, server_key_file from s2secret_user").fetch_one(database).await.unwrap()
    }
}