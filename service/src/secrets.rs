use base64::{engine::general_purpose, Engine as _ };
use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Secret {
    id_secret: Uuid,
    title: String,
    user_name: Option<String>,
    site: Option<String>,
    notes: Option<String>,
}

impl Secret {

    pub async fn descriptive_data_of_all_secrets(database: &PgPool) -> Vec<Self> {
        sqlx::query_as!(Self, "SELECT id_secret,title,user_name,site,notes from secret").fetch_all(database).await.unwrap()
    }

    pub async fn descriptive_data_of_secret(secret_id: &Uuid, database: &PgPool) -> Option<Self> {
        sqlx::query_as!(Self, "SELECT id_secret,title,user_name,site,notes from secret where id_secret = $1", secret_id).fetch_optional(database).await.unwrap()
    }

    pub async fn create_new_secret(title: &String, user_name: Option<&String>,
                                   site: Option<&String>,
                                   notes: Option<&String>,
                                   server_share: &String,
                                   database: &PgPool) -> Uuid {
        let new_secret_id = Uuid::new_v4();
        let server_share_id = Uuid::new_v4();
        let now = Utc::now().naive_utc();
        sqlx::query!("INSERT INTO secret_share(id_secret_share, server_share, created_at, updated_at) VALUES ($1, $2, $3, $4)",
                                server_share_id, server_share, now, now).execute(database).await.unwrap();
        sqlx::query!("INSERT INTO secret(id_secret, title, user_name, site, notes, share_id) VALUES ($1, $2, $3, $4, $5, $6)",
                                new_secret_id, title, user_name, site, notes, server_share_id).execute(database).await.unwrap();
        new_secret_id
    }
}