use base64::{engine::general_purpose, Engine as _ };
use chrono::{NaiveDateTime, Utc};
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
#[derive(Deserialize, Serialize)]
pub struct SecretShare {
    server_share: String,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl Secret {

    pub async fn descriptive_data_of_all_secrets(database: &PgPool, user_id: &Uuid) -> Vec<Self> {
        sqlx::query_as!(Self, "SELECT id_secret,title,user_name,site,notes from secret where user_id = $1", user_id).fetch_all(database).await.unwrap()
    }

    pub async fn descriptive_data_of_secret(secret_id: &Uuid, user_id: &Uuid, database: &PgPool) -> Option<Self> {
        sqlx::query_as!(Self, "SELECT id_secret,title,user_name,site,notes from secret where user_id = $1 and id_secret = $2", user_id,secret_id).fetch_optional(database).await.unwrap()
    }

    pub async fn create_new_secret(title: &String, user_name: Option<&String>,
                                   site: Option<&String>,
                                   notes: Option<&String>,
                                   server_share: &String,
                                   user_id: &Uuid,
                                   database: &PgPool) -> Uuid {
        let new_secret_id = Uuid::new_v4();
        let server_share_id = Uuid::new_v4();
        let now = Utc::now().naive_utc();
        sqlx::query!("INSERT INTO secret(id_secret, title, user_name, site, notes, user_id) VALUES ($1, $2, $3, $4, $5, $6)",
                                new_secret_id, title, user_name, site, notes, user_id).execute(database).await.unwrap();
        sqlx::query!("INSERT INTO secret_share(id_secret_share, server_share, created_at, updated_at, id_secret) VALUES ($1, $2, $3, $4, $5)",
                                server_share_id, server_share, now, now, new_secret_id).execute(database).await.unwrap();
        new_secret_id
    }

    pub async fn modify_secret(secret_id: &Uuid, user_id: &Uuid,title: Option<&String>, user_name: Option<&String>,
                               site: Option<&String>,
                               notes: Option<&String>,
                               server_share: Option<&String>,
                               database: &PgPool) -> Option<Uuid> {
        let secret = Self::descriptive_data_of_secret(secret_id,user_id,database).await;
        match secret {
            Some(secret) => {
                sqlx::query!("UPDATE secret set title = COALESCE($1,title), user_name = COALESCE($2,user_name), site = COALESCE($3,site), notes = COALESCE($4,notes) where id_secret = $5", title,user_name, site, notes, secret_id).execute(database).await.unwrap();
                sqlx::query!("UPDATE secret_share set server_share = COALESCE($1,server_share) where id_secret = $2", server_share, secret_id).execute(database).await.unwrap();
                Some(secret.id_secret)
            },
            None => None
        }
    }

    pub async fn delete_secret(secret_id: &Uuid, user_id: &Uuid, database: &PgPool) -> Option<Uuid> {
        let secret = Self::descriptive_data_of_secret(secret_id,user_id,database).await;
        match secret {
            Some(secret) => {
                sqlx::query!("DELETE from secret_share where id_secret = $1", secret_id).execute(database).await.unwrap();
                sqlx::query!("DELETE from emergency_contact_secret_access where id_secret = $1", secret_id).execute(database).await.unwrap();
                sqlx::query!("DELETE from secret where id_secret = $1", secret_id).execute(database).await.unwrap();
                Some(secret.id_secret)
            },
            None => None
        }
    }
}

impl SecretShare {

    pub async fn secret_share(secret_id: &Uuid, user_id: &Uuid, database: &PgPool) -> Option<Self> {
        sqlx::query_as!(Self, "SELECT server_share, created_at, updated_at from secret_share sh inner join secret s on s.id_secret = sh.id_secret where s.id_secret = $1 and s.user_id = $2", secret_id, user_id).fetch_optional(database).await.unwrap()
    }
}