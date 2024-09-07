use base64::{engine::general_purpose, Engine as _ };
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
    pub async fn descriptive_data(database: &PgPool) -> Vec<Self> {
        let database_secrets = sqlx::query!("SELECT * from secret").fetch_all(database).await.unwrap();
        let mut descriptive_data_of_secrets = Vec::new();
        for secret in database_secrets {
            descriptive_data_of_secrets.push( Self {
                id_secret: secret.id_secret,
                title: general_purpose::STANDARD.encode(&secret.title),
                user_name: match &secret.user_name {
                    Some(user_name) => Some(general_purpose::STANDARD.encode(user_name)),
                    None => None
                },
                site: match &secret.site {
                    Some(site) => Some(general_purpose::STANDARD.encode(site)),
                    None => None
                },
                notes: match &secret.notes {
                    Some(notes) => Some(general_purpose::STANDARD.encode(notes)),
                    None => None
                },
            })
        }
        descriptive_data_of_secrets
    }
}