use base64::{engine::general_purpose, Engine as _ };
use chrono::{NaiveDateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use sharks::{Share, Sharks};
use validator::{Validate, ValidationErrors};

#[derive(Deserialize, Serialize)]
pub struct Secret {
    id_secret: Uuid,
    pub title: Vec<u8>,
    pub user_name: Option<Vec<u8>>,
    pub site: Option<Vec<u8>>,
    pub notes: Option<Vec<u8>>,
    share_updated_at: Option<NaiveDateTime>,
    next_share_update: Option<NaiveDateTime>,
    proactive_protection: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct ShareRenewal {
    pub share: Vec<u8>,
    updated_at: NaiveDateTime
}

#[derive(Deserialize, Serialize)]
pub struct SecretShare {
    server_share: Vec<u8>,
    created_at: NaiveDateTime,
    updated_at: NaiveDateTime,
}

impl Validate for ProactiveProtection {
    fn validate(&self) -> Result<(), ValidationErrors> {
        Ok(())
    }
}
#[derive(Deserialize, Serialize)]
pub enum ProactiveProtection {
    Medium,
    High,
    Extreme
}
fn proactive_protection_to_string(proactive_protection: ProactiveProtection) -> String {
    match proactive_protection {
        ProactiveProtection::Medium => "Medium".to_string(),
        ProactiveProtection::High => "High".to_string(),
        ProactiveProtection::Extreme => "Extreme".to_string(),
    }
}

impl Secret {

    pub async fn descriptive_data_of_all_secrets_and_user(database: &PgPool, user_id: &Uuid) -> Vec<Self> {
        sqlx::query_as!(Self, r#"SELECT s.id_secret,s.title,s.user_name,s.site,s.notes, ss.updated_at as share_updated_at, (ss.updated_at + pp.protection_interval ) as next_share_update, pp.description as "proactive_protection?"
                                        from secret s
                                        inner join secret_share ss on s.id_secret = ss.id_secret 
                                        left join proactive_protection pp on pp.id_proactive_protection = ss.proactive_protection_id 
                                        where s.user_id = $1"#, user_id).fetch_all(database).await.unwrap()
    }

    pub async fn descriptive_data_of_secret_and_user(secret_id: &Uuid, user_id: &Uuid, database: &PgPool) -> Option<Self> {
        sqlx::query_as!(Self, r#"SELECT s.id_secret,s.title,s.user_name,s.site,s.notes, ss.updated_at as share_updated_at, (ss.updated_at + pp.protection_interval ) as next_share_update, pp.description as "proactive_protection?"
                                        from secret s
                                        inner join secret_share ss on s.id_secret = ss.id_secret 
                                        left join proactive_protection pp on pp.id_proactive_protection = ss.proactive_protection_id 
                                        where s.user_id = $1
                                        and s.id_secret = $2"#, user_id,secret_id).fetch_optional(database).await.unwrap()
    }
    
    pub async fn descriptive_data_of_secret(secret_id: &Uuid, database: &PgPool) -> Option<Self> {
        sqlx::query_as!(Self, r#"SELECT s.id_secret,s.title,s.user_name,s.site,s.notes, ss.updated_at as share_updated_at, (ss.updated_at + pp.protection_interval ) as next_share_update, pp.description as "proactive_protection?"
                                        from secret s
                                        inner join secret_share ss on s.id_secret = ss.id_secret 
                                        left join proactive_protection pp on pp.id_proactive_protection = ss.proactive_protection_id 
                                        where s.id_secret = $1"#, secret_id).fetch_optional(database).await.unwrap()
    }

    pub async fn create_new_secret_for_user(title: &Vec<u8>, user_name: Option<&Vec<u8>>,
                                            site: Option<&Vec<u8>>,
                                            notes: Option<&Vec<u8>>,
                                            server_share: &Vec<u8>,
                                            user_id: &Uuid,
                                            database: &PgPool) -> Self {
        let new_secret_id = Uuid::new_v4();
        let server_share_id = Uuid::new_v4();
        let now = Utc::now().naive_utc();
        let mut transaction = database.begin().await.unwrap();
        sqlx::query!("INSERT INTO secret(id_secret, title, user_name, site, notes, user_id) VALUES ($1, $2, $3, $4, $5, $6)",
                                new_secret_id, title, user_name, site, notes, user_id).execute(&mut *transaction).await.unwrap();
        sqlx::query!("INSERT INTO secret_share(id_secret_share, server_share, created_at, updated_at, id_secret) VALUES ($1, $2, $3, $4, $5)",
                                server_share_id, server_share, now, now, new_secret_id).execute(&mut *transaction).await.unwrap();
        transaction.commit().await.unwrap();
        Self::descriptive_data_of_secret(&new_secret_id,&database).await.unwrap()
    }

    pub async fn partially_modify_secret_for_user(secret_id: &Uuid, user_id: &Uuid, title: Option<&Vec<u8>>, user_name: Option<&Vec<u8>>,
                                                  site: Option<&Vec<u8>>,
                                                  notes: Option<&Vec<u8>>,
                                                  server_share: Option<&Vec<u8>>,
                                                  database: &PgPool) -> Option<Self> {
        let secret = Self::descriptive_data_of_secret_and_user(secret_id, user_id, database).await;
        match secret {
            Some(_) => {
                let mut transaction = database.begin().await.unwrap();
                sqlx::query!("UPDATE secret set title = COALESCE($1,title), user_name = COALESCE($2,user_name), site = COALESCE($3,site), notes = COALESCE($4,notes) where id_secret = $5", title,user_name, site, notes, secret_id).execute(&mut *transaction).await.unwrap();
                sqlx::query!("UPDATE secret_share set server_share = COALESCE($1,server_share) where id_secret = $2", server_share, secret_id).execute(&mut *transaction).await.unwrap();
                transaction.commit().await.unwrap();
                Self::descriptive_data_of_secret(&secret_id,&database).await
            },
            None => None
        }
    }

    pub async fn modify_secret_of_user(secret_id: &Uuid, user_id: &Uuid, title: &Vec<u8>, user_name: Option<&Vec<u8>>,
                                       site: Option<&Vec<u8>>,
                                       notes: Option<&Vec<u8>>,
                                       server_share: &Vec<u8>,
                                       database: &PgPool) -> Option<Self> {
        let secret = Self::descriptive_data_of_secret_and_user(secret_id, user_id, database).await;
        match secret {
            Some(secret) => {
                let mut transaction = database.begin().await.unwrap();
                sqlx::query!("UPDATE secret set title = $1, user_name = $2, site = $3, notes = $4 where id_secret = $5", title,user_name, site, notes, secret_id).execute(&mut *transaction).await.unwrap();
                sqlx::query!("UPDATE secret_share set server_share = $1 where id_secret = $2", server_share, secret_id).execute(&mut *transaction).await.unwrap();
                transaction.commit().await.unwrap();
                Self::descriptive_data_of_secret(&secret_id,&database).await
            },
            None => None
        }
    }

    pub async fn delete_secret_of_user(secret_id: &Uuid, user_id: &Uuid, database: &PgPool) -> Option<Uuid> {
        let secret = Self::descriptive_data_of_secret_and_user(secret_id, user_id, database).await;
        match secret {
            Some(secret) => {
                let mut transaction = database.begin().await.unwrap();
                sqlx::query!("DELETE from secret_share where id_secret = $1", secret_id).execute(&mut *transaction).await.unwrap();
                sqlx::query!("DELETE from emergency_contact_secret_access where id_secret = $1", secret_id).execute(&mut *transaction).await.unwrap();
                sqlx::query!("DELETE from secret where id_secret = $1", secret_id).execute(&mut *transaction).await.unwrap();
                transaction.commit().await.unwrap();
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
    
    pub async fn renew_secret_share(secret_id: &Uuid, user_id: &Uuid, renewal_share_from_client: &Share, database: &PgPool) -> Option<ShareRenewal> {
        let mut transaction = database.begin().await.unwrap();
        let secret_share = Self::secret_share(secret_id,user_id,database).await;
        match secret_share {
            Some(secret_share) => {
                let mut server_share = Share::try_from(secret_share.server_share.as_slice()).ok().unwrap();
                let sharks = Sharks(2);
                let server_renewal_shares: Vec<Share> = sharks.proactive_dealer(&server_share).take(2).collect();
                server_share.renew([renewal_share_from_client, &server_renewal_shares[1]]).ok();
                let new_server_share = sqlx::query!("UPDATE secret_share set server_share = $1 where id_secret = $2 returning updated_at", Vec::from(&server_share), secret_id).fetch_one(&mut *transaction).await.unwrap();
                transaction.commit().await.unwrap();
                Some( ShareRenewal { share: Vec::from(&server_renewal_shares[0]), updated_at: new_server_share.updated_at })
            },
            None => None,
        }
    }
    
    pub async fn enable_proactive_protection(secret_id: &Uuid, user_id: &Uuid, proactive_protection: ProactiveProtection, database: &PgPool) -> Option<Secret> {
        let mut transaction = database.begin().await.unwrap();
        let secret_share = Self::secret_share(secret_id,user_id,database).await;
        match secret_share {
            Some(_) => {
                let proactive_protection = sqlx::query!("SELECT id_proactive_protection from proactive_protection where description = $1",proactive_protection_to_string(proactive_protection)).fetch_one(&mut *transaction).await.unwrap();
                sqlx::query!("UPDATE secret_share set proactive_protection_id = $1 where id_secret = $2",proactive_protection.id_proactive_protection,secret_id).execute(& mut * transaction).await.unwrap();
                transaction.commit().await.unwrap();
                Secret::descriptive_data_of_secret(&secret_id, &database).await
            },
            None => None,
        }
    }

    pub async fn disable_proactive_protection(secret_id: &Uuid, user_id: &Uuid, database: &PgPool) -> Option<(Secret)> {
        let mut transaction = database.begin().await.unwrap();
        let secret_share = Self::secret_share(secret_id,user_id,database).await;
        match secret_share {
            Some(_) => {
                sqlx::query!("UPDATE secret_share set proactive_protection_id = null where id_secret = $1",secret_id).execute(& mut * transaction).await.unwrap();
                transaction.commit().await.unwrap();
                Secret::descriptive_data_of_secret(&secret_id, &database).await
            },
            None => None,
        }
    }
}