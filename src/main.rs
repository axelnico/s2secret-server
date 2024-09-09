use axum::{Router, extract::State, Json, routing::{get, post, delete, put}, Error};
use axum::extract::Path;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
use std::env;
use std::sync::Arc;
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use s2secret_service::Secret;

type AppState = Arc<AppStateInner>;

struct AppStateInner {
    database_pool: PgPool,
}

#[derive(Serialize)]
struct S2SecretError<'a> {
    msg: &'a str
}

#[derive(Serialize)]
struct S2SecretCreateResponse {
    id_secret: Uuid
}

#[derive(Deserialize, Serialize)]
struct NewSecretRequest {
    title: String,
    user_name: Option<String>,
    site: Option<String>,
    notes: Option<String>,
    server_share: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let s2secret_database_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let s2secret_database = PgPoolOptions::new().connect(&s2secret_database_url).await.expect("Cannot connect to s2secret database");

    sqlx::migrate!().run(&s2secret_database).await?;

    let s2secret_state = Arc::new(AppStateInner {database_pool:s2secret_database });

    let s2secret = Router::new()
        .route("/", get(health_check))
        .route("/secrets", get(secrets_descriptive_data).post(add_new_secret))
        .route("/secrets/:secret_id", get(secret_descriptive_data)
                                            .patch(modify_secret)
                                            .delete(delete_secret))
        .route("/secrets/:secret_id/share", get(secret_share))
        .route("/secrets/:secret_id/emergency-contacts",
                                              get(secret_emergency_contacts)
                                                  .post(add_emergency_contact_to_secret))
        .route("/secrets/:secret_id/emergency-contacts/:emergency_contact_id",
                                               delete(remove_emergency_contact_from_secret))
        .route("/secrets/:secret_id/emergency-contacts/:emergency_contact_id/send" ,
                                             post(send_emergency_access_data_to_contact))
        .route("/user", get(user_data))
        .route("/user/emergency-contacts", get(emergency_contacts)
                                                .post(create_emergency_contact))
        .route("/user/emergency-contacts/:emergency_contact_id", put(update_emergency_contact)
                                                                 .delete(delete_emergency_contact))
        .fallback(fallback)
        .with_state(s2secret_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, s2secret).await?;
    Ok(())
}

async fn fallback(uri: Uri) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, format!("No route for {uri}"))
}

async fn health_check() -> &'static str {
    "OK"
}

async fn secrets_descriptive_data(s2secret_state: State<AppState>) -> Json<Vec<Secret>> {
    Json(Secret::descriptive_data_of_all_secrets(&s2secret_state.database_pool).await)
}

async fn secret_descriptive_data(Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>) -> impl IntoResponse {
    let secret_descriptive_data = Secret::descriptive_data_of_secret(&secret_id, &s2secret_state.database_pool).await;
    match secret_descriptive_data {
        Some(secret) => Json(secret).into_response(),
        None => (StatusCode::NOT_FOUND, Json(S2SecretError { msg: "Secret not found"})).into_response()
    }
}

async fn modify_secret(Path(secret_id): Path<Uuid>) -> &'static str {
    "TODO: modify a specific secret"
}
async fn delete_secret(Path(secret_id): Path<Uuid>) -> &'static str {
    "TODO: delete all associated data of a specific secret"
}
async fn secret_share(Path(secret_id): Path<Uuid>) -> &'static str {
    "TODO: return server share of secret"
}
async fn add_new_secret(s2secret_state: State<AppState>, secret_request: Json<NewSecretRequest>) -> impl IntoResponse {
    let new_secret_uuid = Secret::create_new_secret(&secret_request.title,
                              secret_request.user_name.as_ref(),
                              secret_request.site.as_ref(),
                              secret_request.notes.as_ref(),
                              &secret_request.server_share,
                              &s2secret_state.database_pool
    ).await;
    (StatusCode::CREATED, Json(S2SecretCreateResponse { id_secret: new_secret_uuid  }))
}

async fn secret_emergency_contacts(Path(secret_id): Path<Uuid>) -> &'static str {
    "TODO: return emergency contacts associated with a secret"
}

async fn add_emergency_contact_to_secret(Path(secret_id): Path<Uuid>) -> &'static str {
    "TODO: Associate an emergency contact to a secret"
}

async fn remove_emergency_contact_from_secret(Path((secret_id,emergency_contact_id)): Path<(Uuid,Uuid)>)
                                              -> &'static str {
    "TODO: Remove an emergency contact from a secret"
}

async fn send_emergency_access_data_to_contact(Path((secret_id,emergency_contact_id)): Path<(Uuid,Uuid)>)
                                               -> &'static str {
    "TODO: Send required emergency access data to a contact"
}

async fn user_data() -> &'static str {
    "TODO: return user data, including server-key-file"
}

async fn emergency_contacts() -> &'static str {
    "TODO: return all emergency contacts of current user"
}

async fn create_emergency_contact() -> &'static str {
    "TODO: create new emergency contact for current user"
}

async fn update_emergency_contact() -> &'static str {
    "TODO: update the entire information of an emergency contact"
}

async fn delete_emergency_contact() -> &'static str {
    "TODO: delete an emergency contact of current user"
}
