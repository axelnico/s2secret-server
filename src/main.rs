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
use s2secret_service::{EmergencyContact, Secret, SecretShare, User};
use opaque_ke::{CipherSuite, ClientRegistration, ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup};
use opaque_ke::rand::rngs::OsRng;
use argon2::Argon2;
use axum_session::{Session, SessionConfig, SessionLayer, SessionMode, SessionStore};
use axum_session_sqlx::{SessionPgPool, SessionPgSession, SessionPgSessionStore};

// Ciphersuite to be used in the OPAQUE protocol
struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2<'static>;
}

type AppState = Arc<AppStateInner>;

struct AppStateInner {
    database_pool: PgPool,
    opaque_ciphersuite: ServerSetup<DefaultCipherSuite>
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
#[derive(Deserialize, Serialize)]
struct SecretPatchRequest {
    title: Option<String>,
    user_name: Option<String>,
    site: Option<String>,
    notes: Option<String>,
    server_share: Option<String>,
}
#[derive(Deserialize, Serialize)]
struct NewEmergencyContactRequest {
    email: String,
    description: String,
    server_key_file: String,
    server_share: String
}

#[derive(Deserialize)]
struct EmergencyAccessRequest {
    id_emergency_contact: Uuid,
    server_ticket: String,
    server_v: String,
    server_a: String
}

#[derive(Deserialize)]
struct UserRegistrationRequest {
    name: String,
    email: String,
    message: RegistrationRequest<DefaultCipherSuite>
}

#[derive(Deserialize)]
struct UserRegistrationFinishResult {
    name: String,
    email: String,
    message: RegistrationUpload<DefaultCipherSuite>
}

#[derive(Deserialize)]
struct UserLoginRequest {
    email: String,
    message: CredentialRequest<DefaultCipherSuite>
}

#[derive(Deserialize)]
struct UserLoginFinishRequest {
    email: String,
    message: CredentialFinalization<DefaultCipherSuite>
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let s2secret_database_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let s2secret_database = PgPoolOptions::new().connect(&s2secret_database_url).await.expect("Cannot connect to s2secret database");

    sqlx::migrate!().run(&s2secret_database).await?;

    let session_config = SessionConfig::default().with_table_name("auth_sessions").with_session_name("session-id");

    let session_store = SessionPgSessionStore::new(Some(s2secret_database.clone().into()), session_config)
        .await?;

    let mut random_number_generator = OsRng;
    let authentication_server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut random_number_generator);

    let s2secret_state = Arc::new(AppStateInner {database_pool:s2secret_database, opaque_ciphersuite: authentication_server_setup });

    let s2secret = Router::new()
        .route("/", get(health_check))
        .route("/secrets", get(secrets_descriptive_data).post(add_new_secret))
        .route("/secrets/{secret_id}", get(secret_descriptive_data)
                                            .patch(modify_secret)
                                            .delete(delete_secret))
        .route("/secrets/{secret_id}/share", get(secret_share))
        .route("/secrets/{secret_id}/emergency-contacts",
                                              get(secret_emergency_contacts)
                                                  .post(add_emergency_contact_to_secret))
        .route("/secrets/{secret_id}/emergency-contacts/{emergency_contact_id}",
                                               delete(remove_emergency_contact_from_secret))
        .route("/secrets/{secret_id}/emergency-contacts/{emergency_contact_id}/send" ,
                                             post(send_emergency_access_data_to_contact))
        .route("/auth/config",get(opaque_config))
        .route("/auth/user/register", post(user_registration_start))
        .route("/auth/user/register-finalize", post(user_registration_finish))
        .route("/auth/user/login", post(user_login_start))
        .route("/auth/user/login-finalize", post(user_login_finish))
        .route("/auth/user/logout", post(user_logout))
        .route("/user", get(user_data))
        .route("/user/emergency-contacts", get(emergency_contacts)
                                                .post(create_emergency_contact))
        .route("/user/emergency-contacts/{emergency_contact_id}", put(update_emergency_contact)
                                                                 .delete(delete_emergency_contact))
        .fallback(fallback)
        .with_state(s2secret_state)
        .layer(SessionLayer::new(session_store));

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

async fn modify_secret(Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>, secret_update_request: Json<SecretPatchRequest>) -> impl IntoResponse {
    let modified_secret_id = Secret::modify_secret(&secret_id,
                                                   secret_update_request.title.as_ref(),
                                                   secret_update_request.user_name.as_ref(),
                                                   secret_update_request.site.as_ref(),
                                                   secret_update_request.notes.as_ref(),
                                                   secret_update_request.server_share.as_ref(),
                                                   &s2secret_state.database_pool).await;

    match modified_secret_id {
        Some(modified_secret_id) => Json(S2SecretCreateResponse { id_secret: modified_secret_id  }).into_response(),
        None => (StatusCode::NOT_FOUND, Json(S2SecretError { msg: "Secret not found"})).into_response()
    }
}
async fn delete_secret(Path(secret_id): Path<Uuid>,s2secret_state: State<AppState>) -> impl IntoResponse {
    let deleted_secret_id = Secret::delete_secret(&secret_id, &s2secret_state.database_pool).await;
    match deleted_secret_id {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => (StatusCode::NOT_FOUND, Json(S2SecretError { msg: "Secret not found"})).into_response()
    }
}
async fn secret_share(Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>) -> impl IntoResponse {
    let secret_share = SecretShare::secret_share(&secret_id,&s2secret_state.database_pool).await;
    match secret_share {
        Some(secret_share) => Json(secret_share).into_response(),
        None => (StatusCode::NOT_FOUND, Json(S2SecretError { msg: "Secret not found"})).into_response()
    }
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

async fn secret_emergency_contacts(Path(secret_id): Path<Uuid>,s2secret_state: State<AppState>) -> Json<Vec<EmergencyContact>> {
    Json(EmergencyContact::emergency_contacts_of_secret(&secret_id,&s2secret_state.database_pool).await)
}

async fn add_emergency_contact_to_secret(Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>, emergency_access_request: Json<EmergencyAccessRequest>) -> impl IntoResponse {
    let emergency_contact_uuid = EmergencyContact::add_emergency_contact_to_secret(&secret_id,
                                                                                   &emergency_access_request.id_emergency_contact,
                                                                                   &emergency_access_request.server_ticket,
                                                                                   &emergency_access_request.server_v,
                                                                                   &emergency_access_request.server_a,
                                                                                   &s2secret_state.database_pool).await;
    match emergency_contact_uuid {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => (StatusCode::BAD_REQUEST, Json(S2SecretError { msg: "Invalid data provided to add emergency contact to secret"})).into_response()
    }
}

async fn remove_emergency_contact_from_secret(Path((secret_id,emergency_contact_id)): Path<(Uuid,Uuid)>,s2secret_state: State<AppState>)
                                              -> impl IntoResponse {
    EmergencyContact::remove_emergency_contact_from_secret(&secret_id,&emergency_contact_id,&s2secret_state.database_pool).await;
    StatusCode::NO_CONTENT.into_response()
}

async fn send_emergency_access_data_to_contact(Path((secret_id,emergency_contact_id)): Path<(Uuid,Uuid)>)
                                               -> &'static str {
    "TODO: Send required emergency access data to a contact"
}

async fn user_data(s2secret_state: State<AppState>) -> Json<User> {
    Json(User::data(&s2secret_state.database_pool).await)
}

async fn emergency_contacts(s2secret_state: State<AppState>) -> Json<Vec<EmergencyContact>> {
    Json(EmergencyContact::emergency_contacts(&s2secret_state.database_pool).await)
}

async fn create_emergency_contact(s2secret_state: State<AppState>, emergency_contact_request: Json<NewEmergencyContactRequest>) -> impl IntoResponse {
    "TODO: create new emergency contact for current user"
}

async fn update_emergency_contact() -> &'static str {
    "TODO: update the entire information of an emergency contact"
}

async fn delete_emergency_contact() -> &'static str {
    "TODO: delete an emergency contact of current user"
}

async fn user_registration_start(s2secret_state: State<AppState>,session: SessionPgSession, user_init_registration_request: Json<UserRegistrationRequest>) -> impl IntoResponse {
    println!("Init registration {} {}", user_init_registration_request.email, user_init_registration_request.name);
    let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
        &s2secret_state.opaque_ciphersuite,
        user_init_registration_request.message.clone(),
        user_init_registration_request.email.as_bytes(),
    ).unwrap();
    Json(server_registration_start_result.message.serialize())
}

async fn user_registration_finish(s2secret_state: State<AppState>,session: SessionPgSession, user_finish_registration_request: Json<UserRegistrationFinishResult>) -> impl IntoResponse {
    println!("Finalizing registration {} {}", user_finish_registration_request.email, user_finish_registration_request.name);
    let password_file = ServerRegistration::<DefaultCipherSuite>::finish(user_finish_registration_request.message.clone());
    User::create_new_user(&s2secret_state.database_pool, &user_finish_registration_request.email, &user_finish_registration_request.name, &*password_file.serialize()).await;
}
#[axum::debug_handler]
async fn user_login_start(s2secret_state: State<AppState>,session: SessionPgSession, user_login_request: Json<UserLoginRequest>) -> impl IntoResponse {
    let mut server_rng = OsRng;
    let password_file_bytes = User::password_file_bytes(&s2secret_state.database_pool, &user_login_request.email).await;
    let server_login_start_result = ServerLogin::<DefaultCipherSuite>::start(
        &mut server_rng,
        &s2secret_state.opaque_ciphersuite,
        match password_file_bytes {
            Some(password_file_bytes) => Some(ServerRegistration::<DefaultCipherSuite>::deserialize(&password_file_bytes).unwrap()),
            None => None
        },
        user_login_request.message.clone(),
        user_login_request.email.as_bytes(),
        ServerLoginStartParameters::default(),
    ).unwrap();
    session.set("login_start_state", server_login_start_result.state.serialize());
    Json(server_login_start_result.message.serialize())
}

async fn user_login_finish(s2secret_state: State<AppState>,session: SessionPgSession, user_login_request: Json<UserLoginFinishRequest>) -> impl IntoResponse {
    let server_login_state: Vec<u8> = session.get("login_start_state").unwrap();
    println!("Session received {}", session.get_session_id());
    let server_login_state = ServerLogin::<DefaultCipherSuite>::deserialize(&server_login_state).unwrap();
    let server_login_finish_result = server_login_state.finish(user_login_request.message.clone()).unwrap();
    session.set("session_key",server_login_finish_result.session_key);
    StatusCode::OK.into_response()
}

async fn user_logout(s2secret_state: State<AppState>, session: SessionPgSession) -> impl IntoResponse {
    session.clear();
    StatusCode::NO_CONTENT.into_response()
}
async fn opaque_config(s2secret_state: State<AppState>) -> impl IntoResponse {
    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, b"password").unwrap();

    Json(client_registration_start_result.message)
}