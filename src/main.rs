use axum::{Router, extract::State, Json, routing::{get, post, delete, put}, Error};
use axum::extract::{FromRequest, Path};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;
use std::env;
use std::sync::Arc;
use aes_gcm::{AeadCore, Aes256Gcm, Key, KeyInit, Nonce};
use aes_gcm::aead::Aead;
use aes_gcm::aead::consts::U12;
use axum::http::{StatusCode, Uri};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use s2secret_service::{EmergencyContact, EmergencyContactSecretAccess, ProactiveProtection, Secret, SecretShare, ShareRenewal, Ticket, User};
use opaque_ke::{CipherSuite, ClientRegistration, ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest, Identifiers, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup};
use opaque_ke::rand::rngs::OsRng;
use argon2::Argon2;
use async_trait::async_trait;
use axum::body::Bytes;
use axum_session::{DatabasePool, ReadOnlySession, Session, SessionConfig, SessionLayer, SessionMode, SessionStore};
use axum_session_sqlx::{SessionPgPool, SessionPgSession, SessionPgSessionStore};
use axum::extract::Request;
use axum::http::header::CONTENT_TYPE;
use axum::middleware::Next;
use axum::response::Response;
use axum_session_auth::{AuthConfig, AuthSession, AuthSessionLayer, Authentication};
use coset::{AsCborValue, CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, HeaderBuilder};
use sharks::{Share, Sharks};
use hmac_sha512::HMAC;
use sqlx::types::chrono::NaiveDateTime;
use bincode::{config, Decode, Encode};
use lettre::{Address, Message, SmtpTransport, Transport};
use lettre::message::{Mailbox, MultiPart, SinglePart};
use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use rand::distr::Alphanumeric;
use rand::Rng;

// Ciphersuite to be used in the OPAQUE protocol
struct DefaultCipherSuite;

impl CipherSuite for DefaultCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeGroup = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::key_exchange::tripledh::TripleDh;
    type Ksf = Argon2<'static>;
}

fn decrypt_using_nonce(key: &[u8], ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>, ()> {
    let key = Key::<Aes256Gcm>::from_slice(&key[..32]);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&nonce[..12]);
    cipher.decrypt(nonce,ciphertext).map_err(|_| ())
}

// Custom CBOR extractor
pub struct Cbor<T>(pub T);

//#[async_trait]
impl<T, S> FromRequest<S> for Cbor<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request(req: axum::extract::Request, state: &S) -> Result<Self, Self::Rejection> {
        let auth_session = req.extensions().get::<AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>>().cloned();
        let bytes = Bytes::from_request(req, state).await
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        match auth_session
        {
            None => {
                let value = ciborium::de::from_reader(bytes.as_ref())
                    .map_err(|_| StatusCode::BAD_REQUEST)?;
                Ok(Cbor(value))
            },
            Some(auth_session) => {
                if auth_session.is_authenticated() {
                    let encryption_key: Vec<u8> =  auth_session.session.get("session_key").ok_or(StatusCode::UNAUTHORIZED)?;
                    let cose_message = CoseEncrypt0::from_slice(bytes.as_ref()).map_err(|_| StatusCode::BAD_REQUEST)?;
                    let nonce = cose_message.unprotected.iv;
                    let cbor_encrypted_payload = cose_message.ciphertext.unwrap_or_default();
                    let decrypted_request_content    = decrypt_using_nonce(&encryption_key,&cbor_encrypted_payload,&nonce).map_err(|_| StatusCode::BAD_REQUEST)?;
                    let value = ciborium::de::from_reader(Bytes::from(decrypted_request_content).as_ref())
                        .map_err(|_| StatusCode::BAD_REQUEST)?;
                    Ok(Cbor(value))
                } else {
                    let value = ciborium::de::from_reader(bytes.as_ref())
                        .map_err(|_| StatusCode::BAD_REQUEST)?;
                    Ok(Cbor(value))
                }
            }
        }
    }
}

impl<T> IntoResponse for Cbor<T>
where
    T: Serialize,
{
    fn into_response(self) -> Response {
        let mut buffer = Vec::new();
        match ciborium::ser::into_writer(&self.0, &mut buffer) {
            Ok(_) => (
                [(CONTENT_TYPE, "application/cbor")],
                buffer
            ).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
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
struct S2SecretUpsertResponse {
    id_secret: Uuid
}

#[derive(Serialize)]
struct EmergencyContactUpsertResponse {
    id_emergency_contact: Uuid
}

#[derive(Serialize)]
struct S2SecretUserUpsertResponse {
    id_user: Uuid
}

#[derive(Debug,Deserialize, Serialize)]
struct SecretUpsertRequest {
    title: Vec<u8>,
    user_name: Option<Vec<u8>>,
    site: Option<Vec<u8>>,
    notes: Option<Vec<u8>>,
    server_share: Vec<u8>,
}
#[derive(Deserialize, Serialize)]
struct SecretPatchRequest {
    title: Option<Vec<u8>>,
    user_name: Option<Vec<u8>>,
    site: Option<Vec<u8>>,
    notes: Option<Vec<u8>>,
    server_share: Option<Vec<u8>>,
}
#[derive(Deserialize, Serialize)]
struct NewEmergencyContactRequest {
    email: String,
    description: Option<String>,
    server_key_file: Vec<u8>,
    server_share: Vec<u8>
}

#[derive(Deserialize, Serialize)]
struct OneTimeSecretCodeRequest {
    email: String,
    secret_code: String,
}

#[derive(Deserialize)]
struct EmergencyAccessRequest {
    id_emergency_contact: Uuid,
    server_ticket: Vec<u8>,
    server_v: Vec<u8>,
    server_a: Vec<u8>
}

#[derive(Deserialize)]
struct EmergencyAccessClientDataRequest {
    encrypted_data_encryption_key: Vec<u8>,
    encrypted_ticket_share: Vec<u8>,
    encrypted_v_share: Vec<u8>,
    encrypted_a_share: Vec<u8>,
    encrypted_a : Vec<u8>
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
    client_identifier: Uuid,
    email: String,
    message: CredentialRequest<DefaultCipherSuite>
}

#[derive(Deserialize)]
struct UserLoginFinishRequest {
    email: String,
    message: CredentialFinalization<DefaultCipherSuite>
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub id: Uuid,
    pub username: String,
    pub anonymous: bool,
}

impl Default for AuthUser {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            anonymous: true,
            username: "guest".into(),
        }
    }
}
#[async_trait]
impl Authentication<AuthUser, Uuid, PgPool> for AuthUser {
    async fn load_user(userid: Uuid, pool: Option<&PgPool>) -> Result<AuthUser, anyhow::Error> {
        let pool = pool.unwrap();

        let user_data = User::data(pool, &userid).await;

        match user_data {
            Some(user) => Ok(AuthUser {
                id: user.id_user,
                username: user.email,
                anonymous: false,
            }),
            None => Err(anyhow::anyhow!("User not found"))
        }
    }

    fn is_authenticated(&self) -> bool {
        !self.anonymous
    }

    fn is_active(&self) -> bool {
        !self.anonymous
    }

    fn is_anonymous(&self) -> bool {
        self.anonymous
    }
}

fn encrypt_with_nonce(key: &[u8], plaintext: &[u8], nonce: Nonce<U12>) -> Result<Vec<u8>, ()> {
    let key = Key::<Aes256Gcm>::from_slice(&key[..32]);
    let cipher = Aes256Gcm::new(&key);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).map_err(|_| ())?;
    Ok(ciphertext)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    let s2secret_database_url = env::var("DATABASE_URL").expect("DATABASE_URL is not set in .env file");
    let s2secret_database = PgPoolOptions::new().connect(&s2secret_database_url).await.expect("Cannot connect to s2secret database");

    sqlx::migrate!().run(&s2secret_database).await?;

    let session_config = SessionConfig::default().with_table_name("auth_sessions").with_session_name("session-id").with_mode(SessionMode::Persistent);
    let manual_session_config = SessionConfig::default().with_table_name("auth_sessions").with_session_name("session-id").with_mode(SessionMode::Manual);


    let auth_config = AuthConfig::<Uuid>::default().with_anonymous_user_id(Some(Uuid::new_v4()));

    let protect_routes_auth_config = AuthConfig::<Uuid>::default().with_anonymous_user_id(None);

    let session_store = SessionPgSessionStore::new(Some(s2secret_database.clone().into()), session_config)
        .await?;

    let protected_session_store = SessionPgSessionStore::new(Some(s2secret_database.clone().into()), manual_session_config)
        .await?;

    let mut random_number_generator = OsRng;
    let authentication_server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut random_number_generator);

    let s2secret_state = Arc::new(AppStateInner {database_pool:s2secret_database.clone(), opaque_ciphersuite: authentication_server_setup });

    let public_routes = Router::new()
        .route("/config",get(opaque_config))
        .layer(
            AuthSessionLayer::<AuthUser, Uuid, SessionPgPool, PgPool>::new(Some(s2secret_database.clone()))
                .with_config(protect_routes_auth_config.clone()),
        )
        .layer(SessionLayer::new(protected_session_store.clone()));

    let anonymous_routes = Router::new()
        .route("/user/register", post(user_registration_start))
        .route("/user/login", post(user_login_start))
        .route("/user/register-finalize", post(user_registration_finish))
        .route("/user/login-finalize", post(user_login_finish))
        .route("/user/2fa", post(user_login_2fa))
        .route("/emergency-contacts/{emergency_contact_id}/secrets/{secret_id}", post(emergency_access))
        .layer(
            AuthSessionLayer::<AuthUser, Uuid, SessionPgPool, PgPool>::new(Some(s2secret_database.clone()))
                .with_config(auth_config.clone()),
        )
        .layer(SessionLayer::new(session_store));


    let protected_routes = Router::new()
        .route("/secrets", get(secrets_descriptive_data).post(add_new_secret))
        .route("/secrets/{secret_id}", get(secret_descriptive_data)
            .patch(partially_modify_secret)
            .put(modify_secret)
            .delete(delete_secret))
        .route("/secrets/{secret_id}/share", get(secret_share))
        .route("/secrets/{secret_id}/enable-proactive-protection", post(enable_proactive_protection))
        .route("/secrets/{secret_id}/disable-proactive-protection", post(disable_proactive_protection))
        .route("/secrets/{secret_id}/renew-share", post(secret_share_renewal))
        .route("/secrets/{secret_id}/emergency-contacts",
               get(secret_emergency_contacts)
                   .post(add_emergency_contact_to_secret))
        .route("/secrets/{secret_id}/emergency-contacts/{emergency_contact_id}",
               delete(remove_emergency_contact_from_secret))
        .route("/secrets/{secret_id}/emergency-contacts/{emergency_contact_id}/send" ,
               post(send_emergency_access_data_to_contact))
        .route("/user", get(user_data))
        .route("/user/emergency-contacts", get(emergency_contacts)
            .post(create_emergency_contact))
        .route("/user/emergency-contacts/{emergency_contact_id}", put(update_emergency_contact)
            .delete(delete_emergency_contact))
        .route("/auth/user/logout", post(user_logout))
        .layer(axum::middleware::from_fn(auth_middleware))
        .layer(
            AuthSessionLayer::<AuthUser, Uuid, SessionPgPool, PgPool>::new(Some(s2secret_database))
                .with_config(protect_routes_auth_config),
        )
        .layer(SessionLayer::new(protected_session_store));

    let s2secret = Router::new()
        .nest("/auth",public_routes)
        .nest("/auth", anonymous_routes)
        .merge(protected_routes)
        .route("/", get(health_check))
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

async fn secrets_descriptive_data(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, s2secret_state: State<AppState>) -> Cbor<Vec<Secret>> {
    Cbor(Secret::descriptive_data_of_all_secrets_and_user(&s2secret_state.database_pool, &auth.id).await)
}

async fn secret_descriptive_data(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>) -> impl IntoResponse {
    let secret_descriptive_data = Secret::descriptive_data_of_secret_and_user(&secret_id, &auth.id, &s2secret_state.database_pool).await;
    match secret_descriptive_data {
        Some(secret) => Cbor(secret).into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}

async fn partially_modify_secret(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>, secret_update_request: Cbor<SecretPatchRequest>) -> impl IntoResponse {
    let modified_secret = Secret::partially_modify_secret_for_user(&secret_id,
                                                                      &auth.id,
                                                                      secret_update_request.0.title.as_ref(),
                                                                      secret_update_request.0.user_name.as_ref(),
                                                                      secret_update_request.0.site.as_ref(),
                                                                      secret_update_request.0.notes.as_ref(),
                                                                      secret_update_request.0.server_share.as_ref(),
                                                                      &s2secret_state.database_pool).await;

    match modified_secret {
        Some(modified_secret) => Cbor(modified_secret).into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}
async fn delete_secret(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path(secret_id): Path<Uuid>,s2secret_state: State<AppState>) -> impl IntoResponse {
    let deleted_secret_id = Secret::delete_secret_of_user(&secret_id, &auth.id, &s2secret_state.database_pool).await;
    match deleted_secret_id {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}
async fn secret_share(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>) -> impl IntoResponse {
    let secret_share = SecretShare::secret_share(&secret_id,&auth.id, &s2secret_state.database_pool).await;
    match secret_share {
        Some(secret_share) => Cbor(secret_share).into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}

async fn secret_share_renewal(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>, renewal_share: Cbor<ShareRenewal>) -> impl IntoResponse {
    let client_share_renewal = SecretShare::renew_secret_share(&secret_id,&auth.id, &Share::try_from(renewal_share.0.share.as_slice()).ok().unwrap(),&s2secret_state.database_pool).await;
    match client_share_renewal {
        Some(client_share_renewal) => Cbor(client_share_renewal).into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}

async fn enable_proactive_protection(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>, requested_protection: Cbor<ProactiveProtection>) -> impl IntoResponse {
    let modified_secret = SecretShare::enable_proactive_protection(&secret_id,&auth.id,requested_protection.0,&s2secret_state.database_pool).await;
    match modified_secret {
        Some(modified_secret) =>Cbor(modified_secret).into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}

async fn disable_proactive_protection(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>) -> impl IntoResponse {
    let modified_secret = SecretShare::disable_proactive_protection(&secret_id,&auth.id,&s2secret_state.database_pool).await;
    match modified_secret {
        Some(modified_secret) =>Cbor(modified_secret).into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}

async fn add_new_secret(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, s2secret_state: State<AppState>, secret_request: Cbor<SecretUpsertRequest>) -> impl IntoResponse {
    let new_secret = Secret::create_new_secret_for_user(&secret_request.0.title,
                                                             secret_request.0.user_name.as_ref(),
                                                             secret_request.0.site.as_ref(),
                                                             secret_request.0.notes.as_ref(),
                                                             &secret_request.0.server_share,
                                                             &auth.id,
                                                             &s2secret_state.database_pool
    ).await;
    (StatusCode::CREATED, Cbor(new_secret))
}

async fn modify_secret(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, s2secret_state: State<AppState>,Path(secret_id): Path<Uuid>, secret_request: Cbor<SecretUpsertRequest>) -> impl IntoResponse {
    let modified_secret = Secret::modify_secret_of_user(&secret_id,
                                                           &auth.id,
                                                           secret_request.0.title.as_ref(),
                                                           secret_request.0.user_name.as_ref(),
                                                           secret_request.0.site.as_ref(),
                                                           secret_request.0.notes.as_ref(),
                                                           secret_request.0.server_share.as_ref(),
                                                           &s2secret_state.database_pool).await;

    match modified_secret {
        Some(modified_secret) => Cbor(modified_secret).into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}

async fn secret_emergency_contacts(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>,Path(secret_id): Path<Uuid>,s2secret_state: State<AppState>) -> Cbor<Vec<EmergencyContact>> {
    Cbor(EmergencyContact::emergency_contacts_of_secret(&secret_id,&auth.id,&s2secret_state.database_pool).await)
}

async fn add_emergency_contact_to_secret(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>,Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>, emergency_access_request: Cbor<EmergencyAccessRequest>) -> impl IntoResponse {
    let emergency_contact_uuid = EmergencyContactSecretAccess::add_emergency_contact_to_secret(&secret_id,
                                                                                   &emergency_access_request.0.id_emergency_contact,
                                                                                   &auth.id,
                                                                                   &emergency_access_request.0.server_ticket,
                                                                                   &emergency_access_request.0.server_v,
                                                                                   &emergency_access_request.0.server_a,
                                                                                   &s2secret_state.database_pool).await;
    match emergency_contact_uuid {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => (StatusCode::BAD_REQUEST, Cbor(S2SecretError { msg: "Invalid data provided to add emergency contact to secret"})).into_response()
    }
}

async fn remove_emergency_contact_from_secret(Path((secret_id,emergency_contact_id)): Path<(Uuid,Uuid)>,s2secret_state: State<AppState>)
                                              -> impl IntoResponse {
    EmergencyContact::remove_emergency_contact_from_secret(&secret_id,&emergency_contact_id,&s2secret_state.database_pool).await;
    StatusCode::NO_CONTENT.into_response()
}

async fn send_emergency_access_data_to_contact(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path((secret_id,emergency_contact_id)): Path<(Uuid,Uuid)>,s2secret_state: State<AppState>, emergency_data_access_to_be_sent: Cbor<EmergencyAccessClientDataRequest>)
                                               -> impl IntoResponse {
    EmergencyContactSecretAccess::send_emergency_access_data_to_emergency_contact(&secret_id,
                                                                                  &emergency_contact_id,
                                                                                  &auth.id,
                                                                                  emergency_data_access_to_be_sent.0.encrypted_data_encryption_key,
                                                                                  emergency_data_access_to_be_sent.0.encrypted_ticket_share,
                                                                                  emergency_data_access_to_be_sent.0.encrypted_v_share,
                                                                                  emergency_data_access_to_be_sent.0.encrypted_a_share,
                                                                                  emergency_data_access_to_be_sent.0.encrypted_a,
                                                                                  &s2secret_state.database_pool).await;
    StatusCode::NO_CONTENT.into_response()
}

async fn user_data(s2secret_state: State<AppState>, auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>) -> impl IntoResponse {
    Cbor(User::data(&s2secret_state.database_pool,&auth.id).await)
}

async fn emergency_contacts(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>,s2secret_state: State<AppState>) -> Cbor<Vec<EmergencyContact>> {
    Cbor(EmergencyContact::emergency_contacts(&s2secret_state.database_pool,&auth.id).await)
}

async fn create_emergency_contact(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, s2secret_state: State<AppState>, emergency_contact_request: Cbor<NewEmergencyContactRequest>) -> impl IntoResponse {
    let new_emergency_contact = EmergencyContact::add_emergency_contact_for_user(&emergency_contact_request.0.email,
                                                             emergency_contact_request.0.description.as_ref(), 
                                                                                      &emergency_contact_request.0.server_key_file, 
                                                                                      &emergency_contact_request.0.server_share,
                                                             &auth.id,
                                                             &s2secret_state.database_pool
    ).await;
    (StatusCode::CREATED, Cbor(new_emergency_contact))
}

async fn update_emergency_contact() -> &'static str {
    "TODO: update the entire information of an emergency contact"
}

async fn delete_emergency_contact(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path(emergency_contact_id): Path<Uuid>,s2secret_state: State<AppState>) -> impl IntoResponse {
    let deleted_emergency_contact_id = EmergencyContact::delete_emergency_contact(&emergency_contact_id, &auth.id, &s2secret_state.database_pool).await;
    match deleted_emergency_contact_id {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Emergency contact not found"})).into_response()
    }
}

async fn user_registration_start(s2secret_state: State<AppState>,session: SessionPgSession, user_init_registration_request: Cbor<UserRegistrationRequest>) -> impl IntoResponse {
    let server_registration_start_result = ServerRegistration::<DefaultCipherSuite>::start(
        &s2secret_state.opaque_ciphersuite,
        user_init_registration_request.0.message.clone(),
        user_init_registration_request.0.email.as_bytes(),
    ).unwrap();
    Cbor(server_registration_start_result.message.serialize())
}

async fn user_registration_finish(s2secret_state: State<AppState>,session: SessionPgSession, user_finish_registration_request: Cbor<UserRegistrationFinishResult>) -> impl IntoResponse {
    let password_file = ServerRegistration::<DefaultCipherSuite>::finish(user_finish_registration_request.0.message.clone());
    let user_created_id = User::create_new_user(&s2secret_state.database_pool, &user_finish_registration_request.0.email, &user_finish_registration_request.0.name, &*password_file.serialize(), &*s2secret_state.opaque_ciphersuite.serialize()).await;
    (StatusCode::CREATED, Cbor(S2SecretUserUpsertResponse { id_user: user_created_id })).into_response()
}
#[axum::debug_handler]
async fn user_login_start(s2secret_state: State<AppState>, auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, user_login_request: Cbor<UserLoginRequest>) -> impl IntoResponse {
    let mut server_rng = OsRng;
    let mut password_file: Option<ServerRegistration<DefaultCipherSuite>> = None;
    let mut server_setup = s2secret_state.opaque_ciphersuite.clone();
    let user_registration_data = User::registration_data(&s2secret_state.database_pool, &user_login_request.0.email).await;
    if let Some(user_registration_data) = user_registration_data {
        password_file = Some(ServerRegistration::<DefaultCipherSuite>::deserialize(&user_registration_data.password_file).unwrap());
        server_setup = ServerSetup::<DefaultCipherSuite>::deserialize(&user_registration_data.server_auth_setup).unwrap();
    }
    let server_login_start_result = ServerLogin::<DefaultCipherSuite>::start(
        &mut server_rng,
        &server_setup,
        password_file,
        user_login_request.0.message.clone(),
        user_login_request.0.email.as_bytes(),
        ServerLoginStartParameters {
            context: None,
            identifiers: Identifiers {
                client: Some(user_login_request.0.client_identifier.as_bytes()),
                server: None
            }
        },
    ).unwrap();
    auth.session.set("login_start_state", server_login_start_result.state.serialize());
    Cbor(server_login_start_result.message.serialize())
}

fn one_time_secret_code() -> String {
    rand::rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}

async fn user_login_finish(s2secret_state: State<AppState>, auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, user_login_request: Cbor<UserLoginFinishRequest>) -> impl IntoResponse {
    let server_login_state: Vec<u8> = auth.session.get("login_start_state").unwrap();
    let server_login_state = ServerLogin::<DefaultCipherSuite>::deserialize(&server_login_state).unwrap();
    let server_login_finish_result = server_login_state.finish(user_login_request.0.message.clone()).map_err(|_| StatusCode::UNAUTHORIZED.into_response()).unwrap();
    auth.session.set("session_key",server_login_finish_result.session_key);
    let email_from = env::var("EMAIL_FROM").expect("EMAIL_FROM is not set in .env file");
    let smtp_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME is not set in .env file");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set in .env file");
    let email_from = Address::try_from(email_from).unwrap();
    let email_to = Address::try_from(String::from("s2secret.test@gmail.com")).unwrap();
    let one_time_secret_code = one_time_secret_code();
    let email = Message::builder()
        .from(Mailbox::new(None,email_from))
        .to(Mailbox::new(None, email_to))
        .subject("S2Secret - One Time Secret Code")
        .header(ContentType::TEXT_PLAIN)
        .body(one_time_secret_code.clone())
        .unwrap();

    let creds = Credentials::new(smtp_username, smtp_password);

    // Open a remote connection to gmail
    let mailer = SmtpTransport::relay("smtp.gmail.com")
        .unwrap()
        .credentials(creds)
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => println!("Email sent successfully!"),
        Err(e) => panic!("Could not send email: {e:?}"),
    }
    
    auth.session.set("one_time_secret_code", one_time_secret_code);
    (StatusCode::OK).into_response()
}

async fn user_login_2fa(s2secret_state: State<AppState>, auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, secret_code_request: Cbor<OneTimeSecretCodeRequest>) -> impl IntoResponse {
    let logged_in_user_id = User::user_id(&s2secret_state.database_pool,&secret_code_request.0.email).await.ok_or_else(|| StatusCode::UNAUTHORIZED.into_response()).unwrap();
    let one_time_secret_code: String = auth.session.get_remove("one_time_secret_code").ok_or_else(|| StatusCode::UNAUTHORIZED.into_response()).unwrap();
    if one_time_secret_code != secret_code_request.0.secret_code {
        StatusCode::UNAUTHORIZED.into_response()
    } else {
        auth.session.renew();
        auth.login_user(logged_in_user_id);
        (StatusCode::OK).into_response()
    }
}

pub async fn auth_middleware(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, request: Request,next: Next) -> Result<Response, StatusCode> {
    if auth.is_authenticated() {
        auth.session.set_store(true);
        if auth.session.get::<String>("one_time_secret_code").is_some() {
            return Err(StatusCode::UNAUTHORIZED);
        }
        let encryption_key: Vec<u8> =  auth.session.get("session_key").ok_or(StatusCode::UNAUTHORIZED)?;
        let response = next.run(request).await;
        let (parts, body) = response.into_parts();
        let body_bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cose_protected_header = HeaderBuilder::new().algorithm(coset::iana::Algorithm::A256GCM).build();
        let cose_unprotected_header = HeaderBuilder::new().content_type(String::from("application/cose")).iv(nonce.to_vec()).build();
        let encrypted_body = CoseEncrypt0Builder::new()
            .protected(cose_protected_header)
            .unprotected(cose_unprotected_header)
            .ciphertext(encrypt_with_nonce(&encryption_key,&body_bytes, nonce).unwrap_or_default())
            .build();
        Ok(Response::from_parts(parts, axum::body::Body::from(encrypted_body.to_vec().unwrap_or_default())))
    }
    else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

async fn user_logout(s2secret_state: State<AppState>, auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>) -> impl IntoResponse {
    auth.session.clear();
    auth.logout_user();
    // TODO: set session store to false
    StatusCode::NO_CONTENT.into_response()
}
async fn opaque_config(s2secret_state: State<AppState>) -> impl IntoResponse {
    let mut client_rng = OsRng;
    let client_registration_start_result =
        ClientRegistration::<DefaultCipherSuite>::start(&mut client_rng, b"password").unwrap();

    Cbor(client_registration_start_result.message)
}

#[derive(Debug,Deserialize, Serialize)]
struct EmergencyContactSecretAccessRequest {
    password_hash: String,
    //one_time_pad: Vec<u8>, TODO: sending the one time pad in clear does not add any protection. Should be encrypted with server public key
    contact_prover_mac: Vec<u8>,
    contact_ticket_share: Vec<u8>,
    contact_prover_mac_share: Vec<u8>,
}

#[derive(Debug,Deserialize, Serialize)]
struct EmergencyContactSecretAccessResponse {
    title: Vec<u8>,
    encrypted_secret: Vec<u8>,
    user_name: Option<Vec<u8>>,
    site: Option<Vec<u8>>,
    notes: Option<Vec<u8>>,
    server_key_file: Vec<u8>,
    server_v: Vec<u8>
}

async fn emergency_access(s2secret_state: State<AppState>,Path((emergency_contact_id,secret_id)): Path<(Uuid,Uuid)>, emergency_access_request: Cbor<EmergencyContactSecretAccessRequest>) -> impl IntoResponse {
    let emergency_contact_secret_access_data = EmergencyContactSecretAccess::emergency_access_for_contact_and_secret(&secret_id,&emergency_contact_id,&s2secret_state.database_pool).await;
    match emergency_contact_secret_access_data {
        Some(emergency_contact_secret_access_data) => {
            let sharks = Sharks(2);
            let server_ticket_share = Share::try_from(emergency_contact_secret_access_data.server_ticket.as_slice()).ok().unwrap();
            let contact_ticket_share = Share::try_from(emergency_access_request.0.contact_ticket_share.as_slice()).ok().unwrap();
            let ticket = sharks.recover([&server_ticket_share,&contact_ticket_share]).ok().unwrap();
            let config = config::standard();
            let (ticket, length) : (Ticket, usize) = bincode::decode_from_slice(&ticket,config).unwrap();
            // TODO: if ticket cannot be recovered return error
            let contact_prover_mac_share = Share::try_from(emergency_access_request.0.contact_prover_mac_share.as_slice()).ok().unwrap();
            let server_mac_share = Share::try_from(emergency_contact_secret_access_data.server_a.as_slice()).ok().unwrap();
            let recovered_mac = sharks.recover([&contact_prover_mac_share,&server_mac_share]).ok().unwrap();
            let is_valid = HMAC::verify([emergency_access_request.0.password_hash.as_bytes(),emergency_access_request.0.contact_ticket_share.as_slice()].concat(), recovered_mac, <&[u8; 64]>::try_from(emergency_access_request.0.contact_prover_mac.as_slice()).unwrap());
            if !is_valid {
                return (StatusCode::UNAUTHORIZED).into_response();
            }
            if emergency_access_request.0.password_hash != ticket.password_hash {
                // TODO: use a counter increment to prevent online brute force attack to password
                // TODO: also use hashing server side, as client side hashing alone is not secure. Not too critical as server hash is not stored directly 
                return (StatusCode::UNAUTHORIZED).into_response();
            }
            // TODO: send a one time code to emergency contact email
            let secret = Secret::descriptive_data_of_secret(&secret_id,&s2secret_state.database_pool).await.unwrap();
            let emergency_contact_data = EmergencyContact::emergency_contact_data(&emergency_contact_id,&s2secret_state.database_pool).await.unwrap();
            // TODO: send email to Contact with OTP
            // TODO: delete emergency data access before sending response
            Cbor(EmergencyContactSecretAccessResponse {
                title: secret.title,
                encrypted_secret: ticket.encrypted_secret,
                user_name: secret.user_name,
                site: secret.site,
                notes: secret.notes,
                server_key_file: emergency_contact_data.server_key_file,
                server_v: emergency_contact_secret_access_data.server_v
            }).into_response()
        },
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Emergency access not found"})).into_response()
    }
}