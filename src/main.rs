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
use s2secret_service::{EmergencyContact, ProactiveProtection, Secret, SecretShare, ShareRenewal, User};
use opaque_ke::{CipherSuite, ClientRegistration, ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginStartParameters, ServerRegistration, ServerSetup};
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
use sharks::Share;
use sqlx::types::chrono::NaiveDateTime;

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
        .route("/secrets/{secret_id}/disable_proactive_protection", post(disable_proactive_protection))
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
    Cbor(Secret::descriptive_data_of_all_secrets(&s2secret_state.database_pool, &auth.id).await)
}

async fn secret_descriptive_data(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>) -> impl IntoResponse {
    let secret_descriptive_data = Secret::descriptive_data_of_secret(&secret_id, &auth.id, &s2secret_state.database_pool).await;
    match secret_descriptive_data {
        Some(secret) => Cbor(secret).into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}

async fn partially_modify_secret(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>, secret_update_request: Cbor<SecretPatchRequest>) -> impl IntoResponse {
    let modified_secret_id = Secret::partially_modify_secret(&secret_id,
                                                             &auth.id,
                                                             secret_update_request.0.title.as_ref(),
                                                             secret_update_request.0.user_name.as_ref(),
                                                             secret_update_request.0.site.as_ref(),
                                                             secret_update_request.0.notes.as_ref(),
                                                             secret_update_request.0.server_share.as_ref(),
                                                             &s2secret_state.database_pool).await;

    match modified_secret_id {
        Some(modified_secret_id) => Cbor(S2SecretUpsertResponse { id_secret: modified_secret_id  }).into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}
async fn delete_secret(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path(secret_id): Path<Uuid>,s2secret_state: State<AppState>) -> impl IntoResponse {
    let deleted_secret_id = Secret::delete_secret(&secret_id, &auth.id, &s2secret_state.database_pool).await;
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
    let protection_enabled = SecretShare::enable_proactive_protection(&secret_id,&auth.id,requested_protection.0,&s2secret_state.database_pool).await;
    match protection_enabled {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}

async fn disable_proactive_protection(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>) -> impl IntoResponse {
    let protection_enabled = SecretShare::disable_proactive_protection(&secret_id,&auth.id,&s2secret_state.database_pool).await;
    match protection_enabled {
        Some(_) => StatusCode::NO_CONTENT.into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}

async fn add_new_secret(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, s2secret_state: State<AppState>, secret_request: Cbor<SecretUpsertRequest>) -> impl IntoResponse {
    let new_secret_uuid = Secret::create_new_secret(&secret_request.0.title,
                              secret_request.0.user_name.as_ref(),
                              secret_request.0.site.as_ref(),
                              secret_request.0.notes.as_ref(),
                              &secret_request.0.server_share,
                              &auth.id,
                              &s2secret_state.database_pool
    ).await;
    (StatusCode::CREATED, Cbor(S2SecretUpsertResponse { id_secret: new_secret_uuid  }))
}

async fn modify_secret(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, s2secret_state: State<AppState>,Path(secret_id): Path<Uuid>, secret_request: Cbor<SecretUpsertRequest>) -> impl IntoResponse {
    let modified_secret_id = Secret::modify_secret(&secret_id,
                                                             &auth.id,
                                                             secret_request.0.title.as_ref(),
                                                             secret_request.0.user_name.as_ref(),
                                                             secret_request.0.site.as_ref(),
                                                             secret_request.0.notes.as_ref(),
                                                             secret_request.0.server_share.as_ref(),
                                                             &s2secret_state.database_pool).await;

    match modified_secret_id {
        Some(modified_secret_id) => Cbor(S2SecretUpsertResponse { id_secret: modified_secret_id  }).into_response(),
        None => (StatusCode::NOT_FOUND, Cbor(S2SecretError { msg: "Secret not found"})).into_response()
    }
}

async fn secret_emergency_contacts(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>,Path(secret_id): Path<Uuid>,s2secret_state: State<AppState>) -> Cbor<Vec<EmergencyContact>> {
    Cbor(EmergencyContact::emergency_contacts_of_secret(&secret_id,&auth.id,&s2secret_state.database_pool).await)
}

async fn add_emergency_contact_to_secret(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>,Path(secret_id): Path<Uuid>, s2secret_state: State<AppState>, emergency_access_request: Cbor<EmergencyAccessRequest>) -> impl IntoResponse {
    let emergency_contact_uuid = EmergencyContact::add_emergency_contact_to_secret(&secret_id,
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

async fn send_emergency_access_data_to_contact(Path((secret_id,emergency_contact_id)): Path<(Uuid,Uuid)>)
                                               -> &'static str {
    "TODO: Send required emergency access data to a contact"
}

async fn user_data(s2secret_state: State<AppState>, auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>) -> impl IntoResponse {
    Cbor(User::data(&s2secret_state.database_pool,&auth.id).await)
}

async fn emergency_contacts(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>,s2secret_state: State<AppState>) -> Cbor<Vec<EmergencyContact>> {
    Cbor(EmergencyContact::emergency_contacts(&s2secret_state.database_pool,&auth.id).await)
}

async fn create_emergency_contact(s2secret_state: State<AppState>, emergency_contact_request: Cbor<NewEmergencyContactRequest>) -> impl IntoResponse {
    "TODO: create new emergency contact for current user"
}

async fn update_emergency_contact() -> &'static str {
    "TODO: update the entire information of an emergency contact"
}

async fn delete_emergency_contact() -> &'static str {
    "TODO: delete an emergency contact of current user"
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
    User::create_new_user(&s2secret_state.database_pool, &user_finish_registration_request.0.email, &user_finish_registration_request.0.name, &*password_file.serialize(), &*s2secret_state.opaque_ciphersuite.serialize()).await;
    (StatusCode::CREATED).into_response()
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
        ServerLoginStartParameters::default(),
    ).unwrap();
    auth.session.set("login_start_state", server_login_start_result.state.serialize());
    Cbor(server_login_start_result.message.serialize())
}

async fn user_login_finish(s2secret_state: State<AppState>, auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, user_login_request: Cbor<UserLoginFinishRequest>) -> impl IntoResponse {
    let server_login_state: Vec<u8> = auth.session.get("login_start_state").unwrap();
    let server_login_state = ServerLogin::<DefaultCipherSuite>::deserialize(&server_login_state).unwrap();
    let server_login_finish_result = server_login_state.finish(user_login_request.0.message.clone()).map_err(|_| StatusCode::UNAUTHORIZED.into_response()).unwrap();
    let logged_in_user_id = User::user_id(&s2secret_state.database_pool,&user_login_request.0.email).await.ok_or_else(|| StatusCode::UNAUTHORIZED.into_response()).unwrap();
    auth.session.renew();
    auth.login_user(logged_in_user_id);
    auth.session.set("session_key",server_login_finish_result.session_key);
    (StatusCode::OK).into_response()
}

pub async fn auth_middleware(auth: AuthSession<AuthUser, Uuid, SessionPgPool, PgPool>, request: Request,next: Next) -> Result<Response, StatusCode> {
    if auth.is_authenticated() {
        auth.session.set_store(true);
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