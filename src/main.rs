use axum::{Router, extract::State, Json, routing::{get,post,delete,put}};
use axum::extract::Path;
use uuid::Uuid;


#[tokio::main]
async fn main() {
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
                                                                 .delete(delete_emergency_contact));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, s2secret).await.unwrap();
}

async fn health_check() -> &'static str {
    "OK"
}

async fn secrets_descriptive_data() -> &'static str {
    "TODO: return descriptive data of all secrets"
}

async fn secret_descriptive_data(Path(secret_id): Path<Uuid>) -> &'static str {
    "TODO: return descriptive data of a specific secret"
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
async fn add_new_secret() {}

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
