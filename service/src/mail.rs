use std::env;
use lettre::{Address, Message, SmtpTransport, Transport};
use lettre::message::header::ContentType;
use lettre::message::Mailbox;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::response::Response;
use crate::cryptography::one_time_secret_code;

pub async fn send_one_time_secret_code_to_user(email: &str) -> Result<String, lettre::transport::smtp::Error> {
    let one_time_secret_code = one_time_secret_code();

    match send_email(email,"S2Secret - One Time Secret Code", one_time_secret_code.clone()).await {
        Ok(_) => Ok(one_time_secret_code),
        Err(e) => Err(e),
    }
}

async fn send_email(to_address: &str, subject: &str, body: String) -> Result<Response, lettre::transport::smtp::Error> {
    let email_from = env::var("EMAIL_FROM").expect("EMAIL_FROM is not set in .env file");
    let smtp_username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME is not set in .env file");
    let smtp_password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD is not set in .env file");
    let email_from = Address::try_from(email_from).unwrap();
    let email_to = Address::try_from(String::from(to_address)).unwrap();
    let email = Message::builder()
        .from(Mailbox::new(None,email_from))
        .to(Mailbox::new(None, email_to))
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(body)
        .unwrap();

    let creds = Credentials::new(smtp_username, smtp_password);

    // Open a remote connection to gmail
    let mailer = SmtpTransport::relay("smtp.gmail.com")
        ?
        .credentials(creds)
        .build();

    // Send the email
    mailer.send(&email)
}