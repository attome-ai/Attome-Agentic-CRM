//! Z4-T7: one-time codes — issued, verified once, Arabic-Indic digits
//! accepted, refused after five wrong tries and after expiry.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use std::sync::Mutex;

use attome_auth::PepperRing;
use attome_auth::otp::{self, OtpChannel, OtpOutcome, OtpSender};
use attome_db::DbPool;
use attome_testkit::skip_if_no_db;
use attome_types::AppError;
use uuid::Uuid;

async fn pool() -> Option<DbPool> {
    Some(attome_testkit::connect(&attome_testkit::migrated_db_url()?, 3).await)
}

fn ring() -> PepperRing {
    PepperRing::new(0, "otp-flow-test-pepper-0123456789abcdef", &[])
}

/// Keeps the last code it was asked to send.
#[derive(Default)]
struct Capture(Mutex<Option<String>>);

impl OtpSender for Capture {
    async fn send(&self, _: Uuid, _: OtpChannel, code: &str) -> Result<(), AppError> {
        *self.0.lock().unwrap() = Some(code.to_owned());
        Ok(())
    }
}

impl Capture {
    fn code(&self) -> String {
        self.0.lock().unwrap().clone().expect("a code was sent")
    }
}

fn wrong(code: &str) -> String {
    let first = code.as_bytes()[0];
    let other = if first == b'9' {
        '0'
    } else {
        (first + 1) as char
    };
    format!("{other}{}", &code[1..])
}

fn arabic(code: &str) -> String {
    code.chars()
        .map(|c| char::from_u32(0x0660 + c.to_digit(10).unwrap()).unwrap())
        .collect()
}

#[tokio::test]
async fn code_verifies_once() {
    let db = skip_if_no_db!(pool().await);
    let user = Uuid::now_v7();
    let sender = Capture::default();
    otp::issue(&db, &ring(), &sender, user, "login", OtpChannel::Sms)
        .await
        .expect("issue");
    let code = sender.code();
    assert_eq!(code.len(), 6);
    assert_eq!(
        otp::verify(&db, &ring(), user, "login", &code)
            .await
            .unwrap(),
        OtpOutcome::Verified
    );
    assert_eq!(
        otp::verify(&db, &ring(), user, "login", &code)
            .await
            .unwrap(),
        OtpOutcome::Refused,
        "a code works once"
    );
    assert_eq!(
        otp::verify(&db, &ring(), user, "other", &code)
            .await
            .unwrap(),
        OtpOutcome::Refused,
        "a code is bound to its purpose"
    );
}

#[tokio::test]
async fn arabic_indic_digits_are_accepted() {
    let db = skip_if_no_db!(pool().await);
    let user = Uuid::now_v7();
    let sender = Capture::default();
    otp::issue(&db, &ring(), &sender, user, "login", OtpChannel::WhatsApp)
        .await
        .expect("issue");
    assert_eq!(
        otp::verify(&db, &ring(), user, "login", &arabic(&sender.code()))
            .await
            .unwrap(),
        OtpOutcome::Verified
    );
}

#[tokio::test]
async fn sixth_attempt_is_refused() {
    let db = skip_if_no_db!(pool().await);
    let user = Uuid::now_v7();
    let sender = Capture::default();
    otp::issue(&db, &ring(), &sender, user, "login", OtpChannel::Email)
        .await
        .expect("issue");
    let code = sender.code();
    for _ in 0..5 {
        assert_eq!(
            otp::verify(&db, &ring(), user, "login", &wrong(&code))
                .await
                .unwrap(),
            OtpOutcome::Refused
        );
    }
    assert_eq!(
        otp::verify(&db, &ring(), user, "login", &code)
            .await
            .unwrap(),
        OtpOutcome::Refused,
        "after five wrong tries even the right code is refused"
    );
}

#[tokio::test]
async fn expired_code_is_refused() {
    let db = skip_if_no_db!(pool().await);
    let user = Uuid::now_v7();
    let sender = Capture::default();
    otp::issue(&db, &ring(), &sender, user, "login", OtpChannel::Sms)
        .await
        .expect("issue");
    sqlx::query(
        "UPDATE one_time_code SET expires_at = now() - interval '1 second' WHERE user_ref = $1",
    )
    .bind(user)
    .execute(&db)
    .await
    .expect("expire");
    assert_eq!(
        otp::verify(&db, &ring(), user, "login", &sender.code())
            .await
            .unwrap(),
        OtpOutcome::Refused
    );
}
