//! Z15-T6: the in-process inbox. Mail sent through the real `send` path
//! (suppression check, message build, SMTP session) arrives in
//! `attome_email::testing::FakeInbox` and reads back by recipient. The fake
//! model server's own tests are `attome-inference`'s `tests/transport.rs`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test helpers: a failed setup step should panic with its message"
)]

use attome_email::testing::FakeInbox;
use attome_testkit::skip_if_no_db;

fn message_to(recipient: &str, subject: &str) -> attome_email::EmailMessage {
    attome_email::EmailMessage {
        to: recipient.to_string(),
        subject: subject.to_string(),
        text_body: "Your quote is ready.".to_string(),
        html_body: None,
        delivery_id: None,
        from_override: None,
        message_id: None,
        in_reply_to: None,
        references: None,
        communication_id: None,
        attachments: Vec::new(),
    }
}

// feature: Z15
#[tokio::test]
async fn inbox_reads_sent_mail() {
    let pool = skip_if_no_db!(attome_testkit::migrated_pool(5).await);
    let inbox = FakeInbox::start().await;
    let first = attome_testkit::unique_email("fake-inbox");
    let second = attome_testkit::unique_email("fake-inbox");

    attome_email::send(&inbox.config(), &pool, message_to(&first, "Quote ready"))
        .await
        .expect("the inbox accepts the first mail");
    attome_email::send(&inbox.config(), &pool, message_to(&second, "Another"))
        .await
        .expect("the inbox accepts the second mail");

    let mail = inbox.messages_to(&first);
    assert_eq!(mail.len(), 1, "{:?}", inbox.messages());
    assert_eq!(mail[0].subject, "Quote ready");
    assert_eq!(mail[0].from, "noreply@example.invalid");
    assert!(
        mail[0].body.contains("Your quote is ready."),
        "{}",
        mail[0].raw
    );
    assert_eq!(inbox.messages().len(), 2, "each send is its own session");
}
