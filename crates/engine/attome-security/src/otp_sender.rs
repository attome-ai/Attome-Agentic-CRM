//! Q5-T5: delivers a sign-in one-time code (`attome_auth::otp`), the weaker
//! second factor a role may allow. Email goes through the email job
//! (`EngineJob::SendEmail`) with the bilingual sign-in-code template, and
//! only to a verified address. SMS and WhatsApp answer
//! `FeatureUnavailable` until those channels exist (J4, J5).

use attome_auth::otp::{OtpChannel, OtpSender};
use attome_db::DbPool;
use attome_types::AppError;
use uuid::Uuid;

/// The platform's sender: email in `lang` (`ar` for Arabic, else English),
/// carrying the deployment's email brand.
pub struct PlatformOtpSender<'a> {
    pub db: &'a DbPool,
    /// The frontend URL the email brand is read for.
    pub frontend_url: &'a str,
    pub lang: &'a str,
}

impl OtpSender for PlatformOtpSender<'_> {
    async fn send(&self, user_id: Uuid, channel: OtpChannel, code: &str) -> Result<(), AppError> {
        match channel {
            OtpChannel::Email => self.send_email(user_id, code).await,
            OtpChannel::Sms | OtpChannel::WhatsApp => Err(AppError::FeatureUnavailable),
        }
    }
}

impl PlatformOtpSender<'_> {
    async fn send_email(&self, user_id: Uuid, code: &str) -> Result<(), AppError> {
        let row: Option<(Option<String>, bool)> =
            sqlx::query_as("SELECT email, email_verified FROM user_account WHERE id = $1")
                .bind(user_id)
                .fetch_optional(self.db)
                .await
                .map_err(AppError::internal)?;
        // Never to an unverified address: the code would go to whoever
        // typed it in at registration.
        let Some(email) = row
            .filter(|(_, verified)| *verified)
            .and_then(|(email, _)| email)
            .filter(|e| !e.trim().is_empty())
        else {
            return Err(AppError::Forbidden);
        };
        let brand = attome_core::theme_store::email_brand(self.db, self.frontend_url).await;
        let (subject, text_body, html_body) =
            attome_email::templates::sign_in_code_in(self.lang, code, &brand);
        let delivery_id = Uuid::now_v7();
        let mut tx = attome_db::tx::begin(self.db).await?;
        attome_email::delivery::record_queued_in_tx(
            &mut tx,
            delivery_id,
            attome_email::delivery::EmailDeliveryKind::Generic,
            &email,
            &subject,
            Some(user_id),
            None,
            None,
        )
        .await
        .map_err(AppError::internal)?;
        let job = attome_core::jobs::EngineJob::SendEmail(Box::new(attome_email::EmailMessage {
            to: email,
            subject,
            text_body,
            html_body: Some(html_body),
            delivery_id: Some(delivery_id),
            from_override: None,
            message_id: None,
            in_reply_to: None,
            references: None,
            communication_id: None,
            attachments: Vec::new(),
            stream: Default::default(),
            list_unsubscribe: None,
        }));
        attome_jobs::enqueue_in_tx(&mut tx, job)
            .await
            .map_err(AppError::internal)?;
        tx.commit().await.map_err(AppError::internal)?;
        Ok(())
    }
}
