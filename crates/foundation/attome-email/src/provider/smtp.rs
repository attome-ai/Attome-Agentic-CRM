//! Z8-T1: the SMTP provider, the relay in `config.email`. The transport,
//! its TLS modes and the reply classification stay in `sender.rs`
//! (`deliver`), unchanged; this is the provider face over them.

use attome_config::EmailSection;

use super::{EmailProvider, OutgoingEmail, ProviderMessageId, SMTP};
use crate::error::SendError;

pub struct Smtp<'a> {
    pub cfg: &'a EmailSection,
}

impl EmailProvider for Smtp<'_> {
    fn name(&self) -> &str {
        SMTP
    }

    async fn send(&self, msg: &OutgoingEmail<'_>) -> Result<ProviderMessageId, SendError> {
        crate::sender::deliver(self.cfg, msg.mime.clone()).await?;
        // An SMTP relay names no id of its own; the message's Message-ID is it.
        Ok(ProviderMessageId(msg.message.message_id.clone()))
    }
}
