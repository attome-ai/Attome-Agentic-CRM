pub mod mailbox;
pub mod rest;
/// J4-T1: SMS segments, senders and the provider codecs.
pub mod sms;
pub mod sms_twilio;
pub mod sms_unifonic;
/// D15-T1: a person's own mailbox and calendar connection.
pub mod user_mail_sync;
/// J7-T1: Teams, Google Meet, Zoom and Jitsi meetings.
pub mod video;
pub mod webchat;
