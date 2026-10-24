/// D15-T3: two-way calendar sync of meetings.
pub mod calendar_sync;
/// S12-T2: what the ERP connectors exchange with Attome.
pub mod erp;
/// J2-T1: the IMAP, Graph and Gmail readers behind `mailbox`.
pub mod mail;
pub mod mailbox;
/// AJ5-T1: SPL National Address lookups and standardisation.
pub mod national_address;
/// S12-T2: Odoo over JSON-RPC.
pub mod odoo;
pub mod reputation;
pub mod rest;
/// S12-T2: SAP Business One over its Service Layer.
pub mod sap_b1;
/// J4-T1: SMS segments, senders and the provider codecs.
pub mod sms;
pub mod sms_twilio;
pub mod sms_unifonic;
/// J8-T1: Messenger, Instagram, Facebook comments and Google reviews.
pub mod social;
/// D15-T1: a person's own mailbox and calendar connection.
pub mod user_mail_sync;
/// J7-T1: Teams, Google Meet, Zoom and Jitsi meetings.
pub mod video;
/// J6-T1: Twilio Voice and an Asterisk PBX.
pub mod voice;
pub mod webchat;
