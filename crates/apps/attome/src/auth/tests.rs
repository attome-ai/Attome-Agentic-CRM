use super::dto::*;
use uuid::Uuid;

#[test]
fn register_request_deserializes_email_and_password() {
    let body: RegisterRequest =
        serde_json::from_str(r#"{"email":"a@b.com","password":"hunter2"}"#).unwrap();
    assert_eq!(body.email, "a@b.com");
    assert_eq!(body.password, "hunter2");
    assert_eq!(body.invitation_token, None);
}

#[test]
fn register_request_deserializes_an_optional_invitation_token() {
    let body: RegisterRequest = serde_json::from_str(
        r#"{"email":"a@b.com","password":"hunter2","invitation_token":"abc.def"}"#,
    )
    .unwrap();
    assert_eq!(body.invitation_token, Some("abc.def".to_string()));
}

#[test]
fn registration_config_info_serializes_the_mode_string() {
    let value = serde_json::to_value(RegistrationConfigInfo {
        mode: "disabled".to_string(),
    })
    .unwrap();
    assert_eq!(value, serde_json::json!({ "mode": "disabled" }));
}

#[test]
fn login_request_deserializes_email_and_password() {
    let body: LoginRequest =
        serde_json::from_str(r#"{"email":"a@b.com","password":"hunter2"}"#).unwrap();
    assert_eq!(body.email, "a@b.com");
    assert_eq!(body.password, "hunter2");
}

#[test]
fn reset_request_body_deserializes_email_only() {
    let body: ResetRequestBody = serde_json::from_str(r#"{"email":"a@b.com"}"#).unwrap();
    assert_eq!(body.email, "a@b.com");
}

#[test]
fn reset_confirm_body_deserializes_token_and_new_password() {
    let body: ResetConfirmBody =
        serde_json::from_str(r#"{"token":"tok","new_password":"newpass1"}"#).unwrap();
    assert_eq!(body.token, "tok");
    assert_eq!(body.new_password, "newpass1");
}

#[test]
fn verify_email_confirm_body_deserializes_token_only() {
    let body: VerifyEmailConfirmBody = serde_json::from_str(r#"{"token":"tok"}"#).unwrap();
    assert_eq!(body.token, "tok");
}

#[test]
fn oidc_callback_query_deserializes_code_and_state() {
    // Bound via axum's Query extractor (serde_urlencoded) on the real
    // request path, not serde_json — but #[derive(Deserialize)]'s field
    // mapping is format-agnostic, so this still pins the struct's field
    // names/types against an accidental rename.
    let query: OidcCallbackQuery =
        serde_json::from_str(r#"{"code":"abc123","state":"xyz789"}"#).unwrap();
    // BAU-25 (F20): both are optional now - a provider error redirect omits
    // them - so this pins the Some shape rather than a bare string.
    assert_eq!(query.code.as_deref(), Some("abc123"));
    assert_eq!(query.state.as_deref(), Some("xyz789"));
    assert_eq!(query.error, None);
}

#[test]
fn mfa_verify_body_deserializes_pending_token_and_code() {
    let body: MfaVerifyBody =
        serde_json::from_str(r#"{"pending_token":"pt","code":"123456"}"#).unwrap();
    assert_eq!(body.pending_token, "pt");
    assert_eq!(body.code, "123456");
}

#[test]
fn mfa_pending_enroll_body_deserializes_pending_token_only() {
    let body: MfaPendingEnrollBody = serde_json::from_str(r#"{"pending_token":"pt"}"#).unwrap();
    assert_eq!(body.pending_token, "pt");
}

#[test]
fn auth_response_serializes_user_id_as_a_uuid_string() {
    let user_id = Uuid::now_v7();
    let value = serde_json::to_value(AuthResponse { user_id }).unwrap();
    assert_eq!(value, serde_json::json!({ "user_id": user_id.to_string() }));
}

#[test]
fn ack_serializes_ok_true() {
    let value = serde_json::to_value(Ack { ok: true }).unwrap();
    assert_eq!(value, serde_json::json!({ "ok": true }));
}

#[test]
fn mfa_challenge_response_serializes_mfa_and_pending_token() {
    let value = serde_json::to_value(MfaChallengeResponse {
        mfa: "required".to_string(),
        pending_token: "pt".to_string(),
        grace_until: None,
        remember_device: false,
        passkey: false,
    })
    .unwrap();
    assert_eq!(
        value,
        serde_json::json!({ "mfa": "required", "pending_token": "pt" })
    );
}

#[test]
fn mfa_pending_confirm_response_serializes_user_id_and_recovery_codes() {
    let user_id = Uuid::now_v7();
    let value = serde_json::to_value(MfaPendingConfirmResponse {
        user_id,
        recovery_codes: vec!["code-1".to_string(), "code-2".to_string()],
    })
    .unwrap();
    assert_eq!(
        value,
        serde_json::json!({
            "user_id": user_id.to_string(),
            "recovery_codes": ["code-1", "code-2"],
        })
    );
}

#[test]
fn google_config_info_serializes_a_configured_client_id_as_a_string() {
    let value = serde_json::to_value(GoogleConfigInfo {
        client_id: Some("client-123".to_string()),
    })
    .unwrap();
    assert_eq!(value, serde_json::json!({ "client_id": "client-123" }));
}

#[test]
fn google_config_info_serializes_an_unconfigured_client_id_as_null() {
    // `google_config`'s handler maps an empty config string to `None` —
    // pinned here is the other half: that `None` actually reaches the
    // client as `null`, not an omitted key or an empty string, so the
    // login page's `client_id === null` check (render no button) is the
    // one it can rely on.
    let value = serde_json::to_value(GoogleConfigInfo { client_id: None }).unwrap();
    assert_eq!(value, serde_json::json!({ "client_id": null }));
}

#[test]
fn oidc_provider_info_never_serializes_issuer_or_client_secret_fields() {
    // Regression guard for the exact leak the doc comment on
    // OidcProviderInfo warns against: this struct must stay a two-field
    // public directory shape, never gain issuer/client_id/client_secret/
    // scopes/email_claim by a careless #[derive] copy from
    // OidcProviderConfig.
    let value = serde_json::to_value(OidcProviderInfo {
        key: "entra".to_string(),
        display_name: "Microsoft Entra".to_string(),
    })
    .unwrap();
    let obj = value.as_object().unwrap();
    assert_eq!(
        obj.len(),
        2,
        "unexpected fields in OidcProviderInfo: {obj:?}"
    );
    assert!(obj.contains_key("key"));
    assert!(obj.contains_key("display_name"));
}
