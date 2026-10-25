"""Builds docs/security/asvs-l2.md from the OWASP ASVS 4.0.3 CSV (roadmap Q21-T5).

Each level 2 requirement gets a status: Tested (named tests prove it), Gap (applies, no
automated proof yet; the owner feature is named), N/A (does not apply, with why) or Process
(a practice outside the code; where its evidence lives). Every cited test is looked up in
the repository and must carry a test attribute; the script stops when one is not found, and
when a level 2 requirement is unmapped.

    curl -sSLo asvs.csv "https://raw.githubusercontent.com/OWASP/ASVS/v4.0.3/4.0/docs_en/OWASP%20Application%20Security%20Verification%20Standard%204.0.3-en.csv"
    python scripts/security/asvs-l2.py . asvs.csv
"""
import csv, pathlib, re, subprocess, sys

REPO = pathlib.Path(sys.argv[1])
CSV = pathlib.Path(sys.argv[2])
OUT = REPO / "docs" / "security" / "asvs-l2.md"

T, G, NA, P = "Tested", "Gap", "N/A", "Process"

# req -> (status, tests or note). Tests are function names; a note is free text.
M = {
 # V1 architecture: practices, cited to where they live.
 "V1.1.1": (P, "Release gate (`attome-release --check`, docs/release.md) and the review rules in CONTRIBUTING.md."),
 "V1.1.2": (P, "docs/security/threat-model.md."),
 "V1.1.3": (P, "Each roadmap task carries do_not and stop_and_ask_if security constraints."),
 "V1.1.4": (P, "docs/security/threat-model.md (trust boundaries) and docs/architecture.md."),
 "V1.1.5": (P, "docs/architecture.md."),
 "V1.1.6": (P, "One authn middleware, one authz policy layer, one SSRF-guarded client (Q21-T1)."),
 "V1.1.7": (P, "CONTRIBUTING.md and the coding guidelines."),
 "V1.2.1": (G, "Owner U1: the installer's service account; container images run as non-root."),
 "V1.2.2": (P, "Postgres and Redis connections authenticate; server-to-server calls are HMAC-signed and replay-checked (S2S)."),
 "V1.2.3": (T, ["admin_routes_forbid_a_non_admin_and_admit_an_admin"]),
 "V1.2.4": (T, ["v4_1_1_unauthenticated_api_is_refused", "an_s2s_caller_is_refused_on_step_up_guarded_routes"]),
 "V1.4.1": (T, ["v4_1_1_unauthenticated_api_is_refused"]),
 "V1.4.4": (T, ["admin_routes_forbid_a_non_admin_and_admit_an_admin"]),
 "V1.4.5": (P, "Privileges are entity and action keys checked by the one authorization layer (attome-security)."),
 "V1.5.1": (P, "Typed field metadata (docs/data-layer.md); validation in the record engine."),
 "V1.5.2": (NA, "No native object serialization reaches clients; JSON only."),
 "V1.5.3": (T, ["an_unknown_field_is_a_validation_error"]),
 "V1.5.4": (T, ["apply_variables_html_escapes_script_markup_in_values"]),
 "V1.6.1": (P, "docs/release-signing.md and the key-ring configuration (config-reference.md)."),
 "V1.6.2": (G, "Owner Z1-T12: cloud secret stores read at boot."),
 "V1.6.3": (T, ["an_old_kid_still_verifies_while_it_stays_in_the_ring_and_fails_once_removed"]),
 "V1.6.4": (P, "The web app holds no secret; sessions are HttpOnly cookies (V3.4)."),
 "V1.7.1": (P, "Structured tracing everywhere (docs/architecture.md)."),
 "V1.7.2": (G, "Owner Q21: SIEM export is configured per deployment; no automated proof of transport."),
 "V1.8.1": (P, "Every attribute carries a sensitivity label (A1-T1)."),
 "V1.8.2": (G, "Owner A1-T2: protections per sensitivity label."),
 "V1.9.1": (G, "Owner Q21: TLS to Postgres and Redis is configuration; no automated proof."),
 "V1.9.2": (G, "Owner Q21: certificate verification on internal links is configuration."),
 "V1.10.1": (P, "Git on GitHub; every change is a reviewed commit."),
 "V1.11.1": (P, "docs/architecture.md."),
 "V1.11.2": (T, ["a_hundred_concurrent_identical_requests_run_the_handler_once"]),
 "V1.12.2": (T, ["a_presigned_download_is_served_as_an_attachment", "a_promoted_file_is_presigned_as_an_attachment"]),
 "V1.14.1": (P, "Deployment isolation per customer (docs/architecture.md)."),
 "V1.14.2": (G, "Owner AC7-T5: signed release binaries wait for the release key."),
 "V1.14.3": (P, "cargo deny in the release gate (deny.toml)."),
 "V1.14.4": (P, "The release gate builds and checks the deployable (docs/release.md)."),
 "V1.14.5": (P, "Helm and compose profiles (deploy/)."),
 "V1.14.6": (NA, "No Flash, ActiveX, Silverlight or Java applets."),
 # V2 authentication.
 "V2.1.1": (T, ["policy_enforces_the_character_minimum_at_its_boundary"]),
 "V2.1.2": (T, ["policy_enforces_the_byte_maximum_at_its_boundary"]),
 "V2.1.3": (G, "Owner Q7: a test that a password is not truncated."),
 "V2.1.4": (T, ["policy_counts_the_minimum_in_characters_not_bytes"]),
 "V2.1.5": (G, "Owner Q7: an HTTP test of password change."),
 "V2.1.6": (G, "Owner Q7: an HTTP test that change needs the current password."),
 "V2.1.7": (T, ["password_policy_refuses_a_shipped_breached_password"]),
 "V2.1.8": (G, "Owner Q7: a strength meter in the web app."),
 "V2.1.9": (T, ["policy_has_no_composition_rules"]),
 "V2.1.10": (P, "No rotation or history rule exists."),
 "V2.1.11": (P, "The sign-in form does not block paste or password managers."),
 "V2.1.12": (G, "Owner Q7: show-password toggle in the web app."),
 "V2.2.1": (T, ["a_throttled_known_account_is_indistinguishable_from_a_throttled_unknown_one", "v2_wrong_password_is_generic"]),
 "V2.2.2": (P, "Email, SMS and WhatsApp codes are second factors and confirmations only (otp.rs)."),
 "V2.2.3": (G, "Owner Q5: notify a user when a credential changes."),
 "V2.3.1": (T, ["an_invitation_token_reused_after_registration_is_rejected"]),
 "V2.3.2": (T, ["registration_then_assertion_succeeds"]),
 "V2.3.3": (NA, "No time-bound authenticators are issued."),
 "V2.4.1": (T, ["an_argon2_recovery_code_still_verifies"]),
 "V2.4.2": (P, "Argon2id with a random 16-byte salt (password.rs)."),
 "V2.4.3": (NA, "PBKDF2 is not used."),
 "V2.4.4": (NA, "bcrypt is not used."),
 "V2.4.5": (P, "API-key secrets add a peppered HMAC (apikey_hash.rs)."),
 "V2.5.1": (T, ["confirm_expires_other_reset_links_and_revokes_every_refresh_token_itself"]),
 "V2.5.2": (NA, "No password hints or secret questions exist."),
 "V2.5.3": (T, ["a_throttled_reset_request_is_identical_for_known_and_unknown_emails"]),
 "V2.5.4": (P, "The first administrator is bootstrapped by email; no default account exists."),
 "V2.5.5": (G, "Owner Q5: notify a user when a factor changes."),
 "V2.5.6": (T, ["confirm_expires_other_reset_links_and_revokes_every_refresh_token_itself"]),
 "V2.5.7": (T, ["admin_mfa_reset_of_an_admin_waits_for_a_second_admin", "admin_mfa_reset_needs_a_step_up"]),
 "V2.6.1": (T, ["a_recovery_code_signs_in_once_and_regeneration_voids_the_old_set"]),
 "V2.6.2": (P, "Recovery codes are random from the OS generator (mfa.rs)."),
 "V2.6.3": (T, ["an_argon2_recovery_code_still_verifies"]),
 "V2.7.1": (P, "SMS codes are a second factor only (otp.rs)."),
 "V2.7.2": (T, ["code_verifies_once"]),
 "V2.7.3": (T, ["code_verifies_once"]),
 "V2.7.4": (P, "Codes go by the configured email, SMS or WhatsApp provider."),
 "V2.7.5": (T, ["code_verifies_once"]),
 "V2.7.6": (P, "Six digits from the OS generator (otp.rs)."),
 "V2.8.1": (T, ["complete_pending_login_rejects_replayed_totp_code_with_a_fresh_pending_token"]),
 "V2.8.2": (P, "TOTP secrets are encrypted at rest (encrypted_columns.rs)."),
 "V2.8.3": (P, "totp-rs (RFC 6238, HMAC-SHA1 as authenticator apps require)."),
 "V2.8.4": (T, ["complete_pending_login_rejects_replayed_totp_code_with_a_fresh_pending_token"]),
 "V2.8.5": (G, "Owner Q5: log and alert on a reused TOTP."),
 "V2.8.6": (NA, "No physical OTP generators are issued."),
 "V2.8.7": (NA, "No biometric verification on the server."),
 "V2.9.1": (P, "Passkey private keys never leave the authenticator (webauthn.rs)."),
 "V2.9.2": (T, ["replayed_challenge_is_refused"]),
 "V2.9.3": (T, ["registration_then_assertion_succeeds", "lower_sign_count_is_refused"]),
 "V2.10.1": (P, "Service accounts use rotating client-credential tokens (S11-T1) or HMAC-signed S2S requests."),
 "V2.10.2": (P, "Service accounts are named and owned (S11)."),
 "V2.10.3": (P, "API-key secrets are stored as peppered hashes (apikey_hash.rs)."),
 "V2.10.4": (P, "Secrets come from the environment through ${VAR} placeholders (config-reference.md)."),
 # V3 sessions.
 "V3.1.1": (T, ["v3_1_1_session_token_never_in_a_url"]),
 "V3.2.1": (T, ["v3_2_1_new_session_token_per_sign_in"]),
 "V3.2.2": (P, "Session JWTs carry a UUIDv7 jti and an HMAC signature (jwt.rs)."),
 "V3.2.3": (T, ["v3_4_session_cookie_flags"]),
 "V3.2.4": (P, "HS256 or EdDSA through jsonwebtoken (jwt.rs)."),
 "V3.3.1": (T, ["logout_writes_a_logout_event_and_an_anonymous_logout_writes_none", "a_revoked_token_is_rejected_without_writing_anything", "a_revoked_token_stays_revoked_after_the_cache_role_is_flushed"]),
 "V3.3.2": (G, "Owner Q8: re-authentication after an idle period."),
 "V3.3.3": (T, ["confirm_expires_other_reset_links_and_revokes_every_refresh_token_itself"]),
 "V3.3.4": (T, ["admin_disable_and_portal_deactivation_revoke_sessions_through_the_real_paths"]),
 "V3.4.1": (T, ["v3_4_session_cookie_flags"]),
 "V3.4.2": (T, ["v3_4_session_cookie_flags"]),
 "V3.4.3": (T, ["v3_4_session_cookie_flags"]),
 "V3.4.4": (T, ["v3_4_session_cookie_flags"]),
 "V3.4.5": (T, ["v3_4_session_cookie_flags"]),
 "V3.5.1": (G, "Owner S11: revoke an OAuth client's tokens from the UI."),
 "V3.5.2": (P, "Browser sessions use session tokens; API keys are for machines only."),
 "V3.5.3": (T, ["an_old_kid_still_verifies_while_it_stays_in_the_ring_and_fails_once_removed"]),
 "V3.7.1": (T, ["api_key_creation_needs_a_step_up_on_the_sessions_own_family", "a_password_step_up_elevates_only_the_callers_family"]),
 # V4 access control.
 "V4.1.1": (T, ["v4_1_1_unauthenticated_api_is_refused"]),
 "V4.1.2": (T, ["a_session_id_cannot_reach_another_users_or_a_dead_family"]),
 "V4.1.3": (T, ["admin_routes_forbid_a_non_admin_and_admit_an_admin"]),
 "V4.1.5": (T, ["an_unreachable_store_refuses_a_google_step_up", "a_query_backed_metric_that_tries_to_write_fails_under_the_readonly_pool_and_is_masked"]),
 "V4.2.1": (T, ["another_users_conversation_is_not_found_on_every_route_and_nothing_changes"]),
 "V4.2.2": (T, ["v4_2_2_cross_site_mutation_is_refused", "csrf_rejected_without_reading_body"]),
 "V4.3.1": (G, "Owner Q5: require MFA for administrators by policy; the policy exists (mfa_policy.rs), no HTTP proof."),
 "V4.3.2": (P, "The web tier serves the built app only; no directory listing."),
 "V4.3.3": (T, ["admin_mfa_reset_of_an_admin_waits_for_a_second_admin"]),
 # V5 validation and encoding.
 "V5.1.1": (G, "Owner S1: a test that a repeated query parameter is refused."),
 "V5.1.2": (T, ["an_unknown_field_is_rejected"]),
 "V5.1.3": (T, ["an_unknown_field_is_a_validation_error"]),
 "V5.1.4": (T, ["a_deep_json_body_is_refused_before_the_handler"]),
 "V5.1.5": (T, ["a_redirect_never_names_a_page_outside_the_audience"]),
 "V5.2.1": (G, "Owner A2: rich-text sanitization (ammonia) has no HTTP test."),
 "V5.2.2": (T, ["arabic_injection_shaped_and_mixed_script_input_is_handled"]),
 "V5.2.3": (G, "Owner Z8: a test that header injection in a subject is refused."),
 "V5.2.4": (P, "The rule language is a typed interpreter with budgets, not eval (attome-rules)."),
 "V5.2.5": (T, ["apply_variables_html_escapes_script_markup_in_values"]),
 "V5.2.6": (T, ["a_redirect_to_the_metadata_address_is_refused", "a_private_rfc1918_target_is_rejected"]),
 "V5.2.7": (G, "Owner Z6: SVG uploads are not sanitized; they are served as attachments only."),
 "V5.2.8": (T, ["apply_variables_html_escapes_script_markup_in_values"]),
 "V5.3.1": (T, ["a_visible_field_substitutes_its_html_escaped_value"]),
 "V5.3.2": (T, ["arabic_injection_shaped_and_mixed_script_input_is_handled"]),
 "V5.3.3": (P, "Angular templates escape by default; bypassSecurityTrust is reviewed."),
 "V5.3.4": (T, ["a_sql_injection_shaped_query_is_returned_as_inert_data", "an_injection_payload_inside_a_field_value_is_still_just_a_string"]),
 "V5.3.5": (P, "Dynamic identifiers come from metadata through quote_ident (guidelines §4)."),
 "V5.3.6": (P, "JSON is built with serde_json, never by string concatenation."),
 "V5.3.7": (NA, "No LDAP."),
 "V5.3.8": (P, "No shell commands run with request input."),
 "V5.3.9": (P, "Files are addressed by stored ids, never by request paths."),
 "V5.3.10": (G, "Owner AG2: XML is built by quick-xml writers; no injection test."),
 "V5.4.1": (P, "Rust; unsafe_code is denied workspace-wide."),
 "V5.4.2": (P, "Rust format strings are compile-time constants."),
 "V5.4.3": (T, ["add_near_the_scan_limit_is_ok_inside_and_exceeded_outside"]),
 "V5.5.1": (T, ["a_tampered_body_is_refused_before_the_nonce_store"]),
 "V5.5.2": (P, "quick-xml does not expand external entities."),
 "V5.5.3": (P, "Only JSON through serde; no native deserialization of untrusted data."),
 "V5.5.4": (P, "The web app parses JSON with JSON.parse (HttpClient)."),
 # V6 cryptography.
 "V6.1.1": (G, "Owner A1-T2: encryption of personal fields at rest by label."),
 "V6.1.2": (G, "Owner A1-T2: encryption of health fields at rest by label."),
 "V6.1.3": (G, "Owner A1-T2: encryption of financial fields at rest by label."),
 "V6.2.1": (P, "Crypto errors map to masked errors (attome-types)."),
 "V6.2.2": (P, "RustCrypto and ring; no custom primitives."),
 "V6.2.3": (T, ["dek_seal_uses_a_fresh_nonce_each_call"]),
 "V6.2.4": (T, ["an_old_kid_still_verifies_while_it_stays_in_the_ring_and_fails_once_removed"]),
 "V6.2.5": (P, "AES-256-GCM only; no ECB or PKCS#1 v1.5 encryption."),
 "V6.2.6": (T, ["dek_seal_uses_a_fresh_nonce_each_call"]),
 "V6.3.1": (P, "Secrets and tokens come from the OS generator."),
 "V6.3.2": (P, "Ids are UUIDv7 (time-ordered); they are not secrets."),
 "V6.4.1": (G, "Owner Z1-T12: cloud secret stores."),
 "V6.4.2": (G, "Owner Q18: an HSM or KMS for key material."),
 # V7 logging and errors.
 "V7.1.1": (T, ["a_google_decode_failure_never_logs_or_returns_the_id_token", "debug_is_redacted"]),
 "V7.1.2": (T, ["emails_are_masked_to_the_first_letter_and_the_domain"]),
 "V7.1.3": (T, ["a_password_login_writes_one_login_event_for_the_account", "a_federated_step_up_writes_one_security_event", "admin_mfa_reset_writes_a_security_audit_event"]),
 "V7.1.4": (T, ["a_masked_failure_carries_its_identifiers_in_the_logged_detail"]),
 "V7.2.1": (T, ["a_password_login_writes_one_login_event_for_the_account", "failed_logins_coalesce_per_window_and_the_sweep_writes_one_summary"]),
 "V7.2.2": (G, "Owner Q21: log every refused authorization decision."),
 "V7.3.1": (P, "Structured JSON logs escape field values (tracing-subscriber)."),
 "V7.3.3": (T, ["audit_chain_has_no_fork_under_concurrent_appends", "a_forged_header_with_a_random_chain_batch_ref_fails_full_chain_and_single_row_verification"]),
 "V7.3.4": (P, "Timestamps are UTC from the host clock; NTP is the host's."),
 "V7.4.1": (T, ["a_panic_returns_the_masked_500_envelope_and_the_server_keeps_serving", "v2_wrong_password_is_generic"]),
 "V7.4.2": (P, "Typed errors and AppError throughout; unwrap is denied in production code."),
 "V7.4.3": (T, ["a_panic_returns_the_masked_500_envelope_and_the_server_keeps_serving"]),
 # V8 data protection.
 "V8.1.1": (T, ["v14_4_api_response_headers"]),
 "V8.1.2": (P, "Caches hold metadata and permissions, not records (docs/caching.md)."),
 "V8.1.3": (P, "The API takes typed JSON bodies; no hidden fields."),
 "V8.1.4": (T, ["a_key_past_its_quota_is_refused"]),
 "V8.2.1": (T, ["v14_4_api_response_headers"]),
 "V8.2.2": (P, "The web app keeps no session data in browser storage."),
 "V8.2.3": (G, "Owner B: clear cached data on sign-out in the web app."),
 "V8.3.1": (T, ["v3_1_1_session_token_never_in_a_url"]),
 "V8.3.2": (G, "Owner Y5-T5: data export and deletion on demand."),
 "V8.3.3": (P, "Consent capture and privacy notices (portal consent routes)."),
 "V8.3.4": (P, "Every attribute carries a sensitivity label (A1-T1)."),
 "V8.3.5": (G, "Owner Q15: audit reads of sensitive fields."),
 "V8.3.6": (P, "Key material uses zeroize where held (attome-auth envelope)."),
 "V8.3.7": (P, "AES-256-GCM envelope encryption (envelope.rs)."),
 "V8.3.8": (G, "Owner A1-T2: retention by sensitivity label."),
 # V9 communications.
 "V9.1.1": (P, "TLS terminates at the edge (nginx or the built-in edge); HSTS is sent on every response (`v14_4_api_response_headers`)."),
 "V9.1.2": (P, "rustls with its default (strong) cipher suites."),
 "V9.1.3": (P, "rustls supports TLS 1.2 and 1.3 only."),
 "V9.2.1": (P, "Outbound TLS verifies against webpki roots (Q21-T1 client)."),
 "V9.2.2": (G, "Owner Q21: TLS on management and monitoring ports."),
 "V9.2.3": (T, ["a_tampered_body_is_refused_before_the_nonce_store"]),
 "V9.2.4": (NA, "Certificate revocation is the edge proxy's (nginx) configuration."),
 # V10 malicious code.
 "V10.2.1": (P, "No phone-home; outbound calls are listed in docs/security/outbound-calls.md."),
 "V10.2.2": (T, ["isolation_headers_on_pages_and_api_responses"]),
 "V10.3.1": (P, "Updates are downloaded over HTTPS and verified (docs/release-signing.md)."),
 "V10.3.2": (G, "Owner AC7-T5: code signing waits for the release key."),
 "V10.3.3": (NA, "DNS is the customer's; no shared subdomains."),
 # V11 business logic.
 "V11.1.1": (T, ["a_two_step_approval_moves_the_record_to_its_target_exactly_once"]),
 "V11.1.2": (T, ["a_decision_racing_a_retry_executes_the_approval_once"]),
 "V11.1.3": (T, ["a_key_past_its_quota_is_refused"]),
 "V11.1.4": (T, ["a_throttled_known_account_is_indistinguishable_from_a_throttled_unknown_one"]),
 "V11.1.5": (T, ["bot_handoff_daily_cap_refuses_once_exhausted"]),
 "V11.1.6": (T, ["a_hundred_concurrent_identical_requests_run_the_handler_once"]),
 "V11.1.7": (G, "Owner Q21: business-level anomaly alerts."),
 "V11.1.8": (G, "Owner Q21: configurable alerting on automated attacks."),
 # V12 files.
 "V12.1.1": (T, ["create_rejects_when_it_would_exceed_the_deployment_storage_quota"]),
 "V12.1.2": (G, "Owner Z6: uncompressed-size limits on archives."),
 "V12.1.3": (T, ["create_rejects_when_it_would_exceed_the_per_user_storage_quota"]),
 "V12.2.1": (T, ["an_html_upload_session_is_refused"]),
 "V12.3.1": (P, "Stored files are keyed by id; the name is metadata only."),
 "V12.3.2": (P, "Stored files are keyed by id; the name is metadata only."),
 "V12.3.3": (P, "Stored files are keyed by id; the name is metadata only."),
 "V12.3.4": (T, ["a_presigned_download_is_served_as_an_attachment"]),
 "V12.3.5": (P, "File metadata never reaches a system API."),
 "V12.3.6": (P, "Extensions run in a sandbox only (Y10); no remote includes."),
 "V12.4.1": (P, "Files live in the object store, never under the web root."),
 "V12.4.2": (T, ["clamd_that_never_answers_is_a_timeout", "clamd_answering_garbage_is_an_unexpected_response_without_leaking_it"]),
 "V12.5.1": (P, "The web tier serves the built app's files only."),
 "V12.5.2": (T, ["a_presigned_download_is_served_as_an_attachment", "an_html_upload_session_is_refused"]),
 "V12.6.1": (T, ["a_private_rfc1918_target_is_rejected", "a_public_purpose_refuses_private_and_metadata_literals"]),
 # V13 API.
 "V13.1.1": (P, "One HTTP stack (axum/hyper) parses every request."),
 "V13.1.3": (T, ["v3_1_1_session_token_never_in_a_url"]),
 "V13.1.4": (T, ["v4_1_1_unauthenticated_api_is_refused", "admin_routes_forbid_a_non_admin_and_admit_an_admin"]),
 "V13.1.5": (T, ["v13_2_5_unexpected_content_type_is_refused"]),
 "V13.2.1": (T, ["admin_routes_forbid_a_non_admin_and_admit_an_admin"]),
 "V13.2.2": (T, ["an_unknown_field_is_a_validation_error", "a_deep_json_body_is_refused_before_the_handler"]),
 "V13.2.3": (T, ["v4_2_2_cross_site_mutation_is_refused"]),
 "V13.2.5": (T, ["v13_2_5_unexpected_content_type_is_refused"]),
 "V13.2.6": (T, ["a_tampered_body_is_refused_before_the_nonce_store"]),
 "V13.3.1": (NA, "No SOAP or XML request bodies."),
 "V13.3.2": (NA, "No WS-Security."),
 "V13.4.1": (T, ["a_deep_json_body_is_refused_before_the_handler"]),
 "V13.4.2": (NA, "No GraphQL; authorization sits in the engine layer."),
 # V14 configuration.
 "V14.1.1": (P, "The release gate (docs/release.md)."),
 "V14.1.2": (P, "Rust release profile; memory safety by the language."),
 "V14.1.3": (P, "Hardened defaults in config.production.example.json."),
 "V14.1.4": (P, "Compose and Helm deploy scripts (deploy/)."),
 "V14.2.1": (P, "cargo deny advisories in the release gate."),
 "V14.2.2": (P, "The release archive ships the binary and its web app only."),
 "V14.2.3": (P, "The web app is self-hosted; no CDN assets."),
 "V14.2.4": (P, "crates.io and npm only; no git dependencies (deny.toml)."),
 "V14.2.5": (P, "SBOM in every release (attome-release sbom.rs; AC7-T11 admin route)."),
 "V14.2.6": (G, "Owner Y10: extensions are sandboxed; third-party crates are not."),
 "V14.3.2": (P, "The fleet console and debug routes compile only into debug builds."),
 "V14.3.3": (T, ["v14_3_3_no_version_in_headers"]),
 "V14.4.1": (T, ["v14_4_api_response_headers"]),
 "V14.4.2": (G, "Owner Q21: API responses carry no Content-Disposition; stored files do (`a_presigned_download_is_served_as_an_attachment`)."),
 "V14.4.3": (T, ["v14_4_3_page_has_csp", "csp_header_carries_the_page_nonce"]),
 "V14.4.4": (T, ["v14_4_api_response_headers"]),
 "V14.4.5": (T, ["v14_4_api_response_headers"]),
 "V14.4.6": (T, ["v14_4_api_response_headers"]),
 "V14.4.7": (T, ["v14_4_3_page_has_csp"]),
 "V14.5.1": (G, "Owner Q21: log requests with unsupported methods."),
 "V14.5.2": (T, ["v4_2_2_cross_site_mutation_is_refused"]),
 "V14.5.3": (T, ["v14_5_3_cors_allow_list", "disallowed_origin_preflight_is_not_echoed"]),
 "V14.5.4": (T, ["ignores_forwarded_for_from_an_untrusted_socket_peer", "forwarded_host_counts_only_from_a_trusted_peer"]),
}

def locate(name):
    out = subprocess.run(["git", "-C", str(REPO), "grep", "--untracked", "-l", "-E", rf"fn {name}\b", "--", "crates"],
                         capture_output=True, text=True).stdout.split()
    for path in out:
        src = (REPO / path).read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(src):
            if re.search(r"fn " + re.escape(name) + r"(?![a-z0-9_])", line) and any("test]" in l for l in src[max(0, i - 15):i]):
                return path
    sys.exit(f"cited test not found: {name}")

rows = [r for r in csv.DictReader(open(CSV, encoding="utf-8")) if r["level2"].strip()]
missing = [r["req_id"] for r in rows if r["req_id"] not in M]
if missing:
    sys.exit("unmapped: " + " ".join(missing))
extra = [k for k in M if k not in {r["req_id"] for r in rows}]
if extra:
    sys.exit("not level 2 requirements: " + " ".join(extra))

counts = {}
lines = []
chapter = None
for r in rows:
    if r["chapter_id"] != chapter:
        chapter = r["chapter_id"]
        lines += ["", f"## {chapter} {r['chapter_name']}", "", "| Requirement | Status | Evidence |", "|---|---|---|"]
    status, ev = M[r["req_id"]]
    counts[status] = counts.get(status, 0) + 1
    if isinstance(ev, list):
        ev = "; ".join(f"`{locate(t)}` `{t}`" for t in ev)
    desc = re.sub(r"\s*\(\[C\d+\]\([^)]*\)\)", "", r["req_description"]).replace("|", "\\|").strip()
    if len(desc) > 140:
        desc = desc[:137].rsplit(" ", 1)[0] + "…"
    lines.append(f"| **{r['req_id']}** {desc} | {status} | {ev} |")

head = f"""# OWASP ASVS 4.0.3 level 2

Every level 2 requirement of the [OWASP Application Security Verification Standard 4.0.3](https://github.com/OWASP/ASVS/tree/v4.0.3)
({len(rows)} requirements) and how Attome meets it (roadmap Q21-T5). Generated from the official
ASVS CSV by `scripts/security/asvs-l2.py` (its docstring says how); each cited test was found
in this repository, with its test attribute, when the page was generated. Edit the map there, not here.

- **Tested**: the named tests prove it. `crates/apps/attome/tests/asvs.rs` proves the
  cookie, CSRF, CORS, header and content-type requirements through the whole server stack
  (`cargo test -p attome --test asvs -- --test-threads=1`); the other tests are cited where they live.
- **Gap**: it applies and has no automated proof yet. The owner is the roadmap feature that closes it.
- **Process**: a practice outside the code; the evidence is where the row says.
- **N/A**: it does not apply, and the row says why.

| Status | Requirements |
|---|---|
""" + "\n".join(f"| {s} | {counts.get(s, 0)} |" for s in (T, G, P, NA))

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(head + "\n" + "\n".join(lines) + "\n", encoding="utf-8", newline="\n")
print(OUT, counts)
