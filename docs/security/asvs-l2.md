# OWASP ASVS 4.0.3 level 2

Every level 2 requirement of the [OWASP Application Security Verification Standard 4.0.3](https://github.com/OWASP/ASVS/tree/v4.0.3)
(259 requirements) and how Attome meets it (roadmap Q21-T5). Generated from the official
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
| Tested | 113 |
| Gap | 41 |
| Process | 91 |
| N/A | 14 |

## V1 Architecture, Design and Threat Modeling

| Requirement | Status | Evidence |
|---|---|---|
| **V1.1.1** Verify the use of a secure software development lifecycle that addresses security in all stages of development. | Process | Release gate (`attome-release --check`, docs/release.md) and the review rules in CONTRIBUTING.md. |
| **V1.1.2** Verify the use of threat modeling for every design change or sprint planning to identify threats, plan for countermeasures, facilitate… | Process | docs/security/threat-model.md. |
| **V1.1.3** Verify that all user stories and features contain functional security constraints, such as "As a user, I should be able to view and edit… | Process | Each roadmap task carries do_not and stop_and_ask_if security constraints. |
| **V1.1.4** Verify documentation and justification of all the application's trust boundaries, components, and significant data flows. | Process | docs/security/threat-model.md (trust boundaries) and docs/architecture.md. |
| **V1.1.5** Verify definition and security analysis of the application's high-level architecture and all connected remote services. | Process | docs/architecture.md. |
| **V1.1.6** Verify implementation of centralized, simple (economy of design), vetted, secure, and reusable security controls to avoid duplicate,… | Process | One authn middleware, one authz policy layer, one SSRF-guarded client (Q21-T1). |
| **V1.1.7** Verify availability of a secure coding checklist, security requirements, guideline, or policy to all developers and testers. | Process | CONTRIBUTING.md and the coding guidelines. |
| **V1.2.1** Verify the use of unique or special low-privilege operating system accounts for all application components, services, and servers. | Gap | Owner U1: the installer's service account; container images run as non-root. |
| **V1.2.2** Verify that communications between application components, including APIs, middleware and data layers, are authenticated. Components… | Process | Postgres and Redis connections authenticate; server-to-server calls are HMAC-signed and replay-checked (S2S). |
| **V1.2.3** Verify that the application uses a single vetted authentication mechanism that is known to be secure, can be extended to include strong… | Tested | `crates/apps/attome/tests/admin_routes_forbid_non_admin.rs` `admin_routes_forbid_a_non_admin_and_admit_an_admin` |
| **V1.2.4** Verify that all authentication pathways and identity management APIs implement consistent authentication security control strength, such… | Tested | `crates/apps/attome/tests/asvs.rs` `v4_1_1_unauthenticated_api_is_refused`; `crates/engine/attome-api/tests/s2s.rs` `an_s2s_caller_is_refused_on_step_up_guarded_routes` |
| **V1.4.1** Verify that trusted enforcement points, such as access control gateways, servers, and serverless functions, enforce access controls.… | Tested | `crates/apps/attome/tests/asvs.rs` `v4_1_1_unauthenticated_api_is_refused` |
| **V1.4.4** Verify the application uses a single and well-vetted access control mechanism for accessing protected data and resources. All requests… | Tested | `crates/apps/attome/tests/admin_routes_forbid_non_admin.rs` `admin_routes_forbid_a_non_admin_and_admit_an_admin` |
| **V1.4.5** Verify that attribute or feature-based access control is used whereby the code checks the user's authorization for a feature/data item… | Process | Privileges are entity and action keys checked by the one authorization layer (attome-security). |
| **V1.5.1** Verify that input and output requirements clearly define how to handle and process data based on type, content, and applicable laws,… | Process | Typed field metadata (docs/data-layer.md); validation in the record engine. |
| **V1.5.2** Verify that serialization is not used when communicating with untrusted clients. If this is not possible, ensure that adequate integrity… | N/A | No native object serialization reaches clients; JSON only. |
| **V1.5.3** Verify that input validation is enforced on a trusted service layer. | Tested | `crates/engine/attome-ai/src/actions/classify.rs` `an_unknown_field_is_a_validation_error` |
| **V1.5.4** Verify that output encoding occurs close to or by the interpreter for which it is intended. | Tested | `crates/engine/attome-notification/src/dispatch.rs` `apply_variables_html_escapes_script_markup_in_values` |
| **V1.6.1** Verify that there is an explicit policy for management of cryptographic keys and that a cryptographic key lifecycle follows a key… | Process | docs/release-signing.md and the key-ring configuration (config-reference.md). |
| **V1.6.2** Verify that consumers of cryptographic services protect key material and other secrets by using key vaults or API based alternatives. | Gap | Owner Z1-T12: cloud secret stores read at boot. |
| **V1.6.3** Verify that all keys and passwords are replaceable and are part of a well-defined process to re-encrypt sensitive data. | Tested | `crates/foundation/attome-auth/src/jwt.rs` `an_old_kid_still_verifies_while_it_stays_in_the_ring_and_fails_once_removed` |
| **V1.6.4** Verify that the architecture treats client-side secrets--such as symmetric keys, passwords, or API tokens--as insecure and never uses… | Process | The web app holds no secret; sessions are HttpOnly cookies (V3.4). |
| **V1.7.1** Verify that a common logging format and approach is used across the system. | Process | Structured tracing everywhere (docs/architecture.md). |
| **V1.7.2** Verify that logs are securely transmitted to a preferably remote system for analysis, detection, alerting, and escalation. | Gap | Owner Q21: SIEM export is configured per deployment; no automated proof of transport. |
| **V1.8.1** Verify that all sensitive data is identified and classified into protection levels. | Process | Every attribute carries a sensitivity label (A1-T1). |
| **V1.8.2** Verify that all protection levels have an associated set of protection requirements, such as encryption requirements, integrity… | Gap | Owner A1-T2: protections per sensitivity label. |
| **V1.9.1** Verify the application encrypts communications between components, particularly when these components are in different containers,… | Gap | Owner Q21: TLS to Postgres and Redis is configuration; no automated proof. |
| **V1.9.2** Verify that application components verify the authenticity of each side in a communication link to prevent person-in-the-middle attacks.… | Gap | Owner Q21: certificate verification on internal links is configuration. |
| **V1.10.1** Verify that a source code control system is in use, with procedures to ensure that check-ins are accompanied by issues or change… | Process | Git on GitHub; every change is a reviewed commit. |
| **V1.11.1** Verify the definition and documentation of all application components in terms of the business or security functions they provide. | Process | docs/architecture.md. |
| **V1.11.2** Verify that all high-value business logic flows, including authentication, session management and access control, do not share… | Tested | `crates/foundation/attome-server/src/middleware/idempotency.rs` `a_hundred_concurrent_identical_requests_run_the_handler_once` |
| **V1.12.2** Verify that user-uploaded files - if required to be displayed or downloaded from the application - are served by either octet stream… | Tested | `crates/foundation/attome-storage/tests/presign_roundtrip.rs` `a_presigned_download_is_served_as_an_attachment`; `crates/engine/attome-api/tests/file_upload_pipeline.rs` `a_promoted_file_is_presigned_as_an_attachment` |
| **V1.14.1** Verify the segregation of components of differing trust levels through well-defined security controls, firewall rules, API gateways,… | Process | Deployment isolation per customer (docs/architecture.md). |
| **V1.14.2** Verify that binary signatures, trusted connections, and verified endpoints are used to deploy binaries to remote devices. | Gap | Owner AC7-T5: signed release binaries wait for the release key. |
| **V1.14.3** Verify that the build pipeline warns of out-of-date or insecure components and takes appropriate actions. | Process | cargo deny in the release gate (deny.toml). |
| **V1.14.4** Verify that the build pipeline contains a build step to automatically build and verify the secure deployment of the application,… | Process | The release gate builds and checks the deployable (docs/release.md). |
| **V1.14.5** Verify that application deployments adequately sandbox, containerize and/or isolate at the network level to delay and deter attackers… | Process | Helm and compose profiles (deploy/). |
| **V1.14.6** Verify the application does not use unsupported, insecure, or deprecated client-side technologies such as NSAPI plugins, Flash,… | N/A | No Flash, ActiveX, Silverlight or Java applets. |

## V2 Authentication

| Requirement | Status | Evidence |
|---|---|---|
| **V2.1.1** Verify that user set passwords are at least 12 characters in length (after multiple spaces are combined). | Tested | `crates/foundation/attome-auth/src/password.rs` `policy_enforces_the_character_minimum_at_its_boundary` |
| **V2.1.2** Verify that passwords of at least 64 characters are permitted, and that passwords of more than 128 characters are denied. | Tested | `crates/foundation/attome-auth/src/password.rs` `policy_enforces_the_byte_maximum_at_its_boundary` |
| **V2.1.3** Verify that password truncation is not performed. However, consecutive multiple spaces may be replaced by a single space. | Gap | Owner Q7: a test that a password is not truncated. |
| **V2.1.4** Verify that any printable Unicode character, including language neutral characters such as spaces and Emojis are permitted in passwords. | Tested | `crates/foundation/attome-auth/src/password.rs` `policy_counts_the_minimum_in_characters_not_bytes` |
| **V2.1.5** Verify users can change their password. | Gap | Owner Q7: an HTTP test of password change. |
| **V2.1.6** Verify that password change functionality requires the user's current and new password. | Gap | Owner Q7: an HTTP test that change needs the current password. |
| **V2.1.7** Verify that passwords submitted during account registration, login, and password change are checked against a set of breached passwords… | Tested | `crates/foundation/attome-auth/src/password_policy.rs` `password_policy_refuses_a_shipped_breached_password` |
| **V2.1.8** Verify that a password strength meter is provided to help users set a stronger password. | Gap | Owner Q7: a strength meter in the web app. |
| **V2.1.9** Verify that there are no password composition rules limiting the type of characters permitted. There should be no requirement for upper… | Tested | `crates/foundation/attome-auth/src/password.rs` `policy_has_no_composition_rules` |
| **V2.1.10** Verify that there are no periodic credential rotation or password history requirements. | Process | No rotation or history rule exists. |
| **V2.1.11** Verify that "paste" functionality, browser password helpers, and external password managers are permitted. | Process | The sign-in form does not block paste or password managers. |
| **V2.1.12** Verify that the user can choose to either temporarily view the entire masked password, or temporarily view the last typed character of… | Gap | Owner Q7: show-password toggle in the web app. |
| **V2.2.1** Verify that anti-automation controls are effective at mitigating breached credential testing, brute force, and account lockout attacks.… | Tested | `crates/apps/attome/tests/account_throttle.rs` `a_throttled_known_account_is_indistinguishable_from_a_throttled_unknown_one`; `crates/apps/attome/tests/asvs.rs` `v2_wrong_password_is_generic` |
| **V2.2.2** Verify that the use of weak authenticators (such as SMS and email) is limited to secondary verification and transaction approval and not… | Process | Email, SMS and WhatsApp codes are second factors and confirmations only (otp.rs). |
| **V2.2.3** Verify that secure notifications are sent to users after updates to authentication details, such as credential resets, email or address… | Gap | Owner Q5: notify a user when a credential changes. |
| **V2.3.1** Verify system generated initial passwords or activation codes SHOULD be securely randomly generated, SHOULD be at least 6 characters… | Tested | `crates/foundation/attome-auth/tests/register_flow.rs` `an_invitation_token_reused_after_registration_is_rejected` |
| **V2.3.2** Verify that enrollment and use of user-provided authentication devices are supported, such as a U2F or FIDO tokens. | Tested | `crates/foundation/attome-auth/tests/webauthn_flow.rs` `registration_then_assertion_succeeds` |
| **V2.3.3** Verify that renewal instructions are sent with sufficient time to renew time bound authenticators. | N/A | No time-bound authenticators are issued. |
| **V2.4.1** Verify that passwords are stored in a form that is resistant to offline attacks. Passwords SHALL be salted and hashed using an approved… | Tested | `crates/foundation/attome-auth/tests/login_mfa.rs` `an_argon2_recovery_code_still_verifies` |
| **V2.4.2** Verify that the salt is at least 32 bits in length and be chosen arbitrarily to minimize salt value collisions among stored hashes. For… | Process | Argon2id with a random 16-byte salt (password.rs). |
| **V2.4.3** Verify that if PBKDF2 is used, the iteration count SHOULD be as large as verification server performance will allow, typically at least… | N/A | PBKDF2 is not used. |
| **V2.4.4** Verify that if bcrypt is used, the work factor SHOULD be as large as verification server performance will allow, with a minimum of 10. | N/A | bcrypt is not used. |
| **V2.4.5** Verify that an additional iteration of a key derivation function is performed, using a salt value that is secret and known only to the… | Process | API-key secrets add a peppered HMAC (apikey_hash.rs). |
| **V2.5.1** Verify that a system generated initial activation or recovery secret is not sent in clear text to the user. | Tested | `crates/foundation/attome-auth/tests/reset_flow.rs` `confirm_expires_other_reset_links_and_revokes_every_refresh_token_itself` |
| **V2.5.2** Verify password hints or knowledge-based authentication (so-called "secret questions") are not present. | N/A | No password hints or secret questions exist. |
| **V2.5.3** Verify password credential recovery does not reveal the current password in any way. | Tested | `crates/apps/attome/tests/account_throttle.rs` `a_throttled_reset_request_is_identical_for_known_and_unknown_emails` |
| **V2.5.4** Verify shared or default accounts are not present (e.g. "root", "admin", or "sa"). | Process | The first administrator is bootstrapped by email; no default account exists. |
| **V2.5.5** Verify that if an authentication factor is changed or replaced, that the user is notified of this event. | Gap | Owner Q5: notify a user when a factor changes. |
| **V2.5.6** Verify forgotten password, and other recovery paths use a secure recovery mechanism, such as time-based OTP (TOTP) or other soft token,… | Tested | `crates/foundation/attome-auth/tests/reset_flow.rs` `confirm_expires_other_reset_links_and_revokes_every_refresh_token_itself` |
| **V2.5.7** Verify that if OTP or multi-factor authentication factors are lost, that evidence of identity proofing is performed at the same level as… | Tested | `crates/engine/attome-api/tests/authz.rs` `admin_mfa_reset_of_an_admin_waits_for_a_second_admin`; `crates/engine/attome-api/tests/authz.rs` `admin_mfa_reset_needs_a_step_up` |
| **V2.6.1** Verify that lookup secrets can be used only once. | Tested | `crates/apps/attome/tests/portal_auth.rs` `a_recovery_code_signs_in_once_and_regeneration_voids_the_old_set` |
| **V2.6.2** Verify that lookup secrets have sufficient randomness (112 bits of entropy), or if less than 112 bits of entropy, salted with a unique… | Process | Recovery codes are random from the OS generator (mfa.rs). |
| **V2.6.3** Verify that lookup secrets are resistant to offline attacks, such as predictable values. | Tested | `crates/foundation/attome-auth/tests/login_mfa.rs` `an_argon2_recovery_code_still_verifies` |
| **V2.7.1** Verify that clear text out of band (NIST "restricted") authenticators, such as SMS or PSTN, are not offered by default, and stronger… | Process | SMS codes are a second factor only (otp.rs). |
| **V2.7.2** Verify that the out of band verifier expires out of band authentication requests, codes, or tokens after 10 minutes. | Tested | `crates/foundation/attome-auth/tests/otp_flow.rs` `code_verifies_once` |
| **V2.7.3** Verify that the out of band verifier authentication requests, codes, or tokens are only usable once, and only for the original… | Tested | `crates/foundation/attome-auth/tests/otp_flow.rs` `code_verifies_once` |
| **V2.7.4** Verify that the out of band authenticator and verifier communicates over a secure independent channel. | Process | Codes go by the configured email, SMS or WhatsApp provider. |
| **V2.7.5** Verify that the out of band verifier retains only a hashed version of the authentication code. | Tested | `crates/foundation/attome-auth/tests/otp_flow.rs` `code_verifies_once` |
| **V2.7.6** Verify that the initial authentication code is generated by a secure random number generator, containing at least 20 bits of entropy… | Process | Six digits from the OS generator (otp.rs). |
| **V2.8.1** Verify that time-based OTPs have a defined lifetime before expiring. | Tested | `crates/foundation/attome-auth/tests/login_mfa.rs` `complete_pending_login_rejects_replayed_totp_code_with_a_fresh_pending_token` |
| **V2.8.2** Verify that symmetric keys used to verify submitted OTPs are highly protected, such as by using a hardware security module or secure… | Process | TOTP secrets are encrypted at rest (encrypted_columns.rs). |
| **V2.8.3** Verify that approved cryptographic algorithms are used in the generation, seeding, and verification of OTPs. | Process | totp-rs (RFC 6238, HMAC-SHA1 as authenticator apps require). |
| **V2.8.4** Verify that time-based OTP can be used only once within the validity period. | Tested | `crates/foundation/attome-auth/tests/login_mfa.rs` `complete_pending_login_rejects_replayed_totp_code_with_a_fresh_pending_token` |
| **V2.8.5** Verify that if a time-based multi-factor OTP token is re-used during the validity period, it is logged and rejected with secure… | Gap | Owner Q5: log and alert on a reused TOTP. |
| **V2.8.6** Verify physical single-factor OTP generator can be revoked in case of theft or other loss. Ensure that revocation is immediately… | N/A | No physical OTP generators are issued. |
| **V2.8.7** Verify that biometric authenticators are limited to use only as secondary factors in conjunction with either something you have and… | N/A | No biometric verification on the server. |
| **V2.9.1** Verify that cryptographic keys used in verification are stored securely and protected against disclosure, such as using a Trusted… | Process | Passkey private keys never leave the authenticator (webauthn.rs). |
| **V2.9.2** Verify that the challenge nonce is at least 64 bits in length, and statistically unique or unique over the lifetime of the cryptographic… | Tested | `crates/foundation/attome-auth/tests/webauthn_flow.rs` `replayed_challenge_is_refused` |
| **V2.9.3** Verify that approved cryptographic algorithms are used in the generation, seeding, and verification. | Tested | `crates/foundation/attome-auth/tests/webauthn_flow.rs` `registration_then_assertion_succeeds`; `crates/foundation/attome-auth/tests/webauthn_flow.rs` `lower_sign_count_is_refused` |
| **V2.10.1** Verify that intra-service secrets do not rely on unchanging credentials such as passwords, API keys or shared accounts with privileged… | Process | Service accounts use rotating client-credential tokens (S11-T1) or HMAC-signed S2S requests. |
| **V2.10.2** Verify that if passwords are required for service authentication, the service account used is not a default credential. (e.g. root/root… | Process | Service accounts are named and owned (S11). |
| **V2.10.3** Verify that passwords are stored with sufficient protection to prevent offline recovery attacks, including local system access. | Process | API-key secrets are stored as peppered hashes (apikey_hash.rs). |
| **V2.10.4** Verify passwords, integrations with databases and third-party systems, seeds and internal secrets, and API keys are managed securely and… | Process | Secrets come from the environment through ${VAR} placeholders (config-reference.md). |

## V3 Session Management

| Requirement | Status | Evidence |
|---|---|---|
| **V3.1.1** Verify the application never reveals session tokens in URL parameters. | Tested | `crates/apps/attome/tests/asvs.rs` `v3_1_1_session_token_never_in_a_url` |
| **V3.2.1** Verify the application generates a new session token on user authentication. | Tested | `crates/apps/attome/tests/asvs.rs` `v3_2_1_new_session_token_per_sign_in` |
| **V3.2.2** Verify that session tokens possess at least 64 bits of entropy. | Process | Session JWTs carry a UUIDv7 jti and an HMAC signature (jwt.rs). |
| **V3.2.3** Verify the application only stores session tokens in the browser using secure methods such as appropriately secured cookies (see section… | Tested | `crates/apps/attome/tests/asvs.rs` `v3_4_session_cookie_flags` |
| **V3.2.4** Verify that session tokens are generated using approved cryptographic algorithms. | Process | HS256 or EdDSA through jsonwebtoken (jwt.rs). |
| **V3.3.1** Verify that logout and expiration invalidate the session token, such that the back button or a downstream relying party does not resume… | Tested | `crates/apps/attome/tests/auth_audit_events.rs` `logout_writes_a_logout_event_and_an_anonymous_logout_writes_none`; `crates/foundation/attome-auth/tests/refresh_flow.rs` `a_revoked_token_is_rejected_without_writing_anything`; `crates/apps/attome/tests/revocation_pool_split.rs` `a_revoked_token_stays_revoked_after_the_cache_role_is_flushed` |
| **V3.3.2** If authenticators permit users to remain logged in, verify that re-authentication occurs periodically both when actively used or after… | Gap | Owner Q8: re-authentication after an idle period. |
| **V3.3.3** Verify that the application gives the option to terminate all other active sessions after a successful password change (including change… | Tested | `crates/foundation/attome-auth/tests/reset_flow.rs` `confirm_expires_other_reset_links_and_revokes_every_refresh_token_itself` |
| **V3.3.4** Verify that users are able to view and (having re-entered login credentials) log out of any or all currently active sessions and devices. | Tested | `crates/apps/attome/tests/portal_auth.rs` `admin_disable_and_portal_deactivation_revoke_sessions_through_the_real_paths` |
| **V3.4.1** Verify that cookie-based session tokens have the 'Secure' attribute set. | Tested | `crates/apps/attome/tests/asvs.rs` `v3_4_session_cookie_flags` |
| **V3.4.2** Verify that cookie-based session tokens have the 'HttpOnly' attribute set. | Tested | `crates/apps/attome/tests/asvs.rs` `v3_4_session_cookie_flags` |
| **V3.4.3** Verify that cookie-based session tokens utilize the 'SameSite' attribute to limit exposure to cross-site request forgery attacks. | Tested | `crates/apps/attome/tests/asvs.rs` `v3_4_session_cookie_flags` |
| **V3.4.4** Verify that cookie-based session tokens use the "__Host-" prefix so cookies are only sent to the host that initially set the cookie. | Tested | `crates/apps/attome/tests/asvs.rs` `v3_4_session_cookie_flags` |
| **V3.4.5** Verify that if the application is published under a domain name with other applications that set or use session cookies that might… | Tested | `crates/apps/attome/tests/asvs.rs` `v3_4_session_cookie_flags` |
| **V3.5.1** Verify the application allows users to revoke OAuth tokens that form trust relationships with linked applications. | Gap | Owner S11: revoke an OAuth client's tokens from the UI. |
| **V3.5.2** Verify the application uses session tokens rather than static API secrets and keys, except with legacy implementations. | Process | Browser sessions use session tokens; API keys are for machines only. |
| **V3.5.3** Verify that stateless session tokens use digital signatures, encryption, and other countermeasures to protect against tampering,… | Tested | `crates/foundation/attome-auth/src/jwt.rs` `an_old_kid_still_verifies_while_it_stays_in_the_ring_and_fails_once_removed` |
| **V3.7.1** Verify the application ensures a full, valid login session or requires re-authentication or secondary verification before allowing any… | Tested | `crates/apps/attome/tests/step_up_enforcement_http.rs` `api_key_creation_needs_a_step_up_on_the_sessions_own_family`; `crates/foundation/attome-auth/tests/step_up.rs` `a_password_step_up_elevates_only_the_callers_family` |

## V4 Access Control

| Requirement | Status | Evidence |
|---|---|---|
| **V4.1.1** Verify that the application enforces access control rules on a trusted service layer, especially if client-side access control is… | Tested | `crates/apps/attome/tests/asvs.rs` `v4_1_1_unauthenticated_api_is_refused` |
| **V4.1.2** Verify that all user and data attributes and policy information used by access controls cannot be manipulated by end users unless… | Tested | `crates/foundation/attome-auth/tests/session_context.rs` `a_session_id_cannot_reach_another_users_or_a_dead_family` |
| **V4.1.3** Verify that the principle of least privilege exists - users should only be able to access functions, data files, URLs, controllers,… | Tested | `crates/apps/attome/tests/admin_routes_forbid_non_admin.rs` `admin_routes_forbid_a_non_admin_and_admit_an_admin` |
| **V4.1.5** Verify that access controls fail securely including when an exception occurs. | Tested | `crates/foundation/attome-auth/tests/step_up.rs` `an_unreachable_store_refuses_a_google_step_up`; `crates/engine/attome-metric/tests/metric.rs` `a_query_backed_metric_that_tries_to_write_fails_under_the_readonly_pool_and_is_masked` |
| **V4.2.1** Verify that sensitive data and APIs are protected against Insecure Direct Object Reference (IDOR) attacks targeting creation, reading,… | Tested | `crates/engine/attome-api/tests/chat_api.rs` `another_users_conversation_is_not_found_on_every_route_and_nothing_changes` |
| **V4.2.2** Verify that the application or framework enforces a strong anti-CSRF mechanism to protect authenticated functionality, and effective… | Tested | `crates/apps/attome/tests/asvs.rs` `v4_2_2_cross_site_mutation_is_refused`; `crates/apps/attome/tests/middleware_pipeline.rs` `csrf_rejected_without_reading_body` |
| **V4.3.1** Verify administrative interfaces use appropriate multi-factor authentication to prevent unauthorized use. | Partial | Q5-T3: password and provider sign-in apply the role policy, which always requires a factor of a `system.admin` holder (`attome_security::mfa_policy::requirement_for`; `tests/mfa_role_policy.rs`). An HTTP-level proof is still owed. |
| **V4.3.2** Verify that directory browsing is disabled unless deliberately desired. Additionally, applications should not allow discovery or… | Process | The web tier serves the built app only; no directory listing. |
| **V4.3.3** Verify the application has additional authorization (such as step up or adaptive authentication) for lower value systems, and / or… | Tested | `crates/engine/attome-api/tests/authz.rs` `admin_mfa_reset_of_an_admin_waits_for_a_second_admin` |

## V5 Validation, Sanitization and Encoding

| Requirement | Status | Evidence |
|---|---|---|
| **V5.1.1** Verify that the application has defenses against HTTP parameter pollution attacks, particularly if the application framework makes no… | Gap | Owner S1: a test that a repeated query parameter is refused. |
| **V5.1.2** Verify that frameworks protect against mass parameter assignment attacks, or that the application has countermeasures to protect against… | Tested | `crates/engine/attome-core/src/formula.rs` `an_unknown_field_is_rejected` |
| **V5.1.3** Verify that all input (HTML form fields, REST requests, URL parameters, HTTP headers, cookies, batch files, RSS feeds, etc) is validated… | Tested | `crates/engine/attome-ai/src/actions/classify.rs` `an_unknown_field_is_a_validation_error` |
| **V5.1.4** Verify that structured data is strongly typed and validated against a defined schema including allowed characters, length and pattern… | Tested | `crates/foundation/attome-server/src/middleware/json_shape.rs` `a_deep_json_body_is_refused_before_the_handler` |
| **V5.1.5** Verify that URL redirects and forwards only allow destinations which appear on an allow list, or show a warning when redirecting to… | Tested | `crates/engine/attome-content/tests/redirect.rs` `a_redirect_never_names_a_page_outside_the_audience` |
| **V5.2.1** Verify that all untrusted HTML input from WYSIWYG editors or similar is properly sanitized with an HTML sanitizer library or framework… | Gap | Owner A2: rich-text sanitization (ammonia) has no HTTP test. |
| **V5.2.2** Verify that unstructured data is sanitized to enforce safety measures such as allowed characters and length. | Tested | `crates/engine/attome-search/src/dsl.rs` `arabic_injection_shaped_and_mixed_script_input_is_handled` |
| **V5.2.3** Verify that the application sanitizes user input before passing to mail systems to protect against SMTP or IMAP injection. | Gap | Owner Z8: a test that header injection in a subject is refused. |
| **V5.2.4** Verify that the application avoids the use of eval() or other dynamic code execution features. Where there is no alternative, any user… | Process | The rule language is a typed interpreter with budgets, not eval (attome-rules). |
| **V5.2.5** Verify that the application protects against template injection attacks by ensuring that any user input being included is sanitized or… | Tested | `crates/engine/attome-notification/src/dispatch.rs` `apply_variables_html_escapes_script_markup_in_values` |
| **V5.2.6** Verify that the application protects against SSRF attacks, by validating or sanitizing untrusted data or HTTP file metadata, such as… | Tested | `crates/apps/attome/tests/outbound_client_guard.rs` `a_redirect_to_the_metadata_address_is_refused`; `crates/engine/attome-events/tests/ssrf.rs` `a_private_rfc1918_target_is_rejected` |
| **V5.2.7** Verify that the application sanitizes, disables, or sandboxes user-supplied Scalable Vector Graphics (SVG) scriptable content,… | Gap | Owner Z6: SVG uploads are not sanitized; they are served as attachments only. |
| **V5.2.8** Verify that the application sanitizes, disables, or sandboxes user-supplied scriptable or expression template language content, such as… | Tested | `crates/engine/attome-notification/src/dispatch.rs` `apply_variables_html_escapes_script_markup_in_values` |
| **V5.3.1** Verify that output encoding is relevant for the interpreter and context required. For example, use encoders specifically for HTML… | Tested | `crates/engine/attome-docgen/tests/hidden_field_renders_empty.rs` `a_visible_field_substitutes_its_html_escaped_value` |
| **V5.3.2** Verify that output encoding preserves the user's chosen character set and locale, such that any Unicode character point is valid and… | Tested | `crates/engine/attome-search/src/dsl.rs` `arabic_injection_shaped_and_mixed_script_input_is_handled` |
| **V5.3.3** Verify that context-aware, preferably automated - or at worst, manual - output escaping protects against reflected, stored, and DOM… | Process | Angular templates escape by default; bypassSecurityTrust is reviewed. |
| **V5.3.4** Verify that data selection or database queries (e.g. SQL, HQL, ORM, NoSQL) use parameterized queries, ORMs, entity frameworks, or are… | Tested | `crates/engine/attome-search/src/dsl.rs` `a_sql_injection_shaped_query_is_returned_as_inert_data`; `crates/engine/attome-search/src/dsl.rs` `an_injection_payload_inside_a_field_value_is_still_just_a_string` |
| **V5.3.5** Verify that where parameterized or safer mechanisms are not present, context-specific output encoding is used to protect against… | Process | Dynamic identifiers come from metadata through quote_ident (guidelines §4). |
| **V5.3.6** Verify that the application protects against JSON injection attacks, JSON eval attacks, and JavaScript expression evaluation. | Process | JSON is built with serde_json, never by string concatenation. |
| **V5.3.7** Verify that the application protects against LDAP injection vulnerabilities, or that specific security controls to prevent LDAP… | N/A | No LDAP. |
| **V5.3.8** Verify that the application protects against OS command injection and that operating system calls use parameterized OS queries or use… | Process | No shell commands run with request input. |
| **V5.3.9** Verify that the application protects against Local File Inclusion (LFI) or Remote File Inclusion (RFI) attacks. | Process | Files are addressed by stored ids, never by request paths. |
| **V5.3.10** Verify that the application protects against XPath injection or XML injection attacks. | Gap | Owner AG2: XML is built by quick-xml writers; no injection test. |
| **V5.4.1** Verify that the application uses memory-safe string, safer memory copy and pointer arithmetic to detect or prevent stack, buffer, or… | Process | Rust; unsafe_code is denied workspace-wide. |
| **V5.4.2** Verify that format strings do not take potentially hostile input, and are constant. | Process | Rust format strings are compile-time constants. |
| **V5.4.3** Verify that sign, range, and input validation techniques are used to prevent integer overflows. | Tested | `crates/foundation/attome-calendar/src/lib.rs` `add_near_the_scan_limit_is_ok_inside_and_exceeded_outside` |
| **V5.5.1** Verify that serialized objects use integrity checks or are encrypted to prevent hostile object creation or data tampering. | Tested | `crates/engine/attome-integration/src/webhook.rs` `a_tampered_body_is_refused_before_the_nonce_store` |
| **V5.5.2** Verify that the application correctly restricts XML parsers to only use the most restrictive configuration possible and to ensure that… | Process | quick-xml does not expand external entities. |
| **V5.5.3** Verify that deserialization of untrusted data is avoided or is protected in both custom code and third-party libraries (such as JSON,… | Process | Only JSON through serde; no native deserialization of untrusted data. |
| **V5.5.4** Verify that when parsing JSON in browsers or JavaScript-based backends, JSON.parse is used to parse the JSON document. Do not use eval()… | Process | The web app parses JSON with JSON.parse (HttpClient). |

## V6 Stored Cryptography

| Requirement | Status | Evidence |
|---|---|---|
| **V6.1.1** Verify that regulated private data is stored encrypted while at rest, such as Personally Identifiable Information (PII), sensitive… | Gap | Owner A1-T2: encryption of personal fields at rest by label. |
| **V6.1.2** Verify that regulated health data is stored encrypted while at rest, such as medical records, medical device details, or de-anonymized… | Gap | Owner A1-T2: encryption of health fields at rest by label. |
| **V6.1.3** Verify that regulated financial data is stored encrypted while at rest, such as financial accounts, defaults or credit history, tax… | Gap | Owner A1-T2: encryption of financial fields at rest by label. |
| **V6.2.1** Verify that all cryptographic modules fail securely, and errors are handled in a way that does not enable Padding Oracle attacks. | Process | Crypto errors map to masked errors (attome-types). |
| **V6.2.2** Verify that industry proven or government approved cryptographic algorithms, modes, and libraries are used, instead of custom coded… | Process | RustCrypto and ring; no custom primitives. |
| **V6.2.3** Verify that encryption initialization vector, cipher configuration, and block modes are configured securely using the latest advice. | Tested | `crates/foundation/attome-auth/src/envelope.rs` `dek_seal_uses_a_fresh_nonce_each_call` |
| **V6.2.4** Verify that random number, encryption or hashing algorithms, key lengths, rounds, ciphers or modes, can be reconfigured, upgraded, or… | Tested | `crates/foundation/attome-auth/src/jwt.rs` `an_old_kid_still_verifies_while_it_stays_in_the_ring_and_fails_once_removed` |
| **V6.2.5** Verify that known insecure block modes (i.e. ECB, etc.), padding modes (i.e. PKCS#1 v1.5, etc.), ciphers with small block sizes (i.e.… | Process | AES-256-GCM only; no ECB or PKCS#1 v1.5 encryption. |
| **V6.2.6** Verify that nonces, initialization vectors, and other single use numbers must not be used more than once with a given encryption key.… | Tested | `crates/foundation/attome-auth/src/envelope.rs` `dek_seal_uses_a_fresh_nonce_each_call` |
| **V6.3.1** Verify that all random numbers, random file names, random GUIDs, and random strings are generated using the cryptographic module's… | Process | Secrets and tokens come from the OS generator. |
| **V6.3.2** Verify that random GUIDs are created using the GUID v4 algorithm, and a Cryptographically-secure Pseudo-random Number Generator… | Process | Ids are UUIDv7 (time-ordered); they are not secrets. |
| **V6.4.1** Verify that a secrets management solution such as a key vault is used to securely create, store, control access to and destroy secrets. | Gap | Owner Z1-T12: cloud secret stores. |
| **V6.4.2** Verify that key material is not exposed to the application but instead uses an isolated security module like a vault for cryptographic… | Gap | Owner Q18: an HSM or KMS for key material. |

## V7 Error Handling and Logging

| Requirement | Status | Evidence |
|---|---|---|
| **V7.1.1** Verify that the application does not log credentials or payment details. Session tokens should only be stored in logs in an… | Tested | `crates/foundation/attome-auth/src/accounts.rs` `a_google_decode_failure_never_logs_or_returns_the_id_token`; `crates/foundation/attome-config/src/secret.rs` `debug_is_redacted` |
| **V7.1.2** Verify that the application does not log other sensitive data as defined under local privacy laws or relevant security policy. | Tested | `crates/engine/attome-portal/src/trusted_account.rs` `emails_are_masked_to_the_first_letter_and_the_domain` |
| **V7.1.3** Verify that the application logs security relevant events including successful and failed authentication events, access control… | Tested | `crates/apps/attome/tests/auth_audit_events.rs` `a_password_login_writes_one_login_event_for_the_account`; `crates/apps/attome/tests/step_up_federated_http.rs` `a_federated_step_up_writes_one_security_event`; `crates/engine/attome-api/tests/authz.rs` `admin_mfa_reset_writes_a_security_audit_event` |
| **V7.1.4** Verify that each log event includes necessary information that would allow for a detailed investigation of the timeline when an event… | Tested | `crates/engine/attome-records/src/query_exec.rs` `a_masked_failure_carries_its_identifiers_in_the_logged_detail` |
| **V7.2.1** Verify that all authentication decisions are logged, without storing sensitive session tokens or passwords. This should include requests… | Tested | `crates/apps/attome/tests/auth_audit_events.rs` `a_password_login_writes_one_login_event_for_the_account`; `crates/apps/attome/tests/auth_audit_events.rs` `failed_logins_coalesce_per_window_and_the_sweep_writes_one_summary` |
| **V7.2.2** Verify that all access control decisions can be logged and all failed decisions are logged. This should include requests with relevant… | Gap | Owner Q21: log every refused authorization decision. |
| **V7.3.1** Verify that all logging components appropriately encode data to prevent log injection. | Process | Structured JSON logs escape field values (tracing-subscriber). |
| **V7.3.3** Verify that security logs are protected from unauthorized access and modification. | Tested | `crates/engine/attome-audit/tests/concurrency.rs` `audit_chain_has_no_fork_under_concurrent_appends`; `crates/engine/attome-audit/tests/dangling_batch_ref.rs` `a_forged_header_with_a_random_chain_batch_ref_fails_full_chain_and_single_row_verification` |
| **V7.3.4** Verify that time sources are synchronized to the correct time and time zone. Strongly consider logging only in UTC if systems are global… | Process | Timestamps are UTC from the host clock; NTP is the host's. |
| **V7.4.1** Verify that a generic message is shown when an unexpected or security sensitive error occurs, potentially with a unique ID which support… | Tested | `crates/foundation/attome-server/src/app.rs` `a_panic_returns_the_masked_500_envelope_and_the_server_keeps_serving`; `crates/apps/attome/tests/asvs.rs` `v2_wrong_password_is_generic` |
| **V7.4.2** Verify that exception handling (or a functional equivalent) is used across the codebase to account for expected and unexpected error… | Process | Typed errors and AppError throughout; unwrap is denied in production code. |
| **V7.4.3** Verify that a "last resort" error handler is defined which will catch all unhandled exceptions. | Tested | `crates/foundation/attome-server/src/app.rs` `a_panic_returns_the_masked_500_envelope_and_the_server_keeps_serving` |

## V8 Data Protection

| Requirement | Status | Evidence |
|---|---|---|
| **V8.1.1** Verify the application protects sensitive data from being cached in server components such as load balancers and application caches. | Tested | `crates/apps/attome/tests/asvs.rs` `v14_4_api_response_headers` |
| **V8.1.2** Verify that all cached or temporary copies of sensitive data stored on the server are protected from unauthorized access or… | Process | Caches hold metadata and permissions, not records (docs/caching.md). |
| **V8.1.3** Verify the application minimizes the number of parameters in a request, such as hidden fields, Ajax variables, cookies and header values. | Process | The API takes typed JSON bodies; no hidden fields. |
| **V8.1.4** Verify the application can detect and alert on abnormal numbers of requests, such as by IP, user, total per hour or day, or whatever… | Tested | `crates/engine/attome-testapp/tests/api_key_quota.rs` `a_key_past_its_quota_is_refused` |
| **V8.2.1** Verify the application sets sufficient anti-caching headers so that sensitive data is not cached in modern browsers. | Tested | `crates/apps/attome/tests/asvs.rs` `v14_4_api_response_headers` |
| **V8.2.2** Verify that data stored in browser storage (such as localStorage, sessionStorage, IndexedDB, or cookies) does not contain sensitive data. | Process | The web app keeps no session data in browser storage. |
| **V8.2.3** Verify that authenticated data is cleared from client storage, such as the browser DOM, after the client or session is terminated. | Gap | Owner B: clear cached data on sign-out in the web app. |
| **V8.3.1** Verify that sensitive data is sent to the server in the HTTP message body or headers, and that query string parameters from any HTTP… | Tested | `crates/apps/attome/tests/asvs.rs` `v3_1_1_session_token_never_in_a_url` |
| **V8.3.2** Verify that users have a method to remove or export their data on demand. | Gap | Owner Y5-T5: data export and deletion on demand. |
| **V8.3.3** Verify that users are provided clear language regarding collection and use of supplied personal information and that users have provided… | Process | Consent capture and privacy notices (portal consent routes). |
| **V8.3.4** Verify that all sensitive data created and processed by the application has been identified, and ensure that a policy is in place on how… | Process | Every attribute carries a sensitivity label (A1-T1). |
| **V8.3.5** Verify accessing sensitive data is audited (without logging the sensitive data itself), if the data is collected under relevant data… | Gap | Owner Q15: audit reads of sensitive fields. |
| **V8.3.6** Verify that sensitive information contained in memory is overwritten as soon as it is no longer required to mitigate memory dumping… | Process | Key material uses zeroize where held (attome-auth envelope). |
| **V8.3.7** Verify that sensitive or private information that is required to be encrypted, is encrypted using approved algorithms that provide both… | Process | AES-256-GCM envelope encryption (envelope.rs). |
| **V8.3.8** Verify that sensitive personal information is subject to data retention classification, such that old or out of date data is deleted… | Gap | Owner A1-T2: retention by sensitivity label. |

## V9 Communication

| Requirement | Status | Evidence |
|---|---|---|
| **V9.1.1** Verify that TLS is used for all client connectivity, and does not fall back to insecure or unencrypted communications. | Process | TLS terminates at the edge (nginx or the built-in edge); HSTS is sent on every response (`v14_4_api_response_headers`). |
| **V9.1.2** Verify using up to date TLS testing tools that only strong cipher suites are enabled, with the strongest cipher suites set as preferred. | Process | rustls with its default (strong) cipher suites. |
| **V9.1.3** Verify that only the latest recommended versions of the TLS protocol are enabled, such as TLS 1.2 and TLS 1.3. The latest version of the… | Process | rustls supports TLS 1.2 and 1.3 only. |
| **V9.2.1** Verify that connections to and from the server use trusted TLS certificates. Where internally generated or self-signed certificates are… | Process | Outbound TLS verifies against webpki roots (Q21-T1 client). |
| **V9.2.2** Verify that encrypted communications such as TLS is used for all inbound and outbound connections, including for management ports,… | Gap | Owner Q21: TLS on management and monitoring ports. |
| **V9.2.3** Verify that all encrypted connections to external systems that involve sensitive information or functions are authenticated. | Tested | `crates/engine/attome-integration/src/webhook.rs` `a_tampered_body_is_refused_before_the_nonce_store` |
| **V9.2.4** Verify that proper certification revocation, such as Online Certificate Status Protocol (OCSP) Stapling, is enabled and configured. | N/A | Certificate revocation is the edge proxy's (nginx) configuration. |

## V10 Malicious Code

| Requirement | Status | Evidence |
|---|---|---|
| **V10.2.1** Verify that the application source code and third party libraries do not contain unauthorized phone home or data collection… | Process | No phone-home; outbound calls are listed in docs/security/outbound-calls.md. |
| **V10.2.2** Verify that the application does not ask for unnecessary or excessive permissions to privacy related features or sensors, such as… | Tested | `crates/foundation/attome-server/src/middleware/security_headers.rs` `isolation_headers_on_pages_and_api_responses` |
| **V10.3.1** Verify that if the application has a client or server auto-update feature, updates should be obtained over secure channels and digitally… | Process | Updates are downloaded over HTTPS and verified (docs/release-signing.md). |
| **V10.3.2** Verify that the application employs integrity protections, such as code signing or subresource integrity. The application must not load… | Gap | Owner AC7-T5: code signing waits for the release key. |
| **V10.3.3** Verify that the application has protection from subdomain takeovers if the application relies upon DNS entries or DNS subdomains, such… | N/A | DNS is the customer's; no shared subdomains. |

## V11 Business Logic

| Requirement | Status | Evidence |
|---|---|---|
| **V11.1.1** Verify that the application will only process business logic flows for the same user in sequential step order and without skipping steps. | Tested | `crates/engine/attome-api/tests/state_lifecycle.rs` `a_two_step_approval_moves_the_record_to_its_target_exactly_once` |
| **V11.1.2** Verify that the application will only process business logic flows with all steps being processed in realistic human time, i.e.… | Tested | `crates/engine/attome-api/tests/approval_lifecycle.rs` `a_decision_racing_a_retry_executes_the_approval_once` |
| **V11.1.3** Verify the application has appropriate limits for specific business actions or transactions which are correctly enforced on a per user… | Tested | `crates/engine/attome-testapp/tests/api_key_quota.rs` `a_key_past_its_quota_is_refused` |
| **V11.1.4** Verify that the application has anti-automation controls to protect against excessive calls such as mass data exfiltration, business… | Tested | `crates/apps/attome/tests/account_throttle.rs` `a_throttled_known_account_is_indistinguishable_from_a_throttled_unknown_one` |
| **V11.1.5** Verify the application has business logic limits or validation to protect against likely business risks or threats, identified using… | Tested | `crates/engine/attome-ai/tests/record_update_field.rs` `bot_handoff_daily_cap_refuses_once_exhausted` |
| **V11.1.6** Verify that the application does not suffer from "Time Of Check to Time Of Use" (TOCTOU) issues or other race conditions for sensitive… | Tested | `crates/foundation/attome-server/src/middleware/idempotency.rs` `a_hundred_concurrent_identical_requests_run_the_handler_once` |
| **V11.1.7** Verify that the application monitors for unusual events or activity from a business logic perspective. For example, attempts to perform… | Gap | Owner Q21: business-level anomaly alerts. |
| **V11.1.8** Verify that the application has configurable alerting when automated attacks or unusual activity is detected. | Gap | Owner Q21: configurable alerting on automated attacks. |

## V12 Files and Resources

| Requirement | Status | Evidence |
|---|---|---|
| **V12.1.1** Verify that the application will not accept large files that could fill up storage or cause a denial of service. | Tested | `crates/engine/attome-api/tests/file_upload_pipeline.rs` `create_rejects_when_it_would_exceed_the_deployment_storage_quota` |
| **V12.1.2** Verify that the application checks compressed files (e.g. zip, gz, docx, odt) against maximum allowed uncompressed size and against… | Gap | Owner Z6: uncompressed-size limits on archives. |
| **V12.1.3** Verify that a file size quota and maximum number of files per user is enforced to ensure that a single user cannot fill up the storage… | Tested | `crates/engine/attome-api/tests/file_upload_pipeline.rs` `create_rejects_when_it_would_exceed_the_per_user_storage_quota` |
| **V12.2.1** Verify that files obtained from untrusted sources are validated to be of expected type based on the file's content. | Tested | `crates/engine/attome-api/tests/file_upload_pipeline.rs` `an_html_upload_session_is_refused` |
| **V12.3.1** Verify that user-submitted filename metadata is not used directly by system or framework filesystems and that a URL API is used to… | Process | Stored files are keyed by id; the name is metadata only. |
| **V12.3.2** Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure, creation, updating or removal of local… | Process | Stored files are keyed by id; the name is metadata only. |
| **V12.3.3** Verify that user-submitted filename metadata is validated or ignored to prevent the disclosure or execution of remote files via Remote… | Process | Stored files are keyed by id; the name is metadata only. |
| **V12.3.4** Verify that the application protects against Reflective File Download (RFD) by validating or ignoring user-submitted filenames in a… | Tested | `crates/foundation/attome-storage/tests/presign_roundtrip.rs` `a_presigned_download_is_served_as_an_attachment` |
| **V12.3.5** Verify that untrusted file metadata is not used directly with system API or libraries, to protect against OS command injection. | Process | File metadata never reaches a system API. |
| **V12.3.6** Verify that the application does not include and execute functionality from untrusted sources, such as unverified content distribution… | Process | Extensions run in a sandbox only (Y10); no remote includes. |
| **V12.4.1** Verify that files obtained from untrusted sources are stored outside the web root, with limited permissions. | Process | Files live in the object store, never under the web root. |
| **V12.4.2** Verify that files obtained from untrusted sources are scanned by antivirus scanners to prevent upload and serving of known malicious… | Tested | `crates/foundation/attome-storage/src/health.rs` `clamd_that_never_answers_is_a_timeout`; `crates/foundation/attome-storage/src/health.rs` `clamd_answering_garbage_is_an_unexpected_response_without_leaking_it` |
| **V12.5.1** Verify that the web tier is configured to serve only files with specific file extensions to prevent unintentional information and source… | Process | The web tier serves the built app's files only. |
| **V12.5.2** Verify that direct requests to uploaded files will never be executed as HTML/JavaScript content. | Tested | `crates/foundation/attome-storage/tests/presign_roundtrip.rs` `a_presigned_download_is_served_as_an_attachment`; `crates/engine/attome-api/tests/file_upload_pipeline.rs` `an_html_upload_session_is_refused` |
| **V12.6.1** Verify that the web or application server is configured with an allow list of resources or systems to which the server can send requests… | Tested | `crates/engine/attome-events/tests/ssrf.rs` `a_private_rfc1918_target_is_rejected`; `crates/foundation/attome-outbound/src/http/mod.rs` `a_public_purpose_refuses_private_and_metadata_literals` |

## V13 API and Web Service

| Requirement | Status | Evidence |
|---|---|---|
| **V13.1.1** Verify that all application components use the same encodings and parsers to avoid parsing attacks that exploit different URI or file… | Process | One HTTP stack (axum/hyper) parses every request. |
| **V13.1.3** Verify API URLs do not expose sensitive information, such as the API key, session tokens etc. | Tested | `crates/apps/attome/tests/asvs.rs` `v3_1_1_session_token_never_in_a_url` |
| **V13.1.4** Verify that authorization decisions are made at both the URI, enforced by programmatic or declarative security at the controller or… | Tested | `crates/apps/attome/tests/asvs.rs` `v4_1_1_unauthenticated_api_is_refused`; `crates/apps/attome/tests/admin_routes_forbid_non_admin.rs` `admin_routes_forbid_a_non_admin_and_admit_an_admin` |
| **V13.1.5** Verify that requests containing unexpected or missing content types are rejected with appropriate headers (HTTP response status 406… | Tested | `crates/apps/attome/tests/asvs.rs` `v13_2_5_unexpected_content_type_is_refused` |
| **V13.2.1** Verify that enabled RESTful HTTP methods are a valid choice for the user or action, such as preventing normal users using DELETE or PUT… | Tested | `crates/apps/attome/tests/admin_routes_forbid_non_admin.rs` `admin_routes_forbid_a_non_admin_and_admit_an_admin` |
| **V13.2.2** Verify that JSON schema validation is in place and verified before accepting input. | Tested | `crates/engine/attome-ai/src/actions/classify.rs` `an_unknown_field_is_a_validation_error`; `crates/foundation/attome-server/src/middleware/json_shape.rs` `a_deep_json_body_is_refused_before_the_handler` |
| **V13.2.3** Verify that RESTful web services that utilize cookies are protected from Cross-Site Request Forgery via the use of at least one or more… | Tested | `crates/apps/attome/tests/asvs.rs` `v4_2_2_cross_site_mutation_is_refused` |
| **V13.2.5** Verify that REST services explicitly check the incoming Content-Type to be the expected one, such as application/xml or application/json. | Tested | `crates/apps/attome/tests/asvs.rs` `v13_2_5_unexpected_content_type_is_refused` |
| **V13.2.6** Verify that the message headers and payload are trustworthy and not modified in transit. Requiring strong encryption for transport (TLS… | Tested | `crates/engine/attome-integration/src/webhook.rs` `a_tampered_body_is_refused_before_the_nonce_store` |
| **V13.3.1** Verify that XSD schema validation takes place to ensure a properly formed XML document, followed by validation of each input field… | N/A | No SOAP or XML request bodies. |
| **V13.3.2** Verify that the message payload is signed using WS-Security to ensure reliable transport between client and service. | N/A | No WS-Security. |
| **V13.4.1** Verify that a query allow list or a combination of depth limiting and amount limiting is used to prevent GraphQL or data layer… | Tested | `crates/foundation/attome-server/src/middleware/json_shape.rs` `a_deep_json_body_is_refused_before_the_handler` |
| **V13.4.2** Verify that GraphQL or other data layer authorization logic should be implemented at the business logic layer instead of the GraphQL layer. | N/A | No GraphQL; authorization sits in the engine layer. |

## V14 Configuration

| Requirement | Status | Evidence |
|---|---|---|
| **V14.1.1** Verify that the application build and deployment processes are performed in a secure and repeatable way, such as CI / CD automation,… | Process | The release gate (docs/release.md). |
| **V14.1.2** Verify that compiler flags are configured to enable all available buffer overflow protections and warnings, including stack… | Process | Rust release profile; memory safety by the language. |
| **V14.1.3** Verify that server configuration is hardened as per the recommendations of the application server and frameworks in use. | Process | Hardened defaults in config.production.example.json. |
| **V14.1.4** Verify that the application, configuration, and all dependencies can be re-deployed using automated deployment scripts, built from a… | Process | Compose and Helm deploy scripts (deploy/). |
| **V14.2.1** Verify that all components are up to date, preferably using a dependency checker during build or compile time. | Process | cargo deny advisories in the release gate. |
| **V14.2.2** Verify that all unneeded features, documentation, sample applications and configurations are removed. | Process | The release archive ships the binary and its web app only. |
| **V14.2.3** Verify that if application assets, such as JavaScript libraries, CSS or web fonts, are hosted externally on a Content Delivery Network… | Process | The web app is self-hosted; no CDN assets. |
| **V14.2.4** Verify that third party components come from pre-defined, trusted and continually maintained repositories. | Process | crates.io and npm only; no git dependencies (deny.toml). |
| **V14.2.5** Verify that a Software Bill of Materials (SBOM) is maintained of all third party libraries in use. | Process | SBOM in every release (attome-release sbom.rs; AC7-T11 admin route). |
| **V14.2.6** Verify that the attack surface is reduced by sandboxing or encapsulating third party libraries to expose only the required behaviour… | Gap | Owner Y10: extensions are sandboxed; third-party crates are not. |
| **V14.3.2** Verify that web or application server and application framework debug modes are disabled in production to eliminate debug features,… | Process | The fleet console and debug routes compile only into debug builds. |
| **V14.3.3** Verify that the HTTP headers or any part of the HTTP response do not expose detailed version information of system components. | Tested | `crates/apps/attome/tests/asvs.rs` `v14_3_3_no_version_in_headers` |
| **V14.4.1** Verify that every HTTP response contains a Content-Type header. Also specify a safe character set (e.g., UTF-8, ISO-8859-1) if the… | Tested | `crates/apps/attome/tests/asvs.rs` `v14_4_api_response_headers` |
| **V14.4.2** Verify that all API responses contain a Content-Disposition: attachment; filename="api.json" header (or other appropriate filename for… | Gap | Owner Q21: API responses carry no Content-Disposition; stored files do (`a_presigned_download_is_served_as_an_attachment`). |
| **V14.4.3** Verify that a Content Security Policy (CSP) response header is in place that helps mitigate impact for XSS attacks like HTML, DOM, JSON,… | Tested | `crates/apps/attome/tests/asvs.rs` `v14_4_3_page_has_csp`; `crates/foundation/attome-server/src/middleware/security_headers.rs` `csp_header_carries_the_page_nonce` |
| **V14.4.4** Verify that all responses contain a X-Content-Type-Options: nosniff header. | Tested | `crates/apps/attome/tests/asvs.rs` `v14_4_api_response_headers` |
| **V14.4.5** Verify that a Strict-Transport-Security header is included on all responses and for all subdomains, such as Strict-Transport-Security:… | Tested | `crates/apps/attome/tests/asvs.rs` `v14_4_api_response_headers` |
| **V14.4.6** Verify that a suitable Referrer-Policy header is included to avoid exposing sensitive information in the URL through the Referer header… | Tested | `crates/apps/attome/tests/asvs.rs` `v14_4_api_response_headers` |
| **V14.4.7** Verify that the content of a web application cannot be embedded in a third-party site by default and that embedding of the exact… | Tested | `crates/apps/attome/tests/asvs.rs` `v14_4_3_page_has_csp` |
| **V14.5.1** Verify that the application server only accepts the HTTP methods in use by the application/API, including pre-flight OPTIONS, and… | Gap | Owner Q21: log requests with unsupported methods. |
| **V14.5.2** Verify that the supplied Origin header is not used for authentication or access control decisions, as the Origin header can easily be… | Tested | `crates/apps/attome/tests/asvs.rs` `v4_2_2_cross_site_mutation_is_refused` |
| **V14.5.3** Verify that the Cross-Origin Resource Sharing (CORS) Access-Control-Allow-Origin header uses a strict allow list of trusted domains and… | Tested | `crates/apps/attome/tests/asvs.rs` `v14_5_3_cors_allow_list`; `crates/apps/attome/tests/middleware_pipeline.rs` `disallowed_origin_preflight_is_not_echoed` |
| **V14.5.4** Verify that HTTP headers added by a trusted proxy or SSO devices, such as a bearer token, are authenticated by the application. | Tested | `crates/foundation/attome-server/src/middleware/client_ip.rs` `ignores_forwarded_for_from_an_untrusted_socket_peer`; `crates/foundation/attome-server/src/middleware/host_gate.rs` `forwarded_host_counts_only_from_a_trusted_peer` |
