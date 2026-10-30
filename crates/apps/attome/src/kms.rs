//! Customer-held master keys, unwrapped once at boot (roadmap Q19-T2).
//!
//! A key the customer keeps in their own key service reaches Attome wrapped:
//! the environment (or the secret store, Z1-T12) holds `NAME_KMS`, the key's
//! ciphertext in base64, and `ATTOME_KMS` names the service that unwraps it.
//! At boot every `*_KMS` value is unwrapped once and `${NAME}` resolves to the
//! plaintext ahead of the secret store and the environment; the map is
//! dropped once the configuration is loaded. Nothing refreshes it and no
//! client outlives the boot: a rotated key takes a restart (D-549).
//!
//! The node is sealed until then. It refuses to start when the key service
//! cannot be reached or refuses a value, when a value does not decode, when a
//! `*_KMS` value is set with no `ATTOME_KMS`, or when `ATTOME_KMS` is set with
//! nothing to unwrap. Errors name the service, the step and the placeholder,
//! never a key.
//!
//! - **AWS KMS** (`aws`, cargo feature `aws-secrets`): `Decrypt` in
//!   `ATTOME_KMS_REGION` or `AWS_REGION`, signed with Signature Version 4 from
//!   `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and optional
//!   `AWS_SESSION_TOKEN`; `ATTOME_KMS_KEY_ID`, when set, pins the key.
//! - **Azure Key Vault** (`azure`, cargo feature `azure-keyvault`): `unwrapkey`
//!   with RSA-OAEP-256 on the key `ATTOME_KMS_KEY_URL`
//!   (`https://<vault>/keys/<name>/<version>`), signed in as the service
//!   principal `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`.
//! - **Google Cloud KMS** (`gcp`, cargo feature `gcp-kms`): `decrypt` on the
//!   key `ATTOME_KMS_KEY_NAME` (`projects/…/cryptoKeys/<key>`), with the
//!   access token `GOOGLE_OAUTH_ACCESS_TOKEN` or one exchanged for the
//!   service account key file `GOOGLE_APPLICATION_CREDENTIALS`. The metadata
//!   server is not used: outbound calls never reach a metadata address.
//! - **HSM over PKCS#11** (`hsm`, cargo feature `hsm`, off by default): the
//!   vendor library `ATTOME_HSM_MODULE` (a DLL on Windows), the token in slot
//!   `ATTOME_HSM_SLOT` (default the first with a token), user PIN
//!   `ATTOME_HSM_PIN`, and the RSA private key labelled
//!   `ATTOME_HSM_KEY_LABEL`, decrypting with RSA-OAEP (SHA-256).
//!
//! An unwrapped value is used as text, so wrap exactly what the placeholder
//! would otherwise hold (a 64-hex key, say); surrounding white space is
//! dropped.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

/// The whole unwrap's limit.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);
/// The suffix a wrapped value's name carries.
const WRAPPED_SUFFIX: &str = "_KMS";
/// Most wrapped values; more is a misconfiguration.
const MAX_WRAPPED: usize = 64;

/// Which key service, from `ATTOME_KMS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kms {
    Aws {
        region: String,
        key_id: Option<String>,
    },
    Azure {
        key_url: String,
    },
    Gcp {
        key_name: String,
    },
    Hsm {
        module: String,
        slot: Option<usize>,
        key_label: String,
    },
}

impl Kms {
    fn label(&self) -> &'static str {
        match self {
            Self::Aws { .. } => "AWS KMS",
            Self::Azure { .. } => "Azure Key Vault",
            Self::Gcp { .. } => "Google Cloud KMS",
            Self::Hsm { .. } => "the HSM",
        }
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// The configured key service from `get` (the environment in production);
/// `Ok(None)` when `ATTOME_KMS` is unset. Pure over `get`.
pub fn kms_from(get: impl Fn(&str) -> Option<String>) -> Result<Option<Kms>, String> {
    let Some(kind) = get("ATTOME_KMS") else {
        return Ok(None);
    };
    match kind.to_ascii_lowercase().as_str() {
        "aws" => {
            let region = get("ATTOME_KMS_REGION")
                .or_else(|| get("AWS_REGION"))
                .ok_or("ATTOME_KMS=aws needs ATTOME_KMS_REGION or AWS_REGION")?;
            Ok(Some(Kms::Aws {
                region,
                key_id: get("ATTOME_KMS_KEY_ID"),
            }))
        }
        "azure" => {
            let key_url =
                get("ATTOME_KMS_KEY_URL").ok_or("ATTOME_KMS=azure needs ATTOME_KMS_KEY_URL")?;
            let parsed = reqwest::Url::parse(&key_url)
                .map_err(|_| "ATTOME_KMS_KEY_URL is not a URL".to_owned())?;
            if parsed.scheme() != "https" || !parsed.path().starts_with("/keys/") {
                return Err(
                    "ATTOME_KMS_KEY_URL must be https://<vault>/keys/<name>[/<version>]".into(),
                );
            }
            Ok(Some(Kms::Azure {
                key_url: key_url.trim_end_matches('/').to_owned(),
            }))
        }
        "gcp" => {
            let key_name =
                get("ATTOME_KMS_KEY_NAME").ok_or("ATTOME_KMS=gcp needs ATTOME_KMS_KEY_NAME")?;
            if !gcp_key_name_ok(&key_name) {
                return Err(
                    "ATTOME_KMS_KEY_NAME must be projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>"
                        .into(),
                );
            }
            Ok(Some(Kms::Gcp { key_name }))
        }
        "hsm" => {
            let module =
                get("ATTOME_HSM_MODULE").ok_or("ATTOME_KMS=hsm needs ATTOME_HSM_MODULE")?;
            let key_label =
                get("ATTOME_HSM_KEY_LABEL").ok_or("ATTOME_KMS=hsm needs ATTOME_HSM_KEY_LABEL")?;
            let slot = match get("ATTOME_HSM_SLOT") {
                None => None,
                Some(s) => Some(
                    s.parse::<usize>()
                        .map_err(|_| "ATTOME_HSM_SLOT is not a slot number".to_owned())?,
                ),
            };
            Ok(Some(Kms::Hsm {
                module,
                slot,
                key_label,
            }))
        }
        other => Err(format!(
            "ATTOME_KMS is {other:?}; it is aws, azure, gcp or hsm, or unset"
        )),
    }
}

/// Whether `name` is a Cloud KMS key's resource name. Pure.
fn gcp_key_name_ok(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').collect();
    parts.len() == 8
        && parts[0] == "projects"
        && parts[2] == "locations"
        && parts[4] == "keyRings"
        && parts[6] == "cryptoKeys"
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        })
}

/// The wrapped values among `vars`: placeholder name (without `_KMS`) to its
/// base64 ciphertext, ordered by name. `ATTOME_KMS` and its settings are not
/// values. The first source a name appears in wins. Pure.
pub fn wrapped_from<I>(vars: I) -> BTreeMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut out = BTreeMap::new();
    for (name, value) in vars {
        let Some(placeholder) = name.strip_suffix(WRAPPED_SUFFIX) else {
            continue;
        };
        if placeholder.is_empty()
            || placeholder == "ATTOME"
            || placeholder.starts_with("ATTOME_KMS")
        {
            continue;
        }
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        out.entry(placeholder.to_owned())
            .or_insert_with(|| value.to_owned());
    }
    out
}

/// One key service's unwrap of one ciphertext.
pub trait Unwrap {
    fn unwrap_key(&self, ciphertext: &[u8]) -> impl Future<Output = Result<Vec<u8>, String>>;
}

/// Unwraps every value in `wrapped` through `kms`: placeholder name to the
/// plaintext as text. Fails on the first value that does not decode, does
/// not unwrap, or is not text, naming its placeholder.
pub async fn unwrap_all<U: Unwrap>(
    kms: &U,
    wrapped: &BTreeMap<String, String>,
) -> Result<HashMap<String, String>, String> {
    if wrapped.len() > MAX_WRAPPED {
        return Err(format!("more than {MAX_WRAPPED} *_KMS values"));
    }
    let mut out = HashMap::with_capacity(wrapped.len());
    for (name, encoded) in wrapped {
        let ciphertext = B64
            .decode(encoded)
            .map_err(|_| format!("{name}_KMS is not base64"))?;
        let plain = kms
            .unwrap_key(&ciphertext)
            .await
            .map_err(|e| format!("{name}_KMS: {e}"))?;
        let text =
            String::from_utf8(plain).map_err(|_| format!("{name}_KMS did not unwrap to text"))?;
        let text = text.trim();
        if text.is_empty() {
            return Err(format!("{name}_KMS unwrapped to nothing"));
        }
        out.insert(name.clone(), text.to_owned());
    }
    Ok(out)
}

/// Unwraps the wrapped values found in the secret store's map (`store`) and
/// the environment, through the configured service: `Ok(None)` when neither
/// `ATTOME_KMS` nor any `*_KMS` value is set. Every refusal keeps the node
/// sealed (see the module doc).
pub async fn load(
    store: Option<&HashMap<String, String>>,
) -> Result<Option<HashMap<String, String>>, String> {
    let from_store = store
        .into_iter()
        .flat_map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())));
    let wrapped = wrapped_from(from_store.chain(std::env::vars()));
    let kms = kms_from(env)?;
    let kms = match (kms, wrapped.keys().next()) {
        (None, None) => return Ok(None),
        (None, Some(name)) => {
            return Err(format!(
                "{name}_KMS is set but ATTOME_KMS is not, so the key cannot be unwrapped"
            ));
        }
        (Some(kms), None) => {
            return Err(format!(
                "ATTOME_KMS names {} but no *_KMS value is set",
                kms.label()
            ));
        }
        (Some(kms), Some(_)) => kms,
    };
    let label = kms.label();
    let keys = tokio::time::timeout(TOTAL_TIMEOUT, unwrap_with(&kms, &wrapped))
        .await
        .map_err(|_| format!("{label}: keys not unwrapped within 15 seconds"))?
        .map_err(|e| format!("{label}: {e}"))?;
    tracing::info!(service = label, keys = keys.len(), "keys unwrapped at boot");
    Ok(Some(keys))
}

async fn unwrap_with(
    kms: &Kms,
    wrapped: &BTreeMap<String, String>,
) -> Result<HashMap<String, String>, String> {
    // The service's host may be a private endpoint inside the operator's
    // network; it comes from the operator's environment, never a request.
    let host = match kms {
        Kms::Aws { region, .. } => format!("kms.{region}.amazonaws.com"),
        Kms::Azure { key_url } => reqwest::Url::parse(key_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_default(),
        Kms::Gcp { .. } => "cloudkms.googleapis.com".to_owned(),
        Kms::Hsm { .. } => String::new(),
    };
    let purpose = attome_outbound::http::Purpose::public("kms").with_private_hosts([host]);
    let client = attome_outbound::http::client(purpose, |b| b.timeout(TOTAL_TIMEOUT))
        .map_err(|_| "could not build the HTTP client".to_owned())?;
    match kms {
        #[cfg(feature = "aws-secrets")]
        Kms::Aws { region, key_id } => {
            let unwrapper = aws::AwsKms::new(client, region, key_id.clone())?;
            unwrap_all(&unwrapper, wrapped).await
        }
        #[cfg(feature = "azure-keyvault")]
        Kms::Azure { key_url } => {
            let token = crate::secret_sources::azure::token(&client).await?;
            let unwrapper = azure::AzureKeyVault {
                client,
                key_url: key_url.clone(),
                token,
            };
            unwrap_all(&unwrapper, wrapped).await
        }
        #[cfg(feature = "gcp-kms")]
        Kms::Gcp { key_name } => {
            let token = gcp::token(&client).await?;
            let unwrapper = gcp::CloudKms {
                client,
                key_name: key_name.clone(),
                token,
            };
            unwrap_all(&unwrapper, wrapped).await
        }
        #[cfg(feature = "hsm")]
        Kms::Hsm {
            module,
            slot,
            key_label,
        } => {
            let pin = env("ATTOME_HSM_PIN").ok_or("ATTOME_KMS=hsm needs ATTOME_HSM_PIN")?;
            let unwrapper = hsm::Hsm::open(module.clone(), *slot, key_label.clone(), pin).await?;
            unwrap_all(&unwrapper, wrapped).await
        }
        #[allow(unreachable_patterns)]
        other => {
            let _ = (client, wrapped);
            Err(format!(
                "this binary was built without support for {}",
                other.label()
            ))
        }
    }
}

#[cfg(feature = "aws-secrets")]
mod aws {
    use super::{B64, Engine};
    use crate::secret_sources::aws::{Credentials, credentials, signed_headers};
    use serde_json::{Value, json};

    pub(super) struct AwsKms {
        client: attome_outbound::http::Outbound,
        region: String,
        host: String,
        key_id: Option<String>,
        creds: Credentials,
    }

    impl AwsKms {
        pub(super) fn new(
            client: attome_outbound::http::Outbound,
            region: &str,
            key_id: Option<String>,
        ) -> Result<Self, String> {
            Ok(Self {
                client,
                region: region.to_owned(),
                host: format!("kms.{region}.amazonaws.com"),
                key_id,
                creds: credentials()?,
            })
        }
    }

    /// The `Decrypt` request body. Pure.
    pub(super) fn decrypt_body(ciphertext: &[u8], key_id: Option<&str>) -> String {
        let mut body = json!({ "CiphertextBlob": B64.encode(ciphertext) });
        if let Some(key_id) = key_id {
            body["KeyId"] = json!(key_id);
        }
        body.to_string()
    }

    /// The plaintext of a `Decrypt` answer. Pure.
    pub(super) fn plaintext_of(answer: &Value) -> Result<Vec<u8>, String> {
        answer["Plaintext"]
            .as_str()
            .and_then(|p| B64.decode(p).ok())
            .ok_or_else(|| "Decrypt gave no plaintext".to_owned())
    }

    impl super::Unwrap for AwsKms {
        async fn unwrap_key(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            let body = decrypt_body(ciphertext, self.key_id.as_deref());
            let headers = signed_headers(
                &self.creds,
                &self.region,
                &self.host,
                "kms",
                "TrentService.Decrypt",
                &body,
                chrono::Utc::now(),
            );
            let mut request = self
                .client
                .post(format!("https://{}/", self.host))
                .body(body);
            for (k, v) in &headers {
                request = request.header(k.as_str(), v.as_str());
            }
            let response = request
                .send()
                .await
                .map_err(|_| "Decrypt could not be reached".to_owned())?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!("Decrypt answered {status}"));
            }
            let answer: Value = response
                .json()
                .await
                .map_err(|_| "Decrypt answered something unreadable".to_owned())?;
            plaintext_of(&answer)
        }
    }
}

#[cfg(feature = "azure-keyvault")]
mod azure {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use serde_json::{Value, json};

    const API_VERSION: &str = "7.4";

    pub(super) struct AzureKeyVault {
        pub(super) client: attome_outbound::http::Outbound,
        pub(super) key_url: String,
        pub(super) token: String,
    }

    /// The `unwrapkey` request body. Pure.
    pub(super) fn unwrap_body(ciphertext: &[u8]) -> String {
        json!({ "alg": "RSA-OAEP-256", "value": B64URL.encode(ciphertext) }).to_string()
    }

    /// The plaintext of an `unwrapkey` answer (base64url, padded or not).
    /// Pure.
    pub(super) fn plaintext_of(answer: &Value) -> Result<Vec<u8>, String> {
        answer["value"]
            .as_str()
            .and_then(|p| B64URL.decode(p.trim_end_matches('=')).ok())
            .ok_or_else(|| "unwrapkey gave no value".to_owned())
    }

    impl super::Unwrap for AzureKeyVault {
        async fn unwrap_key(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            let response = self
                .client
                .post(format!(
                    "{}/unwrapkey?api-version={API_VERSION}",
                    self.key_url
                ))
                .bearer_auth(&self.token)
                .header("content-type", "application/json")
                .body(unwrap_body(ciphertext))
                .send()
                .await
                .map_err(|_| "the vault could not be reached".to_owned())?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!("unwrapkey answered {status}"));
            }
            let answer: Value = response
                .json()
                .await
                .map_err(|_| "unwrapkey answered something unreadable".to_owned())?;
            plaintext_of(&answer)
        }
    }
}

#[cfg(feature = "gcp-kms")]
mod gcp {
    use super::{B64, Engine};
    use serde_json::{Value, json};

    const SCOPE: &str = "https://www.googleapis.com/auth/cloudkms";
    const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";

    pub(super) struct CloudKms {
        pub(super) client: attome_outbound::http::Outbound,
        pub(super) key_name: String,
        pub(super) token: String,
    }

    #[derive(serde::Serialize)]
    struct Claims<'a> {
        iss: &'a str,
        scope: &'a str,
        aud: &'a str,
        iat: i64,
        exp: i64,
    }

    /// The access token: `GOOGLE_OAUTH_ACCESS_TOKEN`, else one exchanged for
    /// a signed assertion of the service account in
    /// `GOOGLE_APPLICATION_CREDENTIALS`.
    pub(super) async fn token(client: &attome_outbound::http::Outbound) -> Result<String, String> {
        if let Some(token) = super::env("GOOGLE_OAUTH_ACCESS_TOKEN") {
            return Ok(token);
        }
        let path = super::env("GOOGLE_APPLICATION_CREDENTIALS")
            .ok_or("GOOGLE_OAUTH_ACCESS_TOKEN or GOOGLE_APPLICATION_CREDENTIALS is needed")?;
        let file = tokio::fs::read_to_string(&path)
            .await
            .map_err(|_| "the service account key file could not be read".to_owned())?;
        let account: Value = serde_json::from_str(&file)
            .map_err(|_| "the service account key file is not JSON".to_owned())?;
        let (Some(email), Some(key)) = (
            account["client_email"].as_str(),
            account["private_key"].as_str(),
        ) else {
            return Err("the service account key file has no client_email or private_key".into());
        };
        let assertion = assertion(email, key, chrono::Utc::now().timestamp())?;
        let response = client
            .post(TOKEN_URI)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|_| "the token endpoint could not be reached".to_owned())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("the token endpoint answered {status}"));
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| "the token endpoint answered something unreadable".to_owned())?;
        body["access_token"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| "the token endpoint gave no access token".to_owned())
    }

    /// The signed JWT a service account trades for a token. Pure but for
    /// the signature.
    pub(super) fn assertion(
        email: &str,
        private_key_pem: &str,
        now: i64,
    ) -> Result<String, String> {
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|_| "the service account private key is not an RSA key".to_owned())?;
        let claims = Claims {
            iss: email,
            scope: SCOPE,
            aud: TOKEN_URI,
            iat: now,
            exp: now + 600,
        };
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &key,
        )
        .map_err(|_| "the service account assertion could not be signed".to_owned())
    }

    /// The `decrypt` request body. Pure.
    pub(super) fn decrypt_body(ciphertext: &[u8]) -> String {
        json!({ "ciphertext": B64.encode(ciphertext) }).to_string()
    }

    /// The plaintext of a `decrypt` answer. Pure.
    pub(super) fn plaintext_of(answer: &Value) -> Result<Vec<u8>, String> {
        answer["plaintext"]
            .as_str()
            .and_then(|p| B64.decode(p).ok())
            .ok_or_else(|| "decrypt gave no plaintext".to_owned())
    }

    impl super::Unwrap for CloudKms {
        async fn unwrap_key(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            let response = self
                .client
                .post(format!(
                    "https://cloudkms.googleapis.com/v1/{}:decrypt",
                    self.key_name
                ))
                .bearer_auth(&self.token)
                .header("content-type", "application/json")
                .body(decrypt_body(ciphertext))
                .send()
                .await
                .map_err(|_| "Cloud KMS could not be reached".to_owned())?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!("decrypt answered {status}"));
            }
            let answer: Value = response
                .json()
                .await
                .map_err(|_| "decrypt answered something unreadable".to_owned())?;
            plaintext_of(&answer)
        }
    }
}

#[cfg(feature = "hsm")]
mod hsm {
    use std::sync::Arc;

    use cryptoki::context::{CInitializeArgs, Pkcs11};
    use cryptoki::mechanism::rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource};
    use cryptoki::mechanism::{Mechanism, MechanismType};
    use cryptoki::object::{Attribute, ObjectClass, ObjectHandle};
    use cryptoki::session::{Session, UserType};
    use cryptoki::types::AuthPin;

    /// An open, logged-in session on the token and the key's handle. PKCS#11
    /// calls block, so each runs on the blocking pool.
    pub(super) struct Hsm {
        inner: Arc<std::sync::Mutex<(Session, ObjectHandle)>>,
    }

    impl Hsm {
        pub(super) async fn open(
            module: String,
            slot: Option<usize>,
            key_label: String,
            pin: String,
        ) -> Result<Self, String> {
            let opened = tokio::task::spawn_blocking(move || {
                let pkcs11 = Pkcs11::new(&module)
                    .map_err(|_| "the PKCS#11 library could not be loaded".to_owned())?;
                pkcs11
                    .initialize(CInitializeArgs::OsThreads)
                    .map_err(|_| "the PKCS#11 library did not initialise".to_owned())?;
                let slots = pkcs11
                    .get_slots_with_token()
                    .map_err(|_| "the HSM's slots could not be listed".to_owned())?;
                let slot = *slots
                    .get(slot.unwrap_or(0))
                    .ok_or("no token in the requested HSM slot")?;
                let session = pkcs11
                    .open_ro_session(slot)
                    .map_err(|_| "no session could be opened on the token".to_owned())?;
                session
                    .login(UserType::User, Some(&AuthPin::new(pin)))
                    .map_err(|_| "the token refused the PIN".to_owned())?;
                let found = session
                    .find_objects(&[
                        Attribute::Class(ObjectClass::PRIVATE_KEY),
                        Attribute::Label(key_label.into_bytes()),
                    ])
                    .map_err(|_| "the key could not be looked up".to_owned())?;
                let key = match found.as_slice() {
                    [key] => *key,
                    [] => return Err("no private key with that label".to_owned()),
                    _ => return Err("more than one private key with that label".to_owned()),
                };
                Ok((session, key))
            })
            .await
            .map_err(|_| "the HSM session task failed".to_owned())??;
            Ok(Self {
                inner: Arc::new(std::sync::Mutex::new(opened)),
            })
        }
    }

    impl super::Unwrap for Hsm {
        async fn unwrap_key(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            let inner = Arc::clone(&self.inner);
            let ciphertext = ciphertext.to_vec();
            tokio::task::spawn_blocking(move || {
                let guard = inner
                    .lock()
                    .map_err(|_| "the HSM session is unusable".to_owned())?;
                let (session, key) = &*guard;
                let params = PkcsOaepParams::new(
                    MechanismType::SHA256,
                    PkcsMgfType::MGF1_SHA256,
                    PkcsOaepSource::empty(),
                );
                session
                    .decrypt(&Mechanism::RsaPkcsOaep(params), *key, &ciphertext)
                    .map_err(|_| "the HSM refused to decrypt".to_owned())
            })
            .await
            .map_err(|_| "the HSM decrypt task failed".to_owned())?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |k| map.get(k).cloned()
    }

    /// A key service that "unwraps" by XOR with one byte, and refuses a
    /// ciphertext starting with 0xFF.
    struct FakeKms(u8);

    impl Unwrap for FakeKms {
        async fn unwrap_key(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            if ciphertext.first() == Some(&0xFF) {
                return Err("the key service refused".into());
            }
            Ok(ciphertext.iter().map(|b| b ^ self.0).collect())
        }
    }

    fn wrap(fake: &FakeKms, plain: &str) -> String {
        B64.encode(plain.bytes().map(|b| b ^ fake.0).collect::<Vec<_>>())
    }

    #[test]
    fn kms_unset_is_none_and_each_service_reads_its_settings() {
        assert_eq!(kms_from(vars(&[])).unwrap(), None);
        assert_eq!(
            kms_from(vars(&[
                ("ATTOME_KMS", "aws"),
                ("AWS_REGION", "me-central-1")
            ]))
            .unwrap(),
            Some(Kms::Aws {
                region: "me-central-1".into(),
                key_id: None
            })
        );
        assert!(kms_from(vars(&[("ATTOME_KMS", "aws")])).is_err());
        assert_eq!(
            kms_from(vars(&[
                ("ATTOME_KMS", "azure"),
                (
                    "ATTOME_KMS_KEY_URL",
                    "https://v.vault.azure.net/keys/attome/0123/"
                )
            ]))
            .unwrap(),
            Some(Kms::Azure {
                key_url: "https://v.vault.azure.net/keys/attome/0123".into()
            })
        );
        assert!(
            kms_from(vars(&[
                ("ATTOME_KMS", "azure"),
                ("ATTOME_KMS_KEY_URL", "http://v.vault.azure.net/keys/a")
            ]))
            .is_err()
        );
        let gcp = "projects/p/locations/me-central2/keyRings/r/cryptoKeys/k";
        assert_eq!(
            kms_from(vars(&[("ATTOME_KMS", "gcp"), ("ATTOME_KMS_KEY_NAME", gcp)])).unwrap(),
            Some(Kms::Gcp {
                key_name: gcp.into()
            })
        );
        assert!(
            kms_from(vars(&[
                ("ATTOME_KMS", "gcp"),
                ("ATTOME_KMS_KEY_NAME", "projects/p/../x")
            ]))
            .is_err()
        );
        assert_eq!(
            kms_from(vars(&[
                ("ATTOME_KMS", "hsm"),
                ("ATTOME_HSM_MODULE", "C:\\vendor\\pkcs11.dll"),
                ("ATTOME_HSM_KEY_LABEL", "attome-master"),
                ("ATTOME_HSM_SLOT", "1"),
            ]))
            .unwrap(),
            Some(Kms::Hsm {
                module: "C:\\vendor\\pkcs11.dll".into(),
                slot: Some(1),
                key_label: "attome-master".into()
            })
        );
        assert!(kms_from(vars(&[("ATTOME_KMS", "vault")])).is_err());
    }

    #[test]
    fn kms_wrapped_values_are_the_kms_suffixed_names() {
        let wrapped = wrapped_from([
            ("JWT_SECRET_KMS".to_owned(), " AAAA ".to_owned()),
            ("ATTOME_KMS".to_owned(), "aws".to_owned()),
            ("ATTOME_KMS_KEY_ID".to_owned(), "alias/x".to_owned()),
            ("EMPTY_KMS".to_owned(), "  ".to_owned()),
            ("PLAIN".to_owned(), "x".to_owned()),
            ("JWT_SECRET_KMS".to_owned(), "later".to_owned()),
        ]);
        assert_eq!(wrapped.len(), 1);
        assert_eq!(wrapped["JWT_SECRET"], "AAAA", "the first source wins");
    }

    #[tokio::test]
    async fn kms_unwraps_every_value_with_a_fake_service() {
        let fake = FakeKms(0x5A);
        let wrapped = BTreeMap::from([
            (
                "JWT_SECRET".to_owned(),
                wrap(&fake, "11".repeat(32).as_str()),
            ),
            (
                "ATTRIBUTE_ENCRYPTION_KEY".to_owned(),
                wrap(&fake, &format!("{}\n", "ab".repeat(32))),
            ),
        ]);
        let keys = unwrap_all(&fake, &wrapped).await.unwrap();
        assert_eq!(keys["JWT_SECRET"], "11".repeat(32));
        assert_eq!(keys["ATTRIBUTE_ENCRYPTION_KEY"], "ab".repeat(32));
    }

    #[tokio::test]
    async fn kms_refusal_or_bad_value_names_the_placeholder_not_the_key() {
        let fake = FakeKms(0x5A);
        let refused = BTreeMap::from([("DB_KEY".to_owned(), B64.encode([0xFF, 1, 2]))]);
        let error = unwrap_all(&fake, &refused).await.unwrap_err();
        assert!(error.starts_with("DB_KEY_KMS:"), "{error}");

        let not_b64 = BTreeMap::from([("DB_KEY".to_owned(), "***".to_owned())]);
        assert_eq!(
            unwrap_all(&fake, &not_b64).await.unwrap_err(),
            "DB_KEY_KMS is not base64"
        );

        let not_text =
            BTreeMap::from([("DB_KEY".to_owned(), B64.encode([0x5A ^ 0xC3, 0x5A ^ 0x28]))]);
        assert_eq!(
            unwrap_all(&fake, &not_text).await.unwrap_err(),
            "DB_KEY_KMS did not unwrap to text"
        );
    }

    #[cfg(feature = "aws-secrets")]
    #[test]
    fn kms_aws_decrypt_body_and_answer() {
        let body: serde_json::Value =
            serde_json::from_str(&aws::decrypt_body(b"wrapped", Some("alias/attome"))).unwrap();
        assert_eq!(body["CiphertextBlob"], B64.encode(b"wrapped"));
        assert_eq!(body["KeyId"], "alias/attome");
        let answer = serde_json::json!({ "Plaintext": B64.encode(b"key") });
        assert_eq!(aws::plaintext_of(&answer).unwrap(), b"key");
        assert!(aws::plaintext_of(&serde_json::json!({})).is_err());
    }

    #[cfg(feature = "azure-keyvault")]
    #[test]
    fn kms_azure_unwrap_body_and_answer() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let body: serde_json::Value =
            serde_json::from_str(&azure::unwrap_body(&[0xFB, 0xFF])).unwrap();
        assert_eq!(body["alg"], "RSA-OAEP-256");
        assert_eq!(body["value"], "-_8");
        let answer = serde_json::json!({ "value": URL_SAFE_NO_PAD.encode(b"key") });
        assert_eq!(azure::plaintext_of(&answer).unwrap(), b"key");
    }

    #[cfg(feature = "gcp-kms")]
    #[test]
    fn kms_gcp_decrypt_body_and_answer() {
        let body: serde_json::Value = serde_json::from_str(&gcp::decrypt_body(b"w")).unwrap();
        assert_eq!(body["ciphertext"], B64.encode(b"w"));
        let answer = serde_json::json!({ "plaintext": B64.encode(b"key") });
        assert_eq!(gcp::plaintext_of(&answer).unwrap(), b"key");
        assert!(gcp::assertion("a@b.iam.gserviceaccount.com", "not a key", 0).is_err());
    }
}
