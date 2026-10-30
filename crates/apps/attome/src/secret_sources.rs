//! Cloud secret stores read once at boot (roadmap Z1-T12).
//!
//! With `ATTOME_SECRET_SOURCE` unset nothing happens: placeholders resolve
//! from the environment and `NAME_FILE` as before. Set to `aws` or `azure`,
//! every secret whose name starts with `ATTOME_SECRET_SOURCE_PREFIX` is read
//! once, before the configuration loads, and `${NAME}` resolves to the
//! secret named prefix + NAME ahead of the environment. The map is dropped
//! once the configuration is loaded; nothing refreshes it and no client
//! outlives the boot (D-549: a rotated secret takes a restart).
//!
//! - **AWS Secrets Manager** (`aws`, cargo feature `aws-secrets`): region
//!   from `ATTOME_SECRET_SOURCE_REGION` or `AWS_REGION`; credentials from
//!   `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and optional
//!   `AWS_SESSION_TOKEN`. Requests are signed with Signature Version 4.
//! - **Azure Key Vault** (`azure`, cargo feature `azure-keyvault`): vault
//!   from `ATTOME_SECRET_SOURCE_VAULT_URL`; a service principal from
//!   `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET`. Vault
//!   names allow letters, digits and `-` only, so a secret `attome-DB-PASSWORD`
//!   under prefix `attome-` answers `${DB_PASSWORD}` (each `-` after the
//!   prefix reads as `_`).
//!
//! The whole read has a 10-second limit. A failure stops the boot with a
//! message naming the source and the step, never a secret's value.

use std::collections::HashMap;
use std::time::Duration;

/// The whole read's limit.
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);
/// Most secrets read; a larger store is a misconfigured prefix.
const MAX_SECRETS: usize = 500;

/// Which store, from `ATTOME_SECRET_SOURCE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Aws { region: String, prefix: String },
    Azure { vault_url: String, prefix: String },
}

fn env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
}

/// The configured source from the environment; `Ok(None)` when unset.
pub fn source_from_env() -> Result<Option<Source>, String> {
    let Some(kind) = env("ATTOME_SECRET_SOURCE") else {
        return Ok(None);
    };
    let prefix = env("ATTOME_SECRET_SOURCE_PREFIX").unwrap_or_default();
    match kind.to_ascii_lowercase().as_str() {
        "aws" => {
            let region = env("ATTOME_SECRET_SOURCE_REGION")
                .or_else(|| env("AWS_REGION"))
                .ok_or(
                    "ATTOME_SECRET_SOURCE=aws needs ATTOME_SECRET_SOURCE_REGION or AWS_REGION",
                )?;
            Ok(Some(Source::Aws { region, prefix }))
        }
        "azure" => {
            let vault_url = env("ATTOME_SECRET_SOURCE_VAULT_URL")
                .ok_or("ATTOME_SECRET_SOURCE=azure needs ATTOME_SECRET_SOURCE_VAULT_URL")?;
            if !vault_url.starts_with("https://") {
                return Err("ATTOME_SECRET_SOURCE_VAULT_URL must be an https:// URL".into());
            }
            Ok(Some(Source::Azure {
                vault_url: vault_url.trim_end_matches('/').to_owned(),
                prefix,
            }))
        }
        other => Err(format!(
            "ATTOME_SECRET_SOURCE is {other:?}; it is aws or azure, or unset"
        )),
    }
}

/// The placeholder name a stored secret answers, or `None` when it is not
/// under the prefix. Pure.
pub fn placeholder_name(source: &Source, secret_name: &str) -> Option<String> {
    match source {
        Source::Aws { prefix, .. } => secret_name
            .strip_prefix(prefix.as_str())
            .filter(|rest| !rest.is_empty())
            .map(str::to_owned),
        Source::Azure { prefix, .. } => secret_name
            .strip_prefix(prefix.as_str())
            .filter(|rest| !rest.is_empty())
            .map(|rest| rest.replace('-', "_")),
    }
}

/// Reads the configured store once: `Ok(None)` when no store is configured,
/// else every secret under the prefix by placeholder name. The error names
/// the source and step, never a value.
pub async fn load() -> Result<Option<HashMap<String, String>>, String> {
    let Some(source) = source_from_env()? else {
        return Ok(None);
    };
    let label = match &source {
        Source::Aws { .. } => "AWS Secrets Manager",
        Source::Azure { .. } => "Azure Key Vault",
    };
    let fetched = tokio::time::timeout(TOTAL_TIMEOUT, fetch(&source))
        .await
        .map_err(|_| format!("{label}: secrets not read within 10 seconds"))?
        .map_err(|e| format!("{label}: {e}"))?;
    let mut map = HashMap::new();
    for (name, value) in fetched {
        if let Some(key) = placeholder_name(&source, &name) {
            map.insert(key, value);
        }
    }
    tracing::info!(
        source = label,
        secrets = map.len(),
        "secret store read at boot"
    );
    Ok(Some(map))
}

/// Loads the configuration with the store (when configured) asked before the
/// environment, then drops what was read.
///
/// Q19-T2: keys unwrapped by the customer's key service (`crate::kms`) are
/// asked first, then the store, then the environment.
pub async fn load_config() -> Result<attome_config::AppConfig, Box<dyn std::error::Error>> {
    let secrets = load().await?;
    let keys = crate::kms::load(secrets.as_ref()).await?;
    let lookup = |key: &str| lookup_in(keys.as_ref(), secrets.as_ref(), key);
    let config = attome_config::AppConfig::from_file_with_lookup(&lookup)?;
    drop(keys);
    drop(secrets);
    Ok(config)
}

/// Q19-T2: `key` from the unwrapped keys, else the secret store. Pure.
fn lookup_in(
    keys: Option<&HashMap<String, String>>,
    secrets: Option<&HashMap<String, String>>,
    key: &str,
) -> Option<String> {
    keys.and_then(|m| m.get(key))
        .or_else(|| secrets.and_then(|m| m.get(key)))
        .cloned()
}

/// [`load_config`] for an explicit path.
pub async fn load_config_from(
    path: String,
) -> Result<attome_config::AppConfig, Box<dyn std::error::Error>> {
    let secrets = load().await?;
    let keys = crate::kms::load(secrets.as_ref()).await?;
    let lookup = |key: &str| lookup_in(keys.as_ref(), secrets.as_ref(), key);
    let config = attome_config::AppConfig::from_path_with_lookup(path, &lookup)?;
    drop(keys);
    drop(secrets);
    Ok(config)
}

async fn fetch(source: &Source) -> Result<Vec<(String, String)>, String> {
    // The store's own host may be a private endpoint inside the operator's
    // network (a VPC endpoint, an Azure private link); it comes from the
    // operator's environment, never from a request.
    let store_host = match source {
        Source::Aws { region, .. } => format!("secretsmanager.{region}.amazonaws.com"),
        Source::Azure { vault_url, .. } => reqwest::Url::parse(vault_url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_default(),
    };
    let purpose =
        attome_outbound::http::Purpose::public("secret-sources").with_private_hosts([store_host]);
    let client = attome_outbound::http::client(purpose, |b| b.timeout(TOTAL_TIMEOUT))
        .map_err(|_| "could not build the HTTP client".to_owned())?;
    match source {
        #[cfg(feature = "aws-secrets")]
        Source::Aws { region, prefix } => aws::fetch(&client, region, prefix).await,
        #[cfg(not(feature = "aws-secrets"))]
        Source::Aws { .. } => {
            let _ = client;
            Err("this binary was built without the aws-secrets feature".into())
        }
        #[cfg(feature = "azure-keyvault")]
        Source::Azure { vault_url, prefix } => azure::fetch(&client, vault_url, prefix).await,
        #[cfg(not(feature = "azure-keyvault"))]
        Source::Azure { .. } => {
            let _ = client;
            Err("this binary was built without the azure-keyvault feature".into())
        }
    }
}

/// Q19-T2: the Signature Version 4 signer is shared with `kms`.
#[cfg(feature = "aws-secrets")]
pub(crate) mod aws {
    use hmac::{Hmac, Mac};
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    const SERVICE: &str = "secretsmanager";

    fn hmac(key: &[u8], data: &str) -> Vec<u8> {
        // HMAC takes a key of any length.
        let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
            Ok(mac) => mac,
            Err(_) => return Vec::new(),
        };
        mac.update(data.as_bytes());
        mac.finalize().into_bytes().to_vec()
    }

    /// The Signature Version 4 signing key. Pure.
    pub(super) fn signing_key(secret: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
        let k_date = hmac(format!("AWS4{secret}").as_bytes(), date);
        let k_region = hmac(&k_date, region);
        let k_service = hmac(&k_region, service);
        hmac(&k_service, "aws4_request")
    }

    pub(crate) struct Credentials {
        pub(crate) access_key: String,
        pub(crate) secret_key: String,
        pub(crate) session_token: Option<String>,
    }

    /// The headers of one signed `POST /` call of `target` on `service`.
    /// Pure.
    pub(crate) fn signed_headers(
        creds: &Credentials,
        region: &str,
        host: &str,
        service: &str,
        target: &str,
        body: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<(String, String)> {
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let mut headers: Vec<(String, String)> = vec![
            ("content-type".into(), "application/x-amz-json-1.1".into()),
            ("host".into(), host.to_owned()),
            ("x-amz-date".into(), amz_date.clone()),
            ("x-amz-target".into(), target.to_owned()),
        ];
        if let Some(token) = &creds.session_token {
            headers.push(("x-amz-security-token".into(), token.clone()));
        }
        headers.sort();
        let canonical_headers: String = headers
            .iter()
            .map(|(k, v)| format!("{k}:{}\n", v.trim()))
            .collect();
        let signed: String = headers
            .iter()
            .map(|(k, _)| k.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let canonical_request = format!(
            "POST\n/\n\n{canonical_headers}\n{signed}\n{}",
            hex::encode(Sha256::digest(body.as_bytes()))
        );
        let scope = format!("{date}/{region}/{service}/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{}",
            hex::encode(Sha256::digest(canonical_request.as_bytes()))
        );
        let signature = hex::encode(hmac(
            &signing_key(&creds.secret_key, &date, region, service),
            &string_to_sign,
        ));
        headers.push((
            "authorization".into(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
                creds.access_key
            ),
        ));
        headers.retain(|(k, _)| k != "host");
        headers
    }

    pub(crate) fn credentials() -> Result<Credentials, String> {
        let access_key = super::env("AWS_ACCESS_KEY_ID")
            .ok_or("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are needed")?;
        let secret_key = super::env("AWS_SECRET_ACCESS_KEY")
            .ok_or("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are needed")?;
        Ok(Credentials {
            access_key,
            secret_key,
            session_token: super::env("AWS_SESSION_TOKEN"),
        })
    }

    pub(super) async fn fetch(
        client: &attome_outbound::http::Outbound,
        region: &str,
        prefix: &str,
    ) -> Result<Vec<(String, String)>, String> {
        let creds = credentials()?;
        let host = format!("secretsmanager.{region}.amazonaws.com");
        let mut out = Vec::new();
        let mut next: Option<String> = None;
        loop {
            let mut body = json!({ "MaxResults": 20 });
            if !prefix.is_empty() {
                body["Filters"] = json!([{ "Key": "name", "Values": [prefix] }]);
            }
            if let Some(token) = &next {
                body["NextToken"] = json!(token);
            }
            let body = body.to_string();
            let headers = signed_headers(
                &creds,
                region,
                &host,
                SERVICE,
                "secretsmanager.BatchGetSecretValue",
                &body,
                chrono::Utc::now(),
            );
            let mut request = client.post(format!("https://{host}/")).body(body);
            for (k, v) in &headers {
                request = request.header(k.as_str(), v.as_str());
            }
            let response = request
                .send()
                .await
                .map_err(|_| "BatchGetSecretValue could not be reached".to_owned())?;
            let status = response.status();
            if !status.is_success() {
                return Err(format!("BatchGetSecretValue answered {status}"));
            }
            let page: Value = response
                .json()
                .await
                .map_err(|_| "BatchGetSecretValue answered something unreadable".to_owned())?;
            if let Some(errors) = page["Errors"].as_array()
                && !errors.is_empty()
            {
                return Err(format!(
                    "BatchGetSecretValue could not read {} secret(s)",
                    errors.len()
                ));
            }
            for item in page["SecretValues"].as_array().into_iter().flatten() {
                if let (Some(name), Some(value)) =
                    (item["Name"].as_str(), item["SecretString"].as_str())
                    && name.starts_with(prefix)
                {
                    out.push((name.to_owned(), value.to_owned()));
                }
            }
            if out.len() > super::MAX_SECRETS {
                return Err(format!(
                    "more than {} secrets under the prefix",
                    super::MAX_SECRETS
                ));
            }
            next = page["NextToken"]
                .as_str()
                .filter(|t| !t.is_empty())
                .map(str::to_owned);
            if next.is_none() {
                return Ok(out);
            }
        }
    }
}

/// Q19-T2: the service-principal sign-in is shared with `kms`.
#[cfg(feature = "azure-keyvault")]
pub(crate) mod azure {
    use serde_json::Value;

    const API_VERSION: &str = "7.4";

    pub(crate) async fn token(client: &attome_outbound::http::Outbound) -> Result<String, String> {
        let need = "AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET are needed";
        let tenant = super::env("AZURE_TENANT_ID").ok_or(need)?;
        let client_id = super::env("AZURE_CLIENT_ID").ok_or(need)?;
        let secret = super::env("AZURE_CLIENT_SECRET").ok_or(need)?;
        if !tenant
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        {
            return Err("AZURE_TENANT_ID is not a tenant id or domain".into());
        }
        let response = client
            .post(format!(
                "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
            ))
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", client_id.as_str()),
                ("client_secret", secret.as_str()),
                ("scope", "https://vault.azure.net/.default"),
            ])
            .send()
            .await
            .map_err(|_| "the sign-in endpoint could not be reached".to_owned())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("sign-in answered {status}"));
        }
        let body: Value = response
            .json()
            .await
            .map_err(|_| "sign-in answered something unreadable".to_owned())?;
        body["access_token"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| "sign-in gave no access token".to_owned())
    }

    async fn get(
        client: &attome_outbound::http::Outbound,
        token: &str,
        url: &str,
    ) -> Result<Value, String> {
        let response = client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| "the vault could not be reached".to_owned())?;
        let status = response.status();
        if !status.is_success() {
            return Err(format!("the vault answered {status}"));
        }
        response
            .json()
            .await
            .map_err(|_| "the vault answered something unreadable".to_owned())
    }

    /// The secret name at the end of a vault item id. Pure.
    pub(super) fn name_of(id: &str) -> Option<&str> {
        id.trim_end_matches('/')
            .rsplit_once("/secrets/")
            .map(|(_, rest)| rest.split('/').next().unwrap_or(rest))
    }

    pub(super) async fn fetch(
        client: &attome_outbound::http::Outbound,
        vault_url: &str,
        prefix: &str,
    ) -> Result<Vec<(String, String)>, String> {
        let token = token(client).await?;
        let mut names = Vec::new();
        let mut url = Some(format!("{vault_url}/secrets?api-version={API_VERSION}"));
        while let Some(page_url) = url.take() {
            // Only the vault's own paging links are followed.
            if !page_url.starts_with(vault_url) {
                return Err("the vault sent a paging link to another host".into());
            }
            let page = get(client, &token, &page_url).await?;
            for item in page["value"].as_array().into_iter().flatten() {
                let enabled = item["attributes"]["enabled"].as_bool().unwrap_or(true);
                if let Some(name) = item["id"].as_str().and_then(name_of)
                    && enabled
                    && name.starts_with(prefix)
                {
                    names.push(name.to_owned());
                }
            }
            if names.len() > super::MAX_SECRETS {
                return Err(format!(
                    "more than {} secrets under the prefix",
                    super::MAX_SECRETS
                ));
            }
            url = page["nextLink"]
                .as_str()
                .filter(|l| !l.is_empty())
                .map(str::to_owned);
        }
        let mut out = Vec::with_capacity(names.len());
        for name in names {
            let item = get(
                client,
                &token,
                &format!("{vault_url}/secrets/{name}?api-version={API_VERSION}"),
            )
            .await?;
            if let Some(value) = item["value"].as_str() {
                out.push((name, value.to_owned()));
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_map_to_placeholders() {
        let aws = Source::Aws {
            region: "me-central-1".into(),
            prefix: "attome/".into(),
        };
        assert_eq!(
            placeholder_name(&aws, "attome/DATABASE_PASSWORD").as_deref(),
            Some("DATABASE_PASSWORD")
        );
        assert_eq!(placeholder_name(&aws, "other/DATABASE_PASSWORD"), None);
        assert_eq!(placeholder_name(&aws, "attome/"), None);
        let azure = Source::Azure {
            vault_url: "https://v.vault.azure.net".into(),
            prefix: "attome-".into(),
        };
        assert_eq!(
            placeholder_name(&azure, "attome-DATABASE-PASSWORD").as_deref(),
            Some("DATABASE_PASSWORD")
        );
    }

    #[test]
    fn unwrapped_keys_resolve_ahead_of_the_store() {
        let keys = HashMap::from([("JWT_SECRET".to_owned(), "from-kms".to_owned())]);
        let store = HashMap::from([
            ("JWT_SECRET".to_owned(), "from-store".to_owned()),
            ("DB_PASSWORD".to_owned(), "pw".to_owned()),
        ]);
        assert_eq!(
            lookup_in(Some(&keys), Some(&store), "JWT_SECRET").as_deref(),
            Some("from-kms")
        );
        assert_eq!(
            lookup_in(Some(&keys), Some(&store), "DB_PASSWORD").as_deref(),
            Some("pw")
        );
        assert_eq!(lookup_in(None, None, "DB_PASSWORD"), None);
    }

    /// The signing key from AWS's own Signature Version 4 example.
    #[cfg(feature = "aws-secrets")]
    #[test]
    fn aws_signing_key_matches_the_documented_example() {
        let key = aws::signing_key(
            "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
            "20120215",
            "us-east-1",
            "iam",
        );
        assert_eq!(
            hex::encode(key),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
    }

    #[cfg(feature = "aws-secrets")]
    #[test]
    fn aws_request_is_signed_without_the_host_header_sent() {
        let creds = aws::Credentials {
            access_key: "AKIDEXAMPLE".into(),
            secret_key: "secret".into(),
            session_token: Some("token".into()),
        };
        let now = chrono::DateTime::parse_from_rfc3339("2026-10-26T09:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let headers = aws::signed_headers(
            &creds,
            "me-central-1",
            "secretsmanager.me-central-1.amazonaws.com",
            "secretsmanager",
            "secretsmanager.BatchGetSecretValue",
            "{}",
            now,
        );
        let auth = &headers
            .iter()
            .find(|(k, _)| k == "authorization")
            .unwrap()
            .1;
        assert!(auth.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261026/me-central-1/secretsmanager/aws4_request, \
             SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature="
        ));
        assert!(headers.iter().all(|(k, _)| k != "host"));
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "x-amz-date" && v == "20261026T090000Z")
        );
    }

    #[cfg(feature = "azure-keyvault")]
    #[test]
    fn azure_item_ids_name_their_secret() {
        assert_eq!(
            azure::name_of("https://v.vault.azure.net/secrets/attome-DB-PASSWORD"),
            Some("attome-DB-PASSWORD")
        );
        assert_eq!(
            azure::name_of("https://v.vault.azure.net/secrets/attome-DB/0123abcd"),
            Some("attome-DB")
        );
        assert_eq!(azure::name_of("https://v.vault.azure.net/keys/x"), None);
    }
}
