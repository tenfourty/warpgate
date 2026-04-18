use anyhow::Context;
use poem::Request;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use time::OffsetDateTime;
use tracing::{debug, info, warn};
use uuid::Uuid;
use warpgate_aws::EksClusterInfo;
use warpgate_ca::{deserialize_certificate, serialize_certificate_serial};
use warpgate_common::auth::AuthStateUserInfo;
use warpgate_common::{Target, TargetKubernetesOptions, TargetOptions, User};
use warpgate_core::auth::step_up::get_cert_last_sso_at;
use warpgate_core::{ConfigProvider, Services};
use warpgate_db_entities::{CertificateCredential, CertificateRevocation};

use crate::server::client_certs::RequestCertificateExt;
use crate::server::step_up::is_cert_step_up_stale;

pub async fn authenticate_and_get_target(
    req: &Request,
    target_name: &str,
    services: &Services,
) -> poem::Result<(AuthStateUserInfo, Target)> {
    // Check for Bearer token authentication (API tokens)
    if let Some(auth_header) = req.headers().get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                let mut config_provider = services.config_provider.lock().await;
                if let Ok(Some(user)) = config_provider.validate_api_token(token).await {
                    // Look up the specific target by name from the URL
                    let targets = config_provider
                        .list_targets()
                        .await
                        .context("listing targets")?;

                    // Find the target with the specified name
                    for target in targets {
                        if target.name == target_name
                            && matches!(target.options, TargetOptions::Kubernetes(_))
                        {
                            if config_provider
                                .authorize_target(&user.username, &target.name)
                                .await
                                .unwrap_or(false)
                            {
                                return Ok(((&user).into(), target));
                            }
                            return Err(poem::Error::from_string(
                                format!("Access denied to target: {target_name}"),
                                poem::http::StatusCode::FORBIDDEN,
                            ));
                        }
                    }

                    return Err(poem::Error::from_string(
                        format!("Kubernetes target not found: {target_name}"),
                        poem::http::StatusCode::NOT_FOUND,
                    ));
                }
            }
        }
    }

    // Check for client certificate authentication
    // Use certificate extracted by middleware if present
    if let Some(client_cert) = req.client_certificate() {
        debug!("Found client certificate from middleware, validating against database");

        match validate_client_certificate(&client_cert.der_bytes, services).await {
            Ok(Some(CertAuthMatch { user_info, cert_id })) => {
                // Look up the specific target by name from the URL
                let mut config_provider = services.config_provider.lock().await;
                let targets = config_provider
                    .list_targets()
                    .await
                    .context("listing targets")?;

                // Find the target with the specified name
                for target in targets {
                    if target.name == target_name
                        && matches!(target.options, TargetOptions::Kubernetes(_))
                    {
                        if config_provider
                            .authorize_target(&user_info.username, &target.name)
                            .await
                            .unwrap_or(false)
                        {
                            // Drop the config_provider lock before taking
                            // `config` + `db` below — matches the SSH A1
                            // ordering (config_provider is never the
                            // outermost lock).
                            drop(config_provider);

                            // Per-cert step-up freshness gate (commit A3).
                            // If `step_up_interval.kubernetes` is set and the
                            // matched cert row's `last_sso_at` is stale or
                            // missing, reject with 401 + `WWW-Authenticate:
                            // SSO <url>` so kubectl operators know to
                            // re-SSO via the gateway web UI.
                            enforce_cert_step_up_gate(req, services, cert_id, &user_info).await?;

                            return Ok((user_info, target));
                        }
                        return Err(poem::Error::from_string(
                            format!("Access denied to target: {target_name}"),
                            poem::http::StatusCode::FORBIDDEN,
                        ));
                    }
                }

                return Err(poem::Error::from_string(
                    format!("Kubernetes target not found: {target_name}"),
                    poem::http::StatusCode::NOT_FOUND,
                ));
            }
            Ok(None) => {
                debug!("Client certificate provided but not found in database");
            }
            Err(e) => {
                warn!(error = %e, "Error validating client certificate");
            }
        }
    } else {
        debug!("No client certificate provided in TLS connection");
    }

    // Return unauthorized if no valid authentication found
    Err(poem::Error::from_string(
        "Unauthorized: Please provide either a valid Bearer token or a client certificate",
        poem::http::StatusCode::UNAUTHORIZED,
    ))
}

pub async fn create_authenticated_client(
    k8s_options: &TargetKubernetesOptions,
    _auth_user: Option<&String>,
    _services: &Services,
) -> anyhow::Result<reqwest::ClientBuilder> {
    debug!(
        server_url = ?k8s_options.cluster_url,
        auth_kind = ?k8s_options.auth,
        tls_config = ?k8s_options.tls,
        "Creating authenticated Kubernetes client"
    );

    // Create HTTP client with the configuration
    let mut client_builder = reqwest::Client::builder();

    if !k8s_options.tls.verify {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }

    match &k8s_options.auth {
        warpgate_common::KubernetesTargetAuth::Token(auth) => {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!(
                    "Bearer {}",
                    auth.token.expose_secret()
                ))
                .context("setting Authorization header")?,
            );
            client_builder = client_builder.default_headers(headers);
        }
        warpgate_common::KubernetesTargetAuth::Certificate(auth) => {
            // Expect PEM certificate and PEM private key in the auth config
            // Combine into a single PEM bundle for reqwest::Identity
            let cert_pem = auth.certificate.expose_secret();
            let key_pem = auth.private_key.expose_secret();
            let mut pem_bundle = String::new();
            pem_bundle.push_str(cert_pem);
            if !pem_bundle.ends_with('\n') {
                pem_bundle.push('\n');
            }
            pem_bundle.push_str(key_pem);
            if !pem_bundle.ends_with('\n') {
                pem_bundle.push('\n');
            }

            let identity = reqwest::Identity::from_pem(pem_bundle.as_bytes())
                .context("Invalid client certificate/key for Kubernetes upstream")?;
            client_builder = client_builder.identity(identity);
        }
        warpgate_common::KubernetesTargetAuth::IamRole(_) => {
            // EKS IAM role authentication: generate a token from the cluster URL
            let EksClusterInfo { name, region } =
                warpgate_aws::find_eks_cluster_by_url(&k8s_options.cluster_url)
                    .await
                    .context("EKS cluster lookup")?;

            let token = warpgate_aws::generate_eks_token(&name, &region)
                .await
                .context("EKS token generation")?;

            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(
                reqwest::header::AUTHORIZATION,
                reqwest::header::HeaderValue::from_str(&format!("Bearer {token}"))
                    .context("setting Authorization header for EKS token")?,
            );
            client_builder = client_builder.default_headers(headers);
        }
    }

    Ok(client_builder)
}

/// Result of a successful client-certificate validation: the authenticated
/// user plus the `credentials_certificate.id` of the row that matched. The
/// cert id is the per-row step-up freshness key — callers consult
/// `credentials_certificate.last_sso_at` on that row to decide whether to
/// gate the request behind a fresh SSO handshake (commit A3).
pub struct CertAuthMatch {
    pub user_info: AuthStateUserInfo,
    pub cert_id: Uuid,
}

// Helper function to validate client certificate against database
pub async fn validate_client_certificate(
    cert_der: &[u8],
    services: &Services,
) -> anyhow::Result<Option<CertAuthMatch>> {
    // Convert DER to PEM format for comparison
    let cert_pem = der_to_pem(cert_der);

    let db = services.db.lock().await;

    // Check if certificate is revoked (by serial number)
    let cert = deserialize_certificate(&cert_pem)?;
    let serial_b64 = serialize_certificate_serial(&cert);
    if CertificateRevocation::Entity::find()
        .filter(CertificateRevocation::Column::SerialNumberBase64.eq(&serial_b64))
        .one(&*db)
        .await?
        .is_some()
    {
        warn!(serial = %serial_b64, "Client certificate is revoked");
        return Ok(None);
    }

    // Find all certificate credentials and match against the provided certificate
    let cert_credentials = CertificateCredential::Entity::find()
        .find_with_related(warpgate_db_entities::User::Entity)
        .all(&*db)
        .await?;

    for (cert_credential, users) in cert_credentials {
        if let Some(user) = users.into_iter().next() {
            // Normalize both certificates for comparison
            let stored_cert = normalize_certificate_pem(&cert_credential.certificate_pem);
            let provided_cert = normalize_certificate_pem(&cert_pem);

            if stored_cert == provided_cert {
                debug!(
                    user = user.username,
                    cert_label = cert_credential.label,
                    "Client certificate validated for user"
                );

                let cert_id = cert_credential.id;

                // Update last_used timestamp
                let mut active_model: CertificateCredential::ActiveModel = cert_credential.into();
                active_model.last_used = Set(Some(OffsetDateTime::now_utc()));
                if let Err(e) = active_model.update(&*db).await {
                    warn!("Failed to update certificate last_used timestamp: {}", e);
                }

                return Ok(Some(CertAuthMatch {
                    user_info: (&User::try_from(user)?).into(),
                    cert_id,
                }));
            }
        }
    }

    Ok(None)
}

fn der_to_pem(der_bytes: &[u8]) -> String {
    use base64::engine::general_purpose;
    use base64::Engine as _;
    let cert_b64 = general_purpose::STANDARD.encode(der_bytes);
    let cert_lines: Vec<String> = cert_b64
        .chars()
        .collect::<Vec<char>>()
        .chunks(64)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect();

    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----",
        cert_lines.join("\n")
    )
}

fn normalize_certificate_pem(pem: &str) -> String {
    pem.lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<&str>>()
        .join("")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// Enforce the Kubernetes per-cert step-up SSO freshness gate (commit A3).
///
/// If `step_up_interval.kubernetes` is unset: no-op (feature disabled).
/// Otherwise, look up `credentials_certificate.last_sso_at` for the matched
/// cert row; if stale (older than the interval, or `NULL`), return a poem
/// 401 `UNAUTHORIZED` carrying a `WWW-Authenticate: SSO <url>` header so a
/// kubectl operator running inside a browser-capable wrapper knows to
/// re-SSO. kubectl itself has no OIDC return-path today — on 401 the user
/// browses to the gateway, completes SSO, and the operator tooling
/// (future) stamps `last_sso_at`.
///
/// Database read failures fail-closed (treated as stale): an internal error
/// reading the freshness column must not silently grant access beyond the
/// interval.
async fn enforce_cert_step_up_gate(
    req: &Request,
    services: &Services,
    cert_id: Uuid,
    user_info: &AuthStateUserInfo,
) -> poem::Result<()> {
    // Hot path: interval absent → feature off → skip DB read entirely.
    let interval = {
        let cfg = services.config.lock().await;
        cfg.store
            .step_up_interval
            .as_ref()
            .and_then(|s| s.kubernetes)
    };
    let Some(interval) = interval else {
        return Ok(());
    };

    let last = {
        let db = services.db.lock().await;
        match get_cert_last_sso_at(&db, cert_id).await {
            Ok(ts) => ts,
            Err(e) => {
                // Fail-closed: a DB error reading the stamp must not let
                // the request through. Treat as stale (None) so the
                // freshness check below rejects.
                warn!(
                    error = ?e,
                    %cert_id,
                    username = %user_info.username,
                    "Kubernetes step-up: failed to read cert last_sso_at; failing closed (stale)"
                );
                None
            }
        }
    };

    if !is_cert_step_up_stale(last, Some(interval), OffsetDateTime::now_utc()) {
        return Ok(());
    }

    info!(
        %cert_id,
        username = %user_info.username,
        "Kubernetes step-up required: cert last_sso_at is stale or missing"
    );

    // Build the gateway login URL so kubectl operators have a target to
    // re-SSO against. Fall back to a header without a URL if the external
    // host isn't configured — still returns 401, just without a hint.
    let sso_header_value = {
        let config = services.config.lock().await;
        match config.construct_external_url(Some(req), None) {
            Ok(mut url) => {
                url.set_path("@warpgate");
                url.set_fragment(Some("/login"));
                format!("SSO url=\"{url}\"")
            }
            Err(e) => {
                warn!(error = ?e, "Kubernetes step-up: external host not configured, omitting SSO URL from WWW-Authenticate");
                "SSO".to_string()
            }
        }
    };

    Err(poem::Error::from_response(
        poem::Response::builder()
            .status(poem::http::StatusCode::UNAUTHORIZED)
            .header(poem::http::header::WWW_AUTHENTICATE, sso_header_value)
            .body("SSO step-up required: client certificate has not completed SSO recently enough. Re-authenticate via the Warpgate web UI."),
    ))
}
