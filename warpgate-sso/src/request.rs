use openidconnect::url::Url;
use openidconnect::{CsrfToken, Nonce, PkceCodeVerifier, RedirectUrl};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use tracing::{debug, error, warn};

use crate::{
    GroupClaim, SsoClient, SsoError, SsoInternalProviderConfig, SsoLoginResponse, SsoResult,
    flatten_group_claim,
};

#[derive(Serialize, Deserialize, Debug)]
pub struct SsoLoginRequest {
    pub(crate) auth_url: Url,
    pub(crate) csrf_token: CsrfToken,
    pub(crate) nonce: Nonce,
    pub(crate) redirect_url: RedirectUrl,
    pub(crate) pkce_verifier: Option<PkceCodeVerifier>,
    pub(crate) config: SsoInternalProviderConfig,
}

impl SsoLoginRequest {
    pub const fn auth_url(&self) -> &Url {
        &self.auth_url
    }

    pub const fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }

    pub fn verify_state(&self, state: &str) -> bool {
        self.csrf_token()
            .secret()
            .as_bytes()
            .ct_eq(state.as_bytes())
            .into()
    }

    pub const fn redirect_url(&self) -> &RedirectUrl {
        &self.redirect_url
    }

    pub async fn verify_code(self, code: String) -> Result<SsoLoginResponse, SsoError> {
        let config = self.config.clone();
        let result = SsoClient::new(config.clone())?
            .finish_login(self.pkce_verifier, self.redirect_url, &self.nonce, code)
            .await?;
        Ok(map_sso_result(&config, result).await)
    }
}

/// Map verified OIDC claims (+ optional userinfo claims) into a SsoLoginResponse.
/// Shared by the interactive code flow and the bearer-token (kubectl) flow.
pub async fn map_sso_result(
    config: &SsoInternalProviderConfig,
    result: SsoResult,
) -> SsoLoginResponse {
    debug!("OIDC claims: {:?}", result.claims);
    debug!("OIDC userinfo claims: {:?}", result.userinfo_claims);

    macro_rules! get_claim {
        ($method:ident) => {
            result
                .claims
                .$method()
                .or(result.userinfo_claims.as_ref().and_then(|x| x.$method()))
        };
    }

    // Username resolution order:
    // 1. Custom username_claim from SSO config (if configured)
    //    Read from raw ID token JSON — NOT via serde(flatten) which could
    //    allow malicious OIDC claims to shadow typed fields like warpgate_roles.
    // 2. preferred_username standard claim
    // 3. email as fallback
    let custom_username =
        resolve_custom_username(config.username_claim(), result.raw_id_token_claims.as_ref());

    let preferred_username = custom_username
        .or_else(|| {
            get_claim!(preferred_username)
                .map(|x| x.as_str())
                .map(ToString::to_string)
        })
        .or_else(|| {
            get_claim!(email)
                .map(|x| x.as_str())
                .map(ToString::to_string)
        });

    let name = get_claim!(name)
        .and_then(|x| x.get(None))
        .map(|x| x.as_str())
        .map(ToString::to_string);

    let email = get_claim!(email)
        .map(|x| x.as_str())
        .map(ToString::to_string);
    let email_verified = get_claim!(email_verified);

    let (access_groups, admin_groups) =
        match crate::google_groups::fetch_groups_if_configured(config, email.as_deref()).await {
            Ok(Some(google_groups)) => (Some(google_groups.clone()), Some(google_groups)),
            Ok(None) => (
                extract_groups(
                    &result,
                    config.roles_claim(),
                    config.role_mappings().is_some(),
                ),
                extract_groups(
                    &result,
                    config.admin_roles_claim(),
                    config.admin_role_mappings().is_some(),
                ),
            ),
            Err(e) => {
                error!("Failed to fetch Google groups: {e}");
                (None, None)
            }
        };

    SsoLoginResponse {
        preferred_username,
        name,
        email,
        email_verified,
        access_roles: access_groups,
        admin_roles: admin_groups,
        id_token: result.token.clone(),
    }
}

/// Resolve the operator-configured custom username claim out of the raw ID
/// token JSON, warning on every way it can fail to resolve.
///
/// The diagnostic matters more than a usual lost log line. This is the whole
/// username path for a provider mapped onto a custom claim (such as
/// `username_claim: "EXTRAUsername"`), and when it yields nothing the caller
/// silently falls through to `preferred_username` and then `email` — so a
/// renamed, misspelled or non-string claim does not fail the login, it logs
/// the user in under a *different* username. That is close to undiagnosable
/// from outside the process, hence one warning per failure mode, each naming
/// the claim.
///
/// The claim *value* is a username and is never logged; the claim *name* and
/// the set of names actually present are (matching `extract_groups` below).
/// An unconfigured `username_claim` is the normal path and stays silent.
fn resolve_custom_username(
    claim_name: Option<&str>,
    raw_id_token_claims: Option<&serde_json::Value>,
) -> Option<String> {
    let claim_name = claim_name?;

    let Some(claims) = raw_id_token_claims else {
        warn!(
            "`username_claim` is set to {claim_name:?} but no raw ID token claims are available; falling back to preferred_username/email"
        );
        return None;
    };

    let Some(value) = claims.get(claim_name) else {
        warn!(
            "`username_claim` {claim_name:?} is not present in the ID token claims; falling back to preferred_username/email. Claims present: {:?}",
            claims
                .as_object()
                .map(|o| o.keys().collect::<Vec<_>>())
                .unwrap_or_default(),
        );
        return None;
    };

    let Some(username) = value.as_str() else {
        warn!(
            "`username_claim` {claim_name:?} is present but is not a JSON string (it is a {}); falling back to preferred_username/email",
            json_type_name(value),
        );
        return None;
    };

    Some(username.to_owned())
}

/// Name a JSON value's type for diagnostics, without revealing its contents.
const fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn extract_groups(result: &SsoResult, claim: &str, warn_if_missing: bool) -> Option<Vec<String>> {
    let userinfo_claims = result
        .userinfo_claims
        .as_ref()
        .map(|u| &u.additional_claims().0);
    let Some(raw) = result
        .claims
        .additional_claims()
        .0
        .get(claim)
        .or_else(|| userinfo_claims.and_then(|c| c.get(claim)))
    else {
        if warn_if_missing {
            warn!(
                "Claim {claim:?} not found - roles will not be synced. ID token claims: {:?}, userinfo claims: {:?}",
                result
                    .claims
                    .additional_claims()
                    .0
                    .keys()
                    .collect::<Vec<_>>(),
                userinfo_claims.map(|c| c.keys().collect::<Vec<_>>()),
            );
        }
        return None;
    };
    match serde_json::from_value::<GroupClaim>(raw.clone()) {
        Ok(claim) => Some(flatten_group_claim(claim)),
        Err(e) => {
            warn!("Claim {claim:?} is not a list of role names, ignoring: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::resolve_custom_username;

    #[test]
    fn a_configured_string_claim_resolves() {
        let claims = json!({"EXTRAUsername": "alice", "email": "alice@example.com"});
        assert_eq!(
            resolve_custom_username(Some("EXTRAUsername"), Some(&claims)),
            Some("alice".to_owned())
        );
    }

    #[test]
    fn an_unconfigured_claim_resolves_to_none_without_inspecting_claims() {
        // The normal path: no `username_claim`, so the caller falls through to
        // `preferred_username`. This must not warn.
        let claims = json!({"EXTRAUsername": "alice"});
        assert_eq!(resolve_custom_username(None, Some(&claims)), None);
        assert_eq!(resolve_custom_username(None, None), None);
    }

    #[test]
    fn a_configured_claim_with_no_raw_claims_at_all_resolves_to_none() {
        assert_eq!(resolve_custom_username(Some("EXTRAUsername"), None), None);
    }

    #[test]
    fn a_configured_claim_absent_from_the_token_resolves_to_none() {
        let claims = json!({"preferred_username": "alice@example.com"});
        assert_eq!(
            resolve_custom_username(Some("EXTRAUsername"), Some(&claims)),
            None
        );
    }

    #[test]
    fn a_configured_claim_that_is_not_a_string_resolves_to_none() {
        for value in [json!(42), json!(null), json!(["alice"]), json!({"u": 1})] {
            let claims = json!({"EXTRAUsername": value});
            assert_eq!(
                resolve_custom_username(Some("EXTRAUsername"), Some(&claims)),
                None,
                "non-string claim {value} must not be used as a username"
            );
        }
    }
}
