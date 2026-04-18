use std::sync::Mutex;

use warpgate_common::WarpgateError;
use warpgate_common::auth::{
    AuthCredential, AuthState, CredentialKind, CredentialMatch, SubmitOutcome,
};

use crate::ConfigProvider;

pub mod step_up;

/// Validate `credential` and, if it passes, record it on `state`.
///
/// Also captures the row id of a matched public key onto the state
/// ([`AuthState::set_matched_pubkey_id`]) so the per-pubkey step-up freshness
/// gate can address the exact `credentials_public_key` row that authenticated.
/// `AuthState::submit_credential` only knows about `bool`, so the match is
/// carried out of the validator through a short-lived cell rather than by
/// widening upstream's validator contract.
pub async fn submit_credential<C: ConfigProvider>(
    state: &mut AuthState,
    credential: AuthCredential,
    cp: &C,
) -> Result<SubmitOutcome, WarpgateError> {
    let matched: Mutex<Option<CredentialMatch>> = Mutex::new(None);
    let matched_ref = &matched;

    let outcome = state
        .submit_credential(credential, move |username, credential| async move {
            let m = cp.validate_credential(&username, &credential).await?;
            if let Ok(mut slot) = matched_ref.lock() {
                *slot = m;
            }
            Ok(m.is_some())
        })
        .await?;

    if let Ok(slot) = matched.lock()
        && let Some(CredentialMatch {
            kind: CredentialKind::PublicKey,
            credential_id: Some(pubkey_id),
        }) = *slot
    {
        state.set_matched_pubkey_id(pubkey_id);
    }

    Ok(outcome)
}
