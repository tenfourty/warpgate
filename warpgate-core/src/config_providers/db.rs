use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use data_encoding::BASE64;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection,
    EntityTrait, ModelTrait, QueryFilter, QueryOrder, Set,
};
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use warpgate_common::auth::{
    AllCredentialsPolicy, AnySingleCredentialPolicy, AuthCredential, CredentialKind,
    CredentialMatch, CredentialPolicy, PerProtocolCredentialPolicy,
};
use warpgate_common::helpers::hash::verify_password_hash;
use warpgate_common::helpers::otp::verify_totp;
use warpgate_common::{
    Role, Target, User, UserAuthCredential, UserPasswordCredential, UserPublicKeyCredential,
    UserRequireCredentialsPolicy, UserSsoCredential, UserTotpCredential, WarpgateError,
};
use warpgate_db_entities as entities;
use warpgate_sso::SsoProviderConfig;

use super::ConfigProvider;

pub struct DatabaseConfigProvider {
    db: Arc<Mutex<DatabaseConnection>>,
}

impl DatabaseConfigProvider {
    pub fn new(db: &Arc<Mutex<DatabaseConnection>>) -> Self {
        Self { db: db.clone() }
    }

    async fn sync_ldap_ssh_keys(
        &self,
        db: &DatabaseConnection,
        user_id: Uuid,
        ldap_server_id: Uuid,
        ldap_object_uuid: &Uuid,
    ) -> Result<(), WarpgateError> {
        // Fetch LDAP server config
        let ldap_server = entities::LdapServer::Entity::find_by_id(ldap_server_id)
            .one(db)
            .await?
            .ok_or_else(|| {
                warpgate_ldap::LdapError::InvalidConfiguration("LDAP server not found".to_string())
            })?;

        if !ldap_server.enabled {
            debug!(
                "LDAP server {} is disabled, skipping SSH key sync",
                ldap_server.name
            );
            return Ok(());
        }

        let ldap_config = warpgate_ldap::LdapConfig::try_from(&ldap_server)?;

        // Find user in LDAP by object UUID
        let ldap_user = warpgate_ldap::find_user_by_uuid(&ldap_config, ldap_object_uuid).await?;

        let Some(ldap_user) = ldap_user else {
            warn!(
                "LDAP user with UUID {} not found in server {}",
                ldap_object_uuid, ldap_server.name
            );
            return Ok(());
        };

        // Delete existing public key credentials for this user
        entities::PublicKeyCredential::Entity::delete_many()
            .filter(entities::PublicKeyCredential::Column::UserId.eq(user_id))
            .exec(db)
            .await?;

        // Insert SSH keys from LDAP
        for ssh_key in &ldap_user.ssh_public_keys {
            let ssh_key = ssh_key.trim();
            if ssh_key.is_empty() {
                continue;
            }

            // Parse and validate the SSH key
            let key_result = russh::keys::PublicKey::from_openssh(ssh_key);
            if let Ok(mut key) = key_result {
                key.set_comment("");
                let openssh_key = key.to_openssh().map_err(russh::keys::Error::from)?;

                entities::PublicKeyCredential::ActiveModel {
                    id: Set(Uuid::new_v4()),
                    user_id: Set(user_id),
                    date_added: Set(Some(OffsetDateTime::now_utc())),
                    last_used: Set(None),
                    label: Set("Public key synchronized from LDAP".to_string()),
                    ..entities::PublicKeyCredential::ActiveModel::from(UserPublicKeyCredential {
                        key: openssh_key.into(),
                    })
                }
                .insert(db)
                .await?;
            } else {
                warn!("Invalid SSH key from LDAP: {}", ssh_key);
            }
        }

        info!(
            "Synced {} SSH key(s) from LDAP for {}",
            ldap_user.ssh_public_keys.len(),
            ldap_user.username
        );

        Ok(())
    }

    async fn maybe_autocreate_sso_user(
        &self,
        db: &DatabaseConnection,
        credential: UserSsoCredential,
        preferred_username: String,
        default_credential_policy: Option<serde_json::Value>,
    ) -> Result<Option<String>, WarpgateError> {
        // Check for LDAP servers with auto-linking enabled
        let ldap_servers: Vec<entities::LdapServer::Model> = entities::LdapServer::Entity::find()
            .filter(entities::LdapServer::Column::Enabled.eq(true))
            .filter(entities::LdapServer::Column::AutoLinkSsoUsers.eq(true))
            .all(db)
            .await?;

        let mut ldap_server_id = None;
        let mut ldap_object_uuid = None;

        for ldap_server in ldap_servers {
            let ldap_config = warpgate_ldap::LdapConfig::try_from(&ldap_server).map_err(|e| {
                warn!(
                    "Failed to parse LDAP config for server {}: {}",
                    ldap_server.name, e
                );
                e
            })?;

            match warpgate_ldap::find_user_by_username(&ldap_config, &preferred_username).await {
                Ok(Some(ldap_user)) => {
                    info!(
                        "Found LDAP user for username {}: {:?}",
                        preferred_username, ldap_user.username
                    );
                    ldap_server_id = Some(ldap_server.id);
                    ldap_object_uuid = Some(ldap_user.object_uuid);
                    break;
                }
                Ok(None) => {
                    debug!(
                        "No LDAP user found with username {} in server {}",
                        preferred_username, ldap_server.name
                    );
                }
                Err(e) => {
                    warn!(
                        "Error searching for LDAP user in {}: {}",
                        ldap_server.name, e
                    );
                }
            }
        }

        let existing_user = entities::User::Entity::find()
            .filter(entities::User::Entity::username_eq_ci(&preferred_username))
            .one(db)
            .await?;

        if existing_user.is_some() {
            error!(
                "Cannot auto-create SSO user with username {preferred_username} because it already exists and does not have a matching SSO credential."
            );
            return Err(WarpgateError::UserAlreadyExists(preferred_username));
        }

        let user = entities::User::ActiveModel {
            id: Set(Uuid::new_v4()),
            username: Set(preferred_username.clone()),
            description: Set("".into()),
            credential_policy: Set(default_credential_policy.unwrap_or_else(|| {
                serde_json::to_value(UserRequireCredentialsPolicy::default()).unwrap_or_default()
            })),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(ldap_server_id),
            ldap_object_uuid: Set(ldap_object_uuid),
            allowed_ip_ranges: Set(serde_json::Value::Null),
        }
        .insert(db)
        .await?;

        let default_roles = entities::Role::Entity::grant_default_roles(db, user.id).await?;

        entities::SsoCredential::ActiveModel {
            id: Set(Uuid::new_v4()),
            user_id: Set(user.id),
            ..credential.into()
        }
        .insert(db)
        .await?;

        if ldap_server_id.is_some() {
            info!(
                "Auto-created SSO user {} and linked to LDAP account",
                preferred_username
            );
        } else {
            info!(
                "Auto-created SSO user {} (no LDAP link)",
                preferred_username
            );
        }

        if !default_roles.is_empty() {
            info!(
                "Assigned default role(s) to auto-created SSO user {}: {:?}",
                preferred_username,
                default_roles
                    .iter()
                    .map(|role| &role.name)
                    .collect::<Vec<_>>()
            );
        }

        Ok(Some(preferred_username))
    }
}

impl ConfigProvider for DatabaseConfigProvider {
    async fn list_users(&mut self) -> Result<Vec<User>, WarpgateError> {
        let db = self.db.lock().await;

        let users = entities::User::Entity::find()
            .order_by_asc(entities::User::Column::Username)
            .all(&*db)
            .await?;

        let users: Result<Vec<User>, _> = users.into_iter().map(TryInto::try_into).collect();

        users
    }

    async fn list_targets(&mut self) -> Result<Vec<Target>, WarpgateError> {
        let db = self.db.lock().await;

        let targets = entities::Target::Entity::find()
            .order_by_asc(entities::Target::Column::Name)
            .all(&*db)
            .await?;

        let targets: Result<Vec<Target>, _> = targets.into_iter().map(TryInto::try_into).collect();

        Ok(targets?)
    }

    async fn get_target_by_name(&mut self, name: &str) -> Result<Option<Target>, WarpgateError> {
        let db = self.db.lock().await;

        let target = entities::Target::Entity::find()
            .filter(entities::Target::Column::Name.eq(name))
            .one(&*db)
            .await?;

        target
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    async fn get_target_by_hostname(
        &mut self,
        hostname: &str,
    ) -> Result<Option<Target>, WarpgateError> {
        let db: tokio::sync::MutexGuard<'_, DatabaseConnection> = self.db.lock().await;

        let hostname_query = match db.get_database_backend() {
            DatabaseBackend::MySql => {
                Expr::cust("JSON_UNQUOTE(JSON_EXTRACT(options, '$.http.external_host'))")
            }
            DatabaseBackend::Postgres => Expr::cust(r"options->'http'->>'external_host'"),
            DatabaseBackend::Sqlite => Expr::cust(r"json_extract(options, '$.http.external_host')"),
        };

        let target = entities::Target::Entity::find()
            .filter(hostname_query.eq(hostname))
            .one(&*db)
            .await?;

        target
            .map(TryInto::try_into)
            .transpose()
            .map_err(Into::into)
    }

    async fn get_credential_policy(
        &mut self,
        username: &str,
        supported_credential_types: &[CredentialKind],
    ) -> Result<Option<Box<dyn CredentialPolicy + Sync + Send>>, WarpgateError> {
        let db = self.db.lock().await;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Entity::username_eq_ci(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(None);
        };

        let user = user_model.load_details(&db).await?;

        let mut available_credential_types = user
            .credentials
            .iter()
            .map(UserAuthCredential::kind)
            .collect::<HashSet<_>>();
        available_credential_types.insert(CredentialKind::WebUserApproval);

        let supported_credential_types = supported_credential_types
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .intersection(&available_credential_types)
            .copied()
            .collect::<HashSet<_>>();

        // "Any single credential" policy should not include WebUserApproval
        // if other authentication methods are available because it could lead to user confusion
        let default_policy = Box::new(AnySingleCredentialPolicy {
            supported_credential_types: if supported_credential_types.len() > 1 {
                supported_credential_types
                    .iter()
                    .copied()
                    .filter(|x| x != &CredentialKind::WebUserApproval)
                    .collect()
            } else {
                supported_credential_types.clone()
            },
        }) as Box<dyn CredentialPolicy + Sync + Send>;

        if let Some(req) = user.credential_policy.clone() {
            let mut policy = PerProtocolCredentialPolicy {
                default: default_policy,
                protocols: HashMap::new(),
            };

            if let Some(p) = req.http {
                policy.protocols.insert(
                    "HTTP",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.mysql {
                policy.protocols.insert(
                    "MySQL",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.postgres {
                policy.protocols.insert(
                    "PostgreSQL",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types: supported_credential_types.clone(),
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }
            if let Some(p) = req.ssh {
                policy.protocols.insert(
                    "SSH",
                    Box::new(AllCredentialsPolicy {
                        supported_credential_types,
                        required_credential_types: p.into_iter().collect(),
                    }),
                );
            }

            Ok(Some(
                Box::new(policy) as Box<dyn CredentialPolicy + Sync + Send>
            ))
        } else {
            Ok(Some(default_policy))
        }
    }

    async fn username_for_sso_credential(
        &mut self,
        client_credential: &AuthCredential,
        preferred_username: Option<String>,
        sso_config: SsoProviderConfig,
    ) -> Result<Option<String>, WarpgateError> {
        let db = self.db.lock().await;

        let AuthCredential::Sso {
            provider: client_provider,
            email: client_email,
        } = client_credential
        else {
            return Ok(None);
        };

        let cred = entities::SsoCredential::Entity::find()
            .filter(
                entities::SsoCredential::Column::Email.eq(client_email).and(
                    entities::SsoCredential::Column::Provider
                        .eq(client_provider)
                        .or(entities::SsoCredential::Column::Provider.is_null()),
                ),
            )
            .one(&*db)
            .await?;

        if let Some(cred) = cred {
            let user = cred.find_related(entities::User::Entity).one(&*db).await?;

            if let Some(user) = user {
                return Ok(Some(user.username));
            }
        }

        if sso_config.auto_create_users {
            let Some(preferred_username) = preferred_username else {
                error!("The OIDC server did not provide a preferred_username claim for this user");
                return Ok(None);
            };
            return self
                .maybe_autocreate_sso_user(
                    &db,
                    UserSsoCredential {
                        email: client_email.clone(),
                        provider: Some(client_provider.clone()),
                    },
                    preferred_username,
                    sso_config.default_credential_policy.clone(),
                )
                .await;
        }

        Ok(None)
    }

    async fn validate_credential(
        &mut self,
        username: &str,
        client_credential: &AuthCredential,
    ) -> Result<Option<CredentialMatch>, WarpgateError> {
        let db = self.db.lock().await;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Entity::username_eq_ci(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(None);
        };

        // Sync SSH keys from LDAP if user is linked
        if matches!(client_credential, AuthCredential::PublicKey { .. })
            && let (Some(ldap_server_id), Some(ldap_object_uuid)) =
                (user_model.ldap_server_id, &user_model.ldap_object_uuid)
            && let Err(e) = self
                .sync_ldap_ssh_keys(&db, user_model.id, ldap_server_id, ldap_object_uuid)
                .await
        {
            warn!(
                "Failed to sync SSH keys from LDAP for user {}: {}",
                username, e
            );
        }

        match client_credential {
            AuthCredential::PublicKey {
                kind,
                public_key_bytes,
            } => {
                let base64_bytes = BASE64.encode(public_key_bytes);
                let openssh_public_key = format!("{kind} {base64_bytes}");
                debug!(
                    username = &user_model.username[..],
                    "Client key: {}", openssh_public_key
                );

                // Query the pubkey rows directly so we can return the matched
                // row id (needed by per-pubkey step-up auth). On duplicate
                // rows with the same bytes (operator error) the smallest id
                // wins — ORDER BY id makes the choice deterministic so A1
                // stamps last_sso_at on the same row every time.
                let matched = entities::PublicKeyCredential::Entity::find()
                    .filter(entities::PublicKeyCredential::Column::UserId.eq(user_model.id))
                    .filter(
                        entities::PublicKeyCredential::Column::OpensshPublicKey
                            .eq(openssh_public_key),
                    )
                    .order_by_asc(entities::PublicKeyCredential::Column::Id)
                    .one(&*db)
                    .await?;

                Ok(matched.map(|row| CredentialMatch {
                    kind: CredentialKind::PublicKey,
                    credential_id: Some(row.id),
                }))
            }
            AuthCredential::Password(client_password) => {
                let user_details = user_model.load_details(&db).await?;
                let matched = user_details.credentials.iter().any(|credential| {
                    matches!(
                        credential,
                        UserAuthCredential::Password(UserPasswordCredential {
                            hash: user_password_hash,
                        }) if verify_password_hash(
                            client_password.expose_secret(),
                            user_password_hash.expose_secret(),
                        )
                        .unwrap_or_else(|e| {
                            error!(
                                username = &user_details.username[..],
                                "Error verifying password hash: {}", e
                            );
                            false
                        })
                    )
                });
                Ok(matched.then_some(CredentialMatch {
                    kind: CredentialKind::Password,
                    credential_id: None,
                }))
            }
            AuthCredential::Otp(client_otp) => {
                let user_details = user_model.load_details(&db).await?;
                let matched = user_details.credentials.iter().any(|credential| {
                    matches!(
                        credential,
                        UserAuthCredential::Totp(UserTotpCredential {
                            key: user_otp_key,
                        }) if verify_totp(client_otp.expose_secret(), user_otp_key)
                    )
                });
                Ok(matched.then_some(CredentialMatch {
                    kind: CredentialKind::Totp,
                    credential_id: None,
                }))
            }
            AuthCredential::Sso {
                provider: client_provider,
                email: client_email,
            } => {
                let user_details = user_model.load_details(&db).await?;
                for credential in &user_details.credentials {
                    if let UserAuthCredential::Sso(UserSsoCredential { provider, email }) =
                        credential
                        && provider.as_ref().unwrap_or(client_provider) == client_provider
                        && email == client_email
                    {
                        return Ok(Some(CredentialMatch {
                            kind: CredentialKind::Sso,
                            credential_id: None,
                        }));
                    }
                }
                Ok(None)
            }
            _ => Err(WarpgateError::InvalidCredentialType),
        }
    }

    async fn authorize_target(
        &mut self,
        username: &str,
        target_name: &str,
    ) -> Result<bool, WarpgateError> {
        let db = self.db.lock().await;

        let target_model = entities::Target::Entity::find()
            .filter(entities::Target::Column::Name.eq(target_name))
            .one(&*db)
            .await?;

        let user_model = entities::User::Entity::find()
            .filter(entities::User::Entity::username_eq_ci(username))
            .one(&*db)
            .await?;

        let Some(user_model) = user_model else {
            error!("Selected user not found: {}", username);
            return Ok(false);
        };

        let Some(target_model) = target_model else {
            warn!("Selected target not found: {}", target_name);
            return Ok(false);
        };

        let target_roles: HashSet<String> = target_model
            .find_related(entities::Role::Entity)
            .all(&*db)
            .await?
            .into_iter()
            .map(Into::<Role>::into)
            .map(|x| x.name)
            .collect();

        let user_assignments = entities::UserRoleAssignment::Entity::find_active()
            .filter(entities::UserRoleAssignment::Column::UserId.eq(user_model.id))
            .all(&*db)
            .await?;

        let user_role_ids: HashSet<Uuid> = user_assignments.iter().map(|a| a.role_id).collect();

        let user_roles: HashSet<String> = entities::Role::Entity::find()
            .filter(entities::Role::Column::Id.is_in(user_role_ids))
            .all(&*db)
            .await?
            .into_iter()
            .map(Into::<Role>::into)
            .map(|x| x.name)
            .collect();

        let intersect = user_roles.intersection(&target_roles).count() > 0;

        Ok(intersect)
    }

    async fn apply_sso_role_mappings(
        &mut self,
        username: &str,
        managed_role_names: Option<Vec<String>>,
        assigned_role_names: Vec<String>,
    ) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;

        let user = entities::User::Entity::find()
            .filter(entities::User::Entity::username_eq_ci(username))
            .one(&*db)
            .await?
            .ok_or_else(|| WarpgateError::UserNotFound(username.into()))?;

        let managed_role_names = match managed_role_names {
            Some(x) => x,
            None => entities::Role::Entity::find()
                .all(&*db)
                .await?
                .into_iter()
                .map(|x| x.name)
                .collect(),
        };

        for role_name in managed_role_names {
            let Some(role) = entities::Role::Entity::find()
                .filter(entities::Role::Column::Name.eq(role_name.clone()))
                .one(&*db)
                .await?
            else {
                warn!("SSO role mapping references non-existent role {role_name:?}, skipping");
                continue;
            };

            let assignment = entities::UserRoleAssignment::Entity::find_active()
                .filter(entities::UserRoleAssignment::Column::UserId.eq(user.id))
                .filter(entities::UserRoleAssignment::Column::RoleId.eq(role.id))
                .one(&*db)
                .await?;

            match (assignment, assigned_role_names.contains(&role_name)) {
                (None, true) => {
                    info!("Adding role {role_name} for user {username} (from SSO)");
                    entities::UserRoleAssignment::Entity::idempotent_grant(
                        &db, user.id, role.id, None,
                    )
                    .await?;
                }
                (Some(assignment), false) => {
                    info!("Removing role {role_name} for user {username} (from SSO)");
                    let mut model: entities::UserRoleAssignment::ActiveModel = assignment.into();
                    model.revoked_at = Set(Some(OffsetDateTime::now_utc()));
                    model.update(&*db).await?;
                }
                _ => (),
            }
        }

        Ok(())
    }

    async fn apply_sso_admin_role_mappings(
        &mut self,
        username: &str,
        managed_admin_role_names: Option<Vec<String>>,
        assigned_admin_role_names: Vec<String>,
    ) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;

        let user = entities::User::Entity::find()
            .filter(entities::User::Entity::username_eq_ci(username))
            .one(&*db)
            .await?
            .ok_or_else(|| WarpgateError::UserNotFound(username.into()))?;

        let managed_admin_role_names = match managed_admin_role_names {
            Some(x) => x,
            None => entities::AdminRole::Entity::find()
                .all(&*db)
                .await?
                .into_iter()
                .map(|x| x.name)
                .collect(),
        };

        for role_name in managed_admin_role_names {
            let role = entities::AdminRole::Entity::find()
                .filter(entities::AdminRole::Column::Name.eq(role_name.clone()))
                .one(&*db)
                .await?
                .ok_or_else(|| WarpgateError::RoleNotFound(role_name.clone()))?;

            let assignment = entities::UserAdminRoleAssignment::Entity::find()
                .filter(entities::UserAdminRoleAssignment::Column::UserId.eq(user.id))
                .filter(entities::UserAdminRoleAssignment::Column::AdminRoleId.eq(role.id))
                .one(&*db)
                .await?;

            match (assignment, assigned_admin_role_names.contains(&role_name)) {
                (None, true) => {
                    info!("Adding admin role {role_name} for user {username} (from SSO)");
                    let values = entities::UserAdminRoleAssignment::ActiveModel {
                        user_id: Set(user.id),
                        admin_role_id: Set(role.id),
                        ..Default::default()
                    };

                    values.insert(&*db).await?;
                }
                (Some(assignment), false) => {
                    info!("Removing admin role {role_name} for user {username} (from SSO)");
                    assignment.delete(&*db).await?;
                }
                _ => (),
            }
        }

        Ok(())
    }

    async fn update_public_key_last_used(
        &self,
        credential: Option<AuthCredential>,
    ) -> Result<(), WarpgateError> {
        let db = self.db.lock().await;

        let Some(AuthCredential::PublicKey {
            kind,
            public_key_bytes,
        }) = credential
        else {
            error!("Invalid or missing public key credential");
            return Err(WarpgateError::InvalidCredentialType);
        };

        // Encode public key and match it against the database
        let base64_bytes = data_encoding::BASE64.encode(&public_key_bytes);
        let openssh_public_key = format!("{kind} {base64_bytes}");

        debug!(
            "Attempting to update last_used for public key: {}",
            openssh_public_key
        );

        // Find the public key credential
        let public_key_credential = entities::PublicKeyCredential::Entity::find()
            .filter(
                entities::PublicKeyCredential::Column::OpensshPublicKey
                    .eq(openssh_public_key.clone()),
            )
            .one(&*db)
            .await?;

        let Some(public_key_credential) = public_key_credential else {
            warn!(
                "Public key not found in the database: {}",
                openssh_public_key
            );
            return Ok(()); // Gracefully return if the key is not found
        };

        // Update the `last_used` (last used) timestamp
        let mut active_model: entities::PublicKeyCredential::ActiveModel =
            public_key_credential.into();
        active_model.last_used = Set(Some(OffsetDateTime::now_utc()));

        active_model.update(&*db).await.map_err(|e| {
            error!("Failed to update last_used for public key: {:?}", e);
            WarpgateError::DatabaseError(e)
        })?;

        Ok(())
    }

    async fn validate_api_token(&mut self, token: &str) -> Result<Option<User>, WarpgateError> {
        let db = self.db.lock().await;
        let Some(api_token) = entities::ApiToken::Entity::find()
            .filter(
                entities::ApiToken::Column::Secret
                    .eq(token)
                    .and(entities::ApiToken::Column::Expiry.gt(OffsetDateTime::now_utc())),
            )
            .one(&*db)
            .await?
        else {
            return Ok(None);
        };

        let Some(user) = api_token
            .find_related(entities::User::Entity)
            .one(&*db)
            .await?
        else {
            return Err(WarpgateError::InconsistentState(
                "No user matching the ticket username".into(),
            ));
        };

        Ok(Some(user.try_into()?))
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use data_encoding::BASE64;
    use russh::keys::{Algorithm, PrivateKey, PublicKeyBase64};
    use sea_orm::{Database, Set};
    use warpgate_common::auth::CredentialMatch;
    use warpgate_common::helpers::hash::hash_password;
    use warpgate_common::helpers::rng::get_crypto_rng;
    use warpgate_common::Secret;
    use warpgate_db_migrations::migrate_database;

    use super::*;

    /// Spin up a fresh in-memory sqlite DB with migrations applied.
    async fn setup_db() -> Arc<Mutex<DatabaseConnection>> {
        let conn = Database::connect("sqlite::memory:").await.unwrap();
        migrate_database(&conn).await.unwrap();
        Arc::new(Mutex::new(conn))
    }

    /// Insert a user with the given username, return the row id.
    async fn insert_user(db: &DatabaseConnection, username: &str) -> Uuid {
        let id = Uuid::new_v4();
        entities::User::ActiveModel {
            id: Set(id),
            username: Set(username.into()),
            description: Set(String::new()),
            credential_policy: Set(serde_json::json!({})),
            rate_limit_bytes_per_second: Set(None),
            ldap_server_id: Set(None),
            ldap_object_uuid: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    /// Insert a public-key credential row for the user, return (row id, key bytes).
    async fn insert_pubkey(db: &DatabaseConnection, user_id: Uuid) -> (Uuid, Algorithm, Bytes) {
        let key = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519).unwrap();
        let public_key = key.public_key();
        let algorithm = public_key.algorithm();
        let public_key_bytes = Bytes::from(public_key.public_key_bytes());
        let base64_bytes = BASE64.encode(&public_key_bytes);
        let openssh_public_key = format!("{algorithm} {base64_bytes}");

        let id = Uuid::new_v4();
        entities::PublicKeyCredential::ActiveModel {
            id: Set(id),
            user_id: Set(user_id),
            label: Set("test key".into()),
            date_added: Set(None),
            last_used: Set(None),
            openssh_public_key: Set(openssh_public_key),
        }
        .insert(db)
        .await
        .unwrap();

        (id, algorithm, public_key_bytes)
    }

    /// Insert a password credential row for the user, return the row id.
    async fn insert_password(db: &DatabaseConnection, user_id: Uuid, password: &str) -> Uuid {
        let id = Uuid::new_v4();
        entities::PasswordCredential::ActiveModel {
            id: Set(id),
            user_id: Set(user_id),
            argon_hash: Set(hash_password(password)),
        }
        .insert(db)
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn unit_validate_credential_pubkey_returns_match_with_row_id() {
        let db = setup_db().await;
        let user_id = insert_user(&*db.lock().await, "alice").await;
        let (pubkey_id, algorithm, key_bytes) = insert_pubkey(&*db.lock().await, user_id).await;

        let mut provider = DatabaseConfigProvider::new(&db);
        let cred = AuthCredential::PublicKey {
            kind: algorithm,
            public_key_bytes: key_bytes,
        };

        let result = provider.validate_credential("alice", &cred).await.unwrap();

        assert_eq!(
            result,
            Some(CredentialMatch {
                kind: CredentialKind::PublicKey,
                credential_id: Some(pubkey_id),
            })
        );
    }

    #[tokio::test]
    async fn unit_validate_credential_pubkey_returns_none_when_no_match() {
        let db = setup_db().await;
        let user_id = insert_user(&*db.lock().await, "alice").await;
        // Insert a real key so the user has at least one pubkey on file.
        insert_pubkey(&*db.lock().await, user_id).await;

        // Offer a *different* public key — should not match any row.
        let other_key = PrivateKey::random(&mut get_crypto_rng(), Algorithm::Ed25519).unwrap();
        let other_public_bytes = Bytes::from(other_key.public_key().public_key_bytes());
        let cred = AuthCredential::PublicKey {
            kind: other_key.public_key().algorithm(),
            public_key_bytes: other_public_bytes,
        };

        let mut provider = DatabaseConfigProvider::new(&db);
        let result = provider.validate_credential("alice", &cred).await.unwrap();

        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn unit_validate_credential_pubkey_smallest_id_wins_on_duplicates() {
        let db = setup_db().await;
        let user_id = insert_user(&*db.lock().await, "alice").await;
        // Insert the same pubkey bytes twice under different rows (simulating operator error).
        let (first_id, algorithm, key_bytes) = insert_pubkey(&*db.lock().await, user_id).await;

        // Dup: encode same key again with its own row id.
        let base64_bytes = BASE64.encode(&key_bytes);
        let openssh_public_key = format!("{algorithm} {base64_bytes}");
        let dup_id = Uuid::new_v4();
        entities::PublicKeyCredential::ActiveModel {
            id: Set(dup_id),
            user_id: Set(user_id),
            label: Set("duplicate".into()),
            date_added: Set(None),
            last_used: Set(None),
            openssh_public_key: Set(openssh_public_key),
        }
        .insert(&*db.lock().await)
        .await
        .unwrap();

        let cred = AuthCredential::PublicKey {
            kind: algorithm,
            public_key_bytes: key_bytes,
        };
        let mut provider = DatabaseConfigProvider::new(&db);
        let result = provider.validate_credential("alice", &cred).await.unwrap();

        // On duplicate rows the smallest id wins — the query is ORDER BY id ASC,
        // so the choice is deterministic across runs (A1 stamps last_sso_at on
        // the same row every time, regardless of DB insertion order).
        let matched = result.expect("expected a match");
        assert_eq!(matched.kind, CredentialKind::PublicKey);
        let id = matched.credential_id.expect("pubkey id populated");
        let expected = std::cmp::min(first_id, dup_id);
        assert_eq!(
            id, expected,
            "expected smallest id {expected} to win, got {id}"
        );
    }

    #[tokio::test]
    async fn unit_validate_credential_password_returns_match_without_id() {
        // For A0 we only need pubkey row ids; password matches still report Some
        // (credential accepted) but credential_id is None until/unless a later
        // step-up surface requires per-row password tracking.
        let db = setup_db().await;
        let user_id = insert_user(&*db.lock().await, "bob").await;
        insert_password(&*db.lock().await, user_id, "hunter2").await;

        let mut provider = DatabaseConfigProvider::new(&db);
        let cred = AuthCredential::Password(Secret::new("hunter2".into()));
        let result = provider.validate_credential("bob", &cred).await.unwrap();

        assert_eq!(
            result,
            Some(CredentialMatch {
                kind: CredentialKind::Password,
                credential_id: None,
            })
        );
    }

    #[tokio::test]
    async fn unit_validate_credential_password_returns_none_on_wrong_password() {
        let db = setup_db().await;
        let user_id = insert_user(&*db.lock().await, "bob").await;
        insert_password(&*db.lock().await, user_id, "hunter2").await;

        let mut provider = DatabaseConfigProvider::new(&db);
        let cred = AuthCredential::Password(Secret::new("wrong".into()));
        let result = provider.validate_credential("bob", &cred).await.unwrap();

        assert_eq!(result, None);
    }
}
