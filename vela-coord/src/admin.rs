use argon2::password_hash::rand_core::OsRng;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, patch, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    net::{Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::{Arc, Mutex},
};
use vela_crypto::MembershipCredential;
use vela_proto::{Candidate, NodeId, PeerCapability};

use super::{
    CoordError, ServerInner, consume_download_token, create_invite, delete_peer_inner,
    revoke_peer_inner, unix_time, update_peer_metadata,
};

const ADMIN_USERNAME: &str = "admin";
const SESSION_TTL_SECONDS: u64 = 24 * 60 * 60;

#[derive(Deserialize, Serialize)]
struct CredentialsFile {
    username: String,
    password_hash: String,
}

pub(crate) struct AdminAuth {
    username: String,
    password_hash: String,
    sessions: Mutex<HashMap<String, u64>>,
}

impl AdminAuth {
    pub(crate) fn load_or_create(path: &Path) -> Result<(Self, Option<String>), CoordError> {
        if path.exists() {
            let file = read_credentials(path)?;
            PasswordHash::new(&file.password_hash)
                .map_err(|error| CoordError::AdminCredentials(error.to_string()))?;
            return Ok((
                Self {
                    username: file.username,
                    password_hash: file.password_hash,
                    sessions: Mutex::new(HashMap::new()),
                },
                None,
            ));
        }

        let password = super::random_token(24);
        let file = CredentialsFile {
            username: ADMIN_USERNAME.to_owned(),
            password_hash: hash_password(&password)?,
        };
        write_credentials(path, &file)?;
        Ok((
            Self {
                username: file.username,
                password_hash: file.password_hash,
                sessions: Mutex::new(HashMap::new()),
            },
            Some(password),
        ))
    }

    pub(crate) fn reset_password(
        path: &Path,
        password: Option<&str>,
    ) -> Result<String, CoordError> {
        let username = path
            .exists()
            .then(|| read_credentials(path).ok().map(|file| file.username))
            .flatten()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| ADMIN_USERNAME.to_owned());
        let password = password
            .map(str::to_owned)
            .unwrap_or_else(|| super::random_token(24));
        if password.len() < 8 {
            return Err(CoordError::AdminCredentials(
                "password must contain at least 8 characters".to_owned(),
            ));
        }
        write_credentials(
            path,
            &CredentialsFile {
                username,
                password_hash: hash_password(&password)?,
            },
        )?;
        Ok(password)
    }

    fn login(&self, username: &str, password: &str) -> Option<(String, u64)> {
        if username != self.username
            || Argon2::default()
                .verify_password(
                    password.as_bytes(),
                    &PasswordHash::new(&self.password_hash).ok()?,
                )
                .is_err()
        {
            return None;
        }
        let expires_at = unix_time().saturating_add(SESSION_TTL_SECONDS);
        let token = super::random_token(32);
        let mut sessions = self.sessions.lock().ok()?;
        sessions.retain(|_, expires| *expires > unix_time());
        sessions.insert(token.clone(), expires_at);
        Some((token, expires_at))
    }

    fn authorize(&self, headers: &HeaderMap) -> Option<u64> {
        let token = headers
            .get(header::AUTHORIZATION)?
            .to_str()
            .ok()?
            .strip_prefix("Bearer ")?;
        let mut sessions = self.sessions.lock().ok()?;
        let expires_at = *sessions.get(token)?;
        if expires_at <= unix_time() {
            sessions.remove(token);
            return None;
        }
        Some(expires_at)
    }

    fn logout(&self, headers: &HeaderMap) {
        let Some(token) = headers
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return;
        };
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(token);
        }
    }
}

fn read_credentials(path: &Path) -> Result<CredentialsFile, CoordError> {
    let data = fs::read(path)?;
    serde_json::from_slice(&data).map_err(|error| CoordError::AdminCredentials(error.to_string()))
}

fn hash_password(password: &str) -> Result<String, CoordError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| CoordError::AdminCredentials(error.to_string()))
}

fn write_credentials(path: &Path, file: &CredentialsFile) -> Result<(), CoordError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_vec_pretty(file)?;
    let temporary = path.with_extension(format!("tmp-{}", super::random_token(8)));
    fs::write(&temporary, data)?;
    set_private(&temporary)?;
    #[cfg(windows)]
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&temporary, path)?;
    set_private(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private(path: &Path) -> Result<(), CoordError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private(_path: &Path) -> Result<(), CoordError> {
    Ok(())
}

pub(crate) fn router() -> Router<Arc<ServerInner>> {
    Router::new()
        .route("/", get(admin_page))
        .route("/admin", get(admin_page))
        .route("/admin/", get(admin_page))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/admin/config", get(config))
        .route("/api/v1/admin/peers", get(list_peers))
        .route(
            "/api/v1/admin/peers/{node_id}",
            patch(update_peer).delete(delete_peer),
        )
        .route("/api/v1/admin/peers/{node_id}/revoke", post(revoke_peer))
        .route(
            "/api/v1/admin/invites",
            get(list_invites).post(create_invite_handler),
        )
        .route("/api/v1/admin/invites/{id}", delete(delete_invite))
        .route("/download/vela-cli", get(download_cli))
}

async fn admin_page() -> Html<&'static str> {
    Html(include_str!("admin.html"))
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    expires_at: u64,
    username: String,
}

async fn login(
    State(state): State<Arc<ServerInner>>,
    Json(request): Json<LoginRequest>,
) -> Response {
    match state.admin.login(&request.username, &request.password) {
        Some((token, expires_at)) => Json(LoginResponse {
            token,
            expires_at,
            username: state.admin.username.clone(),
        })
        .into_response(),
        None => error_response(StatusCode::UNAUTHORIZED, "invalid username or password"),
    }
}

async fn logout(State(state): State<Arc<ServerInner>>, headers: HeaderMap) -> Response {
    state.admin.logout(&headers);
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Serialize)]
struct AdminUser {
    username: String,
}

async fn me(State(state): State<Arc<ServerInner>>, headers: HeaderMap) -> Response {
    if require_admin(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication required");
    }
    Json(AdminUser {
        username: state.admin.username.clone(),
    })
    .into_response()
}

#[derive(Serialize)]
struct ServerConfig {
    tenant: String,
    server_key: String,
    session_ttl_seconds: u64,
    cli_filename: &'static str,
    windows: bool,
}

async fn config(State(state): State<Arc<ServerInner>>, headers: HeaderMap) -> Response {
    if require_admin(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication required");
    }
    Json(ServerConfig {
        tenant: state.tenant.clone(),
        server_key: BASE64.encode(state.signer.public()),
        session_ttl_seconds: SESSION_TTL_SECONDS,
        cli_filename: cli_filename(),
        windows: cfg!(windows),
    })
    .into_response()
}

#[derive(Serialize)]
struct PeerView {
    node_id: String,
    name: String,
    notes: String,
    status: &'static str,
    candidates: Vec<Candidate>,
    virtual_ipv4: Option<Ipv4Addr>,
    virtual_ipv6: Option<Ipv6Addr>,
    capabilities: Vec<PeerCapability>,
    last_seen: Option<u64>,
    credential_expires_at: Option<u64>,
}

async fn list_peers(State(state): State<Arc<ServerInner>>, headers: HeaderMap) -> Response {
    if require_admin(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication required");
    }
    match admin_peers(&state).await {
        Ok(peers) => Json(peers).into_response(),
        Err(error) => internal_error(error),
    }
}

async fn admin_peers(state: &Arc<ServerInner>) -> Result<Vec<PeerView>, CoordError> {
    let rows = {
        let database = state
            .database
            .lock()
            .map_err(|_| CoordError::DatabasePoisoned)?;
        let mut statement = database.prepare(
            "SELECT node_id, name, notes, candidates, virtual_ipv4, virtual_ipv6,
                    capabilities, revoked, last_seen, credential
             FROM peers ORDER BY name, node_id",
        )?;
        statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, Vec<u8>>(9)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let online = state.online.lock().await;
    rows.into_iter()
        .map(
            |(
                node_id,
                name,
                notes,
                candidates,
                virtual_ipv4,
                virtual_ipv6,
                capabilities,
                revoked,
                last_seen,
                credential,
            )| {
                let node_id: [u8; 32] = node_id.try_into().map_err(|_| CoordError::InvalidPeer)?;
                let node_id = NodeId::new(node_id);
                let candidates = serde_json::from_str(&candidates)?;
                let virtual_ipv4 = virtual_ipv4
                    .map(|value| {
                        <[u8; 4]>::try_from(value)
                            .map(Ipv4Addr::from)
                            .map_err(|_| CoordError::InvalidPeer)
                    })
                    .transpose()?;
                let virtual_ipv6 = virtual_ipv6
                    .map(|value| {
                        <[u8; 16]>::try_from(value)
                            .map(Ipv6Addr::from)
                            .map_err(|_| CoordError::InvalidPeer)
                    })
                    .transpose()?;
                let capabilities = serde_json::from_str(&capabilities)?;
                let credential_expires_at =
                    serde_json::from_slice::<MembershipCredential>(&credential)
                        .ok()
                        .map(|credential| credential.expires_at);
                Ok(PeerView {
                    node_id: node_id.to_string(),
                    name,
                    notes,
                    status: if revoked != 0 {
                        "revoked"
                    } else if online.contains_key(&node_id) {
                        "online"
                    } else {
                        "offline"
                    },
                    candidates,
                    virtual_ipv4,
                    virtual_ipv6,
                    capabilities,
                    last_seen: (last_seen > 0).then_some(last_seen as u64),
                    credential_expires_at,
                })
            },
        )
        .collect()
}

#[derive(Deserialize)]
struct PeerUpdateRequest {
    name: String,
    notes: String,
}

async fn update_peer(
    State(state): State<Arc<ServerInner>>,
    headers: HeaderMap,
    AxumPath(node_id): AxumPath<String>,
    Json(request): Json<PeerUpdateRequest>,
) -> Response {
    if require_admin(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication required");
    }
    if request.name.len() > 200 || request.notes.len() > 2_000 {
        return error_response(StatusCode::BAD_REQUEST, "name or notes is too long");
    }
    let node_id = match node_id.parse::<NodeId>() {
        Ok(node_id) => node_id,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid node id"),
    };
    match update_peer_metadata(&state, node_id, &request.name, &request.notes) {
        Ok(true) => match admin_peers(&state).await {
            Ok(peers) => peers
                .into_iter()
                .find(|peer| peer.node_id == node_id.to_string())
                .map(|peer| Json(peer).into_response())
                .unwrap_or_else(|| error_response(StatusCode::NOT_FOUND, "peer not found")),
            Err(error) => internal_error(error),
        },
        Ok(false) => error_response(StatusCode::NOT_FOUND, "peer not found"),
        Err(error) => internal_error(error),
    }
}

async fn revoke_peer(
    State(state): State<Arc<ServerInner>>,
    headers: HeaderMap,
    AxumPath(node_id): AxumPath<String>,
) -> Response {
    if require_admin(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication required");
    }
    let node_id = match node_id.parse::<NodeId>() {
        Ok(node_id) => node_id,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid node id"),
    };
    match revoke_peer_inner(&state, node_id).await {
        Ok(true) => Json(serde_json::json!({"ok": true})).into_response(),
        Ok(false) => error_response(StatusCode::NOT_FOUND, "peer not found"),
        Err(error) => internal_error(error),
    }
}

async fn delete_peer(
    State(state): State<Arc<ServerInner>>,
    headers: HeaderMap,
    AxumPath(node_id): AxumPath<String>,
) -> Response {
    if require_admin(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication required");
    }
    let node_id = match node_id.parse::<NodeId>() {
        Ok(node_id) => node_id,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, "invalid node id"),
    };
    match delete_peer_inner(&state, node_id).await {
        Ok(true) => Json(serde_json::json!({"ok": true})).into_response(),
        Ok(false) => error_response(StatusCode::NOT_FOUND, "peer not found"),
        Err(error) => internal_error(error),
    }
}

#[derive(Deserialize)]
struct CreateInviteRequest {
    name: String,
    notes: String,
    ttl_seconds: u64,
}

async fn create_invite_handler(
    State(state): State<Arc<ServerInner>>,
    headers: HeaderMap,
    Json(request): Json<CreateInviteRequest>,
) -> Response {
    if require_admin(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication required");
    }
    if request.name.len() > 200 || request.notes.len() > 2_000 {
        return error_response(StatusCode::BAD_REQUEST, "name or notes is too long");
    }
    if request.ttl_seconds == 0 || request.ttl_seconds > 30 * 24 * 60 * 60 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "ttl_seconds must be between 1 and 2592000",
        );
    }
    match create_invite(&state, &request.name, &request.notes, request.ttl_seconds) {
        Ok(invite) => Json(invite).into_response(),
        Err(error) => internal_error(error),
    }
}

#[derive(Serialize)]
struct InviteView {
    id: String,
    name: String,
    notes: String,
    created_at: u64,
    expires_at: u64,
    status: &'static str,
}

async fn list_invites(State(state): State<Arc<ServerInner>>, headers: HeaderMap) -> Response {
    if require_admin(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication required");
    }
    match admin_invites(&state) {
        Ok(invites) => Json(invites).into_response(),
        Err(error) => internal_error(error),
    }
}

fn admin_invites(state: &Arc<ServerInner>) -> Result<Vec<InviteView>, CoordError> {
    let database = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?;
    let mut statement = database.prepare(
        "SELECT id, name, notes, created_at, expires_at, used, revoked
         FROM invites ORDER BY created_at DESC",
    )?;
    let now = unix_time() as i64;
    statement
        .query_map([], |row| {
            let id = row
                .get::<_, Option<String>>(0)?
                .unwrap_or_else(|| "legacy".to_owned());
            let created_at = row.get::<_, i64>(3)?.max(0) as u64;
            let expires_at = row.get::<_, i64>(4)?.max(0) as u64;
            let used = row.get::<_, i64>(5)? != 0;
            let revoked = row.get::<_, i64>(6)? != 0;
            let status = if revoked {
                "revoked"
            } else if used {
                "used"
            } else if row.get::<_, i64>(4)? <= now {
                "expired"
            } else {
                "pending"
            };
            Ok(InviteView {
                id,
                name: row.get(1)?,
                notes: row.get(2)?,
                created_at,
                expires_at,
                status,
            })
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(CoordError::Database)
}

async fn delete_invite(
    State(state): State<Arc<ServerInner>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    if require_admin(&state, &headers).is_none() {
        return error_response(StatusCode::UNAUTHORIZED, "authentication required");
    }
    let changed = match state.database.lock() {
        Ok(database) => database
            .execute(
                "UPDATE invites SET revoked = 1, download_used = 1 WHERE id = ?1",
                [&id],
            )
            .map(|changed| changed != 0),
        Err(_) => Err(rusqlite::Error::InvalidQuery),
    };
    match changed {
        Ok(true) => Json(serde_json::json!({"ok": true})).into_response(),
        Ok(false) => error_response(StatusCode::NOT_FOUND, "invite not found"),
        Err(error) => internal_error(CoordError::Database(error)),
    }
}

async fn download_cli(State(state): State<Arc<ServerInner>>, headers: HeaderMap) -> Response {
    let Some(token) = headers
        .get("x-vela-download-token")
        .and_then(|value| value.to_str().ok())
    else {
        return error_response(StatusCode::UNAUTHORIZED, "download token required");
    };
    match consume_download_token(&state, token) {
        Ok(true) => {}
        Ok(false) => {
            return error_response(
                StatusCode::UNAUTHORIZED,
                "invalid or expired download token",
            );
        }
        Err(error) => return internal_error(error),
    }
    let executable = match tokio::fs::read(match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => return internal_error(CoordError::Io(error)),
    })
    .await
    {
        Ok(executable) => executable,
        Err(error) => return internal_error(CoordError::Io(error)),
    };
    let checksum = hex::encode(Sha256::digest(&executable));
    let mut response = Response::new(Body::from(executable));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", cli_filename()))
            .expect("CLI filename is ASCII"),
    );
    response.headers_mut().insert(
        "x-checksum-sha256",
        HeaderValue::from_str(&checksum).expect("checksum is ASCII"),
    );
    response
}

const fn cli_filename() -> &'static str {
    if cfg!(windows) {
        "vela-cli.exe"
    } else {
        "vela-cli"
    }
}

fn require_admin(state: &Arc<ServerInner>, headers: &HeaderMap) -> Option<u64> {
    state.admin.authorize(headers)
}

fn error_response(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

fn internal_error(error: CoordError) -> Response {
    tracing::error!(error = %error, "admin request failed");
    error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
}
