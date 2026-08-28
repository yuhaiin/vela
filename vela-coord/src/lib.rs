//! Lightweight, single-tenant coordination server.
//!
//! The server stores only authorization metadata. Online WebSocket sessions
//! and candidates are in memory, and no data-plane packet enters this crate.

use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
    routing::get,
};
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    net::TcpListener,
    sync::{Mutex as AsyncMutex, mpsc},
};
use tracing::debug;
use vela_crypto::{CryptoError, MembershipCredential, ServerSigner};
use vela_proto::{Candidate, ControlMessage, NodeId, PublicPeerInfo};

#[derive(Clone)]
pub struct CoordServer {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    tenant: String,
    signer: ServerSigner,
    database: Mutex<Connection>,
    online: AsyncMutex<HashMap<NodeId, mpsc::Sender<ControlMessage>>>,
}

impl CoordServer {
    pub fn open(
        database_path: impl AsRef<Path>,
        signer_path: impl AsRef<Path>,
        tenant: impl Into<String>,
    ) -> Result<Self, CoordError> {
        let database_path = database_path.as_ref();
        if let Some(parent) = database_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let connection = Connection::open(database_path)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS peers (
                node_id BLOB PRIMARY KEY,
                signing_public BLOB NOT NULL,
                noise_public BLOB NOT NULL,
                candidates TEXT NOT NULL,
                credential BLOB NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS invites (
                token_hash BLOB PRIMARY KEY,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );",
        )?;
        Ok(Self {
            inner: Arc::new(ServerInner {
                tenant: tenant.into(),
                signer: ServerSigner::load_or_generate(signer_path)?,
                database: Mutex::new(connection),
                online: AsyncMutex::new(HashMap::new()),
            }),
        })
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/ws", get(ws_handler))
            .with_state(self.inner.clone())
    }

    pub async fn serve(&self, listener: TcpListener) -> Result<(), CoordError> {
        axum::serve(listener, self.router())
            .await
            .map_err(|error| CoordError::Server(error.to_string()))
    }

    pub async fn serve_tls(
        &self,
        bind: std::net::SocketAddr,
        certificate: impl AsRef<Path>,
        private_key: impl AsRef<Path>,
    ) -> Result<(), CoordError> {
        let config = RustlsConfig::from_pem_file(certificate, private_key)
            .await
            .map_err(|error| CoordError::Server(error.to_string()))?;
        axum_server::bind_rustls(bind, config)
            .serve(self.router().into_make_service())
            .await
            .map_err(|error| CoordError::Server(error.to_string()))
    }
    pub fn server_public_key(&self) -> [u8; 32] {
        self.inner.signer.public()
    }

    pub fn create_invite(&self, ttl_seconds: u64) -> Result<String, CoordError> {
        let mut token_bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut token_bytes);
        let token = BASE64.encode(token_bytes);
        let hash = *blake3::hash(token.as_bytes()).as_bytes();
        let expires = unix_time().saturating_add(ttl_seconds);
        self.inner
            .database
            .lock()
            .map_err(|_| CoordError::DatabasePoisoned)?
            .execute(
                "INSERT INTO invites(token_hash, expires_at) VALUES(?1, ?2)",
                params![hash.as_slice(), expires as i64],
            )?;
        Ok(token)
    }

    pub async fn revoke_peer(&self, node_id: NodeId) -> Result<(), CoordError> {
        self.inner
            .database
            .lock()
            .map_err(|_| CoordError::DatabasePoisoned)?
            .execute(
                "UPDATE peers SET revoked = 1 WHERE node_id = ?1",
                params![node_id.as_bytes().as_slice()],
            )?;
        if let Some(sender) = self.inner.online.lock().await.remove(&node_id) {
            let _ = sender.send(ControlMessage::Revoke { node_id }).await;
        }
        Ok(())
    }

    pub fn list_peers(&self) -> Result<Vec<NodeId>, CoordError> {
        let database = self
            .inner
            .database
            .lock()
            .map_err(|_| CoordError::DatabasePoisoned)?;
        let mut statement =
            database.prepare("SELECT node_id FROM peers WHERE revoked = 0 ORDER BY node_id")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| {
            let bytes = row?;
            bytes
                .try_into()
                .map(NodeId::new)
                .map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(CoordError::Database)
    }
}

async fn ws_handler(
    State(state): State<Arc<ServerInner>>,
    upgrade: WebSocketUpgrade,
) -> impl IntoResponse {
    upgrade.on_upgrade(move |socket| handle_socket(state, socket))
}

async fn handle_socket(state: Arc<ServerInner>, socket: WebSocket) {
    let (mut writer, mut reader) = socket.split();
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<ControlMessage>(64);
    let writer_task = tokio::spawn(async move {
        while let Some(message) = outbound_rx.recv().await {
            let text = match serde_json::to_string(&message) {
                Ok(text) => text,
                Err(_) => break,
            };
            if writer.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });
    let mut registered = None;
    while let Some(Ok(message)) = reader.next().await {
        let Message::Text(text) = message else {
            continue;
        };
        let request = match serde_json::from_str::<ControlMessage>(&text) {
            Ok(request) => request,
            Err(error) => {
                let _ = outbound_tx
                    .send(error_message("invalid_message", error.to_string()))
                    .await;
                continue;
            }
        };
        match handle_message(&state, &outbound_tx, registered, request).await {
            Ok(next_registered) => registered = next_registered,
            Err(error) => {
                let _ = outbound_tx.send(error.as_control()).await;
            }
        }
    }
    if let Some(node_id) = registered {
        state.online.lock().await.remove(&node_id);
    }
    writer_task.abort();
}

async fn handle_message(
    state: &Arc<ServerInner>,
    outbound: &mpsc::Sender<ControlMessage>,
    registered: Option<NodeId>,
    request: ControlMessage,
) -> Result<Option<NodeId>, CoordError> {
    match request {
        ControlMessage::Register {
            node_id,
            signing_public,
            noise_public,
            credential,
            invite_token,
            candidates,
        } => {
            let signing_public = decode_key(&signing_public)?;
            let noise_public = decode_key(&noise_public)?;
            let expected = NodeId::new(*blake3::hash(&signing_public).as_bytes());
            if expected != node_id {
                return Err(CoordError::InvalidPeer);
            }
            let stored_credential = if credential.is_empty() {
                let token = invite_token.ok_or(CoordError::InviteRequired)?;
                serde_json::to_vec(&register_with_invite(
                    state,
                    node_id,
                    signing_public,
                    noise_public,
                    &token,
                )?)?
            } else {
                let credential_bytes = BASE64
                    .decode(credential)
                    .map_err(|_| CoordError::InvalidCredential)?;
                let credential: MembershipCredential = serde_json::from_slice(&credential_bytes)?;
                credential
                    .verify(&state.signer.public(), unix_time())
                    .map_err(|_| CoordError::InvalidCredential)?;
                if credential.node_id != node_id
                    || credential.signing_public != signing_public
                    || credential.noise_public != noise_public
                    || credential.tenant != state.tenant
                {
                    return Err(CoordError::InvalidCredential);
                }
                let database = state
                    .database
                    .lock()
                    .map_err(|_| CoordError::DatabasePoisoned)?;
                database
                    .query_row(
                        "SELECT credential FROM peers WHERE node_id = ?1 AND revoked = 0",
                        params![node_id.as_bytes().as_slice()],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or(CoordError::PeerNotRegistered)?
            };
            let peer = StoredPeer {
                node_id,
                signing_public,
                noise_public,
                candidates,
                credential: stored_credential.clone(),
            };
            update_peer(state, &peer)?;
            state.online.lock().await.insert(node_id, outbound.clone());
            outbound
                .send(ControlMessage::RegisterOk {
                    credential: BASE64.encode(stored_credential),
                    peers: Vec::new(),
                })
                .await
                .map_err(|_| CoordError::ConnectionClosed)?;
            debug!(node = %node_id, "peer registered");
            Ok(Some(node_id))
        }
        ControlMessage::UpdateCandidates { candidates } => {
            let node_id = registered.ok_or(CoordError::NotRegistered)?;
            let peer = load_peer(state, node_id)?.ok_or(CoordError::PeerNotRegistered)?;
            update_peer(
                state,
                &StoredPeer {
                    node_id,
                    signing_public: peer.signing_public,
                    noise_public: peer.noise_public,
                    candidates,
                    credential: peer.credential,
                },
            )?;
            Ok(registered)
        }
        ControlMessage::LookupPeer { node_id } => {
            let requester = registered.ok_or(CoordError::NotRegistered)?;
            let target = load_peer(state, node_id)?.ok_or(CoordError::PeerNotRegistered)?;
            let requester_info =
                load_peer(state, requester)?.ok_or(CoordError::PeerNotRegistered)?;
            outbound
                .send(ControlMessage::PeerInfo {
                    peer: public_peer(&target)?,
                })
                .await
                .map_err(|_| CoordError::ConnectionClosed)?;
            if let Some(target_sender) = state.online.lock().await.get(&node_id).cloned() {
                let from = public_peer(&requester_info)?;
                let _ = target_sender
                    .send(ControlMessage::ConnectSignal { from, to: node_id })
                    .await;
            }
            Ok(registered)
        }
        ControlMessage::Ping { nonce } => {
            outbound
                .send(ControlMessage::Pong { nonce })
                .await
                .map_err(|_| CoordError::ConnectionClosed)?;
            Ok(registered)
        }
        _ => Err(CoordError::UnsupportedMessage),
    }
}

fn register_with_invite(
    state: &Arc<ServerInner>,
    node_id: NodeId,
    signing_public: [u8; 32],
    noise_public: [u8; 32],
    token: &str,
) -> Result<MembershipCredential, CoordError> {
    let hash = *blake3::hash(token.as_bytes()).as_bytes();
    let database = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?;
    let row: Option<(i64, i64)> = database
        .query_row(
            "SELECT expires_at, used FROM invites WHERE token_hash = ?1",
            params![hash.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let Some((expires_at, used)) = row else {
        return Err(CoordError::InvalidInvite);
    };
    if used != 0 || expires_at < unix_time() as i64 {
        return Err(CoordError::InviteExpired);
    }
    database.execute(
        "UPDATE invites SET used = 1 WHERE token_hash = ?1",
        params![hash.as_slice()],
    )?;
    let identity = vela_crypto::PublicIdentity {
        node_id,
        signing_public,
        noise_public,
    };
    Ok(MembershipCredential::unsigned(
        &identity,
        &state.tenant,
        unix_time().saturating_add(365 * 24 * 3600),
        state.signer.key_id(),
    )
    .sign(&state.signer))
}

#[derive(Clone)]
struct StoredPeer {
    node_id: NodeId,
    signing_public: [u8; 32],
    noise_public: [u8; 32],
    candidates: Vec<Candidate>,
    credential: Vec<u8>,
}

fn update_peer(state: &Arc<ServerInner>, peer: &StoredPeer) -> Result<(), CoordError> {
    let candidates = serde_json::to_string(&peer.candidates)?;
    state.database.lock().map_err(|_| CoordError::DatabasePoisoned)?.execute("INSERT INTO peers(node_id, signing_public, noise_public, candidates, credential, revoked) VALUES(?1, ?2, ?3, ?4, ?5, 0) ON CONFLICT(node_id) DO UPDATE SET signing_public = excluded.signing_public, noise_public = excluded.noise_public, candidates = excluded.candidates, credential = excluded.credential, revoked = 0", params![peer.node_id.as_bytes().as_slice(), peer.signing_public.as_slice(), peer.noise_public.as_slice(), candidates, peer.credential])?;
    Ok(())
}

fn load_peer(state: &Arc<ServerInner>, node_id: NodeId) -> Result<Option<StoredPeer>, CoordError> {
    let database = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?;
    database.query_row("SELECT signing_public, noise_public, candidates, credential FROM peers WHERE node_id = ?1 AND revoked = 0", params![node_id.as_bytes().as_slice()], |row| {
        let signing: Vec<u8> = row.get(0)?; let noise: Vec<u8> = row.get(1)?; let candidates: String = row.get(2)?; let credential: Vec<u8> = row.get(3)?;
        Ok((signing, noise, candidates, credential))
    }).optional()?.map(|(signing, noise, candidates, credential)| {
        Ok(StoredPeer { node_id, signing_public: signing.try_into().map_err(|_| CoordError::InvalidPeer)?, noise_public: noise.try_into().map_err(|_| CoordError::InvalidPeer)?, candidates: serde_json::from_str(&candidates)?, credential })
    }).transpose()
}

fn public_peer(peer: &StoredPeer) -> Result<PublicPeerInfo, CoordError> {
    Ok(PublicPeerInfo {
        node_id: peer.node_id,
        signing_public: BASE64.encode(peer.signing_public),
        noise_public: BASE64.encode(peer.noise_public),
        candidates: peer.candidates.clone(),
        credential: BASE64.encode(&peer.credential),
    })
}

fn decode_key(value: &str) -> Result<[u8; 32], CoordError> {
    BASE64
        .decode(value)
        .map_err(|_| CoordError::InvalidPeer)?
        .try_into()
        .map_err(|_| CoordError::InvalidPeer)
}
fn error_message(code: impl Into<String>, message: impl Into<String>) -> ControlMessage {
    ControlMessage::Error {
        code: code.into(),
        message: message.into(),
    }
}
fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Debug, Error)]
pub enum CoordError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("database mutex poisoned")]
    DatabasePoisoned,
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("random number generation failed")]
    Random,
    #[error("invalid peer")]
    InvalidPeer,
    #[error("invite token required")]
    InviteRequired,
    #[error("invalid invite token")]
    InvalidInvite,
    #[error("invite token expired or already used")]
    InviteExpired,
    #[error("invalid membership credential")]
    InvalidCredential,
    #[error("peer is not registered")]
    PeerNotRegistered,
    #[error("connection is not registered")]
    NotRegistered,
    #[error("unsupported control message")]
    UnsupportedMessage,
    #[error("connection closed")]
    ConnectionClosed,
    #[error("server error: {0}")]
    Server(String),
}

impl CoordError {
    fn as_control(&self) -> ControlMessage {
        error_message("server_error", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    #[test]
    fn invite_registration_is_persisted_and_single_use() {
        let base = std::env::temp_dir().join(format!("vela-coord-test-{}", std::process::id()));
        let db = base.with_extension("db");
        let signer_path = base.with_extension("key");
        let server = CoordServer::open(&db, &signer_path, "test-tenant").unwrap();
        let token = server.create_invite(60).unwrap();
        let identity = vela_crypto::Identity::generate();
        let public = identity.public();
        let credential = register_with_invite(
            &server.inner,
            public.node_id,
            public.signing_public,
            public.noise_public,
            &token,
        )
        .unwrap();
        credential
            .verify(&server.server_public_key(), unix_time())
            .unwrap();
        let peer = StoredPeer {
            node_id: public.node_id,
            signing_public: public.signing_public,
            noise_public: public.noise_public,
            candidates: vec![Candidate::Host(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )],
            credential: serde_json::to_vec(&credential).unwrap(),
        };
        update_peer(&server.inner, &peer).unwrap();
        assert_eq!(server.list_peers().unwrap(), vec![public.node_id]);
        assert!(matches!(
            register_with_invite(
                &server.inner,
                public.node_id,
                public.signing_public,
                public.noise_public,
                &token
            ),
            Err(CoordError::InviteExpired)
        ));
        drop(server);
        let reopened = CoordServer::open(&db, &signer_path, "test-tenant").unwrap();
        assert_eq!(reopened.list_peers().unwrap(), vec![public.node_id]);
        let _ = std::fs::remove_file(db);
        let _ = std::fs::remove_file(signer_path);
    }
}
