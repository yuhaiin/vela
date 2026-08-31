//! Lightweight, single-tenant coordination server.
//!
//! The server stores authorization metadata and the latest peer candidates.
//! Online WebSocket sessions are in memory, and no data-plane packet enters
//! this crate.

use axum::{
    Router,
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::IntoResponse,
    routing::get,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    collections::{HashMap, HashSet},
    net::{Ipv4Addr, Ipv6Addr},
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
use vela_proto::{
    Candidate, ControlMessage, Ipv4Cidr, NetworkSnapshot, NodeId, PeerCapability, PeerInfo,
    PeerSummary, PublicPeerInfo,
};

mod admin;

const VIRTUAL_IPV4_NETWORK_BASE: u32 = u32::from_be_bytes([10, 254, 0, 0]);
const VIRTUAL_IPV4_PREFIX_LEN: u8 = 16;
const VIRTUAL_IPV4_USABLE_HOSTS: u32 = (1 << 16) - 2;

#[derive(Clone)]
pub struct CoordServer {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    pub(crate) tenant: String,
    pub(crate) signer: ServerSigner,
    pub(crate) database: Mutex<Connection>,
    pub(crate) online: AsyncMutex<HashMap<NodeId, HashMap<u64, mpsc::Sender<ControlMessage>>>>,
    pub(crate) snapshot_generation: std::sync::atomic::AtomicU64,
    pub(crate) network_config: Mutex<ServerNetworkConfig>,
    pub(crate) admin: admin::AdminAuth,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ServerNetworkConfig {
    pub(crate) doh_servers: Vec<String>,
    pub(crate) stun_servers: Vec<String>,
}

impl CoordServer {
    pub fn open(
        database_path: impl AsRef<Path>,
        signer_path: impl AsRef<Path>,
        tenant: impl Into<String>,
    ) -> Result<Self, CoordError> {
        let credentials_path = database_path.as_ref().with_extension("admin-credentials");
        Self::open_with_admin_credentials(database_path, signer_path, tenant, credentials_path)
    }

    pub fn open_with_admin_credentials(
        database_path: impl AsRef<Path>,
        signer_path: impl AsRef<Path>,
        tenant: impl Into<String>,
        credentials_path: impl AsRef<Path>,
    ) -> Result<Self, CoordError> {
        Self::open_with_admin_credentials_and_stun_servers(
            database_path,
            signer_path,
            tenant,
            credentials_path,
            Vec::new(),
        )
    }

    pub fn open_with_admin_credentials_and_stun_servers(
        database_path: impl AsRef<Path>,
        signer_path: impl AsRef<Path>,
        tenant: impl Into<String>,
        credentials_path: impl AsRef<Path>,
        stun_servers: Vec<String>,
    ) -> Result<Self, CoordError> {
        Self::open_with_admin_credentials_and_network_config(
            database_path,
            signer_path,
            tenant,
            credentials_path,
            vela_dns::default_servers(),
            stun_servers,
        )
    }

    pub fn open_with_admin_credentials_and_network_config(
        database_path: impl AsRef<Path>,
        signer_path: impl AsRef<Path>,
        tenant: impl Into<String>,
        credentials_path: impl AsRef<Path>,
        doh_servers: Vec<String>,
        stun_servers: Vec<String>,
    ) -> Result<Self, CoordError> {
        let database_path = database_path.as_ref();
        if let Some(parent) = database_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut connection = Connection::open(database_path)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS peers (
                node_id BLOB PRIMARY KEY,
                signing_public BLOB NOT NULL,
                noise_public BLOB NOT NULL,
                candidates TEXT NOT NULL,
                virtual_ipv4 BLOB,
                virtual_ipv6 BLOB,
                credential BLOB NOT NULL,
                capabilities TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                name TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                last_seen INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS invites (
                token_hash BLOB PRIMARY KEY,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                id TEXT UNIQUE,
                name TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0,
                download_token_hash BLOB,
                download_used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );",
        )?;
        let _ = connection.execute("ALTER TABLE peers ADD COLUMN virtual_ipv4 BLOB", []);
        let _ = connection.execute("ALTER TABLE peers ADD COLUMN virtual_ipv6 BLOB", []);
        let _ = connection.execute(
            "ALTER TABLE peers ADD COLUMN name TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = connection.execute(
            "ALTER TABLE peers ADD COLUMN notes TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = connection.execute(
            "ALTER TABLE peers ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = connection.execute("ALTER TABLE invites ADD COLUMN id TEXT", []);
        let _ = connection.execute(
            "ALTER TABLE invites ADD COLUMN name TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = connection.execute(
            "ALTER TABLE invites ADD COLUMN notes TEXT NOT NULL DEFAULT ''",
            [],
        );
        let _ = connection.execute(
            "ALTER TABLE invites ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = connection.execute(
            "ALTER TABLE invites ADD COLUMN revoked INTEGER NOT NULL DEFAULT 0",
            [],
        );
        let _ = connection.execute(
            "ALTER TABLE invites ADD COLUMN download_token_hash BLOB",
            [],
        );
        let _ = connection.execute(
            "ALTER TABLE invites ADD COLUMN download_used INTEGER NOT NULL DEFAULT 0",
            [],
        );
        connection.execute(
            "UPDATE invites SET id = lower(hex(token_hash)) WHERE id IS NULL OR id = ''",
            [],
        )?;
        connection.execute(
            "UPDATE invites SET created_at = expires_at WHERE created_at = 0",
            [],
        )?;
        migrate_virtual_ipv4(&mut connection)?;
        connection.execute(
            "INSERT OR IGNORE INTO metadata(key, value) VALUES('snapshot_generation', 1)",
            [],
        )?;
        let snapshot_generation = connection
            .query_row(
                "SELECT value FROM metadata WHERE key = 'snapshot_generation'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .and_then(|value| u64::try_from(value).ok())
            .filter(|value| *value != 0)
            .unwrap_or(1);
        let network_config = load_network_config(&connection, doh_servers, stun_servers)?;
        let (admin, generated_password) =
            admin::AdminAuth::load_or_create(credentials_path.as_ref())?;
        let server = Self {
            inner: Arc::new(ServerInner {
                tenant: tenant.into(),
                signer: ServerSigner::load_or_generate(signer_path)?,
                database: Mutex::new(connection),
                online: AsyncMutex::new(HashMap::new()),
                snapshot_generation: std::sync::atomic::AtomicU64::new(snapshot_generation),
                network_config: Mutex::new(network_config),
                admin,
            }),
        };
        if let Some(password) = generated_password {
            eprintln!("generated admin password (save it now): {}", password);
        }
        Ok(server)
    }

    pub fn router(&self) -> Router {
        Router::new()
            .route("/ws", get(ws_handler))
            .merge(admin::router())
            .with_state(self.inner.clone())
    }

    pub async fn serve(&self, listener: TcpListener) -> Result<(), CoordError> {
        axum::serve(listener, self.router())
            .await
            .map_err(|error| CoordError::Server(error.to_string()))
    }

    pub fn server_public_key(&self) -> [u8; 32] {
        self.inner.signer.public()
    }

    pub fn create_invite(&self, ttl_seconds: u64) -> Result<String, CoordError> {
        Ok(create_invite(&self.inner, "", "", ttl_seconds)?.invite_token)
    }

    pub fn create_invite_with_metadata(
        &self,
        name: &str,
        notes: &str,
        ttl_seconds: u64,
    ) -> Result<CreatedInvite, CoordError> {
        create_invite(&self.inner, name, notes, ttl_seconds)
    }

    pub fn reset_admin_password(
        credentials_path: impl AsRef<Path>,
        password: Option<&str>,
    ) -> Result<String, CoordError> {
        admin::AdminAuth::reset_password(credentials_path.as_ref(), password)
    }

    pub async fn revoke_peer(&self, node_id: NodeId) -> Result<(), CoordError> {
        if !revoke_peer_inner(&self.inner, node_id).await? {
            return Err(CoordError::PeerNotRegistered);
        }
        Ok(())
    }

    pub async fn delete_peer(&self, node_id: NodeId) -> Result<bool, CoordError> {
        delete_peer_inner(&self.inner, node_id).await
    }

    pub fn update_peer_metadata(
        &self,
        node_id: NodeId,
        name: &str,
        notes: &str,
    ) -> Result<bool, CoordError> {
        update_peer_metadata(&self.inner, node_id, name, notes)
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
    let connection_id: u64 = rand::random();
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
    let heartbeat_tx = outbound_tx.clone();
    let heartbeat_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        loop {
            interval.tick().await;
            if heartbeat_tx
                .send(ControlMessage::Ping {
                    nonce: rand::random(),
                })
                .await
                .is_err()
            {
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
        match handle_message(&state, &outbound_tx, connection_id, registered, request).await {
            Ok(next_registered) => registered = next_registered,
            Err(error) => {
                let _ = outbound_tx.send(error.as_control()).await;
            }
        }
    }
    if let Some(node_id) = registered {
        let mut online = state.online.lock().await;
        if let Some(sessions) = online.get_mut(&node_id) {
            sessions.remove(&connection_id);
            if sessions.is_empty() {
                online.remove(&node_id);
            }
        }
    }
    heartbeat_task.abort();
    writer_task.abort();
}

async fn handle_message(
    state: &Arc<ServerInner>,
    outbound: &mpsc::Sender<ControlMessage>,
    connection_id: u64,
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
            capabilities,
        } => {
            let signing_public = decode_key(&signing_public)?;
            let noise_public = decode_key(&noise_public)?;
            let expected = NodeId::new(*blake3::hash(&signing_public).as_bytes());
            if expected != node_id {
                return Err(CoordError::InvalidPeer);
            }
            let (stored_credential, invite_registration) = if credential.is_empty() {
                let token = invite_token.ok_or(CoordError::InviteRequired)?;
                let registration =
                    register_with_invite(state, node_id, signing_public, noise_public, &token)?;
                (
                    serde_json::to_vec(&registration.credential)?,
                    Some(registration),
                )
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
                let credential = database
                    .query_row(
                        "SELECT credential FROM peers WHERE node_id = ?1 AND revoked = 0",
                        params![node_id.as_bytes().as_slice()],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or(CoordError::PeerNotRegistered)?;
                (credential, None)
            };
            let peer = StoredPeer {
                node_id,
                name: String::new(),
                signing_public,
                noise_public,
                candidates,
                virtual_ipv4: load_peer(state, node_id)?
                    .and_then(|peer| peer.virtual_ipv4)
                    .or(Some(allocate_virtual_ipv4(state, node_id)?)),
                virtual_ipv6: None,
                credential: stored_credential.clone(),
                capabilities,
            };
            update_peer(state, &peer)?;
            if let Some(registration) = invite_registration {
                update_peer_metadata(state, node_id, &registration.name, &registration.notes)?;
            }
            touch_peer(state, node_id)?;
            bump_snapshot(state)?;
            let existing_senders = state
                .online
                .lock()
                .await
                .values()
                .flat_map(|sessions| sessions.values().cloned())
                .collect::<Vec<_>>();
            state
                .online
                .lock()
                .await
                .entry(node_id)
                .or_default()
                .insert(connection_id, outbound.clone());
            let peers = load_peers(state)?
                .into_iter()
                .filter(|peer| peer.node_id != node_id)
                .map(|peer| public_peer(&peer))
                .collect::<Result<Vec<_>, _>>()?;
            let snapshot = network_snapshot(state)?;
            outbound
                .send(ControlMessage::RegisterOk {
                    credential: BASE64.encode(stored_credential),
                    peers,
                    snapshot: snapshot.clone(),
                })
                .await
                .map_err(|_| CoordError::ConnectionClosed)?;
            for sender in existing_senders {
                let _ = sender
                    .send(ControlMessage::Snapshot {
                        snapshot: snapshot.clone(),
                    })
                    .await;
            }
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
                    name: peer.name,
                    signing_public: peer.signing_public,
                    noise_public: peer.noise_public,
                    candidates,
                    virtual_ipv4: peer.virtual_ipv4,
                    virtual_ipv6: peer.virtual_ipv6,
                    credential: peer.credential,
                    capabilities: peer.capabilities,
                },
            )?;
            touch_peer(state, node_id)?;
            bump_snapshot(state)?;
            broadcast_snapshot(state).await?;
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
            let target_senders = state
                .online
                .lock()
                .await
                .get(&node_id)
                .map(|sessions| sessions.values().cloned().collect::<Vec<_>>())
                .unwrap_or_default();
            if !target_senders.is_empty() {
                let from = public_peer(&requester_info)?;
                for target_sender in target_senders {
                    let _ = target_sender
                        .send(ControlMessage::ConnectSignal {
                            from: from.clone(),
                            to: node_id,
                        })
                        .await;
                }
            }
            Ok(registered)
        }
        ControlMessage::ListPeers => {
            let requester = registered.ok_or(CoordError::NotRegistered)?;
            let online = state.online.lock().await;
            let peers = load_peers(state)?
                .into_iter()
                .filter(|peer| peer.node_id != requester)
                .map(|peer| PeerSummary {
                    node_id: peer.node_id,
                    name: peer.name,
                    online: online.contains_key(&peer.node_id),
                    virtual_ipv4: peer.virtual_ipv4,
                    virtual_ipv6: peer.virtual_ipv6,
                    capabilities: peer.capabilities,
                })
                .collect();
            outbound
                .send(ControlMessage::ListPeersOk { peers })
                .await
                .map_err(|_| CoordError::ConnectionClosed)?;
            Ok(registered)
        }
        ControlMessage::Ping { nonce } => {
            outbound
                .send(ControlMessage::Pong { nonce })
                .await
                .map_err(|_| CoordError::ConnectionClosed)?;
            Ok(registered)
        }
        ControlMessage::Pong { .. } => {
            if let Some(node_id) = registered {
                touch_peer(state, node_id)?;
            }
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
) -> Result<InviteRegistration, CoordError> {
    let hash = *blake3::hash(token.as_bytes()).as_bytes();
    let database = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?;
    let row: Option<(String, i64, i64, i64, String, String)> = database
        .query_row(
            "SELECT id, expires_at, used, revoked, name, notes
             FROM invites WHERE token_hash = ?1",
            params![hash.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((_id, expires_at, used, revoked, name, notes)) = row else {
        return Err(CoordError::InvalidInvite);
    };
    if revoked != 0 || used != 0 || expires_at < unix_time() as i64 {
        return Err(CoordError::InviteExpired);
    }
    database.execute(
        "UPDATE invites SET used = 1, download_used = 1 WHERE token_hash = ?1",
        params![hash.as_slice()],
    )?;
    let identity = vela_crypto::PublicIdentity {
        node_id,
        signing_public,
        noise_public,
    };
    Ok(InviteRegistration {
        name,
        notes,
        credential: MembershipCredential::unsigned(
            &identity,
            &state.tenant,
            unix_time().saturating_add(365 * 24 * 3600),
            state.signer.key_id(),
        )
        .sign(&state.signer),
    })
}

#[derive(Clone, Debug)]
struct InviteRegistration {
    name: String,
    notes: String,
    credential: MembershipCredential,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CreatedInvite {
    pub id: String,
    pub invite_token: String,
    pub download_token: String,
    pub name: String,
    pub notes: String,
    pub created_at: u64,
    pub expires_at: u64,
}

fn create_invite(
    state: &Arc<ServerInner>,
    name: &str,
    notes: &str,
    ttl_seconds: u64,
) -> Result<CreatedInvite, CoordError> {
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let invite_token = BASE64.encode(token_bytes);
    let mut download_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut download_bytes);
    let download_token = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        download_bytes,
    );
    let id = random_token(16);
    let token_hash = *blake3::hash(invite_token.as_bytes()).as_bytes();
    let download_token_hash = *blake3::hash(download_token.as_bytes()).as_bytes();
    let created_at = unix_time();
    let expires_at = created_at.saturating_add(ttl_seconds);
    state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?
        .execute(
            "INSERT INTO invites(
                id, token_hash, expires_at, used, name, notes, created_at,
                revoked, download_token_hash, download_used
             ) VALUES(?1, ?2, ?3, 0, ?4, ?5, ?6, 0, ?7, 0)",
            params![
                id,
                token_hash.as_slice(),
                expires_at as i64,
                name,
                notes,
                created_at as i64,
                download_token_hash.as_slice(),
            ],
        )?;
    Ok(CreatedInvite {
        id,
        invite_token,
        download_token,
        name: name.to_owned(),
        notes: notes.to_owned(),
        created_at,
        expires_at,
    })
}

fn random_token(bytes: usize) -> String {
    let mut value = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut value);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, value)
}

#[derive(Clone)]
struct StoredPeer {
    node_id: NodeId,
    name: String,
    signing_public: [u8; 32],
    noise_public: [u8; 32],
    candidates: Vec<Candidate>,
    virtual_ipv4: Option<Ipv4Addr>,
    virtual_ipv6: Option<Ipv6Addr>,
    credential: Vec<u8>,
    capabilities: Vec<PeerCapability>,
}

fn update_peer(state: &Arc<ServerInner>, peer: &StoredPeer) -> Result<(), CoordError> {
    let candidates = serde_json::to_string(&peer.candidates)?;
    let capabilities = serde_json::to_string(&peer.capabilities)?;
    let virtual_ipv4 = peer.virtual_ipv4.map(|address| address.octets().to_vec());
    let virtual_ipv6 = peer.virtual_ipv6.map(|address| address.octets().to_vec());
    state.database.lock().map_err(|_| CoordError::DatabasePoisoned)?.execute("INSERT INTO peers(node_id, signing_public, noise_public, candidates, virtual_ipv4, virtual_ipv6, credential, capabilities, revoked) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0) ON CONFLICT(node_id) DO UPDATE SET signing_public = excluded.signing_public, noise_public = excluded.noise_public, candidates = excluded.candidates, virtual_ipv4 = COALESCE(excluded.virtual_ipv4, peers.virtual_ipv4), virtual_ipv6 = COALESCE(excluded.virtual_ipv6, peers.virtual_ipv6), credential = excluded.credential, capabilities = excluded.capabilities, revoked = 0", params![peer.node_id.as_bytes().as_slice(), peer.signing_public.as_slice(), peer.noise_public.as_slice(), candidates, virtual_ipv4, virtual_ipv6, peer.credential, capabilities])?;
    Ok(())
}

pub(crate) fn update_peer_metadata(
    state: &Arc<ServerInner>,
    node_id: NodeId,
    name: &str,
    notes: &str,
) -> Result<bool, CoordError> {
    let changed = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?
        .execute(
            "UPDATE peers SET name = ?1, notes = ?2 WHERE node_id = ?3",
            params![name, notes, node_id.as_bytes().as_slice()],
        )?;
    Ok(changed != 0)
}

pub(crate) fn touch_peer(state: &Arc<ServerInner>, node_id: NodeId) -> Result<(), CoordError> {
    state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?
        .execute(
            "UPDATE peers SET last_seen = ?1 WHERE node_id = ?2",
            params![unix_time() as i64, node_id.as_bytes().as_slice()],
        )?;
    Ok(())
}

pub(crate) async fn revoke_peer_inner(
    state: &Arc<ServerInner>,
    node_id: NodeId,
) -> Result<bool, CoordError> {
    let changed = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?
        .execute(
            "UPDATE peers SET revoked = 1 WHERE node_id = ?1 AND revoked = 0",
            params![node_id.as_bytes().as_slice()],
        )?;
    if changed == 0 {
        return Ok(false);
    }
    bump_snapshot(state)?;
    disconnect_peer(state, node_id).await;
    broadcast_snapshot(state).await?;
    Ok(true)
}

pub(crate) async fn delete_peer_inner(
    state: &Arc<ServerInner>,
    node_id: NodeId,
) -> Result<bool, CoordError> {
    let changed = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?
        .execute(
            "DELETE FROM peers WHERE node_id = ?1",
            params![node_id.as_bytes().as_slice()],
        )?;
    if changed == 0 {
        return Ok(false);
    }
    bump_snapshot(state)?;
    disconnect_peer(state, node_id).await;
    broadcast_snapshot(state).await?;
    Ok(true)
}

async fn disconnect_peer(state: &Arc<ServerInner>, node_id: NodeId) {
    let senders = state
        .online
        .lock()
        .await
        .remove(&node_id)
        .unwrap_or_default()
        .into_values()
        .collect::<Vec<_>>();
    for sender in senders {
        let _ = sender.send(ControlMessage::Revoke { node_id }).await;
    }
}

pub(crate) fn consume_download_token(
    state: &Arc<ServerInner>,
    token: &str,
) -> Result<bool, CoordError> {
    let hash = *blake3::hash(token.as_bytes()).as_bytes();
    let changed = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?
        .execute(
            "UPDATE invites
             SET download_used = 1
             WHERE download_token_hash = ?1
               AND download_used = 0
               AND revoked = 0
               AND used = 0
               AND expires_at > ?2",
            params![hash.as_slice(), unix_time() as i64],
        )?;
    Ok(changed != 0)
}

fn load_peer(state: &Arc<ServerInner>, node_id: NodeId) -> Result<Option<StoredPeer>, CoordError> {
    let database = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?;
    database.query_row("SELECT name, signing_public, noise_public, candidates, virtual_ipv4, virtual_ipv6, credential, capabilities FROM peers WHERE node_id = ?1 AND revoked = 0", params![node_id.as_bytes().as_slice()], |row| {
        let name: String = row.get(0)?; let signing: Vec<u8> = row.get(1)?; let noise: Vec<u8> = row.get(2)?; let candidates: String = row.get(3)?; let virtual_ipv4: Option<Vec<u8>> = row.get(4)?; let virtual_ipv6: Option<Vec<u8>> = row.get(5)?; let credential: Vec<u8> = row.get(6)?; let capabilities: String = row.get(7)?;
        Ok((name, signing, noise, candidates, virtual_ipv4, virtual_ipv6, credential, capabilities))
    }).optional()?.map(|(name, signing, noise, candidates, virtual_ipv4, virtual_ipv6, credential, capabilities)| {
        Ok(StoredPeer { node_id, name, signing_public: signing.try_into().map_err(|_| CoordError::InvalidPeer)?, noise_public: noise.try_into().map_err(|_| CoordError::InvalidPeer)?, candidates: serde_json::from_str(&candidates)?, virtual_ipv4: decode_ipv4(virtual_ipv4)?, virtual_ipv6: decode_ipv6(virtual_ipv6)?, credential, capabilities: serde_json::from_str(&capabilities)? })
    }).transpose()
}

fn load_peers(state: &Arc<ServerInner>) -> Result<Vec<StoredPeer>, CoordError> {
    let database = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?;
    let mut statement = database.prepare(
        "SELECT node_id, name, signing_public, noise_public, candidates, virtual_ipv4, virtual_ipv6, credential, capabilities
         FROM peers WHERE revoked = 0 ORDER BY node_id",
    )?;
    let rows = statement.query_map([], |row| {
        let node_id: Vec<u8> = row.get(0)?;
        let name: String = row.get(1)?;
        let signing: Vec<u8> = row.get(2)?;
        let noise: Vec<u8> = row.get(3)?;
        let candidates: String = row.get(4)?;
        let virtual_ipv4: Option<Vec<u8>> = row.get(5)?;
        let virtual_ipv6: Option<Vec<u8>> = row.get(6)?;
        let credential: Vec<u8> = row.get(7)?;
        let capabilities: String = row.get(8)?;
        Ok((
            node_id,
            name,
            signing,
            noise,
            candidates,
            virtual_ipv4,
            virtual_ipv6,
            credential,
            capabilities,
        ))
    })?;
    rows.map(|row| {
        let (
            node_id,
            name,
            signing,
            noise,
            candidates,
            virtual_ipv4,
            virtual_ipv6,
            credential,
            capabilities,
        ) = row?;
        Ok(StoredPeer {
            node_id: node_id
                .try_into()
                .map(NodeId::new)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            name,
            signing_public: signing
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            noise_public: noise
                .try_into()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            candidates: serde_json::from_str(&candidates)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            virtual_ipv4: decode_ipv4(virtual_ipv4).map_err(|_| rusqlite::Error::InvalidQuery)?,
            virtual_ipv6: decode_ipv6(virtual_ipv6).map_err(|_| rusqlite::Error::InvalidQuery)?,
            credential,
            capabilities: serde_json::from_str(&capabilities)
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
        })
    })
    .collect::<Result<Vec<_>, _>>()
    .map_err(CoordError::Database)
}

fn public_peer(peer: &StoredPeer) -> Result<PublicPeerInfo, CoordError> {
    Ok(PublicPeerInfo {
        node_id: peer.node_id,
        signing_public: BASE64.encode(peer.signing_public),
        noise_public: BASE64.encode(peer.noise_public),
        candidates: peer.candidates.clone(),
        virtual_ipv4: peer.virtual_ipv4,
        virtual_ipv6: peer.virtual_ipv6,
        credential: BASE64.encode(&peer.credential),
        capabilities: peer.capabilities.clone(),
    })
}

fn private_peer(peer: &StoredPeer) -> PeerInfo {
    PeerInfo {
        node_id: peer.node_id,
        signing_public: peer.signing_public,
        noise_public: peer.noise_public,
        candidates: peer.candidates.clone(),
        virtual_ipv4: peer.virtual_ipv4,
        virtual_ipv6: peer.virtual_ipv6,
        credential: peer.credential.clone(),
        capabilities: peer.capabilities.clone(),
    }
}

fn load_network_config(
    connection: &Connection,
    doh_servers: Vec<String>,
    stun_servers: Vec<String>,
) -> Result<ServerNetworkConfig, CoordError> {
    let stored = |key: &str| {
        connection
            .query_row(
                "SELECT value FROM settings WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
    };
    let doh_default = if doh_servers.is_empty() {
        vela_dns::default_servers()
    } else {
        doh_servers
    };
    let doh_servers = stored("doh_servers")?
        .map(|value| serde_json::from_str(&value))
        .transpose()?
        .filter(|servers: &Vec<String>| !servers.is_empty())
        .unwrap_or(doh_default);
    let stun_servers = stored("stun_servers")?
        .map(|value| serde_json::from_str(&value))
        .transpose()?
        .unwrap_or(stun_servers);
    let config = ServerNetworkConfig {
        doh_servers,
        stun_servers,
    };
    connection.execute(
        "INSERT OR IGNORE INTO settings(key, value) VALUES('doh_servers', ?1)",
        params![serde_json::to_string(&config.doh_servers)?],
    )?;
    connection.execute(
        "INSERT OR IGNORE INTO settings(key, value) VALUES('stun_servers', ?1)",
        params![serde_json::to_string(&config.stun_servers)?],
    )?;
    Ok(config)
}

pub(crate) fn network_config(state: &Arc<ServerInner>) -> Result<ServerNetworkConfig, CoordError> {
    state
        .network_config
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)
        .map(|config| config.clone())
}

pub(crate) async fn update_network_config(
    state: &Arc<ServerInner>,
    config: ServerNetworkConfig,
) -> Result<(), CoordError> {
    let changed = {
        let mut current = state
            .network_config
            .lock()
            .map_err(|_| CoordError::DatabasePoisoned)?;
        if *current == config {
            false
        } else {
            let mut database = state
                .database
                .lock()
                .map_err(|_| CoordError::DatabasePoisoned)?;
            let transaction = database.transaction()?;
            transaction.execute(
                "INSERT INTO settings(key, value) VALUES('doh_servers', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![serde_json::to_string(&config.doh_servers)?],
            )?;
            transaction.execute(
                "INSERT INTO settings(key, value) VALUES('stun_servers', ?1)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![serde_json::to_string(&config.stun_servers)?],
            )?;
            transaction.commit()?;
            *current = config;
            true
        }
    };
    if changed {
        bump_snapshot(state)?;
        broadcast_snapshot(state).await?;
    }
    Ok(())
}

fn network_snapshot(state: &Arc<ServerInner>) -> Result<NetworkSnapshot, CoordError> {
    let digest = blake3::hash(state.tenant.as_bytes());
    let mut network_id = [0u8; 16];
    network_id.copy_from_slice(&digest.as_bytes()[..16]);
    let peers = load_peers(state)?.iter().map(private_peer).collect();
    let config = network_config(state)?;
    Ok(state.signer.sign_snapshot(NetworkSnapshot {
        network_id,
        generation: state
            .snapshot_generation
            .load(std::sync::atomic::Ordering::Acquire),
        virtual_ipv4: Some(Ipv4Cidr {
            address: Ipv4Addr::from(VIRTUAL_IPV4_NETWORK_BASE),
            prefix_len: VIRTUAL_IPV4_PREFIX_LEN,
        }),
        virtual_ipv6: None,
        doh_servers: config.doh_servers,
        stun_servers: config.stun_servers,
        peers,
        expires_at: unix_time().saturating_add(3600),
        signature: Vec::new(),
    }))
}

fn bump_snapshot(state: &Arc<ServerInner>) -> Result<(), CoordError> {
    let database = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?;
    let generation = state
        .snapshot_generation
        .load(std::sync::atomic::Ordering::Acquire)
        .checked_add(1)
        .ok_or(CoordError::SnapshotGenerationOverflow)?;
    database.execute(
        "INSERT INTO metadata(key, value) VALUES('snapshot_generation', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![i64::try_from(generation).map_err(|_| CoordError::SnapshotGenerationOverflow)?],
    )?;
    state
        .snapshot_generation
        .store(generation, std::sync::atomic::Ordering::Release);
    Ok(())
}

async fn broadcast_snapshot(state: &Arc<ServerInner>) -> Result<(), CoordError> {
    let snapshot = network_snapshot(state)?;
    let senders = state
        .online
        .lock()
        .await
        .values()
        .flat_map(|sessions| sessions.values().cloned())
        .collect::<Vec<_>>();
    for sender in senders {
        sender
            .send(ControlMessage::Snapshot {
                snapshot: snapshot.clone(),
            })
            .await
            .map_err(|_| CoordError::ConnectionClosed)?;
    }
    Ok(())
}

fn allocate_virtual_ipv4(
    state: &Arc<ServerInner>,
    node_id: NodeId,
) -> Result<Ipv4Addr, CoordError> {
    let digest = blake3::hash(node_id.as_bytes());
    let start = u32::from_be_bytes(digest.as_bytes()[..4].try_into().expect("hash length"))
        % VIRTUAL_IPV4_USABLE_HOSTS;
    let database = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?;
    for offset in 0..VIRTUAL_IPV4_USABLE_HOSTS {
        let host = 1 + (start + offset) % VIRTUAL_IPV4_USABLE_HOSTS;
        let address = Ipv4Addr::from(VIRTUAL_IPV4_NETWORK_BASE + host);
        let used: Option<i64> = database
            .query_row(
                "SELECT 1 FROM peers WHERE virtual_ipv4 = ?1 LIMIT 1",
                params![address.octets().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if used.is_none() {
            return Ok(address);
        }
    }
    Err(CoordError::AddressPoolExhausted)
}

fn migrate_virtual_ipv4(connection: &mut Connection) -> Result<(), CoordError> {
    let transaction = connection.transaction()?;
    let peers = {
        let mut statement =
            transaction.prepare("SELECT node_id, virtual_ipv4 FROM peers ORDER BY node_id")?;
        statement
            .query_map([], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    let mut used_hosts = HashSet::new();
    let mut updates = Vec::new();
    for (node_id, stored_address) in peers {
        let address = stored_address
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(Ipv4Addr::from);
        let Some(host) = address.and_then(virtual_ipv4_host) else {
            let node_id: [u8; 32] = node_id.try_into().map_err(|_| CoordError::InvalidPeer)?;
            let address = allocate_virtual_ipv4_from_used(NodeId::new(node_id), &mut used_hosts)?;
            updates.push((node_id.to_vec(), address.octets().to_vec()));
            continue;
        };
        if !used_hosts.insert(host) {
            let node_id: [u8; 32] = node_id.try_into().map_err(|_| CoordError::InvalidPeer)?;
            let address = allocate_virtual_ipv4_from_used(NodeId::new(node_id), &mut used_hosts)?;
            updates.push((node_id.to_vec(), address.octets().to_vec()));
        }
    }
    for (node_id, address) in updates {
        transaction.execute(
            "UPDATE peers SET virtual_ipv4 = ?1 WHERE node_id = ?2",
            params![address, node_id],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn virtual_ipv4_host(address: Ipv4Addr) -> Option<u32> {
    let host = u32::from(address).checked_sub(VIRTUAL_IPV4_NETWORK_BASE)?;
    (1..=VIRTUAL_IPV4_USABLE_HOSTS)
        .contains(&host)
        .then_some(host)
}

fn allocate_virtual_ipv4_from_used(
    node_id: NodeId,
    used_hosts: &mut HashSet<u32>,
) -> Result<Ipv4Addr, CoordError> {
    let digest = blake3::hash(node_id.as_bytes());
    let start = u32::from_be_bytes(digest.as_bytes()[..4].try_into().expect("hash length"))
        % VIRTUAL_IPV4_USABLE_HOSTS;
    for offset in 0..VIRTUAL_IPV4_USABLE_HOSTS {
        let host = 1 + (start + offset) % VIRTUAL_IPV4_USABLE_HOSTS;
        if used_hosts.insert(host) {
            return Ok(Ipv4Addr::from(VIRTUAL_IPV4_NETWORK_BASE + host));
        }
    }
    Err(CoordError::AddressPoolExhausted)
}

fn decode_ipv4(value: Option<Vec<u8>>) -> Result<Option<Ipv4Addr>, CoordError> {
    value
        .map(|bytes| {
            let bytes: [u8; 4] = bytes.try_into().map_err(|_| CoordError::InvalidPeer)?;
            Ok(Ipv4Addr::from(bytes))
        })
        .transpose()
}

fn decode_ipv6(value: Option<Vec<u8>>) -> Result<Option<Ipv6Addr>, CoordError> {
    value
        .map(|bytes| {
            let bytes: [u8; 16] = bytes.try_into().map_err(|_| CoordError::InvalidPeer)?;
            Ok(Ipv6Addr::from(bytes))
        })
        .transpose()
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
    #[error("virtual address pool is exhausted")]
    AddressPoolExhausted,
    #[error("snapshot generation counter is exhausted")]
    SnapshotGenerationOverflow,
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
    #[error("admin credentials error: {0}")]
    AdminCredentials(String),
}

impl CoordError {
    fn as_control(&self) -> ControlMessage {
        error_message("server_error", self.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode},
    };
    use std::net::SocketAddr;
    use tower::ServiceExt;

    #[test]
    fn invite_registration_is_persisted_and_single_use() {
        let base = std::env::temp_dir().join(format!("vela-coord-test-{}", std::process::id()));
        let db = base.with_extension("db");
        let signer_path = base.with_extension("key");
        let server = CoordServer::open(&db, &signer_path, "test-tenant").unwrap();
        let token = server.create_invite(60).unwrap();
        let identity = vela_crypto::Identity::generate();
        let public = identity.public();
        let registration = register_with_invite(
            &server.inner,
            public.node_id,
            public.signing_public,
            public.noise_public,
            &token,
        )
        .unwrap();
        registration
            .credential
            .verify(&server.server_public_key(), unix_time())
            .unwrap();
        let peer = StoredPeer {
            node_id: public.node_id,
            name: String::new(),
            signing_public: public.signing_public,
            noise_public: public.noise_public,
            candidates: vec![Candidate::Host(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            )],
            virtual_ipv4: None,
            virtual_ipv6: None,
            credential: serde_json::to_vec(&registration.credential).unwrap(),
            capabilities: vec![PeerCapability::DiagnosticPing],
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

    #[test]
    fn snapshot_generation_survives_restart() {
        let base = std::env::temp_dir().join(format!(
            "vela-coord-generation-test-{}-{}",
            std::process::id(),
            unix_time()
        ));
        let db = base.with_extension("db");
        let signer_path = base.with_extension("key");
        let server = CoordServer::open(&db, &signer_path, "test-tenant").unwrap();
        let initial = server
            .inner
            .snapshot_generation
            .load(std::sync::atomic::Ordering::Acquire);
        bump_snapshot(&server.inner).unwrap();
        let advanced = server
            .inner
            .snapshot_generation
            .load(std::sync::atomic::Ordering::Acquire);
        assert_eq!(advanced, initial + 1);
        drop(server);

        let reopened = CoordServer::open(&db, &signer_path, "test-tenant").unwrap();
        assert_eq!(
            reopened
                .inner
                .snapshot_generation
                .load(std::sync::atomic::Ordering::Acquire),
            advanced
        );
        let _ = std::fs::remove_file(db);
        let _ = std::fs::remove_file(signer_path);
    }

    #[test]
    fn coordinator_stun_servers_are_signed_into_snapshots() {
        let base = std::env::temp_dir().join(format!(
            "vela-coord-stun-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = base.with_extension("db");
        let signer_path = base.with_extension("key");
        let credentials_path = base.with_extension("credentials");
        let server = CoordServer::open_with_admin_credentials_and_stun_servers(
            &db,
            &signer_path,
            "test-tenant",
            &credentials_path,
            vec!["stun.example.test:3478".to_owned()],
        )
        .unwrap();
        let snapshot = network_snapshot(&server.inner).unwrap();
        assert_eq!(snapshot.doh_servers, vela_dns::default_servers());
        assert_eq!(snapshot.stun_servers, vec!["stun.example.test:3478"]);
        vela_crypto::verify_snapshot(&snapshot, &server.server_public_key(), unix_time()).unwrap();
        let _ = std::fs::remove_file(db);
        let _ = std::fs::remove_file(signer_path);
        let _ = std::fs::remove_file(credentials_path);
    }

    #[test]
    fn coordinator_network_config_persists_across_restart() {
        let base = std::env::temp_dir().join(format!(
            "vela-coord-network-config-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = base.with_extension("db");
        let signer_path = base.with_extension("key");
        let credentials_path = base.with_extension("credentials");
        let server = CoordServer::open_with_admin_credentials_and_network_config(
            &db,
            &signer_path,
            "test-tenant",
            &credentials_path,
            vec!["https://resolver.example.test/dns-query".to_owned()],
            vec!["[2001:db8::1]:3478".to_owned()],
        )
        .unwrap();
        let snapshot = network_snapshot(&server.inner).unwrap();
        assert_eq!(
            snapshot.doh_servers,
            vec!["https://resolver.example.test/dns-query"]
        );
        assert_eq!(snapshot.stun_servers, vec!["[2001:db8::1]:3478"]);
        vela_crypto::verify_snapshot(&snapshot, &server.server_public_key(), unix_time()).unwrap();
        drop(server);

        let reopened = CoordServer::open_with_admin_credentials(
            &db,
            &signer_path,
            "test-tenant",
            &credentials_path,
        )
        .unwrap();
        let reopened_snapshot = network_snapshot(&reopened.inner).unwrap();
        assert_eq!(reopened_snapshot.doh_servers, snapshot.doh_servers);
        assert_eq!(reopened_snapshot.stun_servers, snapshot.stun_servers);
        let _ = std::fs::remove_file(db);
        let _ = std::fs::remove_file(signer_path);
        let _ = std::fs::remove_file(credentials_path);
    }

    #[test]
    fn existing_virtual_ipv4_addresses_migrate_to_current_network() {
        let base = std::env::temp_dir().join(format!(
            "vela-coord-address-migration-test-{}-{}",
            std::process::id(),
            unix_time()
        ));
        let db = base.with_extension("db");
        let signer_path = base.with_extension("key");
        let server = CoordServer::open(&db, &signer_path, "test-tenant").unwrap();
        let identity = vela_crypto::Identity::generate();
        let public = identity.public();
        update_peer(
            &server.inner,
            &StoredPeer {
                node_id: public.node_id,
                name: String::new(),
                signing_public: public.signing_public,
                noise_public: public.noise_public,
                candidates: Vec::new(),
                virtual_ipv4: Some(Ipv4Addr::new(100, 74, 105, 149)),
                virtual_ipv6: None,
                credential: Vec::new(),
                capabilities: Vec::new(),
            },
        )
        .unwrap();
        drop(server);

        let reopened = CoordServer::open(&db, &signer_path, "test-tenant").unwrap();
        let peer = load_peer(&reopened.inner, public.node_id).unwrap().unwrap();
        let address = peer.virtual_ipv4.unwrap();
        assert!(virtual_ipv4_host(address).is_some());
        assert_ne!(address, Ipv4Addr::new(100, 74, 105, 149));

        let snapshot = network_snapshot(&reopened.inner).unwrap();
        assert_eq!(
            snapshot.virtual_ipv4,
            Some(Ipv4Cidr {
                address: Ipv4Addr::from(VIRTUAL_IPV4_NETWORK_BASE),
                prefix_len: VIRTUAL_IPV4_PREFIX_LEN,
            })
        );
        snapshot.validate().unwrap();

        let _ = std::fs::remove_file(db);
        let _ = std::fs::remove_file(signer_path);
    }

    #[tokio::test]
    async fn admin_api_manages_invites_and_peers() {
        let base = std::env::temp_dir().join(format!(
            "vela-coord-admin-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let db = base.with_extension("db");
        let signer_path = base.with_extension("key");
        let credentials_path = base.with_extension("credentials");
        let initial = CoordServer::open_with_admin_credentials(
            &db,
            &signer_path,
            "test-tenant",
            &credentials_path,
        )
        .unwrap();
        drop(initial);
        CoordServer::reset_admin_password(&credentials_path, Some("test-password-123")).unwrap();
        let server = CoordServer::open_with_admin_credentials(
            &db,
            &signer_path,
            "test-tenant",
            &credentials_path,
        )
        .unwrap();

        let login = server
            .router()
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"admin","password":"test-password-123"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login.status(), StatusCode::OK);
        let login: serde_json::Value =
            serde_json::from_slice(&to_bytes(login.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        let token = login["token"].as_str().unwrap().to_owned();
        let authorization = format!("Bearer {token}");

        let network_config_response = server
            .router()
            .oneshot(
                Request::patch("/api/v1/admin/config")
                    .header("authorization", &authorization)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"doh_servers":["https://dns.example.test/dns-query"],"stun_servers":["stun.example.test:3478"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(network_config_response.status(), StatusCode::OK);
        let network_config: serde_json::Value = serde_json::from_slice(
            &to_bytes(network_config_response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            network_config["doh_servers"],
            serde_json::json!(["https://dns.example.test/dns-query"])
        );
        assert_eq!(
            network_snapshot(&server.inner).unwrap().stun_servers,
            vec!["stun.example.test:3478"]
        );

        let invite_response = server
            .router()
            .oneshot(
                Request::post("/api/v1/admin/invites")
                    .header("authorization", &authorization)
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"name":"laptop","notes":"test machine","ttl_seconds":3600}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invite_response.status(), StatusCode::OK);
        let invite: CreatedInvite = serde_json::from_slice(
            &to_bytes(invite_response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(!invite.invite_token.is_empty());
        assert!(!invite.download_token.is_empty());

        let invites_response = server
            .router()
            .oneshot(
                Request::get("/api/v1/admin/invites")
                    .header("authorization", &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let invites_body = to_bytes(invites_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let invites_text = String::from_utf8(invites_body.to_vec()).unwrap();
        assert!(!invites_text.contains(&invite.invite_token));
        assert!(!invites_text.contains(&invite.download_token));

        let identity = vela_crypto::Identity::generate();
        let public = identity.public();
        update_peer(
            &server.inner,
            &StoredPeer {
                node_id: public.node_id,
                name: String::new(),
                signing_public: public.signing_public,
                noise_public: public.noise_public,
                candidates: Vec::new(),
                virtual_ipv4: Some(Ipv4Addr::new(10, 254, 0, 10)),
                virtual_ipv6: None,
                credential: Vec::new(),
                capabilities: Vec::new(),
            },
        )
        .unwrap();
        let node_id = public.node_id.to_string();
        let update_path = format!("/api/v1/admin/peers/{node_id}");
        let update_response = server
            .router()
            .oneshot(
                Request::patch(update_path)
                    .header("authorization", &authorization)
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"name":"laptop","notes":"updated"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(update_response.status(), StatusCode::OK);

        let revoke_path = format!("/api/v1/admin/peers/{node_id}/revoke");
        let revoke_response = server
            .router()
            .oneshot(
                Request::post(revoke_path)
                    .header("authorization", &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(revoke_response.status(), StatusCode::OK);
        assert!(server.list_peers().unwrap().is_empty());

        let delete_path = format!("/api/v1/admin/peers/{node_id}");
        let delete_response = server
            .router()
            .oneshot(
                Request::delete(delete_path)
                    .header("authorization", &authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_response.status(), StatusCode::OK);

        let download_path = "/download/vela-cli";
        let download_response = server
            .router()
            .oneshot(
                Request::get(download_path)
                    .header("x-vela-download-token", &invite.download_token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(download_response.status(), StatusCode::OK);
        let second_download = server
            .router()
            .oneshot(
                Request::get(download_path)
                    .header("x-vela-download-token", &invite.download_token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second_download.status(), StatusCode::UNAUTHORIZED);

        let _ = std::fs::remove_file(db);
        let _ = std::fs::remove_file(signer_path);
        let _ = std::fs::remove_file(credentials_path);
    }
}
