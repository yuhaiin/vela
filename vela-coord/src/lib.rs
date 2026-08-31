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
use axum_server::tls_rustls::RustlsConfig;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures_util::{SinkExt, StreamExt};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    collections::HashMap,
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

#[derive(Clone)]
pub struct CoordServer {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    tenant: String,
    signer: ServerSigner,
    database: Mutex<Connection>,
    online: AsyncMutex<HashMap<NodeId, HashMap<u64, mpsc::Sender<ControlMessage>>>>,
    snapshot_generation: std::sync::atomic::AtomicU64,
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
                virtual_ipv4 BLOB,
                virtual_ipv6 BLOB,
                credential BLOB NOT NULL,
                capabilities TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS invites (
                token_hash BLOB PRIMARY KEY,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value INTEGER NOT NULL
            );",
        )?;
        let _ = connection.execute("ALTER TABLE peers ADD COLUMN virtual_ipv4 BLOB", []);
        let _ = connection.execute("ALTER TABLE peers ADD COLUMN virtual_ipv6 BLOB", []);
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
        Ok(Self {
            inner: Arc::new(ServerInner {
                tenant: tenant.into(),
                signer: ServerSigner::load_or_generate(signer_path)?,
                database: Mutex::new(connection),
                online: AsyncMutex::new(HashMap::new()),
                snapshot_generation: std::sync::atomic::AtomicU64::new(snapshot_generation),
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
        if let Some(sessions) = self.inner.online.lock().await.remove(&node_id) {
            for sender in sessions.into_values() {
                let _ = sender.send(ControlMessage::Revoke { node_id }).await;
            }
        }
        bump_snapshot(&self.inner)?;
        broadcast_snapshot(&self.inner).await?;
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
                virtual_ipv4: load_peer(state, node_id)?
                    .and_then(|peer| peer.virtual_ipv4)
                    .or(Some(allocate_virtual_ipv4(state, node_id)?)),
                virtual_ipv6: None,
                credential: stored_credential.clone(),
                capabilities,
            };
            update_peer(state, &peer)?;
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
                    signing_public: peer.signing_public,
                    noise_public: peer.noise_public,
                    candidates,
                    virtual_ipv4: peer.virtual_ipv4,
                    virtual_ipv6: peer.virtual_ipv6,
                    credential: peer.credential,
                    capabilities: peer.capabilities,
                },
            )?;
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
                    online: online.contains_key(&peer.node_id),
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
        ControlMessage::Pong { .. } => Ok(registered),
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

fn load_peer(state: &Arc<ServerInner>, node_id: NodeId) -> Result<Option<StoredPeer>, CoordError> {
    let database = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?;
    database.query_row("SELECT signing_public, noise_public, candidates, virtual_ipv4, virtual_ipv6, credential, capabilities FROM peers WHERE node_id = ?1 AND revoked = 0", params![node_id.as_bytes().as_slice()], |row| {
        let signing: Vec<u8> = row.get(0)?; let noise: Vec<u8> = row.get(1)?; let candidates: String = row.get(2)?; let virtual_ipv4: Option<Vec<u8>> = row.get(3)?; let virtual_ipv6: Option<Vec<u8>> = row.get(4)?; let credential: Vec<u8> = row.get(5)?; let capabilities: String = row.get(6)?;
        Ok((signing, noise, candidates, virtual_ipv4, virtual_ipv6, credential, capabilities))
    }).optional()?.map(|(signing, noise, candidates, virtual_ipv4, virtual_ipv6, credential, capabilities)| {
        Ok(StoredPeer { node_id, signing_public: signing.try_into().map_err(|_| CoordError::InvalidPeer)?, noise_public: noise.try_into().map_err(|_| CoordError::InvalidPeer)?, candidates: serde_json::from_str(&candidates)?, virtual_ipv4: decode_ipv4(virtual_ipv4)?, virtual_ipv6: decode_ipv6(virtual_ipv6)?, credential, capabilities: serde_json::from_str(&capabilities)? })
    }).transpose()
}

fn load_peers(state: &Arc<ServerInner>) -> Result<Vec<StoredPeer>, CoordError> {
    let database = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?;
    let mut statement = database.prepare(
        "SELECT node_id, signing_public, noise_public, candidates, virtual_ipv4, virtual_ipv6, credential, capabilities
         FROM peers WHERE revoked = 0 ORDER BY node_id",
    )?;
    let rows = statement.query_map([], |row| {
        let node_id: Vec<u8> = row.get(0)?;
        let signing: Vec<u8> = row.get(1)?;
        let noise: Vec<u8> = row.get(2)?;
        let candidates: String = row.get(3)?;
        let virtual_ipv4: Option<Vec<u8>> = row.get(4)?;
        let virtual_ipv6: Option<Vec<u8>> = row.get(5)?;
        let credential: Vec<u8> = row.get(6)?;
        let capabilities: String = row.get(7)?;
        Ok((
            node_id,
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

fn network_snapshot(state: &Arc<ServerInner>) -> Result<NetworkSnapshot, CoordError> {
    let digest = blake3::hash(state.tenant.as_bytes());
    let mut network_id = [0u8; 16];
    network_id.copy_from_slice(&digest.as_bytes()[..16]);
    let peers = load_peers(state)?.iter().map(private_peer).collect();
    Ok(state.signer.sign_snapshot(NetworkSnapshot {
        network_id,
        generation: state
            .snapshot_generation
            .load(std::sync::atomic::Ordering::Acquire),
        virtual_ipv4: Some(Ipv4Cidr {
            address: Ipv4Addr::new(100, 64, 0, 0),
            prefix_len: 10,
        }),
        virtual_ipv6: None,
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
    const USABLE_HOSTS: u32 = (1 << 22) - 2;
    const NETWORK_BASE: u32 = u32::from_be_bytes([100, 64, 0, 0]);
    let digest = blake3::hash(node_id.as_bytes());
    let start =
        u32::from_be_bytes(digest.as_bytes()[..4].try_into().expect("hash length")) % USABLE_HOSTS;
    let database = state
        .database
        .lock()
        .map_err(|_| CoordError::DatabasePoisoned)?;
    for offset in 0..USABLE_HOSTS {
        let host = 1 + (start + offset) % USABLE_HOSTS;
        let address = Ipv4Addr::from(NETWORK_BASE | host);
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
            virtual_ipv4: None,
            virtual_ipv6: None,
            credential: serde_json::to_vec(&credential).unwrap(),
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
}
