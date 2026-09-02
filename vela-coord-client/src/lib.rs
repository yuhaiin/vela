//! Versioned WebSocket control-plane client.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use std::{collections::VecDeque, net::IpAddr, time::Duration};
use thiserror::Error;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, client_async_tls_with_config, tungstenite::Message,
};
use tracing::debug;
use url::Url;
use vela_crypto::{Identity, MembershipCredential, verify_snapshot};
use vela_proto::{
    Candidate, ControlMessage, NetworkSnapshot, NodeId, PeerCapability, PeerInfo, PeerSummary,
    PublicPeerInfo,
};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

const CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

pub struct CoordinationClient {
    endpoint: String,
    writer: SplitSink<Ws, Message>,
    reader: SplitStream<Ws>,
    server_public_key: Option<[u8; 32]>,
    pending: VecDeque<ControlMessage>,
}

pub struct Registration {
    pub credential: MembershipCredential,
    pub peers: Vec<PeerInfo>,
    pub snapshot: NetworkSnapshot,
}

impl CoordinationClient {
    pub async fn connect(endpoint: impl AsRef<str>) -> Result<Self, CoordClientError> {
        Self::connect_with_doh(endpoint, &vela_dns::default_servers()).await
    }

    pub async fn connect_with_doh(
        endpoint: impl AsRef<str>,
        doh_servers: &[String],
    ) -> Result<Self, CoordClientError> {
        let endpoint = endpoint.as_ref().to_owned();
        let url = Url::parse(&endpoint).map_err(|_| CoordClientError::InvalidEndpoint)?;
        if !matches!(url.scheme(), "ws" | "wss") {
            return Err(CoordClientError::InvalidEndpoint);
        }
        let host = url.host_str().ok_or(CoordClientError::InvalidEndpoint)?;
        let port = url
            .port_or_known_default()
            .ok_or(CoordClientError::InvalidEndpoint)?;
        let addresses = match host.parse::<IpAddr>() {
            Ok(address) => {
                debug!(
                    debug_marker = "vela-control",
                    host,
                    resolution = "literal-ip",
                    "coordination endpoint uses a literal IP; skipping DoH"
                );
                vec![address]
            }
            Err(_) => {
                let addresses = vela_dns::resolve(host, doh_servers)
                    .await
                    .map_err(|error| CoordClientError::WebSocket(error.to_string()))?;
                debug!(
                    debug_marker = "vela-control",
                    host,
                    resolution = "doh",
                    address_count = addresses.len(),
                    "resolved coordination endpoint with DoH"
                );
                addresses
            }
        };
        let mut last_error = None;
        for address in addresses {
            let address = std::net::SocketAddr::new(address, port);
            debug!(
                debug_marker = "vela-control",
                endpoint = %endpoint,
                address = %address,
                "trying coordination server address"
            );
            let socket = match timeout(CONTROL_CONNECT_TIMEOUT, TcpStream::connect(address)).await {
                Ok(Ok(socket)) => socket,
                Ok(Err(error)) => {
                    debug!(
                        debug_marker = "vela-control",
                        address = %address,
                        error = %error,
                        "coordination TCP connection failed"
                    );
                    last_error = Some(error.to_string());
                    continue;
                }
                Err(_) => {
                    debug!(
                        debug_marker = "vela-control",
                        address = %address,
                        timeout = ?CONTROL_CONNECT_TIMEOUT,
                        "coordination TCP connection timed out"
                    );
                    last_error = Some(format!(
                        "coordination TCP connection to {address} timed out after {CONTROL_CONNECT_TIMEOUT:?}"
                    ));
                    continue;
                }
            };
            match timeout(
                CONTROL_CONNECT_TIMEOUT,
                client_async_tls_with_config(&endpoint, socket, None, None),
            )
            .await
            {
                Ok(Ok((stream, _))) => {
                    debug!(
                        debug_marker = "vela-control",
                        address = %address,
                        "coordination WebSocket connected"
                    );
                    let (writer, reader) = stream.split();
                    return Ok(Self {
                        endpoint,
                        writer,
                        reader,
                        server_public_key: None,
                        pending: VecDeque::new(),
                    });
                }
                Ok(Err(error)) => {
                    debug!(
                        debug_marker = "vela-control",
                        address = %address,
                        error = %error,
                        "coordination WebSocket handshake failed"
                    );
                    last_error = Some(error.to_string());
                }
                Err(_) => {
                    debug!(
                        debug_marker = "vela-control",
                        address = %address,
                        timeout = ?CONTROL_CONNECT_TIMEOUT,
                        "coordination WebSocket handshake timed out"
                    );
                    last_error = Some(format!(
                        "coordination WebSocket handshake to {address} timed out after {CONTROL_CONNECT_TIMEOUT:?}"
                    ));
                }
            }
        }
        Err(CoordClientError::WebSocket(last_error.unwrap_or_else(
            || "no resolved coordination address".to_owned(),
        )))
    }

    pub async fn reconnect(
        &mut self,
        identity: &Identity,
        incarnation: u64,
        credential: Option<&MembershipCredential>,
        candidates: Vec<Candidate>,
        doh_servers: &[String],
    ) -> Result<Registration, CoordClientError> {
        debug!(
            debug_marker = "vela-control",
            endpoint = %self.endpoint,
            candidate_count = candidates.len(),
            "replacing coordination WebSocket connection"
        );
        let mut replacement = Self::connect_with_doh(&self.endpoint, doh_servers).await?;
        if let Some(server_public_key) = self.server_public_key {
            replacement.trust_server_key(server_public_key);
        }
        let registration = replacement
            .register_with_incarnation(identity, incarnation, None, credential, candidates)
            .await?;
        *self = replacement;
        Ok(registration)
    }

    pub fn trust_server_key(&mut self, key: [u8; 32]) {
        self.server_public_key = Some(key);
    }

    pub async fn register(
        &mut self,
        identity: &Identity,
        token: Option<&str>,
        credential: Option<&MembershipCredential>,
        candidates: Vec<Candidate>,
    ) -> Result<Registration, CoordClientError> {
        let mut incarnation = rand::random();
        while incarnation == 0 {
            incarnation = rand::random();
        }
        self.register_with_incarnation(identity, incarnation, token, credential, candidates)
            .await
    }

    pub async fn register_with_incarnation(
        &mut self,
        identity: &Identity,
        incarnation: u64,
        token: Option<&str>,
        credential: Option<&MembershipCredential>,
        candidates: Vec<Candidate>,
    ) -> Result<Registration, CoordClientError> {
        timeout(
            CONTROL_REQUEST_TIMEOUT,
            self.register_with_incarnation_inner(
                identity,
                incarnation,
                token,
                credential,
                candidates,
            ),
        )
        .await
        .map_err(|_| CoordClientError::Timeout("register"))?
    }

    async fn register_with_incarnation_inner(
        &mut self,
        identity: &Identity,
        incarnation: u64,
        token: Option<&str>,
        credential: Option<&MembershipCredential>,
        candidates: Vec<Candidate>,
    ) -> Result<Registration, CoordClientError> {
        let public = identity.public();
        let credential = match credential {
            Some(value) => {
                BASE64.encode(serde_json::to_vec(value).map_err(CoordClientError::Serialization)?)
            }
            None => String::new(),
        };
        self.send(ControlMessage::Register {
            node_id: public.node_id,
            incarnation,
            signing_public: BASE64.encode(public.signing_public),
            noise_public: BASE64.encode(public.noise_public),
            credential,
            invite_token: token.map(str::to_owned),
            candidates,
            capabilities: vec![PeerCapability::DiagnosticPing],
        })
        .await?;
        match self.recv().await? {
            ControlMessage::RegisterOk {
                credential,
                peers,
                snapshot,
            } => {
                let credential = BASE64
                    .decode(credential)
                    .map_err(|_| CoordClientError::InvalidCredential)?;
                let credential: MembershipCredential =
                    serde_json::from_slice(&credential).map_err(CoordClientError::Serialization)?;
                let server_key = self
                    .server_public_key
                    .ok_or(CoordClientError::ServerKeyRequired)?;
                verify_snapshot(&snapshot, &server_key, current_time())
                    .map_err(|_| CoordClientError::InvalidSnapshot)?;
                snapshot.validate().map_err(CoordClientError::Protocol)?;
                for peer in &snapshot.peers {
                    self.verify_peer_credential(peer)?;
                }
                credential
                    .verify(&server_key, current_time())
                    .map_err(|_| CoordClientError::InvalidCredential)?;
                let peers = peers
                    .into_iter()
                    .map(|peer| self.verify_public_peer(peer))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Registration {
                    credential,
                    peers,
                    snapshot,
                })
            }
            ControlMessage::Error { code, message } => {
                Err(CoordClientError::Server { code, message })
            }
            _ => Err(CoordClientError::UnexpectedMessage),
        }
    }

    pub async fn update_candidates(
        &mut self,
        candidates: Vec<Candidate>,
    ) -> Result<(), CoordClientError> {
        self.send(ControlMessage::UpdateCandidates { candidates })
            .await
    }

    /// Updates the published candidates and waits for the corresponding fresh
    /// network snapshot. This turns candidate refresh into a control-plane
    /// request/response instead of treating a successful local socket write as
    /// proof that the server processed the update.
    pub async fn update_candidates_and_get_snapshot(
        &mut self,
        candidates: Vec<Candidate>,
    ) -> Result<NetworkSnapshot, CoordClientError> {
        timeout(
            CONTROL_REQUEST_TIMEOUT,
            self.update_candidates_and_get_snapshot_inner(candidates),
        )
        .await
        .map_err(|_| CoordClientError::Timeout("update candidates"))?
    }

    async fn update_candidates_and_get_snapshot_inner(
        &mut self,
        candidates: Vec<Candidate>,
    ) -> Result<NetworkSnapshot, CoordClientError> {
        self.send(ControlMessage::UpdateCandidates { candidates })
            .await?;
        loop {
            let message = self.recv_wire().await?;
            match message {
                ControlMessage::Snapshot { snapshot } => return Ok(snapshot),
                message @ ControlMessage::ConnectSignal { .. } => {
                    self.pending.push_back(message);
                }
                ControlMessage::Error { code, message } => {
                    return Err(CoordClientError::Server { code, message });
                }
                _ => return Err(CoordClientError::UnexpectedMessage),
            }
        }
    }

    pub async fn lookup_peer(&mut self, node_id: NodeId) -> Result<PeerInfo, CoordClientError> {
        timeout(CONTROL_REQUEST_TIMEOUT, self.lookup_peer_inner(node_id))
            .await
            .map_err(|_| CoordClientError::Timeout("lookup peer"))?
    }

    async fn lookup_peer_inner(&mut self, node_id: NodeId) -> Result<PeerInfo, CoordClientError> {
        self.send(ControlMessage::LookupPeer { node_id }).await?;
        loop {
            match self.recv_wire().await? {
                ControlMessage::PeerInfo { peer } => return self.verify_public_peer(peer),
                ControlMessage::Error { code, message } => {
                    return Err(CoordClientError::Server { code, message });
                }
                ControlMessage::ConnectSignal { .. } => {}
                message @ ControlMessage::Snapshot { .. } => self.pending.push_back(message),
                _ => return Err(CoordClientError::UnexpectedMessage),
            }
        }
    }

    pub async fn list_peers(&mut self) -> Result<Vec<PeerSummary>, CoordClientError> {
        timeout(CONTROL_REQUEST_TIMEOUT, self.list_peers_inner())
            .await
            .map_err(|_| CoordClientError::Timeout("list peers"))?
    }

    async fn list_peers_inner(&mut self) -> Result<Vec<PeerSummary>, CoordClientError> {
        self.send(ControlMessage::ListPeers).await?;
        loop {
            match self.recv_wire().await? {
                ControlMessage::ListPeersOk { peers } => return Ok(peers),
                ControlMessage::Error { code, message } => {
                    return Err(CoordClientError::Server { code, message });
                }
                ControlMessage::ConnectSignal { .. } => {}
                message @ ControlMessage::Snapshot { .. } => self.pending.push_back(message),
                _ => return Err(CoordClientError::UnexpectedMessage),
            }
        }
    }

    pub fn verify_public_peer(&self, peer: PublicPeerInfo) -> Result<PeerInfo, CoordClientError> {
        let peer = PeerInfo::try_from(peer).map_err(CoordClientError::Protocol)?;
        self.verify_peer_credential(&peer)?;
        Ok(peer)
    }

    pub async fn send(&mut self, message: ControlMessage) -> Result<(), CoordClientError> {
        let text = serde_json::to_string(&message).map_err(CoordClientError::Serialization)?;
        self.writer
            .send(Message::Text(text.into()))
            .await
            .map_err(|error| CoordClientError::WebSocket(error.to_string()))
    }

    pub async fn recv(&mut self) -> Result<ControlMessage, CoordClientError> {
        if let Some(message) = self.pending.pop_front() {
            return Ok(message);
        }
        self.recv_wire().await
    }

    async fn recv_wire(&mut self) -> Result<ControlMessage, CoordClientError> {
        loop {
            match self.reader.next().await {
                Some(Ok(Message::Text(text))) => {
                    let message =
                        serde_json::from_str(&text).map_err(CoordClientError::Serialization)?;
                    if let ControlMessage::Ping { nonce } = message {
                        self.send(ControlMessage::Pong { nonce }).await?;
                        continue;
                    }
                    return Ok(message);
                }
                Some(Ok(Message::Binary(bytes))) => {
                    let message =
                        serde_json::from_slice(&bytes).map_err(CoordClientError::Serialization)?;
                    if let ControlMessage::Ping { nonce } = message {
                        self.send(ControlMessage::Pong { nonce }).await?;
                        continue;
                    }
                    return Ok(message);
                }
                Some(Ok(Message::Ping(payload))) => {
                    self.writer
                        .send(Message::Pong(payload))
                        .await
                        .map_err(|error| CoordClientError::WebSocket(error.to_string()))?;
                }
                Some(Ok(Message::Close(_))) | None => {
                    debug!(
                        debug_marker = "vela-control",
                        "coordination WebSocket closed"
                    );
                    return Err(CoordClientError::Closed);
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    debug!(
                        debug_marker = "vela-control",
                        error = %error,
                        "coordination WebSocket read failed"
                    );
                    return Err(CoordClientError::WebSocket(error.to_string()));
                }
            }
        }
    }

    fn verify_peer_credential(&self, peer: &PeerInfo) -> Result<(), CoordClientError> {
        let server_key = self
            .server_public_key
            .ok_or(CoordClientError::ServerKeyRequired)?;
        let credential: MembershipCredential = serde_json::from_slice(&peer.credential)
            .map_err(|_| CoordClientError::InvalidCredential)?;
        credential
            .verify(&server_key, current_time())
            .map_err(|_| CoordClientError::InvalidCredential)?;
        if credential.node_id != peer.node_id
            || credential.signing_public != peer.signing_public
            || credential.noise_public != peer.noise_public
        {
            return Err(CoordClientError::InvalidCredential);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum CoordClientError {
    #[error("invalid coordination endpoint")]
    InvalidEndpoint,
    #[error("WebSocket error: {0}")]
    WebSocket(String),
    #[error("control message serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("protocol error: {0}")]
    Protocol(vela_proto::ProtoError),
    #[error("invalid membership credential")]
    InvalidCredential,
    #[error("invalid network snapshot")]
    InvalidSnapshot,
    #[error("server signing public key has not been configured")]
    ServerKeyRequired,
    #[error("server rejected request: {code}: {message}")]
    Server { code: String, message: String },
    #[error("unexpected control message")]
    UnexpectedMessage,
    #[error("coordination connection closed")]
    Closed,
    #[error("coordination request timed out: {0}")]
    Timeout(&'static str),
}

fn current_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
