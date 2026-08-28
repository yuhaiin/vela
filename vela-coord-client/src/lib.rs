//! Versioned WebSocket control-plane client.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use thiserror::Error;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async, tungstenite::Message};
use url::Url;
use vela_crypto::{Identity, MembershipCredential};
use vela_proto::{
    Candidate, ControlMessage, NodeId, PeerCapability, PeerInfo, PeerSummary, PublicPeerInfo,
};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

pub struct CoordinationClient {
    writer: SplitSink<Ws, Message>,
    reader: SplitStream<Ws>,
    server_public_key: Option<[u8; 32]>,
}

pub struct Registration {
    pub credential: MembershipCredential,
    pub peers: Vec<PeerInfo>,
}

impl CoordinationClient {
    pub async fn connect(endpoint: impl AsRef<str>) -> Result<Self, CoordClientError> {
        let url = Url::parse(endpoint.as_ref()).map_err(|_| CoordClientError::InvalidEndpoint)?;
        let (stream, _) = connect_async(url.as_str())
            .await
            .map_err(|error| CoordClientError::WebSocket(error.to_string()))?;
        let (writer, reader) = stream.split();
        Ok(Self {
            writer,
            reader,
            server_public_key: None,
        })
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
        let public = identity.public();
        let credential = match credential {
            Some(value) => {
                BASE64.encode(serde_json::to_vec(value).map_err(CoordClientError::Serialization)?)
            }
            None => String::new(),
        };
        self.send(ControlMessage::Register {
            node_id: public.node_id,
            signing_public: BASE64.encode(public.signing_public),
            noise_public: BASE64.encode(public.noise_public),
            credential,
            invite_token: token.map(str::to_owned),
            candidates,
            capabilities: vec![PeerCapability::DiagnosticPing],
        })
        .await?;
        match self.recv().await? {
            ControlMessage::RegisterOk { credential, peers } => {
                let credential = BASE64
                    .decode(credential)
                    .map_err(|_| CoordClientError::InvalidCredential)?;
                let credential: MembershipCredential =
                    serde_json::from_slice(&credential).map_err(CoordClientError::Serialization)?;
                let server_key = self
                    .server_public_key
                    .ok_or(CoordClientError::ServerKeyRequired)?;
                credential
                    .verify(&server_key, current_time())
                    .map_err(|_| CoordClientError::InvalidCredential)?;
                let peers = peers
                    .into_iter()
                    .map(|peer| self.verify_public_peer(peer))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Registration { credential, peers })
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

    pub async fn lookup_peer(&mut self, node_id: NodeId) -> Result<PeerInfo, CoordClientError> {
        self.send(ControlMessage::LookupPeer { node_id }).await?;
        loop {
            match self.recv().await? {
                ControlMessage::PeerInfo { peer } => return self.verify_public_peer(peer),
                ControlMessage::Error { code, message } => {
                    return Err(CoordClientError::Server { code, message });
                }
                ControlMessage::ConnectSignal { .. } => {}
                _ => return Err(CoordClientError::UnexpectedMessage),
            }
        }
    }

    pub async fn list_peers(&mut self) -> Result<Vec<PeerSummary>, CoordClientError> {
        self.send(ControlMessage::ListPeers).await?;
        loop {
            match self.recv().await? {
                ControlMessage::ListPeersOk { peers } => return Ok(peers),
                ControlMessage::Error { code, message } => {
                    return Err(CoordClientError::Server { code, message });
                }
                ControlMessage::ConnectSignal { .. } => {}
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
                Some(Ok(Message::Close(_))) | None => return Err(CoordClientError::Closed),
                Some(Ok(_)) => {}
                Some(Err(error)) => return Err(CoordClientError::WebSocket(error.to_string())),
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
    #[error("server signing public key has not been configured")]
    ServerKeyRequired,
    #[error("server rejected request: {code}: {message}")]
    Server { code: String, message: String },
    #[error("unexpected control message")]
    UnexpectedMessage,
    #[error("coordination connection closed")]
    Closed,
}

fn current_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
