//! A thin, test-focused peer module built on top of Vela's direct transport.
//!
//! This crate owns the diagnostic peer lifecycle and result contract. It does
//! not implement a relay or a business data plane.

use serde::{Deserialize, Serialize};
use std::{
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tokio::time::interval;
use vela_coord_client::{CoordClientError, CoordinationClient};
use vela_core::{
    BindOptions, ConnectError, CoreError, DiagnosticPingError, DiagnosticPingResult, NodeConfig,
    TokioDatagramProvider, VelaNode,
};
use vela_crypto::{CryptoError, Identity, MembershipCredential};
use vela_proto::{Candidate, ControlMessage, NodeId, PeerInfo, PeerSummary};

const STATE_FILE: &str = "state.json";
const IDENTITY_FILE: &str = "identity";
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerState {
    pub server: String,
    pub server_key: [u8; 32],
    pub credential: Option<MembershipCredential>,
    pub bind: SocketAddr,
    pub stun_servers: Vec<SocketAddr>,
    pub candidates: Vec<Candidate>,
}

impl PeerState {
    pub fn new(
        server: String,
        server_key: [u8; 32],
        bind: SocketAddr,
        stun_servers: Vec<SocketAddr>,
    ) -> Self {
        Self {
            server,
            server_key,
            credential: None,
            bind,
            stun_servers,
            candidates: Vec::new(),
        }
    }

    pub fn load(dir: impl AsRef<Path>) -> Result<Self, DiagnosticError> {
        let data = fs::read(dir.as_ref().join(STATE_FILE))?;
        Ok(serde_json::from_slice(&data)?)
    }

    pub fn save(&self, dir: impl AsRef<Path>) -> Result<(), DiagnosticError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        let temporary = dir.join("state.json.tmp");
        fs::write(&temporary, serde_json::to_vec_pretty(self)?)?;
        set_private(&temporary)?;
        fs::rename(temporary, dir.join(STATE_FILE))?;
        Ok(())
    }

    pub fn identity_path(dir: impl AsRef<Path>) -> PathBuf {
        dir.as_ref().join(IDENTITY_FILE)
    }
}

pub async fn register(
    state_dir: impl AsRef<Path>,
    server: String,
    server_key: [u8; 32],
    invite: &str,
    bind: SocketAddr,
    stun_servers: Vec<SocketAddr>,
) -> Result<PeerState, DiagnosticError> {
    let state_dir = state_dir.as_ref();
    let identity = Identity::load_or_generate(PeerState::identity_path(state_dir))?;
    let mut state = PeerState::new(server, server_key, bind, stun_servers);
    let peer = DiagnosticPeer::build(state.clone(), identity).await?;
    let mut client = peer.client;
    let candidates = peer.candidates.clone();
    state.candidates = candidates.clone();
    let registration = client
        .register(
            &peer.node.identity().clone(),
            Some(invite),
            None,
            candidates,
        )
        .await?;
    state.credential = Some(registration.credential);
    state.save(state_dir)?;
    Ok(state)
}

pub struct DiagnosticPeer {
    pub node: VelaNode,
    pub client: CoordinationClient,
    pub state: PeerState,
    candidates: Vec<Candidate>,
}

pub struct DiagnosticControl {
    pub client: CoordinationClient,
    pub state: PeerState,
    identity: Identity,
}

impl DiagnosticControl {
    pub async fn open(state_dir: impl AsRef<Path>) -> Result<Self, DiagnosticError> {
        let state_dir = state_dir.as_ref();
        let mut state = PeerState::load(state_dir)?;
        let identity = Identity::load(PeerState::identity_path(state_dir))?;
        let mut client = CoordinationClient::connect(&state.server).await?;
        client.trust_server_key(state.server_key);
        let registration = client
            .register(
                &identity,
                None,
                state.credential.as_ref(),
                state.candidates.clone(),
            )
            .await?;
        state.credential = Some(registration.credential);
        state.save(state_dir)?;
        Ok(Self {
            client,
            state,
            identity,
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.identity.public().node_id
    }

    pub async fn list_peers(&mut self) -> Result<Vec<PeerSummary>, DiagnosticError> {
        Ok(self.client.list_peers().await?)
    }

    pub async fn status(&mut self) -> Result<PeerStatus, DiagnosticError> {
        Ok(PeerStatus {
            node_id: self.node_id(),
            server: self.state.server.clone(),
            bind: self.state.bind,
            candidates: self.state.candidates.clone(),
            credential_expires_at: self
                .state
                .credential
                .as_ref()
                .map(|credential| credential.expires_at),
            peers: self.list_peers().await?,
        })
    }
}

impl DiagnosticPeer {
    pub async fn open(
        state_dir: impl AsRef<Path>,
        bind: Option<SocketAddr>,
        stun_servers: Option<Vec<SocketAddr>>,
    ) -> Result<Self, DiagnosticError> {
        let state_dir = state_dir.as_ref();
        let mut state = PeerState::load(state_dir)?;
        if let Some(bind) = bind {
            state.bind = bind;
        }
        if let Some(stun_servers) = stun_servers {
            state.stun_servers = stun_servers;
        }
        let identity = Identity::load(PeerState::identity_path(state_dir))?;
        let peer = Self::build(state.clone(), identity).await?;
        let mut client = peer.client;
        let registration = client
            .register(
                peer.node.identity(),
                None,
                state.credential.as_ref(),
                peer.candidates.clone(),
            )
            .await?;
        state.credential = Some(registration.credential);
        state.candidates = peer.candidates.clone();
        state.save(state_dir)?;
        for info in registration.peers {
            peer.node.register_peer(info).await?;
        }
        Ok(Self {
            node: peer.node,
            client,
            state,
            candidates: peer.candidates,
        })
    }

    async fn build(state: PeerState, identity: Identity) -> Result<Self, DiagnosticError> {
        let provider = Arc::new(TokioDatagramProvider::new(Vec::new()));
        let node = VelaNode::builder()
            .identity(identity)
            .datagram_provider(provider)
            .config(NodeConfig {
                bind: BindOptions {
                    local_addr: state.bind,
                },
                ..NodeConfig::default()
            })
            .build()
            .await?;

        let local_addr = node.local_addr()?;
        let mut candidates = if state.bind.ip().is_unspecified() {
            Vec::new()
        } else {
            vec![Candidate::Host(SocketAddr::new(
                state.bind.ip(),
                local_addr.port(),
            ))]
        };
        if !state.stun_servers.is_empty() {
            let stun = node
                .gather_server_reflexive_candidates(&vela_stun::StunConfig {
                    servers: state.stun_servers.clone(),
                    ..vela_stun::StunConfig::default()
                })
                .await?;
            candidates.extend(stun);
        }
        node.start().await?;
        let mut client = CoordinationClient::connect(&state.server).await?;
        client.trust_server_key(state.server_key);
        Ok(Self {
            node,
            client,
            state,
            candidates,
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.node.node_id()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, DiagnosticError> {
        Ok(self.node.local_addr()?)
    }

    pub fn candidates(&self) -> &[Candidate] {
        &self.candidates
    }

    pub async fn list_peers(&mut self) -> Result<Vec<PeerSummary>, DiagnosticError> {
        Ok(self.client.list_peers().await?)
    }

    pub async fn status(&mut self) -> Result<PeerStatus, DiagnosticError> {
        Ok(PeerStatus {
            node_id: self.node_id(),
            server: self.state.server.clone(),
            bind: self.state.bind,
            candidates: self.candidates.clone(),
            credential_expires_at: self
                .state
                .credential
                .as_ref()
                .map(|credential| credential.expires_at),
            peers: self.list_peers().await?,
        })
    }

    pub async fn refresh_candidates(&mut self) -> Result<(), DiagnosticError> {
        self.client
            .update_candidates(self.candidates.clone())
            .await?;
        Ok(())
    }

    pub async fn ping(
        &mut self,
        target: NodeId,
        count: usize,
        timeout: Duration,
    ) -> Result<PingReport, DiagnosticError> {
        let peer = self.client.lookup_peer(target).await?;
        self.node.register_peer(peer.clone()).await?;
        let connect_started = Instant::now();
        let handle = self.node.connect(target).await?;
        let connect_ms = connect_started.elapsed().as_millis();
        let local_addr = self.node.local_addr()?;
        let result = handle.diagnostic_ping(count, timeout).await?;
        Ok(PingReport::from_result(
            target, peer, connect_ms, local_addr, result,
        ))
    }

    pub async fn run(mut self) -> Result<(), DiagnosticError> {
        let mut refresh = interval(DEFAULT_REFRESH_INTERVAL);
        loop {
            tokio::select! {
                message = self.client.recv() => match message? {
                    ControlMessage::ConnectSignal { from, to } if to == self.node_id() => {
                        let peer = self.client.verify_public_peer(from)?;
                        self.node.register_peer(peer).await?;
                    }
                    ControlMessage::Revoke { node_id } if node_id == self.node_id() => {
                        return Err(DiagnosticError::Revoked);
                    }
                    _ => {}
                },
                _ = refresh.tick() => self.refresh_candidates().await?,
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerStatus {
    pub node_id: NodeId,
    pub server: String,
    pub bind: SocketAddr,
    pub candidates: Vec<Candidate>,
    pub credential_expires_at: Option<u64>,
    pub peers: Vec<PeerSummary>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PingReport {
    pub target: NodeId,
    pub direct: bool,
    pub local_addr: SocketAddr,
    pub path: SocketAddr,
    pub candidate_type: String,
    pub connect_ms: u128,
    pub rtts_ms: Vec<u128>,
    pub min_rtt_ms: u128,
    pub max_rtt_ms: u128,
    pub avg_rtt_ms: u128,
}

impl PingReport {
    fn from_result(
        target: NodeId,
        peer: PeerInfo,
        connect_ms: u128,
        local_addr: SocketAddr,
        result: DiagnosticPingResult,
    ) -> Self {
        let rtts_ms = result
            .rtts
            .iter()
            .map(Duration::as_millis)
            .collect::<Vec<_>>();
        let min_rtt_ms = rtts_ms.iter().copied().min().unwrap_or_default();
        let max_rtt_ms = rtts_ms.iter().copied().max().unwrap_or_default();
        let avg_rtt_ms = rtts_ms.iter().sum::<u128>() / rtts_ms.len() as u128;
        let candidate_type = peer
            .candidates
            .iter()
            .find(|candidate| candidate.address() == result.path)
            .map(|candidate| match candidate {
                Candidate::Host(_) => "host",
                Candidate::ServerReflexive(_) => "server_reflexive",
                Candidate::PeerReflexive(_) => "peer_reflexive",
            })
            .unwrap_or("observed")
            .to_owned();
        Self {
            target,
            direct: true,
            local_addr,
            path: result.path,
            candidate_type,
            connect_ms,
            rtts_ms,
            min_rtt_ms,
            max_rtt_ms,
            avg_rtt_ms,
        }
    }
}

#[derive(Debug, Error)]
pub enum DiagnosticError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("state serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("identity/credential error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("coordination error: {0}")]
    Coordination(#[from] CoordClientError),
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    #[error("direct connection error: {0}")]
    Connect(#[from] ConnectError),
    #[error("diagnostic ping error: {0}")]
    Ping(#[from] DiagnosticPingError),
    #[error("peer registration was revoked")]
    Revoked,
}

fn set_private(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
