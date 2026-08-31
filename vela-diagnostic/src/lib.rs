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
use tracing::warn;
use vela_coord_client::{CoordClientError, CoordinationClient};
use vela_core::{
    BindOptions, ConnectError, CoreError, DiagnosticPingError, DiagnosticPingResult, NodeConfig,
    TokioDatagramProvider, VelaNode,
};
use vela_crypto::{CryptoError, Identity, MembershipCredential};
use vela_proto::{Candidate, ControlMessage, NetworkSnapshot, NodeId, PeerInfo, PeerSummary};

const STATE_FILE: &str = "state.json";
const IDENTITY_FILE: &str = "identity";
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

fn effective_bind(bind: Option<SocketAddr>) -> SocketAddr {
    // The default bind is runtime policy, not a persisted peer setting. Keep
    // old state files from silently forcing a peer back to IPv4-only mode.
    bind.unwrap_or_else(|| BindOptions::default().local_addr)
}

fn default_doh_servers() -> Vec<String> {
    vela_stun::default_doh_servers()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerState {
    pub server: String,
    pub server_key: [u8; 32],
    pub credential: Option<MembershipCredential>,
    pub bind: SocketAddr,
    #[serde(default = "default_doh_servers")]
    pub doh_servers: Vec<String>,
    pub stun_servers: Vec<String>,
    #[serde(default)]
    pub manual_stun_servers: Vec<String>,
    pub candidates: Vec<Candidate>,
    pub snapshot: Option<NetworkSnapshot>,
}

impl PeerState {
    pub fn new(
        server: String,
        server_key: [u8; 32],
        bind: SocketAddr,
        stun_servers: Vec<String>,
    ) -> Self {
        Self {
            server,
            server_key,
            credential: None,
            bind,
            doh_servers: default_doh_servers(),
            stun_servers: stun_servers.clone(),
            manual_stun_servers: stun_servers,
            candidates: Vec::new(),
            snapshot: None,
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
    stun_servers: Vec<String>,
) -> Result<PeerState, DiagnosticError> {
    let state_dir = state_dir.as_ref();
    let identity = Identity::load_or_generate(PeerState::identity_path(state_dir))?;
    let mut peer = DiagnosticPeer::build(
        PeerState::new(server, server_key, bind, stun_servers.clone()),
        identity,
        state_dir,
        stun_servers,
    )
    .await?;
    let candidates = peer.candidates.clone();
    let registration = peer
        .client
        .register(peer.node.identity(), Some(invite), None, candidates.clone())
        .await?;
    peer.state.credential = Some(registration.credential);
    peer.state.candidates = candidates;
    peer.apply_snapshot(registration.snapshot).await?;
    peer.refresh_candidates().await?;
    Ok(peer.state)
}

pub struct DiagnosticPeer {
    pub node: VelaNode,
    pub client: CoordinationClient,
    pub state: PeerState,
    candidates: Vec<Candidate>,
    state_dir: PathBuf,
    manual_stun_servers: Vec<String>,
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
        let mut client =
            CoordinationClient::connect_with_doh(&state.server, &state.doh_servers).await?;
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
        state.snapshot = Some(registration.snapshot.clone());
        state.doh_servers = effective_doh_servers(&registration.snapshot.doh_servers);
        state.stun_servers = merge_stun_servers(
            &state.manual_stun_servers,
            &registration.snapshot.stun_servers,
        );
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
            doh_servers: self.state.doh_servers.clone(),
            stun_servers: self.state.stun_servers.clone(),
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
        stun_servers: Option<Vec<String>>,
    ) -> Result<Self, DiagnosticError> {
        let state_dir = state_dir.as_ref();
        let mut state = PeerState::load(state_dir)?;
        state.bind = effective_bind(bind);
        // Keep an explicitly configured local STUN endpoint across restarts;
        // coordinator endpoints are merged into it when a snapshot arrives.
        let manual_stun_servers = stun_servers.unwrap_or_else(|| state.manual_stun_servers.clone());
        if !manual_stun_servers.is_empty() {
            state.manual_stun_servers = manual_stun_servers.clone();
            state.stun_servers = manual_stun_servers.clone();
        }
        let identity = Identity::load(PeerState::identity_path(state_dir))?;
        let mut peer = Self::build(state, identity, state_dir, manual_stun_servers).await?;
        let registration = peer
            .client
            .register(
                peer.node.identity(),
                None,
                peer.state.credential.as_ref(),
                peer.candidates.clone(),
            )
            .await?;
        peer.state.credential = Some(registration.credential);
        peer.state.candidates = peer.candidates.clone();
        peer.apply_snapshot(registration.snapshot).await?;
        peer.refresh_candidates().await?;
        peer.node.start().await?;
        peer.state.save(state_dir)?;
        Ok(peer)
    }

    async fn build(
        state: PeerState,
        identity: Identity,
        state_dir: impl AsRef<Path>,
        manual_stun_servers: Vec<String>,
    ) -> Result<Self, DiagnosticError> {
        let provider = Arc::new(TokioDatagramProvider::new(Vec::new()));
        let local = state.snapshot.as_ref().and_then(|snapshot| {
            snapshot
                .peers
                .iter()
                .find(|peer| peer.node_id == identity.public().node_id)
        });
        let node = VelaNode::builder()
            .identity(identity)
            .datagram_provider(provider)
            .config(NodeConfig {
                bind: BindOptions {
                    local_addr: state.bind,
                },
                network_id: state
                    .snapshot
                    .as_ref()
                    .map_or([0; 16], |snapshot| snapshot.network_id),
                server_public_key: Some(state.server_key),
                virtual_ipv4: local.and_then(|peer| peer.virtual_ipv4),
                virtual_ipv6: local.and_then(|peer| peer.virtual_ipv6),
                ..NodeConfig::default()
            })
            .build()
            .await?;

        let mut candidates = node.local_candidates();
        if !state.stun_servers.is_empty() {
            match node
                .gather_server_reflexive_candidates(&vela_stun::StunConfig {
                    servers: state.stun_servers.clone(),
                    doh_servers: state.doh_servers.clone(),
                    ..vela_stun::StunConfig::default()
                })
                .await
            {
                Ok(stun_candidates) => candidates.extend(stun_candidates),
                Err(error) if candidates.is_empty() => return Err(error.into()),
                Err(error) => {
                    warn!(error = %error, "initial STUN gathering failed; using host candidates");
                }
            }
        }
        let candidates = unique_candidates(candidates);
        if candidates.is_empty() {
            return Err(DiagnosticError::NoCandidates);
        }
        let mut client =
            CoordinationClient::connect_with_doh(&state.server, &state.doh_servers).await?;
        client.trust_server_key(state.server_key);
        Ok(Self {
            node,
            client,
            state,
            candidates,
            state_dir: state_dir.as_ref().to_path_buf(),
            manual_stun_servers,
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
            doh_servers: self.state.doh_servers.clone(),
            stun_servers: self.state.stun_servers.clone(),
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
        let candidates = match self.collect_candidates().await {
            Ok(candidates) => candidates,
            Err(error) if !self.candidates.is_empty() => {
                warn!(error = %error, "keeping the last known candidates after refresh failure");
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if candidates == self.candidates {
            return Ok(());
        }
        self.client.update_candidates(candidates.clone()).await?;
        self.candidates = candidates.clone();
        self.state.candidates = candidates;
        self.state.save(&self.state_dir)?;
        Ok(())
    }

    pub async fn reconnect(&mut self) -> Result<NetworkSnapshot, DiagnosticError> {
        let mut candidates = self.node.local_candidates();
        retain_server_reflexive_candidates(&mut candidates, &self.candidates);
        let candidates = unique_candidates(candidates);
        let registration = self
            .client
            .reconnect(
                self.node.identity(),
                self.state.credential.as_ref(),
                candidates.clone(),
                &self.state.doh_servers,
            )
            .await?;
        self.state.credential = Some(registration.credential);
        self.candidates = candidates.clone();
        self.state.candidates = candidates;
        let snapshot = registration.snapshot;
        self.apply_snapshot(snapshot.clone()).await?;
        // The snapshot may have changed the STUN server list while the
        // control connection was down. Refresh both address families before
        // advertising the reconnected peer as fully up to date.
        self.refresh_candidates().await?;
        self.state.save(&self.state_dir)?;
        Ok(snapshot)
    }

    pub fn is_retryable_control_error(error: &DiagnosticError) -> bool {
        matches!(
            error,
            DiagnosticError::Coordination(
                CoordClientError::WebSocket(_) | CoordClientError::Closed
            )
        )
    }

    pub async fn apply_snapshot(
        &mut self,
        snapshot: NetworkSnapshot,
    ) -> Result<bool, DiagnosticError> {
        let previous_doh_servers = self.state.doh_servers.clone();
        let previous_stun_servers = self.state.stun_servers.clone();
        self.node.apply_snapshot(snapshot.clone()).await?;
        self.state.doh_servers = effective_doh_servers(&snapshot.doh_servers);
        self.state.stun_servers =
            merge_stun_servers(&self.manual_stun_servers, &snapshot.stun_servers);
        self.state.snapshot = Some(snapshot);
        self.state.save(&self.state_dir)?;
        Ok(self.state.doh_servers != previous_doh_servers
            || self.state.stun_servers != previous_stun_servers)
    }

    async fn collect_candidates(&self) -> Result<Vec<Candidate>, DiagnosticError> {
        let mut candidates = self.node.local_candidates();
        if !self.state.stun_servers.is_empty() {
            match self
                .node
                .gather_server_reflexive_candidates(&vela_stun::StunConfig {
                    servers: self.state.stun_servers.clone(),
                    doh_servers: self.state.doh_servers.clone(),
                    ..vela_stun::StunConfig::default()
                })
                .await
            {
                Ok(stun_candidates) => candidates.extend(stun_candidates),
                Err(error) if candidates.is_empty() => return Err(error.into()),
                Err(error) => {
                    warn!(error = %error, "STUN refresh failed; using host and cached server-reflexive candidates");
                    retain_server_reflexive_candidates(&mut candidates, &self.candidates);
                }
            }
        }
        let candidates = unique_candidates(candidates);
        if candidates.is_empty() {
            return Err(DiagnosticError::NoCandidates);
        }
        Ok(candidates)
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
        let mut control_connected = true;
        let mut reconnect_backoff = Duration::from_secs(1);
        let mut reconnect_sleep = Box::pin(tokio::time::sleep(Duration::ZERO));
        loop {
            tokio::select! {
                message = self.client.recv(), if control_connected => {
                    match message {
                        Ok(ControlMessage::ConnectSignal { from, to }) if to == self.node_id() => {
                            let peer = self.client.verify_public_peer(from)?;
                            self.node.register_peer(peer).await?;
                        }
                        Ok(ControlMessage::Snapshot { snapshot }) => {
                            let refresh_candidates = self.apply_snapshot(snapshot).await?;
                            if refresh_candidates {
                                if let Err(error) = self.refresh_candidates().await {
                                    if !Self::is_retryable_control_error(&error) {
                                        return Err(error);
                                    }
                                    warn!(error = %error, "coordination refresh failed; retrying");
                                    control_connected = false;
                                    reconnect_sleep.as_mut().reset(
                                        tokio::time::Instant::now() + reconnect_backoff,
                                    );
                                }
                            }
                        }
                        Ok(ControlMessage::Revoke { node_id }) if node_id == self.node_id() => {
                            return Err(DiagnosticError::Revoked);
                        }
                        Ok(_) => {}
                        Err(error) => {
                            let error = DiagnosticError::Coordination(error);
                            if !Self::is_retryable_control_error(&error) {
                                return Err(error);
                            }
                            warn!(error = %error, "coordination connection lost; retrying");
                            control_connected = false;
                            reconnect_sleep.as_mut().reset(
                                tokio::time::Instant::now() + reconnect_backoff,
                            );
                        }
                    }
                }
                _ = refresh.tick(), if control_connected => {
                    if let Err(error) = self.refresh_candidates().await {
                        if !Self::is_retryable_control_error(&error) {
                            return Err(error);
                        }
                        warn!(error = %error, "coordination refresh failed; retrying");
                        control_connected = false;
                        reconnect_sleep.as_mut().reset(
                            tokio::time::Instant::now() + reconnect_backoff,
                        );
                    }
                }
                _ = &mut reconnect_sleep, if !control_connected => {
                    match self.reconnect().await {
                        Ok(_) => {
                            control_connected = true;
                            reconnect_backoff = Duration::from_secs(1);
                        }
                        Err(error) if Self::is_retryable_control_error(&error) => {
                            warn!(error = %error, backoff = ?reconnect_backoff, "coordination reconnect failed");
                            reconnect_sleep.as_mut().reset(
                                tokio::time::Instant::now() + reconnect_backoff,
                            );
                            reconnect_backoff = reconnect_backoff
                                .saturating_mul(2)
                                .min(Duration::from_secs(30));
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerStatus {
    pub node_id: NodeId,
    pub server: String,
    pub bind: SocketAddr,
    pub doh_servers: Vec<String>,
    pub stun_servers: Vec<String>,
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
    #[error("no usable local or server-reflexive candidates were found")]
    NoCandidates,
}

fn merge_stun_servers(local: &[String], remote: &[String]) -> Vec<String> {
    let mut servers = local.to_vec();
    for server in remote {
        if !servers.contains(server) {
            servers.push(server.clone());
        }
    }
    servers
}

fn effective_doh_servers(servers: &[String]) -> Vec<String> {
    if servers.is_empty() {
        default_doh_servers()
    } else {
        servers.to_vec()
    }
}

fn unique_candidates(candidates: Vec<Candidate>) -> Vec<Candidate> {
    let mut unique = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if !unique.contains(&candidate) {
            unique.push(candidate);
        }
    }
    unique
}

fn retain_server_reflexive_candidates(candidates: &mut Vec<Candidate>, previous: &[Candidate]) {
    for candidate in previous {
        if matches!(candidate, Candidate::ServerReflexive(_)) && !candidates.contains(candidate) {
            candidates.push(candidate.clone());
        }
    }
}

fn set_private(_path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(_path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_bind_ignores_persisted_ipv4_only_setting() {
        let persisted = "0.0.0.0:0".parse().unwrap();
        assert_eq!(effective_bind(None), "[::]:0".parse().unwrap());
        assert_eq!(effective_bind(Some(persisted)), persisted);
    }

    #[test]
    fn failed_stun_refresh_keeps_cached_server_reflexive_candidates() {
        let mut candidates = vec![Candidate::Host("192.0.2.10:40000".parse().unwrap())];
        let previous = vec![Candidate::ServerReflexive(
            "198.51.100.10:40000".parse().unwrap(),
        )];

        retain_server_reflexive_candidates(&mut candidates, &previous);

        assert_eq!(
            candidates,
            vec![
                Candidate::Host("192.0.2.10:40000".parse().unwrap()),
                Candidate::ServerReflexive("198.51.100.10:40000".parse().unwrap()),
            ]
        );
    }

    #[test]
    fn cached_server_reflexive_candidates_are_not_duplicated() {
        let cached = Candidate::ServerReflexive("198.51.100.10:40000".parse().unwrap());
        let mut candidates = vec![cached.clone()];

        retain_server_reflexive_candidates(&mut candidates, std::slice::from_ref(&cached));

        assert_eq!(candidates, vec![cached]);
    }
}
