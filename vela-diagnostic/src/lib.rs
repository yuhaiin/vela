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
use tracing::{debug, warn};
use vela_coord_client::{CoordClientError, CoordinationClient};
use vela_core::{
    AddressFamily, BindOptions, ConnectError, CoreError, DiagnosticPingError, DiagnosticPingResult,
    NodeConfig, TokioDatagramProvider, VelaEvent, VelaNode,
};
use vela_crypto::{CryptoError, Identity, MembershipCredential};
use vela_proto::{Candidate, ControlMessage, NetworkSnapshot, NodeId, PeerInfo, PeerSummary};

const STATE_FILE: &str = "state.json";
const IDENTITY_FILE: &str = "identity";
pub const CANDIDATE_REFRESH_INTERVAL: Duration = Duration::from_secs(20);

fn default_doh_servers() -> Vec<String> {
    vela_stun::default_doh_servers()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerState {
    pub server: String,
    #[serde(with = "vela_proto::base64_32_serde")]
    pub server_key: [u8; 32],
    pub credential: Option<MembershipCredential>,
    #[serde(default)]
    pub last_local_addrs: Vec<SocketAddr>,
    #[serde(default = "default_doh_servers")]
    pub doh_servers: Vec<String>,
    pub stun_servers: Vec<String>,
    #[serde(default)]
    pub manual_stun_servers: Vec<String>,
    pub candidates: Vec<Candidate>,
    pub snapshot: Option<NetworkSnapshot>,
}

impl PeerState {
    pub fn new(server: String, server_key: [u8; 32], stun_servers: Vec<String>) -> Self {
        Self {
            server,
            server_key,
            credential: None,
            last_local_addrs: Vec::new(),
            doh_servers: default_doh_servers(),
            stun_servers: stun_servers.clone(),
            manual_stun_servers: stun_servers,
            candidates: Vec::new(),
            snapshot: None,
        }
    }

    pub fn load(dir: impl AsRef<Path>) -> Result<Self, DiagnosticError> {
        let data = fs::read(dir.as_ref().join(STATE_FILE))?;
        let mut value: serde_json::Value = serde_json::from_slice(&data)?;
        if is_legacy_snapshot(&value) {
            if let Some(state) = value.as_object_mut() {
                // The persisted snapshot is only a cache. Its old signature
                // and peer schema must not be treated as an authoritative
                // network view after a protocol upgrade.
                state.insert("snapshot".to_owned(), serde_json::Value::Null);
            }
        }
        Ok(serde_json::from_value(value)?)
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

fn is_legacy_snapshot(state: &serde_json::Value) -> bool {
    let Some(snapshot) = state.get("snapshot").and_then(serde_json::Value::as_object) else {
        return false;
    };
    snapshot.get("online_peers").is_none()
        || snapshot
            .get("peers")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|peers| peers.iter().any(|peer| peer.get("incarnation").is_none()))
}

pub async fn register(
    state_dir: impl AsRef<Path>,
    server: String,
    server_key: [u8; 32],
    invite: &str,
    port: u16,
    stun_servers: Vec<String>,
) -> Result<PeerState, DiagnosticError> {
    let state_dir = state_dir.as_ref();
    let identity = Identity::load_or_generate(PeerState::identity_path(state_dir))?;
    let mut peer = DiagnosticPeer::build(
        PeerState::new(server, server_key, stun_servers.clone()),
        identity,
        state_dir,
        stun_servers,
        port,
        None,
    )
    .await?;
    let candidates = peer.candidates.clone();
    let registration = peer
        .client
        .register_with_incarnation(
            peer.node.identity(),
            peer.node.incarnation(),
            Some(invite),
            None,
            candidates.clone(),
        )
        .await?;
    peer.state.credential = Some(registration.credential);
    peer.state.candidates = candidates;
    peer.apply_snapshot(registration.snapshot).await?;
    peer.refresh_candidates().await?;
    peer.state.last_local_addrs = peer.node.local_addrs()?;
    peer.state.save(state_dir)?;
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
            local_addrs: self.state.last_local_addrs.clone(),
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
        port: Option<u16>,
        stun_servers: Option<Vec<String>>,
    ) -> Result<Self, DiagnosticError> {
        let state_dir = state_dir.as_ref();
        let mut state = PeerState::load(state_dir)?;
        // Keep an explicitly configured local STUN endpoint across restarts;
        // coordinator endpoints are merged into it when a snapshot arrives.
        let manual_stun_servers = stun_servers.unwrap_or_else(|| state.manual_stun_servers.clone());
        if !manual_stun_servers.is_empty() {
            state.manual_stun_servers = manual_stun_servers.clone();
            state.stun_servers = manual_stun_servers.clone();
        }
        let identity = Identity::load(PeerState::identity_path(state_dir))?;
        let (port, preferred_ports) = match port {
            Some(port) => (port, None),
            None => (0, preferred_local_ports(&state.last_local_addrs)),
        };
        let mut peer = Self::build(
            state,
            identity,
            state_dir,
            manual_stun_servers,
            port,
            preferred_ports,
        )
        .await?;
        let registration = peer
            .client
            .register_with_incarnation(
                peer.node.identity(),
                peer.node.incarnation(),
                None,
                peer.state.credential.as_ref(),
                peer.candidates.clone(),
            )
            .await?;
        peer.state.credential = Some(registration.credential);
        peer.state.candidates = peer.candidates.clone();
        peer.apply_snapshot(registration.snapshot).await?;
        peer.refresh_candidates().await?;
        peer.state.last_local_addrs = peer.node.local_addrs()?;
        peer.node.start().await?;
        peer.state.save(state_dir)?;
        Ok(peer)
    }

    async fn build(
        state: PeerState,
        identity: Identity,
        state_dir: impl AsRef<Path>,
        manual_stun_servers: Vec<String>,
        port: u16,
        preferred_ports: Option<[Option<u16>; 2]>,
    ) -> Result<Self, DiagnosticError> {
        let provider = match preferred_ports {
            Some(preferred_ports) => Arc::new(TokioDatagramProvider::with_preferred_ports(
                Vec::new(),
                preferred_ports,
            )),
            None => Arc::new(TokioDatagramProvider::new(Vec::new())),
        };
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
                bind: BindOptions { port },
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

    pub fn local_addrs(&self) -> Result<Vec<SocketAddr>, DiagnosticError> {
        Ok(self.node.local_addrs()?)
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
            local_addrs: self.node.local_addrs()?,
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
        let unchanged = candidates == self.candidates;
        if unchanged {
            debug!(
                debug_marker = "vela-candidates",
                candidate_count = candidates.len(),
                "candidate refresh produced no changes"
            );
        }
        debug!(
            debug_marker = "vela-candidates",
            candidates = ?candidates,
            "uploading refreshed local candidates"
        );
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
        debug!(
            debug_marker = "vela-control",
            candidate_count = candidates.len(),
            "reconnecting coordination client"
        );
        let registration = self
            .client
            .reconnect(
                self.node.identity(),
                self.node.incarnation(),
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
        debug!(
            debug_marker = "vela-control",
            generation = snapshot.generation,
            "coordination client restored"
        );
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
        debug!(
            debug_marker = "vela-candidates",
            host_candidate_count = candidates.len(),
            stun_server_count = self.state.stun_servers.len(),
            "collecting local host and STUN candidates"
        );
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
                Ok(stun_candidates) => {
                    debug!(
                        debug_marker = "vela-stun",
                        candidate_count = stun_candidates.len(),
                        "STUN candidate collection completed"
                    );
                    candidates.extend(stun_candidates)
                }
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
        debug!(
            debug_marker = "vela-candidates",
            candidates = ?candidates,
            "candidate collection completed"
        );
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
        let local_addrs = self.node.local_addrs()?;
        let result = handle.diagnostic_ping(count, timeout).await?;
        Ok(PingReport::from_result(
            target,
            peer,
            connect_ms,
            local_addrs,
            result,
        ))
    }

    pub async fn run(mut self) -> Result<(), DiagnosticError> {
        let mut refresh = interval(CANDIDATE_REFRESH_INTERVAL);
        let mut control_connected = true;
        let mut reconnect_backoff = Duration::from_secs(1);
        let mut reconnect_sleep = Box::pin(tokio::time::sleep(Duration::ZERO));
        loop {
            tokio::select! {
                message = self.client.recv(), if control_connected => {
                    match message {
                        Ok(ControlMessage::ConnectSignal { from, to }) if to == self.node_id() => {
                            debug!(
                                debug_marker = "vela-control",
                                from = %from.node_id,
                                "received peer connect signal"
                            );
                            let peer = self.client.verify_public_peer(from)?;
                            self.node.register_peer(peer).await?;
                        }
                        Ok(ControlMessage::Snapshot { snapshot }) => {
                            debug!(
                                debug_marker = "vela-control",
                                generation = snapshot.generation,
                                peer_count = snapshot.peers.len(),
                                "received network snapshot"
                            );
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
                            warn!(
                                debug_marker = "vela-control",
                                error = %error,
                                "coordination connection lost; retrying"
                            );
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
                    debug!(debug_marker = "vela-control", "starting coordination reconnect");
                    match self.reconnect().await {
                        Ok(_) => {
                            debug!(debug_marker = "vela-control", "coordination reconnect succeeded");
                            control_connected = true;
                            reconnect_backoff = Duration::from_secs(1);
                        }
                        Err(error) if Self::is_retryable_control_error(&error) => {
                            warn!(
                                debug_marker = "vela-control",
                                error = %error,
                                backoff = ?reconnect_backoff,
                                "coordination reconnect failed"
                            );
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
                event = self.node.next_event() => {
                    match event {
                        Some(VelaEvent::TransportFailed { family, error }) => {
                            return Err(DiagnosticError::TransportFailed { family, error });
                        }
                        Some(_) => {}
                        None => return Err(DiagnosticError::TransportFailed {
                            family: None,
                            error: "Vela node stopped".to_owned(),
                        }),
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
    pub local_addrs: Vec<SocketAddr>,
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
    pub local_addrs: Vec<SocketAddr>,
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
        local_addrs: Vec<SocketAddr>,
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
            local_addrs,
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
    #[error("UDP transport failed ({family:?}): {error}")]
    TransportFailed {
        family: Option<AddressFamily>,
        error: String,
    },
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

fn preferred_local_ports(local_addrs: &[SocketAddr]) -> Option<[Option<u16>; 2]> {
    let ports = [
        local_addrs
            .iter()
            .find(|address| address.is_ipv4() && address.port() != 0)
            .map(SocketAddr::port),
        local_addrs
            .iter()
            .find(|address| address.is_ipv6() && address.port() != 0)
            .map(SocketAddr::port),
    ];
    (ports != [None, None]).then_some(ports)
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
    fn legacy_bind_state_is_ignored_and_ports_start_empty() {
        let state: PeerState = serde_json::from_value(serde_json::json!({
            "server": "ws://127.0.0.1/ws",
            "server_key": vec![0u8; 32],
            "credential": null,
            "bind": "0.0.0.0:4567",
            "stun_servers": [],
            "candidates": [],
            "snapshot": null,
        }))
        .unwrap();
        assert!(state.last_local_addrs.is_empty());
    }

    #[test]
    fn legacy_snapshot_is_discarded_during_state_load() {
        let directory = std::env::temp_dir().join(format!(
            "vela-diagnostic-legacy-state-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join(STATE_FILE),
            serde_json::to_vec(&serde_json::json!({
                "server": "ws://127.0.0.1/ws",
                "server_key": vec![0u8; 32],
                "credential": null,
                "last_local_addrs": [],
                "doh_servers": [],
                "stun_servers": [],
                "manual_stun_servers": [],
                "candidates": [],
                "snapshot": {
                    "network_id": vec![0u8; 16],
                    "generation": 1,
                    "virtual_ipv4": null,
                    "virtual_ipv6": null,
                    "doh_servers": [],
                    "stun_servers": [],
                    "peers": [{
                        "node_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "signing_public": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "noise_public": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                        "candidates": [],
                        "virtual_ipv4": null,
                        "virtual_ipv6": null,
                        "credential": "",
                        "capabilities": []
                    }],
                    "expires_at": 1,
                    "signature": []
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let state = PeerState::load(&directory).unwrap();
        assert!(state.snapshot.is_none());

        let _ = fs::remove_file(directory.join(STATE_FILE));
        let _ = fs::remove_dir(directory);
    }

    #[test]
    fn preferred_ports_are_derived_per_address_family() {
        let local_addrs = vec![
            "0.0.0.0:40123".parse().unwrap(),
            "[::]:40124".parse().unwrap(),
        ];
        assert_eq!(
            preferred_local_ports(&local_addrs),
            Some([Some(40123), Some(40124)])
        );
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
