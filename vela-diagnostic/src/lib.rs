//! A thin, test-focused peer module built on top of Vela's direct transport.
//!
//! This crate owns the diagnostic peer lifecycle and result contract. It does
//! not implement a relay or a business data plane.

use axum::{Json, Router, extract::State, response::Html, routing::get};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{net::TcpListener, sync::RwLock, time::interval};
use tracing::{debug, warn};
use vela_coord_client::{CoordClientError, CoordinationClient};
use vela_core::{
    AddressFamily, BindOptions, ConnectError, CoreError, DatagramProvider, DiagnosticPingError,
    DiagnosticPingResult, NodeConfig, PeerRuntimeStatus, TokioDatagramProvider,
    TransportReceiveStats, VelaEvent, VelaNode,
};
use vela_crypto::{CryptoError, Identity, MembershipCredential};
use vela_proto::{Candidate, ControlMessage, NetworkSnapshot, NodeId, PeerInfo, PeerSummary};

mod local_control;
mod runtime;

pub use local_control::LocalControlClient;
pub use runtime::{
    DiagnosticRuntime, MAX_PING_COUNT, MAX_PING_TIMEOUT, MIN_PING_TIMEOUT, RuntimeHandle,
    RuntimeProcess,
};

const STATE_FILE: &str = "state.json";
const IDENTITY_FILE: &str = "identity";
pub const CANDIDATE_REFRESH_INTERVAL: Duration = Duration::from_secs(20);
const DASHBOARD_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const DASHBOARD_PEER_REFRESH_INTERVAL: Duration = Duration::from_secs(5);

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashboardCoordinatorStatus {
    pub connected: bool,
    pub checked_at: u64,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashboardPeer {
    pub node_id: NodeId,
    pub name: String,
    pub coordinator_online: bool,
    pub coordinator_last_seen_at: Option<u64>,
    pub virtual_ipv4: Option<std::net::Ipv4Addr>,
    pub virtual_ipv6: Option<std::net::Ipv6Addr>,
    pub capabilities: Vec<vela_proto::PeerCapability>,
    pub last_status_at: Option<u64>,
    pub direct: PeerRuntimeStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    pub generated_at: u64,
    pub node_id: NodeId,
    pub server: String,
    pub coordinator: DashboardCoordinatorStatus,
    pub local_udp_addresses: Vec<SocketAddr>,
    pub published_candidates: Vec<Candidate>,
    pub snapshot_generation: Option<u64>,
    pub snapshot_expires_at: Option<u64>,
    pub credential_expires_at: Option<u64>,
    pub transport_receive: TransportReceiveStats,
    pub tun_packet_queue_drops: u64,
    pub peers: Vec<DashboardPeer>,
}

struct DashboardStore {
    snapshot: RwLock<DashboardSnapshot>,
}

impl DashboardStore {
    fn new(snapshot: DashboardSnapshot) -> Self {
        Self {
            snapshot: RwLock::new(snapshot),
        }
    }
}

#[derive(Clone)]
pub struct DashboardHandle {
    store: Arc<DashboardStore>,
}

impl DashboardHandle {
    pub async fn serve(&self, bind: SocketAddr) -> Result<(), DiagnosticError> {
        let listener = TcpListener::bind(bind).await?;
        let app = Router::new()
            .route("/", get(dashboard_page))
            .route("/api/v1/dashboard", get(dashboard_data))
            .with_state(Arc::clone(&self.store));
        axum::serve(listener, app)
            .await
            .map_err(DiagnosticError::Io)
    }
}

async fn dashboard_page() -> Html<&'static str> {
    Html(include_str!("dashboard.html"))
}

async fn dashboard_data(State(state): State<Arc<DashboardStore>>) -> Json<DashboardSnapshot> {
    Json(state.snapshot.read().await.clone())
}

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
        NodeConfig::default().virtual_mtu,
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
        Self::open_with_mtu(
            state_dir,
            port,
            stun_servers,
            NodeConfig::default().virtual_mtu,
        )
        .await
    }

    pub async fn open_with_mtu(
        state_dir: impl AsRef<Path>,
        port: Option<u16>,
        stun_servers: Option<Vec<String>>,
        virtual_mtu: usize,
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
            virtual_mtu,
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
        if let Err(error) = peer.state.save(state_dir) {
            peer.node.shutdown().await;
            return Err(error);
        }
        Ok(peer)
    }

    async fn build(
        state: PeerState,
        identity: Identity,
        state_dir: impl AsRef<Path>,
        manual_stun_servers: Vec<String>,
        port: u16,
        preferred_ports: Option<[Option<u16>; 2]>,
        virtual_mtu: usize,
    ) -> Result<Self, DiagnosticError> {
        let provider = match preferred_ports {
            Some(preferred_ports) => Arc::new(TokioDatagramProvider::with_preferred_ports(
                Vec::new(),
                preferred_ports,
            )),
            None => Arc::new(TokioDatagramProvider::new(Vec::new())),
        };
        Self::build_with_provider(
            state,
            identity,
            state_dir,
            manual_stun_servers,
            port,
            provider,
            virtual_mtu,
        )
        .await
    }

    async fn build_with_provider(
        state: PeerState,
        identity: Identity,
        state_dir: impl AsRef<Path>,
        manual_stun_servers: Vec<String>,
        port: u16,
        provider: Arc<dyn DatagramProvider>,
        virtual_mtu: usize,
    ) -> Result<Self, DiagnosticError> {
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
                max_payload_size: virtual_mtu,
                network_id: state
                    .snapshot
                    .as_ref()
                    .map_or([0; 16], |snapshot| snapshot.network_id),
                server_public_key: Some(state.server_key),
                virtual_ipv4: local.and_then(|peer| peer.virtual_ipv4),
                virtual_ipv6: local.and_then(|peer| peer.virtual_ipv6),
                virtual_mtu,
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
        let peers = self.list_peers().await?;
        Ok(self.status_snapshot(&peers))
    }

    pub(crate) fn status_snapshot(&self, peers: &[PeerSummary]) -> PeerStatus {
        PeerStatus {
            node_id: self.node_id(),
            server: self.state.server.clone(),
            local_addrs: self.node.local_addrs().unwrap_or_default(),
            doh_servers: self.state.doh_servers.clone(),
            stun_servers: self.state.stun_servers.clone(),
            candidates: self.candidates.clone(),
            credential_expires_at: self
                .state
                .credential
                .as_ref()
                .map(|credential| credential.expires_at),
            peers: peers.to_vec(),
        }
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
        let snapshot = self
            .client
            .update_candidates_and_get_snapshot(candidates.clone())
            .await?;
        self.apply_snapshot(snapshot).await?;
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
        // Candidate refresh applies the coordinator's newest snapshot. Return
        // that snapshot to the runtime so its TUN route watcher does not
        // briefly regress to the older snapshot carried by RegisterOk.
        let snapshot = self.state.snapshot.clone().unwrap_or(snapshot);
        self.state.save(&self.state_dir)?;
        debug!(
            debug_marker = "vela-control",
            generation = snapshot.generation,
            "coordination client restored"
        );
        Ok(snapshot)
    }

    /// Ask the coordinator to notify the remote peer to start its own direct
    /// connection attempt. The lookup response is intentionally ignored by
    /// callers that already have the peer state; the coordinator's lookup
    /// side effect is the bilateral probe signal.
    pub async fn request_peer_connection(
        &mut self,
        peer_id: NodeId,
    ) -> Result<(), DiagnosticError> {
        self.client.lookup_peer(peer_id).await.map(|_| ())?;
        Ok(())
    }

    pub fn is_retryable_control_error(error: &DiagnosticError) -> bool {
        matches!(
            error,
            DiagnosticError::Coordination(
                CoordClientError::WebSocket(_)
                    | CoordClientError::Closed
                    | CoordClientError::Timeout(_)
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

    pub async fn run(self) -> Result<(), DiagnosticError> {
        self.run_loop(None).await
    }

    pub async fn open_dashboard(&mut self) -> Result<DashboardHandle, DiagnosticError> {
        let summaries = self.list_peers().await?;
        Ok(DashboardHandle {
            store: Arc::new(DashboardStore::new(
                self.dashboard_snapshot(true, &summaries, None).await,
            )),
        })
    }

    /// Runs the peer together with a loopback-only read-only dashboard.
    pub async fn run_with_dashboard(self, bind: SocketAddr) -> Result<(), DiagnosticError> {
        let mut peer = self;
        let dashboard = peer.open_dashboard().await?;
        let server = dashboard.serve(bind);
        tokio::select! {
            result = peer.run_loop(Some(dashboard.clone())) => result,
            result = server => result,
        }
    }

    pub(crate) async fn dashboard_snapshot(
        &self,
        coordinator_connected: bool,
        summaries: &[PeerSummary],
        last_error: Option<String>,
    ) -> DashboardSnapshot {
        let runtime = self.node.peer_statuses().await;
        let summary_by_id = summaries
            .iter()
            .map(|summary| (summary.node_id, summary))
            .collect::<HashMap<_, _>>();
        let peers = runtime
            .into_iter()
            .map(|direct| {
                let summary = summary_by_id.get(&direct.node_id).copied();
                let last_status_at = [
                    summary.and_then(|summary| summary.last_seen),
                    direct.connected_at,
                    direct.path_changed_at,
                    direct.attempt.as_ref().map(|attempt| attempt.started_at),
                    direct
                        .last_failure
                        .as_ref()
                        .map(|failure| failure.occurred_at),
                ]
                .into_iter()
                .flatten()
                .max();
                DashboardPeer {
                    node_id: direct.node_id,
                    name: summary.map_or_else(String::new, |summary| summary.name.clone()),
                    coordinator_online: summary.is_some_and(|summary| summary.online),
                    coordinator_last_seen_at: summary.and_then(|summary| summary.last_seen),
                    virtual_ipv4: direct.virtual_ipv4,
                    virtual_ipv6: direct.virtual_ipv6,
                    capabilities: direct.capabilities.clone(),
                    last_status_at,
                    direct,
                }
            })
            .collect();
        DashboardSnapshot {
            generated_at: unix_time(),
            node_id: self.node_id(),
            server: self.state.server.clone(),
            coordinator: DashboardCoordinatorStatus {
                connected: coordinator_connected,
                checked_at: unix_time(),
                last_error,
            },
            local_udp_addresses: self.node.local_addrs().unwrap_or_default(),
            published_candidates: self.candidates.clone(),
            snapshot_generation: self
                .state
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.generation),
            snapshot_expires_at: self
                .state
                .snapshot
                .as_ref()
                .map(|snapshot| snapshot.expires_at),
            credential_expires_at: self
                .state
                .credential
                .as_ref()
                .map(|credential| credential.expires_at),
            transport_receive: self.node.transport_receive_stats(),
            tun_packet_queue_drops: 0,
            peers,
        }
    }

    pub async fn publish_dashboard(
        &self,
        dashboard: &DashboardHandle,
        coordinator_connected: bool,
        summaries: &[PeerSummary],
        last_error: Option<String>,
    ) {
        *dashboard.store.snapshot.write().await = self
            .dashboard_snapshot(coordinator_connected, summaries, last_error)
            .await;
    }

    async fn run_loop(mut self, dashboard: Option<DashboardHandle>) -> Result<(), DiagnosticError> {
        let mut refresh = interval(CANDIDATE_REFRESH_INTERVAL);
        let mut dashboard_refresh = interval(DASHBOARD_REFRESH_INTERVAL);
        let mut dashboard_peer_refresh = interval(DASHBOARD_PEER_REFRESH_INTERVAL);
        let mut control_connected = true;
        let mut dashboard_error = None;
        let mut pending_reconnects = HashSet::new();
        let mut dashboard_peers = if dashboard.is_some() {
            self.list_peers().await?
        } else {
            Vec::new()
        };
        if let Some(store) = dashboard.as_ref() {
            self.publish_dashboard(store, true, &dashboard_peers, None)
                .await;
        }
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
                            let peer_id = peer.node_id;
                            self.node.register_peer(peer).await?;
                            let node = self.node.clone();
                            tokio::spawn(async move {
                                if let Err(error) = node.connect(peer_id).await {
                                    warn!(
                                        debug_marker = "vela-session",
                                        peer_id = %peer_id,
                                        error = %error,
                                        "peer connection triggered by coordination signal failed"
                                    );
                                }
                            });
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
                                    dashboard_error = Some(error.to_string());
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
                            dashboard_error = Some(error.to_string());
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
                        dashboard_error = Some(error.to_string());
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
                            dashboard_error = None;
                            reconnect_backoff = Duration::from_secs(1);
                            let pending = std::mem::take(&mut pending_reconnects);
                            for peer_id in pending {
                                if let Err(error) = self.request_peer_connection(peer_id).await {
                                    if !Self::is_retryable_control_error(&error) {
                                        return Err(error);
                                    }
                                    pending_reconnects.insert(peer_id);
                                    dashboard_error = Some(error.to_string());
                                    warn!(
                                        debug_marker = "vela-control",
                                        peer_id = %peer_id,
                                        error = %error,
                                        "failed to flush bilateral reconnect signal"
                                    );
                                    control_connected = false;
                                    reconnect_sleep.as_mut().reset(
                                        tokio::time::Instant::now() + reconnect_backoff,
                                    );
                                    break;
                                }
                            }
                        }
                        Err(error) if Self::is_retryable_control_error(&error) => {
                            dashboard_error = Some(error.to_string());
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
                _ = dashboard_refresh.tick(), if dashboard.is_some() => {
                    if let Some(store) = dashboard.as_ref() {
                        self.publish_dashboard(
                            store,
                            control_connected,
                            &dashboard_peers,
                            dashboard_error.clone(),
                        ).await;
                    }
                }
                _ = dashboard_peer_refresh.tick(), if dashboard.is_some() && control_connected => {
                    match self.list_peers().await {
                        Ok(peers) => {
                            dashboard_peers = peers;
                            dashboard_error = None;
                        }
                        Err(error) if Self::is_retryable_control_error(&error) => {
                            dashboard_error = Some(error.to_string());
                            control_connected = false;
                            reconnect_sleep.as_mut().reset(
                                tokio::time::Instant::now() + reconnect_backoff,
                            );
                        }
                        Err(error) => return Err(error),
                    }
                }
                event = self.node.next_event() => {
                    match event {
                        Some(VelaEvent::TransportFailed { family, error }) => {
                            return Err(DiagnosticError::TransportFailed { family, error });
                        }
                        Some(
                            VelaEvent::PeerConnectionRequested(peer_id)
                            | VelaEvent::PeerReconnectRequested(peer_id),
                        ) => {
                            if !control_connected {
                                pending_reconnects.insert(peer_id);
                                continue;
                            }
                            if let Err(error) = self.request_peer_connection(peer_id).await {
                                if !Self::is_retryable_control_error(&error) {
                                    return Err(error);
                                }
                                pending_reconnects.insert(peer_id);
                                dashboard_error = Some(error.to_string());
                                warn!(
                                    debug_marker = "vela-control",
                                    peer_id = %peer_id,
                                    error = %error,
                                    "failed to signal peer for bilateral connection; retrying coordination"
                                );
                                control_connected = false;
                                reconnect_sleep.as_mut().reset(
                                    tokio::time::Instant::now() + reconnect_backoff,
                                );
                            }
                        }
                        Some(_) => {}
                        None => return Err(DiagnosticError::TransportFailed {
                            family: None,
                            error: "Vela node stopped".to_owned(),
                        }),
                    }
                    if let Some(store) = dashboard.as_ref() {
                        self.publish_dashboard(
                            store,
                            control_connected,
                            &dashboard_peers,
                            dashboard_error.clone(),
                        ).await;
                    }
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
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
    #[error("a peer service is already running for this state directory")]
    AlreadyRunning,
    #[error("peer service is not running for this state directory")]
    ServiceUnavailable,
    #[error("local control protocol error: {0}")]
    ControlProtocol(String),
    #[error("local control service rejected request: {code}: {message}")]
    ControlRequest { code: String, message: String },
    #[error("ping request is outside the supported range: {0}")]
    InvalidPingRequest(String),
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

pub(crate) fn set_private(_path: &Path) -> Result<(), std::io::Error> {
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
    use async_trait::async_trait;
    use std::{net::Ipv4Addr, sync::Mutex as StdMutex};
    use tokio::net::TcpListener;
    use vela_coord::CoordServer;
    use vela_core::DatagramSocket;
    use vela_proto::{PacketType, WirePacket};

    struct RecordingProvider {
        inner: TokioDatagramProvider,
        sent_probes: Arc<StdMutex<Vec<SocketAddr>>>,
    }

    struct RecordingSocket {
        inner: Arc<dyn DatagramSocket>,
        sent_probes: Arc<StdMutex<Vec<SocketAddr>>>,
    }

    impl RecordingProvider {
        fn new(address: SocketAddr, sent_probes: Arc<StdMutex<Vec<SocketAddr>>>) -> Self {
            Self {
                inner: TokioDatagramProvider::new(vec![Candidate::Host(address)]),
                sent_probes,
            }
        }
    }

    #[async_trait]
    impl DatagramProvider for RecordingProvider {
        async fn bind(&self, options: BindOptions) -> Result<Arc<dyn DatagramSocket>, CoreError> {
            let inner = self.inner.bind(options).await?;
            Ok(Arc::new(RecordingSocket {
                inner,
                sent_probes: Arc::clone(&self.sent_probes),
            }))
        }

        fn local_candidates(&self) -> Vec<Candidate> {
            self.inner.local_candidates()
        }
    }

    #[async_trait]
    impl DatagramSocket for RecordingSocket {
        async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> std::io::Result<usize> {
            if WirePacket::decode(bytes)
                .ok()
                .is_some_and(|packet| packet.header.packet_type == PacketType::Probe)
            {
                self.sent_probes
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(target);
            }
            self.inner.send_to(bytes, target).await
        }

        async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            self.inner.recv_from(buffer).await
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        fn local_addrs(&self) -> std::io::Result<Vec<SocketAddr>> {
            self.inner.local_addrs()
        }

        async fn shutdown(&self) {
            self.inner.shutdown().await;
        }

        fn failure_family(&self) -> Option<AddressFamily> {
            self.inner.failure_family()
        }
    }

    async fn build_registered_peer(
        state_dir: &Path,
        server: &str,
        server_key: [u8; 32],
        invite: &str,
        identity: Identity,
        address: SocketAddr,
        sent_probes: Arc<StdMutex<Vec<SocketAddr>>>,
    ) -> DiagnosticPeer {
        let mut peer = DiagnosticPeer::build_with_provider(
            PeerState::new(server.to_owned(), server_key, Vec::new()),
            identity.clone(),
            state_dir,
            Vec::new(),
            address.port(),
            Arc::new(RecordingProvider::new(address, sent_probes)),
            NodeConfig::default().virtual_mtu,
        )
        .await
        .unwrap();
        let registration = peer
            .client
            .register_with_incarnation(
                peer.node.identity(),
                peer.node.incarnation(),
                Some(invite),
                None,
                peer.candidates.clone(),
            )
            .await
            .unwrap();
        peer.state.credential = Some(registration.credential);
        peer.state.candidates = peer.candidates.clone();
        peer.apply_snapshot(registration.snapshot).await.unwrap();
        peer.node.start().await.unwrap();
        peer
    }

    fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        let mut checksum = 0u32;
        for chunk in packet.chunks(2) {
            checksum = checksum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
            while checksum > u32::from(u16::MAX) {
                checksum = (checksum & u32::from(u16::MAX)) + (checksum >> 16);
            }
        }
        packet[10..12].copy_from_slice(&(!(checksum as u16)).to_be_bytes());
        packet
    }

    #[tokio::test]
    async fn coordination_signal_establishes_peer_when_incoming_probe_wins() {
        let base = std::env::temp_dir().join(format!(
            "vela-diagnostic-bilateral-probe-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let db = base.with_extension("db");
        let signer = base.with_extension("key");
        let state_a = base.with_extension("a");
        let state_b = base.with_extension("b");
        let server = CoordServer::open(&db, &signer, "integration").unwrap();
        let invite_a = server.create_invite(60).unwrap();
        let invite_b = server.create_invite(60).unwrap();
        let server_key = server.server_public_key();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_address = listener.local_addr().unwrap();
        let server_task = tokio::spawn(async move { server.serve(listener).await.unwrap() });
        tokio::time::sleep(Duration::from_millis(20)).await;

        let address_a = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let address_b = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let sent_a = Arc::new(StdMutex::new(Vec::new()));
        let sent_b = Arc::new(StdMutex::new(Vec::new()));
        let server_url = format!("ws://{server_address}/ws");
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let peer_a = build_registered_peer(
            &state_a,
            &server_url,
            server_key,
            &invite_a,
            identity_a,
            address_a,
            Arc::clone(&sent_a),
        )
        .await;
        let peer_b = build_registered_peer(
            &state_b,
            &server_url,
            server_key,
            &invite_b,
            identity_b,
            address_b,
            Arc::clone(&sent_b),
        )
        .await;
        let peer = peer_b
            .state
            .snapshot
            .as_ref()
            .unwrap()
            .peers
            .iter()
            .find(|peer| peer.node_id == peer_b.node_id())
            .cloned()
            .unwrap();
        let node_b = peer_b.node.clone();
        let peer_b_id = peer_b.node_id();
        let peer_b_task = tokio::spawn(async move { peer_b.run().await });
        peer_a.node.register_peer(peer).await.unwrap();
        let source = peer_a
            .state
            .snapshot
            .as_ref()
            .unwrap()
            .peers
            .iter()
            .find(|peer| peer.node_id == peer_a.node_id())
            .and_then(|peer| peer.virtual_ipv4)
            .unwrap();
        let destination = peer_a
            .node
            .peer_statuses()
            .await
            .into_iter()
            .find(|status| status.node_id == peer_b_id)
            .and_then(|status| status.virtual_ipv4)
            .unwrap();
        peer_a
            .node
            .send_ip(ipv4_packet(source, destination))
            .await
            .unwrap();
        let node_a = peer_a.node.clone();
        let peer_a_task = tokio::spawn(async move { peer_a.run().await });
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let a_sent = sent_a
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .contains(&address_b);
                let b_connected =
                    node_b.peer_statuses().await.into_iter().any(|status| {
                        matches!(status.state, vela_core::PeerRuntimeState::Connected)
                    });
                if a_sent && b_connected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            sent_a
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&address_b)
        );
        assert!(
            node_b
                .peer_statuses()
                .await
                .into_iter()
                .any(|status| matches!(status.state, vela_core::PeerRuntimeState::Connected))
        );

        peer_a_task.abort();
        node_b.shutdown().await;
        node_a.shutdown().await;
        peer_b_task.abort();
        server_task.abort();
        let _ = std::fs::remove_dir_all(&state_a);
        let _ = std::fs::remove_dir_all(&state_b);
        let _ = std::fs::remove_file(db);
        let _ = std::fs::remove_file(signer);
    }

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
