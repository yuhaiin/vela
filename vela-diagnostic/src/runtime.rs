use crate::{
    DiagnosticError, DiagnosticPeer, PeerStatus, PingReport,
    local_control::{ControlEndpoint, LocalControlServer},
};
use bytes::Bytes;
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Notify, RwLock, Semaphore, mpsc, oneshot, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, interval},
};
use tracing::{debug, info, warn};
use vela_core::{NodeConfig, SendError, VelaEvent, VelaNode};
use vela_proto::{NetworkSnapshot, NodeId, PeerInfo, PeerSummary};

pub const MAX_PING_COUNT: usize = 32;
pub const MIN_PING_TIMEOUT: Duration = Duration::from_millis(100);
pub const MAX_PING_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONCURRENT_PINGS: usize = 8;
const COMMAND_QUEUE_CAPACITY: usize = 256;
// Absorb short TUN writer bursts without making the control loop wait. The
// queue remains bounded; sustained pressure is still visible in the drop
// counter instead of growing memory without limit.
const PACKET_QUEUE_CAPACITY: usize = 4096;

pub(crate) struct RuntimeStore {
    snapshot: RwLock<RuntimeSnapshot>,
}

struct RuntimeSnapshot {
    status: PeerStatus,
    peers: Vec<PeerSummary>,
    dashboard: crate::DashboardSnapshot,
}

impl RuntimeStore {
    async fn new(peer: &DiagnosticPeer, peers: Vec<PeerSummary>) -> Self {
        let status = peer.status_snapshot(&peers);
        let dashboard = peer.dashboard_snapshot(true, &peers, None).await;
        Self {
            snapshot: RwLock::new(RuntimeSnapshot {
                status,
                peers,
                dashboard,
            }),
        }
    }

    pub(crate) async fn update(
        &self,
        status: PeerStatus,
        peers: Vec<PeerSummary>,
        dashboard: crate::DashboardSnapshot,
    ) {
        *self.snapshot.write().await = RuntimeSnapshot {
            status,
            peers,
            dashboard,
        };
    }

    pub(crate) async fn status(&self) -> PeerStatus {
        self.snapshot.read().await.status.clone()
    }

    pub(crate) async fn peers(&self) -> Vec<PeerSummary> {
        self.snapshot.read().await.peers.clone()
    }

    pub(crate) async fn dashboard(&self) -> crate::DashboardSnapshot {
        self.snapshot.read().await.dashboard.clone()
    }
}

pub(crate) enum RuntimeCommand {
    SnapshotExpired,
    Ping {
        target: NodeId,
        count: usize,
        timeout: Duration,
        reply: oneshot::Sender<Result<PingReport, DiagnosticError>>,
    },
}

#[derive(Clone)]
pub struct RuntimeHandle {
    node_id: NodeId,
    node: VelaNode,
    commands: mpsc::Sender<RuntimeCommand>,
    snapshot_expired_notified: Arc<AtomicBool>,
    endpoint: ControlEndpoint,
    stop: Arc<Notify>,
}

impl RuntimeHandle {
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn endpoint(&self) -> &ControlEndpoint {
        &self.endpoint
    }

    pub async fn send_ip(&self, packet: impl Into<Bytes>) -> Result<(), SendError> {
        let result = self.node.send_ip(packet).await;
        if matches!(result, Err(SendError::SnapshotExpired)) {
            if !self.snapshot_expired_notified.swap(true, Ordering::AcqRel)
                && self
                    .commands
                    .try_send(RuntimeCommand::SnapshotExpired)
                    .is_err()
            {
                self.snapshot_expired_notified
                    .store(false, Ordering::Release);
            }
        } else if result.is_ok() {
            self.snapshot_expired_notified
                .store(false, Ordering::Release);
        }
        result
    }

    pub async fn send_ip_batch(&self, packets: &[Bytes]) -> Vec<Result<(), SendError>> {
        let results = self.node.send_ip_batch(packets).await;
        for result in &results {
            if matches!(result, Err(SendError::SnapshotExpired)) {
                if !self.snapshot_expired_notified.swap(true, Ordering::AcqRel)
                    && self
                        .commands
                        .try_send(RuntimeCommand::SnapshotExpired)
                        .is_err()
                {
                    self.snapshot_expired_notified
                        .store(false, Ordering::Release);
                }
            } else if result.is_ok() {
                self.snapshot_expired_notified
                    .store(false, Ordering::Release);
            }
        }
        results
    }

    pub fn stop(&self) {
        self.stop.notify_one();
    }
}

pub struct RuntimeIo {
    pub packets: mpsc::Receiver<(NodeId, vela_ip::IpPacket)>,
    pub snapshots: watch::Receiver<Option<NetworkSnapshot>>,
}

pub struct RuntimeProcess {
    pub handle: RuntimeHandle,
    pub io: RuntimeIo,
    pub task: JoinHandle<Result<(), DiagnosticError>>,
}

pub struct DiagnosticRuntime {
    peer: DiagnosticPeer,
    store: Arc<RuntimeStore>,
    commands: mpsc::Receiver<RuntimeCommand>,
    packet_tx: mpsc::Sender<(NodeId, vela_ip::IpPacket)>,
    snapshot_tx: watch::Sender<Option<NetworkSnapshot>>,
    ping_limit: Arc<Semaphore>,
    connections: JoinSet<()>,
    pings: JoinSet<()>,
    control: Option<LocalControlServer>,
    stop: Arc<Notify>,
    snapshot_expired_notified: Arc<AtomicBool>,
    tun_packet_queue_drops: Arc<AtomicU64>,
}

impl DiagnosticRuntime {
    pub async fn open(
        state_dir: impl AsRef<Path>,
        port: Option<u16>,
        stun_servers: Option<Vec<String>>,
        dashboard_bind: SocketAddr,
    ) -> Result<RuntimeProcess, DiagnosticError> {
        Self::open_with_mtu(
            state_dir,
            port,
            stun_servers,
            dashboard_bind,
            NodeConfig::default().virtual_mtu,
        )
        .await
    }

    pub async fn open_with_mtu(
        state_dir: impl AsRef<Path>,
        port: Option<u16>,
        stun_servers: Option<Vec<String>>,
        dashboard_bind: SocketAddr,
        virtual_mtu: usize,
    ) -> Result<RuntimeProcess, DiagnosticError> {
        let state_dir = state_dir.as_ref();
        let lock = crate::local_control::StateLock::acquire(state_dir)?;
        let peer =
            DiagnosticPeer::open_with_mtu(state_dir, port, stun_servers, virtual_mtu).await?;
        Self::start_with_lock(peer, dashboard_bind, lock).await
    }

    pub async fn start(
        peer: DiagnosticPeer,
        dashboard_bind: SocketAddr,
    ) -> Result<RuntimeProcess, DiagnosticError> {
        let lock = crate::local_control::StateLock::acquire(&peer.state_dir)?;
        Self::start_with_lock(peer, dashboard_bind, lock).await
    }

    async fn start_with_lock(
        peer: DiagnosticPeer,
        dashboard_bind: SocketAddr,
        lock: crate::local_control::StateLock,
    ) -> Result<RuntimeProcess, DiagnosticError> {
        let mut peer = peer;
        let summaries = match peer.list_peers().await {
            Ok(summaries) => summaries,
            Err(error) => {
                peer.node.shutdown().await;
                return Err(error);
            }
        };
        let store = Arc::new(RuntimeStore::new(&peer, summaries).await);
        let (commands, command_rx) = mpsc::channel(COMMAND_QUEUE_CAPACITY);
        let (packet_tx, packet_rx) = mpsc::channel(PACKET_QUEUE_CAPACITY);
        let tun_packet_queue_drops = Arc::new(AtomicU64::new(0));
        let snapshot_expired_notified = Arc::new(AtomicBool::new(false));
        let (snapshot_tx, snapshot_rx) = watch::channel(peer.state.snapshot.clone());
        let stop = Arc::new(Notify::new());
        let control = match LocalControlServer::start_with_lock(
            &peer.state_dir,
            peer.node_id(),
            peer.node.incarnation(),
            Arc::clone(&store),
            commands.clone(),
            dashboard_bind,
            lock,
        )
        .await
        {
            Ok(control) => control,
            Err(error) => {
                peer.node.shutdown().await;
                return Err(error);
            }
        };
        let endpoint = control.endpoint().clone();
        let handle = RuntimeHandle {
            node_id: peer.node_id(),
            node: peer.node.clone(),
            commands: commands.clone(),
            snapshot_expired_notified: Arc::clone(&snapshot_expired_notified),
            endpoint,
            stop: Arc::clone(&stop),
        };
        let task_runtime = Self {
            peer,
            store,
            commands: command_rx,
            packet_tx,
            snapshot_tx,
            ping_limit: Arc::new(Semaphore::new(MAX_CONCURRENT_PINGS)),
            connections: JoinSet::new(),
            pings: JoinSet::new(),
            control: Some(control),
            stop,
            snapshot_expired_notified,
            tun_packet_queue_drops,
        };
        let task = tokio::spawn(task_runtime.run());
        Ok(RuntimeProcess {
            handle,
            io: RuntimeIo {
                packets: packet_rx,
                snapshots: snapshot_rx,
            },
            task,
        })
    }

    async fn run(mut self) -> Result<(), DiagnosticError> {
        let result = self.run_loop().await;
        self.connections.shutdown().await;
        self.pings.shutdown().await;
        self.peer.node.shutdown().await;
        if let Some(control) = self.control.take() {
            control.shutdown().await;
        }
        result
    }

    async fn run_loop(&mut self) -> Result<(), DiagnosticError> {
        let mut refresh = interval(crate::CANDIDATE_REFRESH_INTERVAL);
        refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut dashboard_refresh = interval(Duration::from_secs(1));
        dashboard_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut dashboard_peer_refresh = interval(Duration::from_secs(5));
        dashboard_peer_refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut control_connected = true;
        let mut dashboard_error = None;
        let mut pending_reconnects = HashSet::new();
        let mut dashboard_peers = self.peer.list_peers().await?;
        self.publish_state(control_connected, &dashboard_peers, None)
            .await;
        let mut reconnect_backoff = Duration::from_secs(1);
        let mut reconnect_sleep = Box::pin(tokio::time::sleep(Duration::ZERO));
        let mut event_batch = Vec::with_capacity(64);

        loop {
            tokio::select! {
                _ = self.stop.notified() => {
                    return Ok(());
                }
                command = self.commands.recv() => {
                    match command {
                        Some(RuntimeCommand::SnapshotExpired) => {
                            if control_connected
                                && self.snapshot_expired_notified.load(Ordering::Acquire)
                            {
                                control_connected = false;
                                dashboard_error = Some("network snapshot has expired".to_owned());
                                reconnect_sleep.as_mut().reset(
                                    tokio::time::Instant::now() + reconnect_backoff,
                                );
                            }
                        }
                        Some(RuntimeCommand::Ping { target, count, timeout, reply }) => {
                            self.start_ping(target, count, timeout, reply).await;
                        }
                        None => return Ok(()),
                    }
                }
                Some(result) = self.connections.join_next(), if !self.connections.is_empty() => {
                    if let Err(error) = result {
                        warn!(error = %error, "peer connection task failed");
                    }
                }
                Some(result) = self.pings.join_next(), if !self.pings.is_empty() => {
                    if let Err(error) = result {
                        warn!(error = %error, "diagnostic ping task failed");
                    }
                }
                message = self.peer.client.recv(), if control_connected => {
                    match message {
                        Ok(vela_proto::ControlMessage::ConnectSignal { from, to }) if to == self.peer.node_id() => {
                            let remote = self.peer.client.verify_public_peer(from)?;
                            let peer_id = remote.node_id;
                            self.peer.node.register_peer(remote).await?;
                            let node = self.peer.node.clone();
                            self.connections.spawn(async move {
                                if let Err(error) = node.connect(peer_id).await {
                                    warn!(peer_id = %peer_id, error = %error, "peer connection triggered by coordination signal failed");
                                }
                            });
                        }
                        Ok(vela_proto::ControlMessage::Snapshot { snapshot }) => {
                            let changed = self.peer.apply_snapshot(snapshot.clone()).await?;
                            self.snapshot_tx.send_replace(Some(snapshot));
                            self.snapshot_expired_notified
                                .store(false, Ordering::Release);
                            if changed {
                                self.refresh_after_config_change(
                                    &mut control_connected,
                                    &mut dashboard_error,
                                    &mut reconnect_sleep,
                                    reconnect_backoff,
                                ).await?;
                            }
                        }
                        Ok(vela_proto::ControlMessage::Revoke { node_id }) if node_id == self.peer.node_id() => {
                            return Err(DiagnosticError::Revoked);
                        }
                        Ok(_) => {}
                        Err(error) => {
                            let error = DiagnosticError::Coordination(error);
                            if !DiagnosticPeer::is_retryable_control_error(&error) {
                                return Err(error);
                            }
                            dashboard_error = Some(error.to_string());
                            control_connected = false;
                            reconnect_sleep.as_mut().reset(
                                tokio::time::Instant::now() + reconnect_backoff,
                            );
                        }
                    }
                }
                _ = refresh.tick(), if control_connected => {
                    if let Err(error) = self.peer.refresh_candidates().await {
                        if !DiagnosticPeer::is_retryable_control_error(&error) {
                            return Err(error);
                        }
                        dashboard_error = Some(error.to_string());
                        control_connected = false;
                        reconnect_sleep.as_mut().reset(
                            tokio::time::Instant::now() + reconnect_backoff,
                        );
                    }
                }
                _ = &mut reconnect_sleep, if !control_connected => {
                    match self.peer.reconnect().await {
                        Ok(snapshot) => {
                            self.snapshot_tx.send_replace(Some(snapshot));
                            self.snapshot_expired_notified
                                .store(false, Ordering::Release);
                            control_connected = true;
                            dashboard_error = None;
                            reconnect_backoff = Duration::from_secs(1);
                            while let Some(peer_id) = pending_reconnects.iter().next().copied() {
                                if let Err(error) = self.peer.request_peer_connection(peer_id).await {
                                    if !DiagnosticPeer::is_retryable_control_error(&error) {
                                        return Err(error);
                                    }
                                    dashboard_error = Some(error.to_string());
                                    control_connected = false;
                                    reconnect_sleep.as_mut().reset(
                                        tokio::time::Instant::now() + reconnect_backoff,
                                    );
                                    break;
                                }
                                pending_reconnects.remove(&peer_id);
                            }
                        }
                        Err(error) if DiagnosticPeer::is_retryable_control_error(&error) => {
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
                            reconnect_backoff = reconnect_backoff.saturating_mul(2).min(Duration::from_secs(30));
                        }
                        Err(error) => return Err(error),
                    }
                }
                _ = dashboard_refresh.tick() => {
                    self.publish_state(control_connected, &dashboard_peers, dashboard_error.clone()).await;
                }
                _ = dashboard_peer_refresh.tick(), if control_connected => {
                    match self.peer.list_peers().await {
                        Ok(peers) => {
                            dashboard_peers = peers;
                            dashboard_error = None;
                        }
                        Err(error) if DiagnosticPeer::is_retryable_control_error(&error) => {
                            dashboard_error = Some(error.to_string());
                            control_connected = false;
                            reconnect_sleep.as_mut().reset(
                                tokio::time::Instant::now() + reconnect_backoff,
                            );
                        }
                        Err(error) => return Err(error),
                    }
                }
                received = self.peer.node.next_event_batch(&mut event_batch, 64) => {
                    if received == 0 {
                        return Err(DiagnosticError::TransportFailed {
                            family: None,
                            error: "Vela node stopped".to_owned(),
                        });
                    }
                    let mut publish_state = false;
                    for event in event_batch.drain(..) {
                        publish_state |= match event {
                            VelaEvent::IpPacket { peer, packet } => {
                                match self.packet_tx.try_send((peer, packet)) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        self.tun_packet_queue_drops
                                            .fetch_add(1, Ordering::Relaxed);
                                        // Keep consuming core events when the TUN-facing
                                        // queue is full. Dropping an IP packet is safer
                                        // than blocking probes, handshakes and keepalives;
                                        // TCP will retransmit it and UDP is lossy already.
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        return Err(DiagnosticError::ServiceUnavailable);
                                    }
                                }
                                false
                            }
                            VelaEvent::PeerConnectionRequested(peer_id)
                            | VelaEvent::PeerReconnectRequested(peer_id) => {
                                if !control_connected {
                                    pending_reconnects.insert(peer_id);
                                    false
                                } else {
                                    if let Err(error) =
                                        self.peer.request_peer_connection(peer_id).await
                                    {
                                        if !DiagnosticPeer::is_retryable_control_error(&error) {
                                            return Err(error);
                                        }
                                        pending_reconnects.insert(peer_id);
                                        dashboard_error = Some(error.to_string());
                                        control_connected = false;
                                        reconnect_sleep.as_mut().reset(
                                            tokio::time::Instant::now() + reconnect_backoff,
                                        );
                                    }
                                    true
                                }
                            }
                            VelaEvent::PeerConnecting(peer_id) => {
                                debug!(peer_id = %peer_id, "peer session connecting");
                                true
                            }
                            VelaEvent::PeerConnected(peer_id) => {
                                info!(peer_id = %peer_id, "peer session connected");
                                true
                            }
                            VelaEvent::PeerDisconnected(peer_id) => {
                                warn!(peer_id = %peer_id, "peer session disconnected");
                                true
                            }
                            VelaEvent::PeerUnreachable(peer_id) => {
                                warn!(peer_id = %peer_id, "peer is unreachable");
                                true
                            }
                            VelaEvent::PathChanged(peer_id, path) => {
                                info!(peer_id = %peer_id, path = %path, "peer path changed");
                                true
                            }
                            VelaEvent::TransportFailed { family, error } => {
                                return Err(DiagnosticError::TransportFailed { family, error });
                            }
                        };
                    }
                    if publish_state {
                        self.publish_state(
                            control_connected,
                            &dashboard_peers,
                            dashboard_error.clone(),
                        )
                        .await;
                    }
                }
            }
        }
    }

    async fn start_ping(
        &mut self,
        target: NodeId,
        count: usize,
        timeout: Duration,
        reply: oneshot::Sender<Result<PingReport, DiagnosticError>>,
    ) {
        if let Err(error) = validate_ping(count, timeout) {
            let _ = reply.send(Err(error));
            return;
        }
        let Some(peer) = self
            .peer
            .state
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.peers.iter().find(|peer| peer.node_id == target))
            .cloned()
        else {
            let _ = reply.send(Err(DiagnosticError::InvalidPingRequest(
                "target peer is not present in the active snapshot".to_owned(),
            )));
            return;
        };
        if let Err(error) = self.peer.node.register_peer(peer.clone()).await {
            let _ = reply.send(Err(error.into()));
            return;
        }
        let node = self.peer.node.clone();
        let limit = Arc::clone(&self.ping_limit);
        self.pings.spawn(async move {
            let result = async {
                let _permit = limit
                    .acquire_owned()
                    .await
                    .map_err(|_| DiagnosticError::ServiceUnavailable)?;
                ping_peer(node, peer, count, timeout).await
            }
            .await;
            let _ = reply.send(result);
        });
    }

    async fn refresh_after_config_change(
        &mut self,
        control_connected: &mut bool,
        dashboard_error: &mut Option<String>,
        reconnect_sleep: &mut std::pin::Pin<Box<tokio::time::Sleep>>,
        reconnect_backoff: Duration,
    ) -> Result<(), DiagnosticError> {
        if let Err(error) = self.peer.refresh_candidates().await {
            if !DiagnosticPeer::is_retryable_control_error(&error) {
                return Err(error);
            }
            *dashboard_error = Some(error.to_string());
            *control_connected = false;
            reconnect_sleep
                .as_mut()
                .reset(tokio::time::Instant::now() + reconnect_backoff);
        }
        Ok(())
    }

    async fn publish_state(
        &self,
        control_connected: bool,
        peers: &[PeerSummary],
        error: Option<String>,
    ) {
        let status = self.peer.status_snapshot(peers);
        let mut dashboard = self
            .peer
            .dashboard_snapshot(control_connected, peers, error)
            .await;
        dashboard.tun_packet_queue_drops = self.tun_packet_queue_drops.load(Ordering::Relaxed);
        self.store.update(status, peers.to_vec(), dashboard).await;
    }
}

async fn ping_peer(
    node: VelaNode,
    peer: PeerInfo,
    count: usize,
    timeout: Duration,
) -> Result<PingReport, DiagnosticError> {
    let target = peer.node_id;
    let connect_started = Instant::now();
    let handle = node.connect(target).await?;
    let connect_ms = connect_started.elapsed().as_millis();
    let local_addrs = node.local_addrs()?;
    let result = handle.diagnostic_ping(count, timeout).await?;
    Ok(PingReport::from_result(
        target,
        peer,
        connect_ms,
        local_addrs,
        result,
    ))
}

fn validate_ping(count: usize, timeout: Duration) -> Result<(), DiagnosticError> {
    if !(1..=MAX_PING_COUNT).contains(&count) {
        return Err(DiagnosticError::InvalidPingRequest(format!(
            "count must be between 1 and {MAX_PING_COUNT}"
        )));
    }
    if !(MIN_PING_TIMEOUT..=MAX_PING_TIMEOUT).contains(&timeout) {
        return Err(DiagnosticError::InvalidPingRequest(format!(
            "timeout must be between {MIN_PING_TIMEOUT:?} and {MAX_PING_TIMEOUT:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_limits_are_bounded() {
        assert!(validate_ping(1, MIN_PING_TIMEOUT).is_ok());
        assert!(validate_ping(MAX_PING_COUNT, MAX_PING_TIMEOUT).is_ok());
        assert!(validate_ping(0, MIN_PING_TIMEOUT).is_err());
        assert!(validate_ping(MAX_PING_COUNT + 1, MIN_PING_TIMEOUT).is_err());
        assert!(validate_ping(1, MIN_PING_TIMEOUT - Duration::from_millis(1)).is_err());
        assert!(validate_ping(1, MAX_PING_TIMEOUT + Duration::from_millis(1)).is_err());
    }
}
