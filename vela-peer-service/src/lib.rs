//! Owns the complete lifetime of a running Vela peer attached to a kernel TUN.
//!
//! Frontends start this service and request shutdown through [`PeerService`].
//! The service owns the TUN device, route leases, control runtime, packet
//! forwarding tasks, and reconnect supervisor, so those resources share one
//! cleanup boundary.

mod ffi;

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    sync::watch,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing::{info, warn};
use vela_crypto::MembershipCredential;
use vela_diagnostic::{
    ControlEndpoint, DashboardSnapshot, DiagnosticError, DiagnosticPeer, DiagnosticRuntime,
    PeerConfig, PeerSecrets, RuntimeProcess,
};
use vela_proto::{NetworkSnapshot, NodeId};
use vela_tun::{RouteLease, RouteManager, TunConfig, TunDevice, TunError};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_RESTART_DELAY: Duration = Duration::from_secs(1);
const MAX_RESTART_DELAY: Duration = Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct PeerServiceConfig {
    pub state_dir: PathBuf,
    pub port: Option<u16>,
    pub stun_servers: Option<Vec<String>>,
    pub dashboard_bind: SocketAddr,
    pub mtu: usize,
    pub tun_name: String,
}

/// Secret material remains owned by the app's secure store and is copied into
/// the helper only in memory when the service starts.
#[derive(Clone)]
pub struct PeerServiceMaterial {
    pub state_dir: PathBuf,
    pub peer: PeerConfig,
    pub secrets: PeerSecrets,
    pub port: Option<u16>,
    pub mtu: usize,
    pub tun_name: String,
}

#[derive(Clone)]
enum PeerServiceSource {
    State(PeerServiceConfig),
    Material(Box<PeerServiceMaterial>),
}

impl PeerServiceSource {
    fn mtu(&self) -> usize {
        match self {
            Self::State(config) => config.mtu,
            Self::Material(config) => config.mtu,
        }
    }

    fn tun_name(&self) -> &str {
        match self {
            Self::State(config) => &config.tun_name,
            Self::Material(config) => &config.tun_name,
        }
    }

    async fn open_runtime(&self) -> Result<RuntimeProcess, PeerServiceError> {
        match self {
            Self::State(config) => Ok(DiagnosticRuntime::open_with_mtu(
                &config.state_dir,
                config.port,
                config.stun_servers.clone(),
                config.dashboard_bind,
                config.mtu,
            )
            .await?),
            Self::Material(config) => {
                let peer = DiagnosticPeer::open_with_material(
                    config.peer.clone(),
                    config.secrets.clone(),
                    &config.state_dir,
                    config.port,
                    config.mtu,
                )
                .await?;
                Ok(DiagnosticRuntime::start_without_control(peer).await?)
            }
        }
    }
}

pub struct PeerService {
    node_id: NodeId,
    tun_name: String,
    endpoint: ControlEndpoint,
    credentials: watch::Receiver<Option<MembershipCredential>>,
    dashboard: watch::Receiver<DashboardSnapshot>,
    stop: watch::Sender<bool>,
    task: Option<JoinHandle<Result<(), PeerServiceError>>>,
}

#[derive(Default)]
struct TunNetworkState {
    route_leases: HashMap<IpAddr, RouteLease>,
    local_addresses: HashMap<IpAddr, u8>,
}

impl PeerService {
    /// Starts the Vela peer, creates its TUN, and applies the initial routes.
    ///
    /// The returned value owns the service lifetime. Calling [`Self::stop`],
    /// dropping the value, or closing its shutdown sender tears down packet
    /// forwarding, the peer runtime, and routes installed by this service.
    pub async fn start(config: PeerServiceConfig) -> Result<Self, PeerServiceError> {
        Self::start_source(PeerServiceSource::State(config)).await
    }

    /// Starts from app-owned settings and secrets without reading or writing
    /// private material in the state directory.
    pub async fn start_with_material(
        config: PeerServiceMaterial,
    ) -> Result<Self, PeerServiceError> {
        Self::start_source(PeerServiceSource::Material(Box::new(config))).await
    }

    async fn start_source(source: PeerServiceSource) -> Result<Self, PeerServiceError> {
        let mut process = source.open_runtime().await?;

        // The initial snapshot is applied below before the supervisor starts.
        // Mark it as observed so run_peer_once does not immediately apply the
        // same addresses and routes a second time when it first polls changed().
        let snapshot = process.io.snapshots.borrow_and_update().clone();
        let Some(snapshot) = snapshot else {
            stop_process(process).await;
            return Err(PeerServiceError::NoNetworkSnapshot);
        };

        let tun = match TunDevice::open(TunConfig {
            name: source.tun_name().to_owned(),
            mtu: source.mtu(),
        }) {
            Ok(tun) => tun,
            Err(error) => {
                stop_process(process).await;
                return Err(error.into());
            }
        };
        let tun_name = tun.name().to_owned();
        let routes = match RouteManager::for_tun(&tun).await {
            Ok(routes) => routes,
            Err(error) => {
                stop_process(process).await;
                return Err(error.into());
            }
        };
        let initial_mtu = source.mtu().min(vela_core::DEFAULT_VIRTUAL_MTU);
        if let Err(error) = routes.set_mtu(initial_mtu).await {
            stop_process(process).await;
            return Err(error.into());
        }

        let mut network = TunNetworkState::default();
        if let Err(error) =
            apply_tun_snapshot(process.handle.node_id(), &routes, &mut network, &snapshot).await
        {
            release_route_leases(&mut network.route_leases).await;
            stop_process(process).await;
            return Err(error);
        }

        let node_id = process.handle.node_id();
        let endpoint = process.handle.endpoint().clone();
        let credentials = process.io.credentials.clone();
        let dashboard = process.io.dashboard.clone();
        let (stop, stop_rx) = watch::channel(false);
        let task = tokio::spawn(run_peer_supervisor(
            process,
            tun,
            routes,
            network,
            source,
            credentials.clone(),
            stop_rx,
        ));

        Ok(Self {
            node_id,
            tun_name,
            endpoint,
            credentials,
            dashboard,
            stop,
            task: Some(task),
        })
    }

    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    pub fn tun_name(&self) -> &str {
        &self.tun_name
    }

    pub fn dashboard_url(&self) -> Option<String> {
        self.endpoint
            .address
            .map(|address| format!("http://{address}"))
    }

    /// Receives refreshed membership credentials so an app can persist them
    /// back to its secure credential store.
    pub fn credential_updates(&self) -> watch::Receiver<Option<MembershipCredential>> {
        self.credentials.clone()
    }

    pub fn dashboard_updates(&self) -> watch::Receiver<DashboardSnapshot> {
        self.dashboard.clone()
    }

    /// Requests shutdown and waits for route and peer cleanup to finish.
    pub async fn stop(mut self) -> Result<(), PeerServiceError> {
        self.stop.send_replace(true);
        self.wait().await
    }

    /// Waits until the service exits or reports a fatal peer error.
    pub async fn wait(&mut self) -> Result<(), PeerServiceError> {
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        // Awaiting a mutable JoinHandle by reference is cancellation-safe. A
        // caller may select between this future and status updates; canceling
        // that wait must leave the task available for a later wait or stop.
        let result = task.await;
        self.task.take();
        result.map_err(PeerServiceError::TaskJoin)?
    }
}

impl Drop for PeerService {
    fn drop(&mut self) {
        self.stop.send_replace(true);
    }
}

#[derive(Debug, Error)]
pub enum PeerServiceError {
    #[error(transparent)]
    Diagnostic(#[from] DiagnosticError),
    #[error(transparent)]
    Tun(#[from] TunError),
    #[error("peer state has no network snapshot; register first")]
    NoNetworkSnapshot,
    #[error("peer service task failed: {0}")]
    TaskJoin(#[source] tokio::task::JoinError),
    #[error("peer service stopped unexpectedly: {0}")]
    Runtime(String),
}

async fn run_peer_supervisor(
    mut process: RuntimeProcess,
    tun: TunDevice,
    routes: RouteManager,
    mut network: TunNetworkState,
    mut source: PeerServiceSource,
    credentials: watch::Receiver<Option<MembershipCredential>>,
    mut stop: watch::Receiver<bool>,
) -> Result<(), PeerServiceError> {
    let tun = Arc::new(tun);
    let mut restart_delay = DEFAULT_RESTART_DELAY;

    loop {
        match run_peer_once(process, Arc::clone(&tun), &routes, &mut network, &mut stop).await {
            Ok(()) => {
                release_route_leases(&mut network.route_leases).await;
                return Ok(());
            }
            Err(error) => {
                warn!(
                    debug_marker = "vela-lifecycle",
                    error = %error,
                    restart_delay = ?restart_delay,
                    "peer runtime stopped; restarting"
                );
            }
        }

        loop {
            if !wait_for_peer_restart(restart_delay, &mut stop).await {
                info!(debug_marker = "vela-lifecycle", "peer shutdown requested");
                release_route_leases(&mut network.route_leases).await;
                return Ok(());
            }

            if let PeerServiceSource::Material(config) = &mut source
                && let Some(credential) = credentials.borrow().clone()
            {
                config.secrets.credential = credential;
            }
            let next_process = match source.open_runtime().await {
                Ok(process) => process,
                Err(error) => {
                    warn!(
                        debug_marker = "vela-lifecycle",
                        error = %error,
                        "peer runtime restart failed"
                    );
                    restart_delay = next_restart_delay(restart_delay);
                    continue;
                }
            };
            let snapshot = next_process.io.snapshots.borrow().clone();
            let Some(snapshot) = snapshot else {
                stop_process(next_process).await;
                warn!(
                    debug_marker = "vela-lifecycle",
                    "peer runtime restart produced no network snapshot"
                );
                restart_delay = next_restart_delay(restart_delay);
                continue;
            };
            if let Err(error) = apply_tun_snapshot(
                next_process.handle.node_id(),
                &routes,
                &mut network,
                &snapshot,
            )
            .await
            {
                stop_process(next_process).await;
                warn!(
                    debug_marker = "vela-lifecycle",
                    error = %error,
                    "peer runtime restart snapshot could not be applied"
                );
                restart_delay = next_restart_delay(restart_delay);
                continue;
            }

            info!(debug_marker = "vela-lifecycle", "peer runtime restarted");
            process = next_process;
            restart_delay = DEFAULT_RESTART_DELAY;
            break;
        }
    }
}

fn next_restart_delay(delay: Duration) -> Duration {
    delay.saturating_mul(2).min(MAX_RESTART_DELAY)
}

async fn stop_process(process: RuntimeProcess) {
    process.handle.stop();
    let _ = process.task.await;
}

async fn release_route_leases(leases: &mut HashMap<IpAddr, RouteLease>) {
    let pending = std::mem::take(leases);
    if timeout(SHUTDOWN_TIMEOUT, async move {
        for lease in pending.into_values() {
            let _ = lease.release().await;
        }
    })
    .await
    .is_err()
    {
        warn!(
            timeout = ?SHUTDOWN_TIMEOUT,
            "timed out while releasing TUN routes during shutdown"
        );
    }
}

async fn wait_for_peer_restart(delay: Duration, stop: &mut watch::Receiver<bool>) -> bool {
    if *stop.borrow() {
        return false;
    }
    tokio::select! {
        _ = sleep(delay) => true,
        changed = stop.changed() => changed.is_ok() && !*stop.borrow(),
    }
}

async fn apply_tun_snapshot(
    node_id: NodeId,
    routes: &RouteManager,
    network: &mut TunNetworkState,
    snapshot: &NetworkSnapshot,
) -> Result<(), PeerServiceError> {
    snapshot
        .validate()
        .map_err(|error| PeerServiceError::Runtime(format!("invalid network snapshot: {error}")))?;
    let local = snapshot
        .peers
        .iter()
        .find(|peer| peer.node_id == node_id)
        .ok_or_else(|| PeerServiceError::Runtime("snapshot does not contain this node".into()))?;
    tracing::debug!(
        debug_marker = "vela-tun",
        node_id = %node_id,
        generation = snapshot.generation,
        peer_count = snapshot.peers.len(),
        "applying network snapshot to TUN"
    );
    let mut desired_local_addresses = HashMap::new();
    if let (Some(address), Some(cidr)) = (local.virtual_ipv4, snapshot.virtual_ipv4) {
        desired_local_addresses.insert(IpAddr::V4(address), cidr.prefix_len);
    }
    if let (Some(address), Some(cidr)) = (local.virtual_ipv6, snapshot.virtual_ipv6) {
        desired_local_addresses.insert(IpAddr::V6(address), cidr.prefix_len);
    }

    let stale_local_addresses = network
        .local_addresses
        .iter()
        .filter(|(address, prefix)| desired_local_addresses.get(address) != Some(prefix))
        .map(|(&address, &prefix)| (address, prefix))
        .collect::<Vec<_>>();
    for (address, prefix_len) in stale_local_addresses {
        routes.remove_local_address(address, prefix_len).await?;
        network.local_addresses.remove(&address);
    }
    for (address, prefix_len) in desired_local_addresses {
        ensure_local_address(routes, &mut network.local_addresses, address, prefix_len).await?;
    }

    // Host routes belong to signed membership, not current coordinator online
    // state, so a peer disconnect does not cause route churn.
    let desired = vela_tun::snapshot_route_addresses(snapshot, node_id)?
        .into_iter()
        .collect::<HashSet<_>>();
    let missing = desired
        .iter()
        .copied()
        .filter(|address| !network.route_leases.contains_key(address))
        .collect::<Vec<_>>();
    for address in missing {
        let lease = routes.claim_host_route(address).await?;
        network.route_leases.insert(address, lease);
    }
    let stale = network
        .route_leases
        .keys()
        .copied()
        .filter(|address| !desired.contains(address))
        .collect::<Vec<_>>();
    for address in stale {
        if let Some(lease) = network.route_leases.remove(&address) {
            let _ = lease.release().await;
        }
    }
    Ok(())
}

async fn ensure_local_address(
    routes: &RouteManager,
    local_addresses: &mut HashMap<IpAddr, u8>,
    address: IpAddr,
    prefix_len: u8,
) -> Result<(), PeerServiceError> {
    if local_addresses.get(&address) == Some(&prefix_len) {
        return Ok(());
    }
    routes.add_local_address(address, prefix_len).await?;
    local_addresses.insert(address, prefix_len);
    Ok(())
}

async fn run_peer_once(
    process: RuntimeProcess,
    tun: Arc<TunDevice>,
    routes: &RouteManager,
    network: &mut TunNetworkState,
    stop: &mut watch::Receiver<bool>,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    let vela_diagnostic::RuntimeProcess {
        handle,
        io,
        task: mut runtime_task,
    } = process;
    let mut mtu_updates = io.mtu;
    let initial_mtu = *mtu_updates.borrow();
    if let Err(error) = routes.set_mtu(initial_mtu).await {
        handle.stop();
        let _ = runtime_task.await;
        return Err(Box::new(error));
    }
    let tun_reader = Arc::clone(&tun);
    let reader_handle = handle.clone();
    let mut tun_to_vela = tokio::spawn(async move {
        let mut packets = Vec::with_capacity(64);
        loop {
            tun_reader
                .recv_many(&mut packets, 64)
                .await
                .map_err(|error| error.to_string())?;
            for (packet, result) in packets
                .iter()
                .zip(reader_handle.send_ip_batch(&packets).await)
            {
                let packet_len = packet.len();
                match result {
                    Ok(()) => tracing::debug!(
                        debug_marker = "vela-tun",
                        packet_len,
                        "handed TUN packet to Vela core"
                    ),
                    Err(vela_core::SendError::Ip(error)) => tracing::debug!(
                        debug_marker = "vela-tun",
                        packet_len,
                        error = %error,
                        "dropping invalid or unrouted packet from TUN"
                    ),
                    Err(vela_core::SendError::QueueFull) => tracing::debug!(
                        debug_marker = "vela-tun",
                        packet_len,
                        "dropping packet because the peer send queue is full"
                    ),
                    Err(vela_core::SendError::SnapshotExpired) => tracing::warn!(
                        debug_marker = "vela-control",
                        packet_len,
                        "network snapshot expired; waiting for runtime reconnect"
                    ),
                    Err(error) => tracing::debug!(
                        debug_marker = "vela-tun",
                        packet_len,
                        error = %error,
                        "dropping packet after a transient Vela send failure"
                    ),
                }
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    });
    let tun_writer = Arc::clone(&tun);
    let mut vela_to_tun = tokio::spawn(async move {
        let mut packets = io.packets;
        let mut batch = Vec::with_capacity(64);
        loop {
            batch.clear();
            let received = packets.recv_many(&mut batch, 64).await;
            if received == 0 {
                return Err::<(), _>("peer runtime packet channel closed".to_owned());
            }
            for (_peer, packet) in batch.drain(..) {
                tun_writer
                    .send(packet.as_bytes())
                    .await
                    .map_err(|error| error.to_string())?;
            }
        }
    });
    let mut snapshots = io.snapshots;

    let mut runtime_result = None;
    let mut shutdown_requested = false;
    let loop_result: Result<(), Box<dyn Error + Send + Sync>> = loop {
        tokio::select! {
            result = &mut runtime_task => {
                runtime_result = Some(match result {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => Err(Box::new(error) as Box<dyn Error + Send + Sync>),
                    Err(error) => Err(Box::new(error) as Box<dyn Error + Send + Sync>),
                });
                break Ok(());
            }
            result = &mut tun_to_vela => {
                break match result {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => Err(std::io::Error::other(error).into()),
                    Err(error) => Err(Box::new(error)),
                };
            }
            result = &mut vela_to_tun => {
                break match result {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => Err(std::io::Error::other(error).into()),
                    Err(error) => Err(Box::new(error)),
                };
            }
            changed = snapshots.changed() => {
                if changed.is_err() {
                    break Ok(());
                }
                let snapshot = snapshots.borrow().clone();
                if let Some(snapshot) = snapshot {
                    if let Err(error) = apply_tun_snapshot(
                        handle.node_id(),
                        routes,
                        network,
                        &snapshot,
                    ).await {
                        break Err(Box::new(error));
                    }
                }
            }
            changed = mtu_updates.changed() => {
                if changed.is_err() {
                    break Ok(());
                }
                let mtu = *mtu_updates.borrow_and_update();
                if let Err(error) = routes.set_mtu(mtu).await {
                    break Err(Box::new(error));
                }
                info!(debug_marker = "vela-mtu", mtu, "updated TUN MTU from path discovery");
            }
            changed = stop.changed() => {
                shutdown_requested = changed.is_err() || *stop.borrow();
                if shutdown_requested {
                    break Ok(());
                }
            }
        }
    };

    tun_to_vela.abort();
    vela_to_tun.abort();
    if shutdown_requested {
        handle.stop();
        let _ = runtime_task.await;
        return Ok(());
    }
    if runtime_result.is_none() {
        handle.stop();
        runtime_result = Some(
            runtime_task
                .await
                .map_err(|error| -> Box<dyn Error + Send + Sync> { Box::new(error) })?
                .map_err(|error| -> Box<dyn Error + Send + Sync> { Box::new(error) }),
        );
    }
    loop_result.and(runtime_result.expect("runtime result is set"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shutdown_interrupts_a_pending_peer_restart() {
        let (stop, mut receiver) = watch::channel(false);
        stop.send_replace(true);

        assert!(!wait_for_peer_restart(Duration::from_secs(30), &mut receiver).await);
    }

    #[tokio::test]
    async fn dropping_the_shutdown_owner_stops_the_service() {
        let (stop, mut receiver) = watch::channel(false);
        drop(stop);

        assert!(!wait_for_peer_restart(Duration::from_secs(30), &mut receiver).await);
    }

    #[test]
    fn reconnect_delay_doubles_and_has_a_cap() {
        assert_eq!(
            next_restart_delay(Duration::from_secs(1)),
            Duration::from_secs(2)
        );
        assert_eq!(
            next_restart_delay(Duration::from_secs(20)),
            MAX_RESTART_DELAY
        );
        assert_eq!(next_restart_delay(MAX_RESTART_DELAY), MAX_RESTART_DELAY);
    }
}
