//! Embeddable direct UDP peer transport.
//!
//! The core owns peer/session state and Tokio tasks. Hosts can provide the
//! actual direct UDP socket through [`DatagramProvider`] to select an
//! interface, source address, routing domain or platform-specific socket
//! options without making Vela know about those details.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use if_addrs::get_if_addrs;
use rand::RngCore;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    net::UdpSocket,
    sync::{Mutex, Notify, mpsc, oneshot},
    time::{Instant, timeout},
};
use tracing::{debug, warn};
use vela_coord_client::{CoordClientError, CoordinationClient, Registration};
use vela_crypto::{
    CryptoError, CryptoPolicy, Identity, MembershipCredential, NoiseHandshake, SessionCipher,
    verify_snapshot,
};
use vela_ip::{IpPacket, RouteTable};
use vela_proto::{
    Candidate, Header, NetworkSnapshot, NodeId, PacketType, PeerInfo, ProtoError, PublicPeerInfo,
    WirePacket,
};

#[derive(Clone, Debug)]
pub struct BindOptions {
    pub local_addr: SocketAddr,
}

impl Default for BindOptions {
    fn default() -> Self {
        Self {
            local_addr: "[::]:0".parse().expect("valid default socket address"),
        }
    }
}

#[async_trait]
pub trait DatagramSocket: Send + Sync {
    async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> io::Result<usize>;
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
}

#[async_trait]
pub trait DatagramProvider: Send + Sync {
    async fn bind(&self, options: BindOptions) -> Result<Arc<dyn DatagramSocket>, CoreError>;
    fn local_candidates(&self) -> Vec<Candidate>;

    /// Returns the interface selected for the default local socket, if any.
    ///
    /// Providers that manage their own socket and candidates can leave this
    /// unset. The built-in provider uses it to keep fallback host candidates
    /// consistent with the interface-bound socket.
    fn local_interface(&self) -> Option<String> {
        None
    }
}

pub struct TokioDatagramProvider {
    pub host_candidates: Vec<Candidate>,
    selected_interface: StdMutex<Option<DefaultRouteInterface>>,
}

impl TokioDatagramProvider {
    pub fn new(host_candidates: Vec<Candidate>) -> Self {
        Self {
            host_candidates,
            selected_interface: StdMutex::new(None),
        }
    }
}

#[derive(Clone, Debug)]
struct DefaultRouteInterface {
    name: String,
    index: Option<std::num::NonZeroU32>,
}

fn default_route_interface(bind_addr: SocketAddr) -> io::Result<Option<DefaultRouteInterface>> {
    let mut routes = route_manager::RouteManager::new()?;
    let route = if bind_addr.is_ipv4() {
        default_route(&mut routes, true)?
    } else {
        // The dual-stack socket uses the IPv4 default route when available;
        // this is also the route used for IPv4-mapped destinations. Fall back
        // to IPv6-only systems where no IPv4 default route exists.
        match default_route(&mut routes, true)? {
            Some(route) => Some(route),
            None => default_route(&mut routes, false)?,
        }
    };
    let Some(route) = route else {
        return Ok(None);
    };
    let Some(name) = route.if_name().cloned() else {
        return Ok(None);
    };
    Ok(Some(DefaultRouteInterface {
        name,
        index: route.if_index().and_then(std::num::NonZeroU32::new),
    }))
}

#[cfg(target_os = "linux")]
fn default_route(
    routes: &mut route_manager::RouteManager,
    ipv4: bool,
) -> io::Result<Option<route_manager::Route>> {
    // route_manager lists policy-routing tables as well as the main table.
    // Vela/Tailscale may install a catch-all route in another table, but that
    // is not the host's ordinary default egress route. Use the main table.
    let mut candidates = routes
        .list()?
        .into_iter()
        .filter(|route| {
            route.prefix() == 0 && route.destination().is_ipv4() == ipv4 && route.table() == 254
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|route| route.metric().unwrap_or(u32::MAX));
    Ok(candidates.into_iter().next())
}

#[cfg(not(target_os = "linux"))]
fn default_route(
    routes: &mut route_manager::RouteManager,
    ipv4: bool,
) -> io::Result<Option<route_manager::Route>> {
    let destination = if ipv4 {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    routes.find_route(&destination)
}

#[cfg(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
))]
fn bind_socket_to_interface(
    socket: &Socket,
    interface: &DefaultRouteInterface,
    ipv4: bool,
) -> io::Result<()> {
    let Some(index) = interface.index else {
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux",))]
        {
            return socket.bind_device(Some(interface.name.as_bytes()));
        }
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux",)))]
        {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "default route has no interface index",
            ));
        }
    };

    #[cfg(target_os = "linux")]
    {
        // On Linux both methods map to SO_BINDTOIFINDEX. Setting it twice can
        // fail with EPERM even when the first call succeeded.
        let _ = ipv4;
        socket.bind_device_by_index_v4(Some(index))
    }
    #[cfg(not(target_os = "linux"))]
    {
        if ipv4 {
            socket.bind_device_by_index_v4(Some(index))
        } else {
            socket.bind_device_by_index_v6(Some(index))
        }
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "fuchsia",
    target_os = "linux",
    target_os = "ios",
    target_os = "visionos",
    target_os = "macos",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
)))]
fn bind_socket_to_interface(
    _socket: &Socket,
    _interface: &DefaultRouteInterface,
) -> io::Result<()> {
    // Windows and BSD platforms use the system route for outgoing packets;
    // socket2 does not expose an interface-binding option for them.
    Ok(())
}

#[async_trait]
impl DatagramProvider for TokioDatagramProvider {
    async fn bind(&self, options: BindOptions) -> Result<Arc<dyn DatagramSocket>, CoreError> {
        let domain = if options.local_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        let selected_interface = if options.local_addr.ip().is_unspecified() {
            Some(default_route_interface(options.local_addr)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    "no main-table default-route interface is available",
                )
            })?)
        } else {
            None
        };
        if let Some(interface) = &selected_interface {
            tracing::info!(
                interface = %interface.name,
                index = ?interface.index,
                "binding peer UDP socket to the default-route interface"
            );
            bind_socket_to_interface(&socket, interface, options.local_addr.is_ipv4())?;
        }
        if options.local_addr.is_ipv6() && options.local_addr.ip().is_unspecified() {
            socket.set_only_v6(false)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&options.local_addr.into())?;
        *self
            .selected_interface
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = selected_interface;
        Ok(Arc::new(TokioDatagramSocket {
            socket: UdpSocket::from_std(socket.into())?,
        }))
    }

    fn local_candidates(&self) -> Vec<Candidate> {
        self.host_candidates.clone()
    }

    fn local_interface(&self) -> Option<String> {
        self.selected_interface
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|interface| interface.name.clone())
    }
}

fn host_candidates(
    bind_addr: SocketAddr,
    port: u16,
    interface_name: Option<&str>,
) -> Vec<Candidate> {
    if !bind_addr.ip().is_unspecified() {
        return vec![Candidate::Host(SocketAddr::new(bind_addr.ip(), port))];
    }

    // An unspecified IPv6 socket is created as dual-stack below, so it can
    // reach IPv4 peers as well. Advertise both address families in that case.
    let include_ipv4 = bind_addr.is_ipv4() || bind_addr.is_ipv6();
    let include_ipv6 = bind_addr.is_ipv6();
    let Ok(interfaces) = get_if_addrs() else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for interface in interfaces {
        if interface_name.is_some_and(|name| interface.name != name) {
            continue;
        }
        if interface.is_loopback() || interface.is_link_local() {
            continue;
        }
        let address = interface.ip();
        if (address.is_ipv4() && include_ipv4) || (address.is_ipv6() && include_ipv6) {
            let candidate = Candidate::Host(SocketAddr::new(address, port));
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }
    }
    candidates
}

struct TokioDatagramSocket {
    socket: UdpSocket,
}

#[async_trait]
impl DatagramSocket for TokioDatagramSocket {
    async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(bytes, target).await
    }
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buffer).await
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

struct StunSocketAdapter {
    inner: Arc<Inner>,
    pending: Mutex<Option<oneshot::Receiver<StunResponse>>>,
}

type StunResponse = (Vec<u8>, SocketAddr);
type StunWaiter = (Instant, oneshot::Sender<StunResponse>);

const STUN_MAGIC_COOKIE: [u8; 4] = 0x2112_A442u32.to_be_bytes();

fn stun_transaction_id(input: &[u8]) -> Option<[u8; 12]> {
    if input.len() < 20 || input[0] & 0xc0 != 0 || input[4..8] != STUN_MAGIC_COOKIE {
        return None;
    }
    input[8..20].try_into().ok()
}

#[async_trait]
impl vela_stun::StunSocket for StunSocketAdapter {
    async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> io::Result<usize> {
        if !self.inner.started.load(Ordering::Acquire) {
            return self.inner.socket.send_to(bytes, target).await;
        }
        let Some(transaction) = stun_transaction_id(bytes) else {
            return self.inner.socket.send_to(bytes, target).await;
        };
        let (sender, receiver) = oneshot::channel();
        {
            let mut waiters = self.inner.stun_waiters.lock().await;
            let now = Instant::now();
            waiters.retain(|_, (deadline, _)| *deadline > now);
            waiters.insert(transaction, (now + Duration::from_secs(10), sender));
        }
        *self.pending.lock().await = Some(receiver);
        match self.inner.socket.send_to(bytes, target).await {
            Ok(length) => Ok(length),
            Err(error) => {
                self.inner.stun_waiters.lock().await.remove(&transaction);
                self.pending.lock().await.take();
                Err(error)
            }
        }
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        if !self.inner.started.load(Ordering::Acquire) {
            return self.inner.socket.recv_from(buffer).await;
        }
        let receiver = self.pending.lock().await.take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "STUN receive has no pending request",
            )
        })?;
        let (bytes, source) = receiver.await.map_err(|_| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "STUN request was cancelled",
            )
        })?;
        if bytes.len() > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "STUN response is larger than the receive buffer",
            ));
        }
        buffer[..bytes.len()].copy_from_slice(&bytes);
        Ok((bytes.len(), source))
    }
}

#[derive(Clone)]
pub struct NodeConfig {
    pub bind: BindOptions,
    pub max_payload_size: usize,
    pub per_peer_queue_limit: usize,
    pub keepalive_interval: Duration,
    pub connect_timeout: Duration,
    pub reconnect_backoff: Duration,
    pub crypto_policy: CryptoPolicy,
    pub server_public_key: Option<[u8; 32]>,
    pub network_id: [u8; 16],
    pub virtual_ipv4: Option<Ipv4Addr>,
    pub virtual_ipv6: Option<Ipv6Addr>,
    pub virtual_mtu: usize,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            bind: BindOptions::default(),
            max_payload_size: 1200,
            per_peer_queue_limit: 32,
            keepalive_interval: Duration::from_secs(20),
            connect_timeout: Duration::from_secs(8),
            reconnect_backoff: Duration::from_secs(1),
            crypto_policy: CryptoPolicy::PreferHybrid,
            server_public_key: None,
            network_id: [0; 16],
            virtual_ipv4: None,
            virtual_ipv6: None,
            virtual_mtu: 1200,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TrafficSample {
    pub peer: Option<NodeId>,
    pub direction: TrafficDirection,
    pub path: SocketAddr,
    pub payload_bytes: usize,
    pub encrypted_bytes: usize,
    pub wire_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrafficDirection {
    Sent,
    Received,
}

pub trait TrafficObserver: Send + Sync {
    fn record(&self, sample: TrafficSample);
}

#[derive(Clone, Default)]
pub struct VelaNodeBuilder {
    identity: Option<Identity>,
    provider: Option<Arc<dyn DatagramProvider>>,
    config: NodeConfig,
    observer: Option<Arc<dyn TrafficObserver>>,
}

impl VelaNodeBuilder {
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }
    pub fn datagram_provider(mut self, provider: Arc<dyn DatagramProvider>) -> Self {
        self.provider = Some(provider);
        self
    }
    pub fn config(mut self, config: NodeConfig) -> Self {
        self.config = config;
        self
    }
    pub fn traffic_observer(mut self, observer: Arc<dyn TrafficObserver>) -> Self {
        self.observer = Some(observer);
        self
    }

    pub async fn build(self) -> Result<VelaNode, CoreError> {
        if self.config.crypto_policy == CryptoPolicy::RequireHybrid {
            return Err(CoreError::HybridCryptoUnavailable);
        }
        let identity = self.identity.unwrap_or_else(Identity::generate);
        let provider = self.provider.ok_or(CoreError::MissingProvider)?;
        let socket = provider.bind(self.config.bind.clone()).await?;
        let (event_tx, event_rx) = mpsc::channel(256);
        let local_addresses = self
            .config
            .virtual_ipv4
            .into_iter()
            .map(IpAddr::V4)
            .chain(self.config.virtual_ipv6.into_iter().map(IpAddr::V6))
            .collect::<Vec<_>>();
        let network_id = self.config.network_id;
        let local_ipv4 = self.config.virtual_ipv4;
        let local_ipv6 = self.config.virtual_ipv6;
        let inner = Arc::new(Inner {
            identity,
            socket,
            provider,
            config: self.config,
            observer: self.observer,
            peers: Mutex::new(HashMap::new()),
            routes: Mutex::new(RouteTable::new(local_addresses)),
            event_tx,
            event_rx: Mutex::new(Some(event_rx)),
            shutdown: Notify::new(),
            started: AtomicBool::new(false),
            network_id: Mutex::new(network_id),
            snapshot_generation: AtomicU64::new(0),
            snapshot_expires_at: AtomicU64::new(u64::MAX),
            local_ipv4: Mutex::new(local_ipv4),
            local_ipv6: Mutex::new(local_ipv6),
            stun_waiters: Mutex::new(HashMap::new()),
        });
        Ok(VelaNode { inner })
    }
}

#[derive(Clone)]
pub struct VelaNode {
    inner: Arc<Inner>,
}

impl VelaNode {
    pub fn builder() -> VelaNodeBuilder {
        VelaNodeBuilder::default()
    }

    pub fn identity(&self) -> &Identity {
        &self.inner.identity
    }
    pub fn node_id(&self) -> NodeId {
        self.inner.identity.public().node_id
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.socket.local_addr()
    }
    pub fn local_candidates(&self) -> Vec<Candidate> {
        let candidates = self.inner.provider.local_candidates();
        if !candidates.is_empty() {
            candidates
        } else {
            let Ok(local_addr) = self.local_addr() else {
                return Vec::new();
            };
            let interface_name = self.inner.provider.local_interface();
            host_candidates(
                self.inner.config.bind.local_addr,
                local_addr.port(),
                interface_name.as_deref(),
            )
        }
    }

    pub async fn gather_server_reflexive_candidates(
        &self,
        config: &vela_stun::StunConfig,
    ) -> Result<Vec<Candidate>, CoreError> {
        let socket = StunSocketAdapter {
            inner: Arc::clone(&self.inner),
            pending: Mutex::new(None),
        };
        Ok(vela_stun::binding(&socket, config)
            .await?
            .into_iter()
            .map(Candidate::ServerReflexive)
            .collect())
    }

    pub async fn start(&self) -> Result<(), CoreError> {
        if self.inner.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let reader = Arc::clone(&self.inner);
        tokio::spawn(async move {
            reader.read_loop().await;
        });
        let maintenance = Arc::clone(&self.inner);
        tokio::spawn(async move {
            maintenance.keepalive_loop().await;
        });
        Ok(())
    }

    pub async fn shutdown(&self) {
        self.inner.shutdown.notify_waiters();
    }

    pub async fn register_peer(&self, info: PeerInfo) -> Result<(), CoreError> {
        validate_peer_info(&info)?;
        validate_peer_membership(&info, self.inner.config.server_public_key)?;
        let peer_id = info.node_id;
        let peer_addresses = info
            .virtual_ipv4
            .into_iter()
            .map(IpAddr::V4)
            .chain(info.virtual_ipv6.into_iter().map(IpAddr::V6))
            .collect::<Vec<_>>();
        let replacement = Arc::new(PeerState::new(info));
        let previous = {
            let mut routes = self.inner.routes.lock().await;
            let mut peers = self.inner.peers.lock().await;
            let previous = peers.insert(peer_id, replacement);
            if let Some(previous) = &previous {
                if let Some(address) = previous.info.virtual_ipv4 {
                    routes.remove(&IpAddr::V4(address));
                }
                if let Some(address) = previous.info.virtual_ipv6 {
                    routes.remove(&IpAddr::V6(address));
                }
            }
            for address in peer_addresses {
                routes.insert(address, peer_id);
            }
            previous
        };
        if let Some(previous) = previous {
            let disconnected = previous.active.lock().await.take().is_some();
            *previous.attempt.lock().await = None;
            previous.queue.lock().await.clear();
            if disconnected {
                self.inner.emit(VelaEvent::PeerDisconnected(peer_id)).await;
            }
        }
        Ok(())
    }

    /// Removes a peer and its exact host routes, closing its active session.
    pub async fn remove_peer(&self, peer_id: NodeId) -> Result<bool, CoreError> {
        let peer = {
            let mut routes = self.inner.routes.lock().await;
            let mut peers = self.inner.peers.lock().await;
            let Some(peer) = peers.remove(&peer_id) else {
                return Ok(false);
            };
            if let Some(address) = peer.info.virtual_ipv4 {
                routes.remove(&IpAddr::V4(address));
            }
            if let Some(address) = peer.info.virtual_ipv6 {
                routes.remove(&IpAddr::V6(address));
            }
            peer
        };
        *peer.active.lock().await = None;
        *peer.attempt.lock().await = None;
        peer.queue.lock().await.clear();
        self.inner.emit(VelaEvent::PeerDisconnected(peer_id)).await;
        Ok(true)
    }

    /// Atomically replaces the node's membership view and host routes.
    ///
    /// The coordinator signs the complete membership set. Replacing the set
    /// in one operation ensures that an address is never routed using a peer
    /// record from a different generation of the snapshot.
    pub async fn apply_snapshot(&self, snapshot: NetworkSnapshot) -> Result<(), CoreError> {
        if let Some(server_public_key) = self.inner.config.server_public_key {
            verify_snapshot(&snapshot, &server_public_key, unix_time())?;
        }
        snapshot.validate()?;
        if snapshot.expires_at <= unix_time() {
            return Err(CoreError::SnapshotExpired);
        }
        let configured_network = self.inner.config.network_id;
        if configured_network != [0; 16] && configured_network != snapshot.network_id {
            return Err(CoreError::NetworkMismatch);
        }
        let current_generation = self.inner.snapshot_generation.load(Ordering::Acquire);
        if snapshot.generation < current_generation {
            return Err(CoreError::StaleSnapshot);
        }
        let local = snapshot
            .peers
            .iter()
            .find(|peer| peer.node_id == self.node_id())
            .ok_or(CoreError::LocalPeerMissing)?;
        validate_peer_info(local)?;
        let local_addresses = local
            .virtual_ipv4
            .into_iter()
            .map(IpAddr::V4)
            .chain(local.virtual_ipv6.into_iter().map(IpAddr::V6))
            .collect::<Vec<_>>();
        if local_addresses.is_empty() {
            return Err(CoreError::LocalAddressMissing);
        }
        let local_ipv4 = local.virtual_ipv4;
        let local_ipv6 = local.virtual_ipv6;

        let mut replacement = HashMap::with_capacity(snapshot.peers.len().saturating_sub(1));
        for info in snapshot.peers {
            validate_peer_info(&info)?;
            validate_peer_membership(&info, self.inner.config.server_public_key)?;
            if info.node_id != self.node_id() {
                replacement.insert(info.node_id, Arc::new(PeerState::new(info)));
            }
        }
        let mut routes = RouteTable::new(local_addresses);
        for peer in replacement.values() {
            if let Some(address) = peer.info.virtual_ipv4 {
                routes.insert(IpAddr::V4(address), peer.info.node_id);
            }
            if let Some(address) = peer.info.virtual_ipv6 {
                routes.insert(IpAddr::V6(address), peer.info.node_id);
            }
        }

        // send_payload takes the route lock before the peer lock, so preserve
        // that order when swapping both views.
        let mut route_guard = self.inner.routes.lock().await;
        let mut peer_guard = self.inner.peers.lock().await;
        let old_peers = peer_guard.values().cloned().collect::<Vec<_>>();
        *route_guard = routes;
        *peer_guard = replacement;
        drop(peer_guard);
        drop(route_guard);
        *self.inner.network_id.lock().await = snapshot.network_id;
        *self.inner.local_ipv4.lock().await = local_ipv4;
        *self.inner.local_ipv6.lock().await = local_ipv6;
        self.inner
            .snapshot_generation
            .store(snapshot.generation, Ordering::Release);
        self.inner
            .snapshot_expires_at
            .store(snapshot.expires_at, Ordering::Release);
        for peer in old_peers {
            let disconnected = peer.active.lock().await.take().is_some();
            *peer.attempt.lock().await = None;
            peer.queue.lock().await.clear();
            if disconnected {
                self.inner
                    .emit(VelaEvent::PeerDisconnected(peer.info.node_id))
                    .await;
            }
        }
        Ok(())
    }

    pub async fn send_ip(&self, packet: impl Into<Bytes>) -> Result<(), SendError> {
        let packet = IpPacket::parse(packet.into()).map_err(SendError::Ip)?;
        let peer_id = self
            .inner
            .routes
            .lock()
            .await
            .validate_outbound(&packet)
            .map_err(SendError::Ip)?;
        let peer = self
            .inner
            .peers
            .lock()
            .await
            .get(&peer_id)
            .cloned()
            .ok_or(SendError::UnknownPeer)?;
        let should_connect =
            peer.active.lock().await.is_none() && peer.attempt.lock().await.is_none();
        let result = self.inner.send_payload(&peer, packet.into_bytes()).await;
        if result.is_ok() && should_connect {
            let node = self.clone();
            tokio::spawn(async move {
                let _ = node.connect(peer_id).await;
            });
        }
        result
    }

    pub async fn register_with_coordination(
        &self,
        client: &mut CoordinationClient,
        invite_token: Option<&str>,
        credential: Option<&MembershipCredential>,
    ) -> Result<Registration, CoreError> {
        let registration = client
            .register(
                &self.inner.identity,
                invite_token,
                credential,
                self.local_candidates(),
            )
            .await?;
        self.apply_snapshot(registration.snapshot.clone()).await?;
        Ok(registration)
    }

    pub async fn update_candidates_with_coordination(
        &self,
        client: &mut CoordinationClient,
    ) -> Result<(), CoreError> {
        client
            .update_candidates(self.local_candidates())
            .await
            .map_err(CoreError::from)
    }

    pub async fn connect_via_coordination(
        &self,
        client: &mut CoordinationClient,
        peer_id: NodeId,
    ) -> Result<PeerHandle, ConnectError> {
        let peer = client
            .lookup_peer(peer_id)
            .await
            .map_err(CoreError::from)
            .map_err(ConnectError::Core)?;
        self.register_peer(peer).await.map_err(ConnectError::Core)?;
        self.connect(peer_id).await
    }

    pub async fn add_public_peer(&self, peer: PublicPeerInfo) -> Result<(), CoreError> {
        self.register_peer(peer.try_into()?).await
    }

    pub async fn connect(&self, peer_id: NodeId) -> Result<PeerHandle, ConnectError> {
        if !self.inner.started.load(Ordering::Acquire) {
            return Err(ConnectError::NotStarted);
        }
        if unix_time() >= self.inner.snapshot_expires_at.load(Ordering::Acquire) {
            return Err(ConnectError::Core(CoreError::SnapshotExpired));
        }
        let peer = self
            .inner
            .peers
            .lock()
            .await
            .get(&peer_id)
            .cloned()
            .ok_or(ConnectError::UnknownPeer)?;
        let _connect_guard = peer.connect.lock().await;
        if peer.active.lock().await.is_some() {
            return Ok(PeerHandle {
                node: self.clone(),
                peer_id,
            });
        }
        self.inner.emit(VelaEvent::PeerConnecting(peer_id)).await;
        let candidates = peer.info.candidates.clone();
        if candidates.is_empty() {
            return Err(ConnectError::NoCandidates);
        }
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let session_id = random_session_id();
        {
            let mut attempt = peer.attempt.lock().await;
            *attempt = Some(Attempt {
                session_id,
                handshake: None,
            });
        }
        let node_id = self.node_id();
        let timestamp = unix_time();
        let send_probes = || async {
            let payload = encode_probe(
                node_id,
                peer_id,
                session_id,
                timestamp,
                nonce,
                &self.inner.identity,
            );
            for candidate in &candidates {
                let _ = self
                    .inner
                    .send_packet(
                        candidate.address(),
                        PacketType::Probe,
                        session_id,
                        0,
                        &payload,
                    )
                    .await;
            }
        };
        send_probes().await;
        let deadline = Instant::now() + self.inner.config.connect_timeout;
        let mut next_probe = Instant::now() + Duration::from_millis(250);
        loop {
            if peer.active.lock().await.is_some() {
                return Ok(PeerHandle {
                    node: self.clone(),
                    peer_id,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                *peer.attempt.lock().await = None;
                self.inner.emit(VelaEvent::PeerUnreachable(peer_id)).await;
                return Err(ConnectError::Timeout);
            }
            if Instant::now() >= next_probe {
                send_probes().await;
                next_probe = Instant::now() + Duration::from_millis(250);
                continue;
            }
            let wait_for_probe = next_probe.saturating_duration_since(Instant::now());
            let wait_for = remaining.min(wait_for_probe);
            if timeout(wait_for, peer.notify.notified()).await.is_err() {
                continue;
            }
            if peer.active.lock().await.is_none() && Instant::now() >= deadline {
                *peer.attempt.lock().await = None;
                self.inner.emit(VelaEvent::PeerUnreachable(peer_id)).await;
                return Err(ConnectError::Timeout);
            }
        }
    }

    pub async fn next_event(&self) -> Option<VelaEvent> {
        let mut receiver = self.inner.event_rx.lock().await;
        receiver.as_mut()?.recv().await
    }
}

struct Inner {
    identity: Identity,
    socket: Arc<dyn DatagramSocket>,
    provider: Arc<dyn DatagramProvider>,
    config: NodeConfig,
    observer: Option<Arc<dyn TrafficObserver>>,
    peers: Mutex<HashMap<NodeId, Arc<PeerState>>>,
    routes: Mutex<RouteTable>,
    network_id: Mutex<[u8; 16]>,
    snapshot_generation: AtomicU64,
    snapshot_expires_at: AtomicU64,
    local_ipv4: Mutex<Option<Ipv4Addr>>,
    local_ipv6: Mutex<Option<Ipv6Addr>>,
    stun_waiters: Mutex<HashMap<[u8; 12], StunWaiter>>,
    event_tx: mpsc::Sender<VelaEvent>,
    event_rx: Mutex<Option<mpsc::Receiver<VelaEvent>>>,
    shutdown: Notify,
    started: AtomicBool,
}

impl Inner {
    async fn read_loop(self: Arc<Self>) {
        let mut buffer = vec![0u8; 65535];
        loop {
            tokio::select! {
                _ = self.shutdown.notified() => break,
                result = self.socket.recv_from(&mut buffer) => match result {
                    Ok((length, source)) => {
                        if let Some(transaction) = stun_transaction_id(&buffer[..length]) {
                            let waiter = self.stun_waiters.lock().await.remove(&transaction);
                            if let Some((_, sender)) = waiter {
                                let _ = sender.send((buffer[..length].to_vec(), source));
                            }
                            continue;
                        }
                        if let Err(error) = self.handle_packet(&buffer[..length], source).await { debug!(%error, %source, "dropping invalid Vela packet"); }
                    }
                    Err(error) => { warn!(%error, "Vela UDP receive loop stopped"); break; }
                }
            }
        }
    }

    async fn keepalive_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.config.keepalive_interval);
        loop {
            tokio::select! {
                _ = self.shutdown.notified() => break,
                _ = interval.tick() => {
                    let peers = self.peers.lock().await.values().cloned().collect::<Vec<_>>();
                    for peer in peers {
                        let membership_expired = self
                            .config
                            .server_public_key
                            .is_some_and(|server_key| {
                                validate_peer_membership(&peer.info, Some(server_key)).is_err()
                            });
                        if unix_time() >= self.snapshot_expires_at.load(Ordering::Acquire)
                            || membership_expired
                        {
                            let disconnected = peer.active.lock().await.take().is_some();
                            *peer.attempt.lock().await = None;
                            peer.queue.lock().await.clear();
                            if disconnected {
                                self.emit(VelaEvent::PeerDisconnected(peer.info.node_id)).await;
                            }
                            continue;
                        }
                        let (keepalive, rekey_path) = {
                            let mut active = peer.active.lock().await;
                            let Some(session) = active.as_mut() else {
                                continue;
                            };
                            if session.needs_rekey() {
                                let path = session.path;
                                active.take();
                                (None, Some(path))
                            } else {
                                let sequence = session.tx_sequence.fetch_add(1, Ordering::Relaxed);
                                let packet = encrypt_payload(session, PacketType::KeepAlive, sequence, &[])
                                    .ok()
                                    .map(|payload| (session.path, session.session_id, sequence, payload));
                                (packet, None)
                            }
                        };
                        if let Some((path, session_id, sequence, payload)) = keepalive {
                            let _ = self.send_packet(path, PacketType::KeepAlive, session_id, sequence, &payload).await;
                        }
                        if let Some(path) = rekey_path {
                            *peer.attempt.lock().await = None;
                            if self.identity.public().node_id < peer.info.node_id {
                                let session_id = random_session_id();
                                *peer.attempt.lock().await = Some(Attempt {
                                    session_id,
                                    handshake: None,
                                });
                                let _ = self.start_initiator(&peer, path, session_id).await;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn handle_packet(&self, input: &[u8], source: SocketAddr) -> Result<(), CoreError> {
        if unix_time() >= self.snapshot_expires_at.load(Ordering::Acquire) {
            return Err(CoreError::SnapshotExpired);
        }
        let packet = WirePacket::decode(input)?;
        match packet.header.packet_type {
            PacketType::Probe => self.handle_probe(packet, source).await,
            PacketType::ProbeResponse => self.handle_probe_response(packet, source).await,
            PacketType::Handshake => self.handle_handshake(packet, source).await,
            PacketType::Data
            | PacketType::KeepAlive
            | PacketType::DiagnosticPing
            | PacketType::DiagnosticPong => self.handle_data(packet, source).await,
        }
    }

    async fn handle_probe(&self, packet: WirePacket, source: SocketAddr) -> Result<(), CoreError> {
        let probe = decode_probe(&packet.payload)?;
        if probe.receiver != self.identity.public().node_id {
            return Err(CoreError::InvalidProbe);
        }
        let peer = self.peer_for(probe.sender).await?;
        validate_peer_membership(&peer.info, self.config.server_public_key)?;
        verify_probe(&probe, &peer.info)?;
        let payload = encode_probe(
            self.identity.public().node_id,
            probe.sender,
            probe.session_id,
            probe.timestamp,
            probe.nonce,
            &self.identity,
        );
        self.send_packet(
            source,
            PacketType::ProbeResponse,
            probe.session_id,
            0,
            &payload,
        )
        .await?;
        self.emit(VelaEvent::PeerConnecting(probe.sender)).await;
        if self.identity.public().node_id < probe.sender {
            let mut attempt = peer.attempt.lock().await;
            let can_replace = attempt
                .as_ref()
                .is_none_or(|value| value.handshake.is_none());
            if can_replace
                && attempt.as_ref().map(|value| value.session_id) != Some(probe.session_id)
            {
                *attempt = Some(Attempt {
                    session_id: probe.session_id,
                    handshake: None,
                });
            }
            drop(attempt);
            self.start_initiator(&peer, source, probe.session_id)
                .await?;
        }
        Ok(())
    }

    async fn handle_probe_response(
        &self,
        packet: WirePacket,
        source: SocketAddr,
    ) -> Result<(), CoreError> {
        let probe = decode_probe(&packet.payload)?;
        if probe.receiver != self.identity.public().node_id {
            return Err(CoreError::InvalidProbe);
        }
        let peer = self.peer_for(probe.sender).await?;
        validate_peer_membership(&peer.info, self.config.server_public_key)?;
        verify_probe(&probe, &peer.info)?;
        let attempt = peer.attempt.lock().await;
        if attempt.as_ref().map(|value| value.session_id) != Some(probe.session_id) {
            return Ok(());
        }
        drop(attempt);
        if self.identity.public().node_id < probe.sender {
            self.start_initiator(&peer, source, probe.session_id)
                .await?;
        }
        Ok(())
    }

    async fn start_initiator(
        &self,
        peer: &Arc<PeerState>,
        path: SocketAddr,
        session_id: u64,
    ) -> Result<(), CoreError> {
        if peer.active.lock().await.is_some() {
            return Ok(());
        }
        let mut attempt = peer.attempt.lock().await;
        let Some(attempt_value) = attempt.as_mut() else {
            return Ok(());
        };
        if attempt_value.session_id != session_id {
            return Ok(());
        }
        if attempt_value.handshake.is_some() {
            return Ok(());
        }
        let mut handshake = NoiseHandshake::initiator(&self.identity, &peer.info.noise_public)?;
        let message = handshake.write_message(&self.handshake_context().await?)?;
        attempt_value.handshake = Some(handshake);
        drop(attempt);
        let mut payload = Vec::with_capacity(33 + message.len());
        payload.push(1);
        payload.extend_from_slice(self.identity.public().node_id.as_bytes());
        payload.extend_from_slice(&message);
        self.send_packet(path, PacketType::Handshake, session_id, 0, &payload)
            .await?;
        self.emit(VelaEvent::PeerConnecting(peer.info.node_id))
            .await;
        Ok(())
    }

    async fn handle_handshake(
        &self,
        packet: WirePacket,
        source: SocketAddr,
    ) -> Result<(), CoreError> {
        if packet.payload.len() < 34 {
            return Err(CoreError::InvalidHandshake);
        }
        let role = packet.payload[0];
        let sender = NodeId::new(packet.payload[1..33].try_into().expect("checked sender"));
        let peer = self.peer_for(sender).await?;
        validate_peer_membership(&peer.info, self.config.server_public_key)?;
        if peer.active.lock().await.is_some() {
            return Ok(());
        }
        if role == 1 {
            if self.identity.public().node_id < sender {
                return Ok(());
            }
            let mut handshake = NoiseHandshake::responder(&self.identity)?;
            let context = handshake.read_message(&packet.payload[33..])?;
            self.validate_handshake_context(&context, sender, &peer.info)
                .await?;
            let response = handshake.write_message(&self.handshake_context().await?)?;
            let keys = handshake.into_session()?;
            let mut payload = Vec::with_capacity(33 + response.len());
            payload.push(2);
            payload.extend_from_slice(self.identity.public().node_id.as_bytes());
            payload.extend_from_slice(&response);
            self.send_packet(
                source,
                PacketType::Handshake,
                packet.header.session_id,
                0,
                &payload,
            )
            .await?;
            self.establish(&peer, packet.header.session_id, source, keys.cipher(false))
                .await;
        } else if role == 2 {
            if self.identity.public().node_id > sender {
                return Ok(());
            }
            let mut attempt = peer.attempt.lock().await;
            if attempt.as_ref().map(|value| value.session_id) != Some(packet.header.session_id) {
                return Ok(());
            }
            let Some(mut handshake) = attempt.as_mut().and_then(|value| value.handshake.take())
            else {
                return Ok(());
            };
            let context = handshake.read_message(&packet.payload[33..])?;
            self.validate_handshake_context(&context, sender, &peer.info)
                .await?;
            let keys = handshake.into_session()?;
            drop(attempt);
            self.establish(&peer, packet.header.session_id, source, keys.cipher(true))
                .await;
        }
        Ok(())
    }

    async fn handle_data(&self, packet: WirePacket, source: SocketAddr) -> Result<(), CoreError> {
        let peers = self
            .peers
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for peer in peers {
            let mut active = peer.active.lock().await;
            let Some(session) = active.as_mut() else {
                continue;
            };
            if session.session_id != packet.header.session_id {
                continue;
            }
            if let Some(server_key) = self.config.server_public_key {
                if validate_peer_membership(&peer.info, Some(server_key)).is_err() {
                    active.take();
                    drop(active);
                    *peer.attempt.lock().await = None;
                    peer.queue.lock().await.clear();
                    self.emit(VelaEvent::PeerDisconnected(peer.info.node_id))
                        .await;
                    return Err(CoreError::PeerCredentialExpired);
                }
            }
            let aad = encoded_header(&packet.header);
            let plaintext =
                session
                    .cipher
                    .decrypt(packet.header.sequence, &aad, &packet.payload)?;
            if !session.replay.accept(packet.header.sequence) {
                return Ok(());
            }
            let path_changed = session.path != source;
            session.path = source;
            let mut events = Vec::new();
            if path_changed {
                events.push(VelaEvent::PathChanged(peer.info.node_id, source));
            }
            let mut response = None;
            match packet.header.packet_type {
                PacketType::Data => {
                    let ip_packet = IpPacket::parse(plaintext).map_err(CoreError::Ip)?;
                    let destination = ip_packet.destination();
                    if !self.routes.lock().await.is_local(destination) {
                        return Err(CoreError::Ip(vela_ip::IpError::DestinationUnknown(
                            destination,
                        )));
                    }
                    self.observe(TrafficSample {
                        peer: Some(peer.info.node_id),
                        direction: TrafficDirection::Received,
                        path: source,
                        payload_bytes: ip_packet.as_bytes().len(),
                        encrypted_bytes: packet.payload.len(),
                        wire_bytes: input_wire_len(&packet),
                    });
                    events.push(VelaEvent::IpPacket {
                        peer: peer.info.node_id,
                        packet: ip_packet,
                    });
                }
                PacketType::KeepAlive => {}
                PacketType::DiagnosticPing => {
                    if plaintext.len() != DIAGNOSTIC_NONCE_LEN {
                        return Err(CoreError::InvalidDiagnosticPing);
                    }
                    let sequence = session.tx_sequence.fetch_add(1, Ordering::Relaxed);
                    let encrypted =
                        encrypt_payload(session, PacketType::DiagnosticPong, sequence, &plaintext)?;
                    response = Some((session.path, session.session_id, sequence, encrypted));
                }
                PacketType::DiagnosticPong => {
                    if plaintext.len() != DIAGNOSTIC_NONCE_LEN {
                        return Err(CoreError::InvalidDiagnosticPing);
                    }
                    let nonce: [u8; DIAGNOSTIC_NONCE_LEN] = plaintext
                        .try_into()
                        .expect("diagnostic nonce length checked");
                    if let Some(waiter) = session.ping_waiters.remove(&nonce) {
                        let _ = waiter.send(source);
                    }
                }
                PacketType::Probe | PacketType::ProbeResponse | PacketType::Handshake => {
                    return Err(CoreError::InvalidDiagnosticPing);
                }
            }
            drop(active);
            for event in events {
                self.emit(event).await;
            }
            if let Some((path, session_id, sequence, payload)) = response {
                self.send_packet(
                    path,
                    PacketType::DiagnosticPong,
                    session_id,
                    sequence,
                    &payload,
                )
                .await?;
            }
            return Ok(());
        }
        Ok(())
    }

    async fn establish(
        &self,
        peer: &Arc<PeerState>,
        session_id: u64,
        path: SocketAddr,
        cipher: SessionCipher,
    ) {
        let mut active = peer.active.lock().await;
        if active.is_some() {
            return;
        }
        *active = Some(ActiveSession {
            session_id,
            path,
            cipher,
            tx_sequence: AtomicU64::new(1),
            replay: ReplayWindow::default(),
            ping_waiters: HashMap::new(),
            created_at: Instant::now(),
            tx_bytes: AtomicU64::new(0),
        });
        drop(active);
        *peer.attempt.lock().await = None;
        peer.notify.notify_waiters();
        self.emit(VelaEvent::PeerConnected(peer.info.node_id)).await;
        self.flush_queue(peer).await;
    }

    async fn flush_queue(&self, peer: &Arc<PeerState>) {
        loop {
            let payload = peer.queue.lock().await.pop_front();
            let Some(payload) = payload else { break };
            if self.send_payload(peer, payload).await.is_err() {
                break;
            }
        }
    }

    async fn send_payload(&self, peer: &Arc<PeerState>, payload: Bytes) -> Result<(), SendError> {
        if unix_time() >= self.snapshot_expires_at.load(Ordering::Acquire) {
            if peer.active.lock().await.take().is_some() {
                self.emit(VelaEvent::PeerDisconnected(peer.info.node_id))
                    .await;
            }
            *peer.attempt.lock().await = None;
            peer.queue.lock().await.clear();
            return Err(SendError::SnapshotExpired);
        }
        let packet = IpPacket::parse(payload.clone()).map_err(SendError::Ip)?;
        let routed_peer = self
            .routes
            .lock()
            .await
            .validate_outbound(&packet)
            .map_err(SendError::Ip)?;
        if routed_peer != peer.info.node_id {
            return Err(SendError::WrongPeer);
        }
        if packet.as_bytes().len() > self.config.virtual_mtu {
            return Err(SendError::PacketTooLarge);
        }
        if payload.len() > self.config.max_payload_size {
            return Err(SendError::PacketTooLarge);
        }
        let mut active = peer.active.lock().await;
        let Some(session) = active.as_mut() else {
            let mut queue = peer.queue.lock().await;
            if queue.len() >= self.config.per_peer_queue_limit {
                return Err(SendError::QueueFull);
            }
            queue.push_back(payload);
            return Ok(());
        };
        let sequence = session.tx_sequence.fetch_add(1, Ordering::Relaxed);
        let encrypted_len = payload.len() + 16;
        let header = Header::new(
            PacketType::Data,
            session.session_id,
            sequence,
            encrypted_len,
        )
        .map_err(SendError::Protocol)?;
        let aad = encoded_header(&header);
        let encrypted = session
            .cipher
            .encrypt(sequence, &aad, &payload)
            .map_err(SendError::Crypto)?;
        let packet = WirePacket {
            header,
            payload: Bytes::from(encrypted),
        }
        .encode()
        .map_err(SendError::Protocol)?;
        self.socket
            .send_to(&packet, session.path)
            .await
            .map_err(SendError::Io)?;
        session
            .tx_bytes
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        self.observe(TrafficSample {
            peer: Some(peer.info.node_id),
            direction: TrafficDirection::Sent,
            path: session.path,
            payload_bytes: payload.len(),
            encrypted_bytes: encrypted_len,
            wire_bytes: packet.len(),
        });
        Ok(())
    }

    async fn send_packet(
        &self,
        target: SocketAddr,
        packet_type: PacketType,
        session_id: u64,
        sequence: u64,
        payload: &[u8],
    ) -> Result<(), CoreError> {
        let header = Header::new(packet_type, session_id, sequence, payload.len())?;
        let packet = WirePacket {
            header,
            payload: Bytes::copy_from_slice(payload),
        }
        .encode()?;
        self.socket.send_to(&packet, target).await?;
        Ok(())
    }

    async fn peer_for(&self, node_id: NodeId) -> Result<Arc<PeerState>, CoreError> {
        self.peers
            .lock()
            .await
            .get(&node_id)
            .cloned()
            .ok_or(CoreError::UnknownPeer(node_id))
    }

    async fn handshake_context(&self) -> Result<Vec<u8>, CoreError> {
        let network_id = *self.network_id.lock().await;
        let ipv4 = *self.local_ipv4.lock().await;
        let ipv6 = *self.local_ipv6.lock().await;
        let generation = self.snapshot_generation.load(Ordering::Acquire);
        Ok(encode_handshake_context(
            network_id,
            self.identity.public().node_id,
            ipv4,
            ipv6,
            generation,
        ))
    }

    async fn validate_handshake_context(
        &self,
        bytes: &[u8],
        sender: NodeId,
        peer: &PeerInfo,
    ) -> Result<(), CoreError> {
        let expected_network_id = *self.network_id.lock().await;
        let context = decode_handshake_context(bytes).ok_or(CoreError::InvalidHandshake)?;
        if context.network_id != expected_network_id
            || context.generation != self.snapshot_generation.load(Ordering::Acquire)
            || context.node_id != sender
            || context.node_id != peer.node_id
            || context.virtual_ipv4 != peer.virtual_ipv4
            || context.virtual_ipv6 != peer.virtual_ipv6
        {
            return Err(CoreError::InvalidHandshake);
        }
        Ok(())
    }

    async fn emit(&self, event: VelaEvent) {
        let _ = self.event_tx.send(event).await;
    }
    fn observe(&self, sample: TrafficSample) {
        if let Some(observer) = &self.observer {
            observer.record(sample);
        }
    }
}

#[derive(Clone)]
pub struct PeerHandle {
    node: VelaNode,
    peer_id: NodeId,
}

impl PeerHandle {
    pub fn node_id(&self) -> NodeId {
        self.peer_id
    }

    pub async fn send_ip(&self, payload: impl Into<Bytes>) -> Result<(), SendError> {
        let peer = self
            .node
            .inner
            .peers
            .lock()
            .await
            .get(&self.peer_id)
            .cloned()
            .ok_or(SendError::UnknownPeer)?;
        let should_connect =
            peer.active.lock().await.is_none() && peer.attempt.lock().await.is_none();
        let result = self.node.inner.send_payload(&peer, payload.into()).await;
        if result.is_ok() && should_connect {
            let node = self.node.clone();
            let peer_id = self.peer_id;
            tokio::spawn(async move {
                let _ = node.connect(peer_id).await;
            });
        }
        result
    }

    pub async fn diagnostic_ping(
        &self,
        count: usize,
        timeout_duration: Duration,
    ) -> Result<DiagnosticPingResult, DiagnosticPingError> {
        if count == 0 {
            return Err(DiagnosticPingError::InvalidCount);
        }
        let peer = self
            .node
            .inner
            .peers
            .lock()
            .await
            .get(&self.peer_id)
            .cloned()
            .ok_or(DiagnosticPingError::UnknownPeer)?;
        let mut rtts = Vec::with_capacity(count);
        let mut path = None;
        for _ in 0..count {
            let mut nonce = [0u8; DIAGNOSTIC_NONCE_LEN];
            rand::rngs::OsRng.fill_bytes(&mut nonce);
            let (receiver, nonce, target, session_id, sequence, encrypted) = {
                let mut active = peer.active.lock().await;
                let session = active.as_mut().ok_or(DiagnosticPingError::NotConnected)?;
                let sequence = session.tx_sequence.fetch_add(1, Ordering::Relaxed);
                let (sender, receiver) = oneshot::channel();
                session.ping_waiters.insert(nonce, sender);
                let encrypted =
                    encrypt_payload(session, PacketType::DiagnosticPing, sequence, &nonce)
                        .map_err(DiagnosticPingError::Core)?;
                (
                    receiver,
                    nonce,
                    session.path,
                    session.session_id,
                    sequence,
                    encrypted,
                )
            };
            let started = Instant::now();
            if let Err(error) = self
                .node
                .inner
                .send_packet(
                    target,
                    PacketType::DiagnosticPing,
                    session_id,
                    sequence,
                    &encrypted,
                )
                .await
            {
                if let Some(session) = peer.active.lock().await.as_mut() {
                    session.ping_waiters.remove(&nonce);
                }
                return Err(DiagnosticPingError::Core(error));
            }
            match timeout(timeout_duration, receiver).await {
                Ok(Ok(response_path)) => {
                    path = Some(response_path);
                    rtts.push(started.elapsed());
                }
                _ => {
                    if let Some(session) = peer.active.lock().await.as_mut() {
                        session.ping_waiters.remove(&nonce);
                    }
                    return Err(DiagnosticPingError::Timeout);
                }
            }
        }
        Ok(DiagnosticPingResult {
            peer: self.peer_id,
            path: path.expect("count is non-zero"),
            rtts,
        })
    }
}

pub const DIAGNOSTIC_NONCE_LEN: usize = 16;

#[derive(Clone, Debug)]
pub struct DiagnosticPingResult {
    pub peer: NodeId,
    pub path: SocketAddr,
    pub rtts: Vec<Duration>,
}

#[derive(Clone, Debug)]
pub enum VelaEvent {
    PeerConnecting(NodeId),
    PeerConnected(NodeId),
    PeerDisconnected(NodeId),
    PeerUnreachable(NodeId),
    PathChanged(NodeId, SocketAddr),
    IpPacket { peer: NodeId, packet: IpPacket },
}

struct PeerState {
    info: PeerInfo,
    connect: Mutex<()>,
    attempt: Mutex<Option<Attempt>>,
    active: Mutex<Option<ActiveSession>>,
    notify: Notify,
    queue: Mutex<VecDeque<Bytes>>,
}

impl PeerState {
    fn new(info: PeerInfo) -> Self {
        Self {
            info,
            connect: Mutex::new(()),
            attempt: Mutex::new(None),
            active: Mutex::new(None),
            notify: Notify::new(),
            queue: Mutex::new(VecDeque::new()),
        }
    }
}

struct Attempt {
    session_id: u64,
    handshake: Option<NoiseHandshake>,
}

struct ActiveSession {
    session_id: u64,
    path: SocketAddr,
    cipher: SessionCipher,
    tx_sequence: AtomicU64,
    replay: ReplayWindow,
    ping_waiters: HashMap<[u8; DIAGNOSTIC_NONCE_LEN], oneshot::Sender<SocketAddr>>,
    created_at: Instant,
    tx_bytes: AtomicU64,
}

impl ActiveSession {
    fn needs_rekey(&self) -> bool {
        self.created_at.elapsed() >= Duration::from_secs(3600)
            || self.tx_bytes.load(Ordering::Relaxed) >= 1 << 30
    }
}

const REPLAY_WINDOW_SIZE: usize = 1024;
const REPLAY_WORDS: usize = REPLAY_WINDOW_SIZE / u64::BITS as usize;

#[derive(Default)]
struct ReplayWindow {
    highest: Option<u64>,
    bits: [u64; REPLAY_WORDS],
}

impl ReplayWindow {
    fn accept(&mut self, sequence: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.bits[0] = 1;
            return true;
        };
        if sequence > highest {
            let shift = sequence - highest;
            self.shift_left(shift);
            self.bits[0] |= 1;
            self.highest = Some(sequence);
            true
        } else {
            let distance = highest - sequence;
            if distance >= REPLAY_WINDOW_SIZE as u64 {
                return false;
            }
            let word = distance as usize / u64::BITS as usize;
            let bit = distance as usize % u64::BITS as usize;
            if self.bits[word] & (1 << bit) != 0 {
                return false;
            }
            self.bits[word] |= 1 << bit;
            true
        }
    }

    fn shift_left(&mut self, shift: u64) {
        if shift >= REPLAY_WINDOW_SIZE as u64 {
            self.bits = [0; REPLAY_WORDS];
            return;
        }
        let shift = shift as usize;
        let word_shift = shift / u64::BITS as usize;
        let bit_shift = shift % u64::BITS as usize;
        let old = self.bits;
        self.bits = [0; REPLAY_WORDS];
        for index in (word_shift..REPLAY_WORDS).rev() {
            self.bits[index] |= old[index - word_shift] << bit_shift;
            if bit_shift != 0 && index > word_shift {
                self.bits[index] |= old[index - word_shift - 1] >> (u64::BITS as usize - bit_shift);
            }
        }
    }
}

#[derive(Clone, Copy)]
struct Probe {
    sender: NodeId,
    receiver: NodeId,
    session_id: u64,
    timestamp: u64,
    nonce: [u8; 16],
    signature: [u8; 64],
}

fn encode_probe(
    sender: NodeId,
    receiver: NodeId,
    session_id: u64,
    timestamp: u64,
    nonce: [u8; 16],
    identity: &Identity,
) -> Vec<u8> {
    let mut data = Vec::with_capacity(32 + 32 + 8 + 8 + 16 + 64);
    data.extend_from_slice(sender.as_bytes());
    data.extend_from_slice(receiver.as_bytes());
    data.extend_from_slice(&session_id.to_be_bytes());
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&identity.sign(&probe_signing_bytes(&data)));
    data
}

fn probe_signing_bytes(data: &[u8]) -> Vec<u8> {
    let mut signed = b"VELA-PROBE-v1".to_vec();
    signed.extend_from_slice(data);
    signed
}

fn decode_probe(data: &[u8]) -> Result<Probe, CoreError> {
    if data.len() != 160 {
        return Err(CoreError::InvalidProbe);
    }
    Ok(Probe {
        sender: NodeId::new(data[..32].try_into().unwrap()),
        receiver: NodeId::new(data[32..64].try_into().unwrap()),
        session_id: u64::from_be_bytes(data[64..72].try_into().unwrap()),
        timestamp: u64::from_be_bytes(data[72..80].try_into().unwrap()),
        nonce: data[80..96].try_into().unwrap(),
        signature: data[96..160].try_into().unwrap(),
    })
}

fn verify_probe(probe: &Probe, info: &PeerInfo) -> Result<(), CoreError> {
    if probe.sender != info.node_id {
        return Err(CoreError::InvalidProbe);
    }
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(probe.sender.as_bytes());
    data.extend_from_slice(probe.receiver.as_bytes());
    data.extend_from_slice(&probe.session_id.to_be_bytes());
    data.extend_from_slice(&probe.timestamp.to_be_bytes());
    data.extend_from_slice(&probe.nonce);
    let key = ed25519_dalek::VerifyingKey::from_bytes(&info.signing_public)
        .map_err(|_| CoreError::InvalidProbe)?;
    key.verify_strict(
        &probe_signing_bytes(&data),
        &ed25519_dalek::Signature::from_bytes(&probe.signature),
    )
    .map_err(|_| CoreError::InvalidProbe)?;
    if probe.timestamp.abs_diff(unix_time()) > 90 {
        return Err(CoreError::InvalidProbe);
    }
    Ok(())
}

const HANDSHAKE_CONTEXT_MAGIC: &[u8] = b"VELA-HS-v1";

struct HandshakeContext {
    network_id: [u8; 16],
    generation: u64,
    node_id: NodeId,
    virtual_ipv4: Option<Ipv4Addr>,
    virtual_ipv6: Option<Ipv6Addr>,
}

fn encode_handshake_context(
    network_id: [u8; 16],
    node_id: NodeId,
    virtual_ipv4: Option<Ipv4Addr>,
    virtual_ipv6: Option<Ipv6Addr>,
    generation: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + 16 + 8 + 32 + 1 + 4 + 1 + 16);
    out.extend_from_slice(HANDSHAKE_CONTEXT_MAGIC);
    out.extend_from_slice(&network_id);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(node_id.as_bytes());
    match virtual_ipv4 {
        Some(address) => {
            out.push(1);
            out.extend_from_slice(&address.octets());
        }
        None => {
            out.push(0);
            out.extend_from_slice(&[0; 4]);
        }
    }
    match virtual_ipv6 {
        Some(address) => {
            out.push(1);
            out.extend_from_slice(&address.octets());
        }
        None => {
            out.push(0);
            out.extend_from_slice(&[0; 16]);
        }
    }
    out
}

fn decode_handshake_context(bytes: &[u8]) -> Option<HandshakeContext> {
    let magic_len = HANDSHAKE_CONTEXT_MAGIC.len();
    if bytes.len() != magic_len + 16 + 8 + 32 + 1 + 4 + 1 + 16
        || &bytes[..magic_len] != HANDSHAKE_CONTEXT_MAGIC
    {
        return None;
    }
    let mut offset = magic_len;
    let network_id = bytes[offset..offset + 16].try_into().ok()?;
    offset += 16;
    let generation = u64::from_be_bytes(bytes[offset..offset + 8].try_into().ok()?);
    offset += 8;
    let node_id = NodeId::new(bytes[offset..offset + 32].try_into().ok()?);
    offset += 32;
    let virtual_ipv4 = match bytes[offset] {
        0 => None,
        1 => {
            let octets: [u8; 4] = bytes[offset + 1..offset + 5].try_into().ok()?;
            Some(Ipv4Addr::from(octets))
        }
        _ => return None,
    };
    offset += 5;
    let virtual_ipv6 = match bytes[offset] {
        0 => None,
        1 => {
            let octets: [u8; 16] = bytes[offset + 1..offset + 17].try_into().ok()?;
            Some(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(HandshakeContext {
        network_id,
        generation,
        node_id,
        virtual_ipv4,
        virtual_ipv6,
    })
}

fn validate_peer_info(info: &PeerInfo) -> Result<(), CoreError> {
    if NodeId::new(*blake3::hash(&info.signing_public).as_bytes()) != info.node_id {
        return Err(CoreError::InvalidPeer);
    }
    Ok(())
}

fn validate_peer_membership(
    info: &PeerInfo,
    server_public_key: Option<[u8; 32]>,
) -> Result<(), CoreError> {
    let Some(server_public_key) = server_public_key else {
        return Ok(());
    };
    let credential: MembershipCredential =
        serde_json::from_slice(&info.credential).map_err(|_| CoreError::InvalidPeer)?;
    credential
        .verify(&server_public_key, unix_time())
        .map_err(|_| CoreError::PeerCredentialExpired)?;
    if credential.node_id != info.node_id
        || credential.signing_public != info.signing_public
        || credential.noise_public != info.noise_public
    {
        return Err(CoreError::InvalidPeer);
    }
    Ok(())
}
fn random_session_id() -> u64 {
    let mut value = 0;
    while value == 0 {
        value = rand::random();
    }
    value
}
fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}
fn encoded_header(header: &Header) -> Vec<u8> {
    let mut bytes = BytesMut::with_capacity(vela_proto::HEADER_LEN);
    header.encode(&mut bytes);
    bytes.to_vec()
}
fn encrypt_payload(
    session: &ActiveSession,
    packet_type: PacketType,
    sequence: u64,
    payload: &[u8],
) -> Result<Vec<u8>, CoreError> {
    let header = Header::new(
        packet_type,
        session.session_id,
        sequence,
        payload.len() + 16,
    )?;
    Ok(session
        .cipher
        .encrypt(sequence, &encoded_header(&header), payload)?)
}
fn input_wire_len(packet: &WirePacket) -> usize {
    vela_proto::HEADER_LEN + packet.payload.len()
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtoError),
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("IP packet error: {0}")]
    Ip(#[from] vela_ip::IpError),
    #[error("coordination client error: {0}")]
    Coordination(#[from] CoordClientError),
    #[error("STUN error: {0}")]
    Stun(#[from] vela_stun::StunError),
    #[error("missing DatagramProvider")]
    MissingProvider,
    #[error("hybrid post-quantum crypto is not available in this build")]
    HybridCryptoUnavailable,
    #[error("unknown peer {0}")]
    UnknownPeer(NodeId),
    #[error("invalid peer identity")]
    InvalidPeer,
    #[error("invalid connectivity probe")]
    InvalidProbe,
    #[error("invalid handshake")]
    InvalidHandshake,
    #[error("invalid diagnostic ping payload")]
    InvalidDiagnosticPing,
    #[error("network snapshot has expired")]
    SnapshotExpired,
    #[error("network snapshot belongs to a different network")]
    NetworkMismatch,
    #[error("network snapshot is older than the active snapshot")]
    StaleSnapshot,
    #[error("network snapshot does not contain this node")]
    LocalPeerMissing,
    #[error("network snapshot does not assign a local virtual address")]
    LocalAddressMissing,
    #[error("peer membership credential has expired or is invalid")]
    PeerCredentialExpired,
}

#[derive(Debug, Error)]
pub enum ConnectError {
    #[error("node has not been started")]
    NotStarted,
    #[error("unknown peer")]
    UnknownPeer,
    #[error("peer has no candidates")]
    NoCandidates,
    #[error("connection timed out")]
    Timeout,
    #[error("core error: {0}")]
    Core(#[from] CoreError),
}

#[derive(Debug, Error)]
pub enum SendError {
    #[error("unknown peer")]
    UnknownPeer,
    #[error("packet is routed to a different peer")]
    WrongPeer,
    #[error("peer is not connected")]
    NotConnected,
    #[error("peer send queue is full")]
    QueueFull,
    #[error("packet is larger than configured max payload")]
    PacketTooLarge,
    #[error("network snapshot has expired")]
    SnapshotExpired,
    #[error("IP packet error: {0}")]
    Ip(#[from] vela_ip::IpError),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtoError),
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
}

#[derive(Debug, Error)]
pub enum DiagnosticPingError {
    #[error("diagnostic ping count must be greater than zero")]
    InvalidCount,
    #[error("unknown peer")]
    UnknownPeer,
    #[error("peer is not connected")]
    NotConnected,
    #[error("diagnostic ping timed out")]
    Timeout,
    #[error("core error: {0}")]
    Core(#[from] CoreError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use vela_crypto::ServerSigner;
    use vela_proto::{Candidate, Ipv4Cidr, NetworkSnapshot};

    fn peer_info(identity: &Identity, address: SocketAddr, virtual_ipv4: Ipv4Addr) -> PeerInfo {
        let public = identity.public();
        PeerInfo {
            node_id: public.node_id,
            signing_public: public.signing_public,
            noise_public: public.noise_public,
            candidates: vec![Candidate::Host(address)],
            virtual_ipv4: Some(virtual_ipv4),
            virtual_ipv6: None,
            credential: Vec::new(),
            capabilities: Vec::new(),
        }
    }

    #[test]
    fn explicit_ipv6_bind_is_advertised_as_a_host_candidate() {
        let bind: SocketAddr = "[2001:db8::10]:0".parse().unwrap();
        let candidates = host_candidates(bind, 45101, None);
        assert_eq!(
            candidates,
            vec![Candidate::Host("[2001:db8::10]:45101".parse().unwrap())]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_interface_binding_matches_socket_address_family() {
        let mut routes = route_manager::RouteManager::new().unwrap();
        let Some(route) = routes
            .find_route(&IpAddr::V4(Ipv4Addr::UNSPECIFIED))
            .unwrap()
        else {
            return;
        };
        let Some(index) = route.if_index().and_then(std::num::NonZeroU32::new) else {
            return;
        };
        let interface = DefaultRouteInterface {
            name: route.if_name().unwrap_or("unknown").to_owned(),
            index: Some(index),
        };

        let ipv4_socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        bind_socket_to_interface(&ipv4_socket, &interface, true).unwrap();

        let ipv6_socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        bind_socket_to_interface(&ipv6_socket, &interface, false).unwrap();
    }

    #[tokio::test]
    async fn two_nodes_establish_an_encrypted_local_datagram_session() {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let address_a: SocketAddr = "127.0.0.1:45101".parse().unwrap();
        let address_b: SocketAddr = "127.0.0.1:45102".parse().unwrap();
        let provider_a = Arc::new(TokioDatagramProvider::new(vec![Candidate::Host(address_a)]));
        let provider_b = Arc::new(TokioDatagramProvider::new(vec![Candidate::Host(address_b)]));
        let config_a = NodeConfig {
            bind: BindOptions {
                local_addr: address_a,
            },
            connect_timeout: Duration::from_secs(2),
            virtual_ipv4: Some(Ipv4Addr::new(10, 254, 0, 1)),
            ..NodeConfig::default()
        };
        let config_b = NodeConfig {
            bind: BindOptions {
                local_addr: address_b,
            },
            connect_timeout: Duration::from_secs(2),
            virtual_ipv4: Some(Ipv4Addr::new(10, 254, 0, 2)),
            ..NodeConfig::default()
        };
        let node_a = VelaNode::builder()
            .identity(identity_a.clone())
            .datagram_provider(provider_a)
            .config(config_a)
            .build()
            .await
            .unwrap();
        let node_b = VelaNode::builder()
            .identity(identity_b.clone())
            .datagram_provider(provider_b)
            .config(config_b)
            .build()
            .await
            .unwrap();
        node_a
            .register_peer(peer_info(
                &identity_b,
                address_b,
                Ipv4Addr::new(10, 254, 0, 2),
            ))
            .await
            .unwrap();
        node_b
            .register_peer(peer_info(
                &identity_a,
                address_a,
                Ipv4Addr::new(10, 254, 0, 1),
            ))
            .await
            .unwrap();
        node_a.start().await.unwrap();
        node_b.start().await.unwrap();
        let a_id = node_a.node_id();
        let b_id = node_b.node_id();
        let handle_a = node_a.connect(b_id).await.unwrap();
        let diagnostic = handle_a
            .diagnostic_ping(3, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(diagnostic.peer, b_id);
        assert_eq!(diagnostic.path, address_b);
        assert_eq!(diagnostic.rtts.len(), 3);
        let mut packet = vec![0u8; 20 + 12];
        packet[0] = 0x45;
        let packet_len = packet.len() as u16;
        packet[2..4].copy_from_slice(&packet_len.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&[10, 254, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 254, 0, 2]);
        packet[20..].copy_from_slice(b"hello from A");
        let mut checksum = 0u32;
        for chunk in packet[..20].chunks(2) {
            checksum = checksum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
            while checksum > u32::from(u16::MAX) {
                checksum = (checksum & u32::from(u16::MAX)) + (checksum >> 16);
            }
        }
        packet[10..12].copy_from_slice(&(!(checksum as u16)).to_be_bytes());
        handle_a.send_ip(packet).await.unwrap();
        let event = timeout(Duration::from_secs(1), async {
            loop {
                if let Some(event @ VelaEvent::IpPacket { .. }) = node_b.next_event().await {
                    break event;
                }
            }
        })
        .await
        .unwrap();
        assert!(
            matches!(event, VelaEvent::IpPacket { peer, ref packet } if peer == a_id && packet.destination() == IpAddr::V4(Ipv4Addr::new(10, 254, 0, 2)))
        );
        node_a.shutdown().await;
        node_b.shutdown().await;
    }

    #[tokio::test]
    async fn default_dual_stack_nodes_establish_an_ipv6_session() {
        if UdpSocket::bind("[::1]:0").await.is_err() {
            return;
        }

        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let node_a = VelaNode::builder()
            .identity(identity_a.clone())
            .datagram_provider(Arc::new(TokioDatagramProvider::new(Vec::new())))
            .config(NodeConfig {
                bind: BindOptions {
                    local_addr: "[::1]:0".parse().unwrap(),
                },
                virtual_ipv4: Some(Ipv4Addr::new(10, 254, 0, 3)),
                ..NodeConfig::default()
            })
            .build()
            .await
            .unwrap();
        let node_b = VelaNode::builder()
            .identity(identity_b.clone())
            .datagram_provider(Arc::new(TokioDatagramProvider::new(Vec::new())))
            .config(NodeConfig {
                bind: BindOptions {
                    local_addr: "[::1]:0".parse().unwrap(),
                },
                virtual_ipv4: Some(Ipv4Addr::new(10, 254, 0, 4)),
                ..NodeConfig::default()
            })
            .build()
            .await
            .unwrap();
        let address_a = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            node_a.local_addr().unwrap().port(),
        );
        let address_b = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            node_b.local_addr().unwrap().port(),
        );
        node_a
            .register_peer(peer_info(
                &identity_b,
                address_b,
                Ipv4Addr::new(10, 254, 0, 4),
            ))
            .await
            .unwrap();
        node_b
            .register_peer(peer_info(
                &identity_a,
                address_a,
                Ipv4Addr::new(10, 254, 0, 3),
            ))
            .await
            .unwrap();
        node_a.start().await.unwrap();
        node_b.start().await.unwrap();

        let handle = node_a.connect(node_b.node_id()).await.unwrap();
        let diagnostic = handle
            .diagnostic_ping(1, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(diagnostic.path, address_b);

        node_a.shutdown().await;
        node_b.shutdown().await;
    }

    #[tokio::test]
    async fn signed_snapshot_replaces_routes_and_rejects_revoked_peers() {
        let signer = ServerSigner::generate();
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let address: SocketAddr = "127.0.0.1:45105".parse().unwrap();
        let network_id = [9; 16];
        let virtual_a = Ipv4Addr::new(10, 254, 0, 11);
        let virtual_b = Ipv4Addr::new(10, 254, 0, 12);
        let credential = |identity: &Identity| {
            MembershipCredential::unsigned(
                &identity.public(),
                "snapshot-test",
                unix_time() + 60,
                signer.key_id(),
            )
            .sign(&signer)
        };
        let peer = |identity: &Identity, virtual_ipv4, credential| {
            let public = identity.public();
            PeerInfo {
                node_id: public.node_id,
                signing_public: public.signing_public,
                noise_public: public.noise_public,
                candidates: vec![Candidate::Host(address)],
                virtual_ipv4: Some(virtual_ipv4),
                virtual_ipv6: None,
                credential: serde_json::to_vec(&credential).unwrap(),
                capabilities: Vec::new(),
            }
        };
        let local = peer(&identity_a, virtual_a, credential(&identity_a));
        let remote = peer(&identity_b, virtual_b, credential(&identity_b));
        let node = VelaNode::builder()
            .identity(identity_a.clone())
            .datagram_provider(Arc::new(TokioDatagramProvider::new(vec![Candidate::Host(
                address,
            )])))
            .config(NodeConfig {
                bind: BindOptions {
                    local_addr: address,
                },
                network_id,
                server_public_key: Some(signer.public()),
                virtual_ipv4: Some(virtual_a),
                ..NodeConfig::default()
            })
            .build()
            .await
            .unwrap();
        let make_snapshot = |generation, peers| {
            signer.sign_snapshot(NetworkSnapshot {
                network_id,
                generation,
                virtual_ipv4: Some(Ipv4Cidr {
                    address: Ipv4Addr::new(10, 254, 0, 0),
                    prefix_len: 16,
                }),
                virtual_ipv6: None,
                doh_servers: Vec::new(),
                stun_servers: Vec::new(),
                peers,
                expires_at: unix_time() + 60,
                signature: Vec::new(),
            })
        };
        node.apply_snapshot(make_snapshot(1, vec![local.clone(), remote.clone()]))
            .await
            .unwrap();
        assert!(
            node.send_ip(ipv4_test_packet(virtual_a, virtual_b))
                .await
                .is_ok()
        );

        node.apply_snapshot(make_snapshot(2, vec![local]))
            .await
            .unwrap();
        assert!(matches!(
            node.send_ip(ipv4_test_packet(virtual_a, virtual_b)).await,
            Err(SendError::Ip(vela_ip::IpError::DestinationUnknown(address)))
                if address == IpAddr::V4(virtual_b)
        ));
        assert!(matches!(
            node.apply_snapshot(make_snapshot(1, vec![remote])).await,
            Err(CoreError::StaleSnapshot)
        ));
    }

    fn ipv4_test_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        let mut checksum = 0u32;
        for chunk in packet[..20].chunks_exact(2) {
            checksum = checksum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
            while checksum > u32::from(u16::MAX) {
                checksum = (checksum & u32::from(u16::MAX)) + (checksum >> 16);
            }
        }
        packet[10..12].copy_from_slice(&(!(checksum as u16)).to_be_bytes());
        packet
    }

    #[test]
    fn replay_window_allows_bounded_reordering_and_rejects_replays() {
        let mut window = ReplayWindow::default();
        assert!(window.accept(100));
        assert!(window.accept(98));
        assert!(window.accept(101));
        assert!(!window.accept(98));
        assert!(window.accept(100 + REPLAY_WINDOW_SIZE as u64));
        assert!(!window.accept(99));
    }
}
