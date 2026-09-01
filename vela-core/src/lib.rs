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
use serde::Serialize;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::{HashMap, VecDeque},
    fmt, io,
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
    task::JoinHandle,
    time::{Instant, timeout},
};
use tracing::{debug, info, warn};
use vela_coord_client::{CoordClientError, CoordinationClient, Registration};
use vela_crypto::{
    CryptoError, CryptoPolicy, Identity, MembershipCredential, NoiseHandshake, SessionCipher,
    verify_snapshot,
};
use vela_ip::{IpPacket, RouteTable};
use vela_proto::{
    Candidate, Header, NetworkSnapshot, NodeId, PacketType, PeerCapability, PeerInfo, ProtoError,
    PublicPeerInfo, WirePacket,
};

#[derive(Clone, Debug, Default)]
pub struct BindOptions {
    /// Port used by both address families. Zero asks the provider for fresh
    /// ephemeral ports, one for each socket.
    pub port: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    fn of(address: SocketAddr) -> Self {
        if address.is_ipv4() {
            Self::Ipv4
        } else {
            Self::Ipv6
        }
    }
}

impl fmt::Display for AddressFamily {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        })
    }
}

#[async_trait]
pub trait DatagramSocket: Send + Sync {
    async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> io::Result<usize>;
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn local_addr(&self) -> io::Result<SocketAddr>;

    fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(vec![self.local_addr()?])
    }

    async fn shutdown(&self) {}

    fn failure_family(&self) -> Option<AddressFamily> {
        None
    }
}

#[async_trait]
pub trait DatagramProvider: Send + Sync {
    async fn bind(&self, options: BindOptions) -> Result<Arc<dyn DatagramSocket>, CoreError>;
    fn local_candidates(&self) -> Vec<Candidate>;

    /// Returns the interfaces selected for the default local sockets.
    ///
    /// Providers that manage their own socket and candidates can leave this
    /// unset. The built-in provider uses it to keep fallback host candidates
    /// consistent with the interface-bound socket.
    fn local_interfaces(&self) -> Vec<(AddressFamily, String)> {
        Vec::new()
    }
}

pub struct TokioDatagramProvider {
    pub host_candidates: Vec<Candidate>,
    selected_interfaces: StdMutex<Vec<(AddressFamily, DefaultRouteInterface)>>,
    preferred_ports: Option<[Option<u16>; 2]>,
}

impl TokioDatagramProvider {
    pub fn new(host_candidates: Vec<Candidate>) -> Self {
        Self {
            host_candidates,
            selected_interfaces: StdMutex::new(Vec::new()),
            preferred_ports: None,
        }
    }

    pub fn with_preferred_ports(
        host_candidates: Vec<Candidate>,
        preferred_ports: [Option<u16>; 2],
    ) -> Self {
        Self {
            host_candidates,
            selected_interfaces: StdMutex::new(Vec::new()),
            preferred_ports: Some(preferred_ports),
        }
    }
}

#[derive(Clone, Debug)]
struct DefaultRouteInterface {
    name: String,
    index: Option<std::num::NonZeroU32>,
}

fn default_route_interface(ipv4: bool) -> io::Result<Option<DefaultRouteInterface>> {
    let mut routes = route_manager::RouteManager::new()?;
    let route = default_route(&mut routes, ipv4)?;
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
    _ipv4: bool,
) -> io::Result<()> {
    // Windows and BSD platforms use the system route for outgoing packets;
    // socket2 does not expose an interface-binding option for them.
    Ok(())
}

fn bind_udp_socket(
    family: AddressFamily,
    port: u16,
    interface: Option<&DefaultRouteInterface>,
) -> Result<UdpSocket, CoreError> {
    let socket = Socket::new(
        match family {
            AddressFamily::Ipv4 => Domain::IPV4,
            AddressFamily::Ipv6 => Domain::IPV6,
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )
    .map_err(|source| CoreError::DatagramBind {
        family,
        port,
        source,
    })?;
    if family == AddressFamily::Ipv6 {
        socket
            .set_only_v6(true)
            .map_err(|source| CoreError::DatagramBind {
                family,
                port,
                source,
            })?;
    }
    if let Some(interface) = interface {
        bind_socket_to_interface(&socket, interface, family == AddressFamily::Ipv4).map_err(
            |source| CoreError::DatagramBind {
                family,
                port,
                source,
            },
        )?;
    }
    socket
        .set_nonblocking(true)
        .map_err(|source| CoreError::DatagramBind {
            family,
            port,
            source,
        })?;
    let local_addr = match family {
        AddressFamily::Ipv4 => SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)),
        AddressFamily::Ipv6 => SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)),
    };
    socket
        .bind(&local_addr.into())
        .map_err(|source| CoreError::DatagramBind {
            family,
            port,
            source,
        })?;
    UdpSocket::from_std(socket.into()).map_err(CoreError::Io)
}

fn bind_socket_pair(
    ports: [u16; 2],
    interfaces: [Option<&DefaultRouteInterface>; 2],
) -> Result<(UdpSocket, UdpSocket), CoreError> {
    let ipv4 = bind_udp_socket(AddressFamily::Ipv4, ports[0], interfaces[0])?;
    let ipv6 = bind_udp_socket(AddressFamily::Ipv6, ports[1], interfaces[1])?;
    Ok((ipv4, ipv6))
}

#[async_trait]
impl DatagramProvider for TokioDatagramProvider {
    async fn bind(&self, options: BindOptions) -> Result<Arc<dyn DatagramSocket>, CoreError> {
        let mut interfaces = [None, None];
        if self.host_candidates.is_empty() {
            for (slot, family) in [AddressFamily::Ipv4, AddressFamily::Ipv6]
                .into_iter()
                .enumerate()
            {
                interfaces[slot] = match default_route_interface(family == AddressFamily::Ipv4) {
                    Ok(interface) => interface,
                    Err(error) => {
                        tracing::debug!(
                            debug_marker = "vela-udp",
                            %family,
                            error = %error,
                            "failed to find default route; leaving socket unpinned"
                        );
                        None
                    }
                };
            }
        }
        let preferred = self.preferred_ports;
        let attempts = if options.port != 0 {
            vec![[options.port, options.port]]
        } else {
            let mut attempts = Vec::new();
            if let Some(preferred) = preferred {
                let ports = [preferred[0].unwrap_or(0), preferred[1].unwrap_or(0)];
                if ports != [0, 0] {
                    attempts.push(ports);
                }
            }
            if attempts.last() != Some(&[0, 0]) {
                attempts.push([0, 0]);
            }
            attempts
        };
        let mut last_error = None;
        for (attempt, ports) in attempts.into_iter().enumerate() {
            match bind_socket_pair(ports, [interfaces[0].as_ref(), interfaces[1].as_ref()]) {
                Ok((ipv4, ipv6)) => {
                    let local_addrs = [ipv4.local_addr()?, ipv6.local_addr()?];
                    *self
                        .selected_interfaces
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = interfaces
                        .into_iter()
                        .enumerate()
                        .filter_map(|(index, interface)| {
                            interface.map(|interface| {
                                ([AddressFamily::Ipv4, AddressFamily::Ipv6][index], interface)
                            })
                        })
                        .collect();
                    if attempt > 0 {
                        tracing::debug!(
                            debug_marker = "vela-udp",
                            ?local_addrs,
                            "preferred UDP ports were unavailable; using fresh ports"
                        );
                    }
                    return Ok(Arc::new(TokioDatagramSocket::new(ipv4, ipv6, local_addrs)));
                }
                Err(error) => {
                    tracing::debug!(
                        debug_marker = "vela-udp",
                        ?ports,
                        attempt,
                        error = %error,
                        "failed to bind both peer UDP sockets"
                    );
                    last_error = Some(error);
                    if options.port != 0 {
                        break;
                    }
                }
            }
        }
        Err(last_error.expect("at least one UDP bind attempt"))
    }

    fn local_candidates(&self) -> Vec<Candidate> {
        self.host_candidates.clone()
    }

    fn local_interfaces(&self) -> Vec<(AddressFamily, String)> {
        self.selected_interfaces
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(family, interface)| (*family, interface.name.clone()))
            .collect()
    }
}

fn host_candidates(
    local_addrs: &[SocketAddr],
    selected_interfaces: &[(AddressFamily, String)],
) -> Vec<Candidate> {
    let Ok(interfaces) = get_if_addrs() else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for interface in interfaces {
        let family = AddressFamily::of(SocketAddr::new(interface.ip(), 0));
        let Some(port) = local_addrs
            .iter()
            .find(|address| AddressFamily::of(**address) == family)
            .map(SocketAddr::port)
        else {
            continue;
        };
        if !selected_interfaces
            .iter()
            .any(|(selected_family, name)| *selected_family == family && name == &interface.name)
        {
            continue;
        }
        if interface.is_loopback() || interface.is_link_local() {
            continue;
        }
        let address = interface.ip();
        let candidate = Candidate::Host(SocketAddr::new(address, port));
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }
    candidates
}

type DatagramMessage = io::Result<(Vec<u8>, SocketAddr)>;

struct TokioDatagramSocket {
    ipv4: Arc<UdpSocket>,
    ipv6: Arc<UdpSocket>,
    receiver: Mutex<mpsc::Receiver<DatagramMessage>>,
    shutdown: Arc<Notify>,
    closed: Arc<AtomicBool>,
    readers: StdMutex<Vec<JoinHandle<()>>>,
    failure_family: Arc<StdMutex<Option<AddressFamily>>>,
    local_addrs: [SocketAddr; 2],
}

impl TokioDatagramSocket {
    fn new(ipv4: UdpSocket, ipv6: UdpSocket, local_addrs: [SocketAddr; 2]) -> Self {
        let ipv4 = Arc::new(ipv4);
        let ipv6 = Arc::new(ipv6);
        let shutdown = Arc::new(Notify::new());
        let closed = Arc::new(AtomicBool::new(false));
        let failure_family = Arc::new(StdMutex::new(None));
        let (sender, receiver) = mpsc::channel(256);
        let readers = vec![
            spawn_datagram_reader(
                AddressFamily::Ipv4,
                Arc::clone(&ipv4),
                sender.clone(),
                Arc::clone(&shutdown),
                Arc::clone(&closed),
                Arc::clone(&failure_family),
            ),
            spawn_datagram_reader(
                AddressFamily::Ipv6,
                Arc::clone(&ipv6),
                sender,
                Arc::clone(&shutdown),
                Arc::clone(&closed),
                Arc::clone(&failure_family),
            ),
        ];
        Self {
            ipv4,
            ipv6,
            receiver: Mutex::new(receiver),
            shutdown,
            closed,
            readers: StdMutex::new(readers),
            failure_family,
            local_addrs,
        }
    }
}

fn spawn_datagram_reader(
    family: AddressFamily,
    socket: Arc<UdpSocket>,
    sender: mpsc::Sender<DatagramMessage>,
    shutdown: Arc<Notify>,
    closed: Arc<AtomicBool>,
    failure_family: Arc<StdMutex<Option<AddressFamily>>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 65535];
        loop {
            if closed.load(Ordering::Acquire) {
                return;
            }
            let result = tokio::select! {
                _ = shutdown.notified() => return,
                result = socket.recv_from(&mut buffer) => result,
            };
            let (length, source) = match result {
                Ok(value) => value,
                Err(error) => {
                    if !closed.load(Ordering::Acquire) {
                        *failure_family
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(family);
                        let error = io::Error::new(
                            error.kind(),
                            format!("{family} UDP receive failed: {error}"),
                        );
                        tokio::select! {
                            _ = shutdown.notified() => {}
                            _ = sender.send(Err(error)) => {}
                        }
                    }
                    return;
                }
            };
            let packet = Ok((buffer[..length].to_vec(), source));
            tokio::select! {
                _ = shutdown.notified() => return,
                result = sender.send(packet) => {
                    if result.is_err() {
                        return;
                    }
                }
            }
        }
    })
}

#[async_trait]
impl DatagramSocket for TokioDatagramSocket {
    async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> io::Result<usize> {
        if self.closed.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "UDP socket is shut down",
            ));
        }
        match target {
            SocketAddr::V4(_) => self.ipv4.send_to(bytes, target).await,
            SocketAddr::V6(_) => self.ipv6.send_to(bytes, target).await,
        }
    }
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let packet = self.receiver.lock().await.recv().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "UDP socket receive queue closed",
            )
        })??;
        if packet.0.len() > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP datagram is larger than the receive buffer",
            ));
        }
        buffer[..packet.0.len()].copy_from_slice(&packet.0);
        Ok((packet.0.len(), packet.1))
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addrs[0])
    }
    fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        Ok(self.local_addrs.to_vec())
    }
    async fn shutdown(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.shutdown.notify_waiters();
            self.shutdown.notify_one();
        }
        let readers = std::mem::take(
            &mut *self
                .readers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        );
        for reader in readers {
            let _ = reader.await;
        }
    }
    fn failure_family(&self) -> Option<AddressFamily> {
        *self
            .failure_family
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for TokioDatagramSocket {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.shutdown.notify_waiters();
        self.shutdown.notify_one();
        for reader in self
            .readers
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .drain(..)
        {
            reader.abort();
        }
    }
}

struct StunSocketAdapter {
    inner: Arc<Inner>,
    pending: Mutex<Option<oneshot::Receiver<StunResponse>>>,
}

type StunResponse = (Vec<u8>, SocketAddr);
type StunWaiter = (Instant, SocketAddr, oneshot::Sender<StunResponse>);

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
            waiters.retain(|_, (deadline, _, _)| *deadline > now);
            waiters.insert(transaction, (now + Duration::from_secs(10), target, sender));
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
            per_peer_queue_limit: 256,
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
    incarnation: Option<u64>,
    provider: Option<Arc<dyn DatagramProvider>>,
    config: NodeConfig,
    observer: Option<Arc<dyn TrafficObserver>>,
}

impl VelaNodeBuilder {
    pub fn identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }
    pub fn incarnation(mut self, incarnation: u64) -> Self {
        self.incarnation = Some(incarnation);
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
        let incarnation = self.incarnation.unwrap_or_else(random_session_id);
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
            incarnation,
            socket,
            provider,
            config: self.config,
            observer: self.observer,
            peers: Mutex::new(HashMap::new()),
            routes: Mutex::new(RouteTable::new(local_addresses)),
            event_tx,
            event_rx: Mutex::new(Some(event_rx)),
            shutdown: Notify::new(),
            stopping: AtomicBool::new(false),
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
    pub fn incarnation(&self) -> u64 {
        self.inner.incarnation
    }
    /// Returns the first local socket address for compatibility with callers
    /// that only understand one address family.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addrs()?
            .into_iter()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no local UDP sockets"))
    }
    pub fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
        self.inner.socket.local_addrs()
    }
    pub fn local_candidates(&self) -> Vec<Candidate> {
        let candidates = self.inner.provider.local_candidates();
        if !candidates.is_empty() {
            candidates
        } else {
            let Ok(local_addrs) = self.local_addrs() else {
                return Vec::new();
            };
            host_candidates(&local_addrs, &self.inner.provider.local_interfaces())
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
        self.inner.stopping.store(true, Ordering::Release);
        self.inner.shutdown.notify_waiters();
        self.inner.stun_waiters.lock().await.clear();
        self.inner.socket.shutdown().await;
    }

    pub async fn register_peer(&self, info: PeerInfo) -> Result<(), CoreError> {
        validate_peer_info(&info)?;
        validate_peer_membership(&info, self.inner.config.server_public_key)?;
        let peer_id = info.node_id;
        if let Some(peer) = self.inner.peers.lock().await.get(&peer_id).cloned() {
            if peer.info() == info {
                // Repeated coordinator lookups are common during bilateral
                // punching. Keep an unchanged active session instead of
                // replacing it and manufacturing a disconnect/reconnect.
                peer.online.store(true, Ordering::Release);
                return Ok(());
            }
        }
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
                let previous_info = previous.info();
                if let Some(address) = previous_info.virtual_ipv4 {
                    routes.remove(&IpAddr::V4(address));
                }
                if let Some(address) = previous_info.virtual_ipv6 {
                    routes.remove(&IpAddr::V6(address));
                }
            }
            for address in peer_addresses {
                routes.insert(address, peer_id);
            }
            previous
        };
        if let Some(previous) = previous {
            let previous_info = previous.info();
            previous.online.store(false, Ordering::Release);
            previous.reconnect.lock().await.requested = false;
            let disconnected = previous.active.lock().await.take().is_some();
            *previous.attempt.lock().await = None;
            previous.queue.lock().await.clear();
            previous.notify.notify_waiters();
            if disconnected {
                self.inner
                    .emit(VelaEvent::PeerDisconnected(previous_info.node_id))
                    .await;
            }
        }
        Ok(())
    }

    /// Removes a peer and its exact host routes, closing its active session.
    pub async fn remove_peer(&self, peer_id: NodeId) -> Result<bool, CoreError> {
        let Some(peer) = self.inner.peers.lock().await.get(&peer_id).cloned() else {
            return Ok(false);
        };
        let _connect_guard = peer.connect.lock().await;
        let peer = {
            let mut routes = self.inner.routes.lock().await;
            let mut peers = self.inner.peers.lock().await;
            if !peers
                .get(&peer_id)
                .is_some_and(|current| Arc::ptr_eq(current, &peer))
            {
                return Ok(false);
            }
            let peer = peers.remove(&peer_id).expect("peer checked above");
            let peer_info = peer.info();
            if let Some(address) = peer_info.virtual_ipv4 {
                routes.remove(&IpAddr::V4(address));
            }
            if let Some(address) = peer_info.virtual_ipv6 {
                routes.remove(&IpAddr::V6(address));
            }
            peer
        };
        peer.online.store(false, Ordering::Release);
        peer.reconnect.lock().await.requested = false;
        *peer.active.lock().await = None;
        *peer.attempt.lock().await = None;
        peer.queue.lock().await.clear();
        peer.notify.notify_waiters();
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

        let online_peers = snapshot
            .online_peers
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        let old_peers = self.inner.peers.lock().await.clone();
        let mut replacement = HashMap::with_capacity(snapshot.peers.len().saturating_sub(1));
        let mut reconnect_peers = Vec::new();
        let mut reconnect_ids = std::collections::HashSet::new();
        for info in snapshot.peers {
            validate_peer_info(&info)?;
            validate_peer_membership(&info, self.inner.config.server_public_key)?;
            if info.node_id != self.node_id() {
                if let Some(peer) = old_peers.get(&info.node_id) {
                    let retain = can_retain_session(peer, &info).await;
                    if !retain {
                        self.inner.invalidate_session(peer, true).await;
                    }
                    peer.update_info(info.clone());
                    let online = online_peers.contains(&info.node_id);
                    peer.online.store(online, Ordering::Release);
                    if online {
                        let mut reconnect = peer.reconnect.lock().await;
                        if reconnect.requested {
                            reconnect.attempts = 0;
                            if reconnect_ids.insert(info.node_id) {
                                reconnect_peers.push(peer.clone());
                            }
                        }
                    }
                    replacement.insert(info.node_id, peer.clone());
                    continue;
                }
                let online = online_peers.contains(&info.node_id);
                replacement.insert(info.node_id, Arc::new(PeerState::with_online(info, online)));
            }
        }
        let mut routes = RouteTable::new(local_addresses);
        for peer in replacement.values() {
            let peer_info = peer.info();
            if let Some(address) = peer_info.virtual_ipv4 {
                routes.insert(IpAddr::V4(address), peer_info.node_id);
            }
            if let Some(address) = peer_info.virtual_ipv6 {
                routes.insert(IpAddr::V6(address), peer_info.node_id);
            }
        }
        let replacement_ids = replacement
            .keys()
            .copied()
            .collect::<std::collections::HashSet<_>>();

        // send_payload takes the route lock before the peer lock, so preserve
        // that order when swapping both views.
        let mut route_guard = self.inner.routes.lock().await;
        let mut peer_guard = self.inner.peers.lock().await;
        let old_peers = peer_guard.clone();
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
        for (peer_id, peer) in old_peers {
            if replacement_ids.contains(&peer_id) {
                continue;
            }
            peer.online.store(false, Ordering::Release);
            peer.reconnect.lock().await.requested = false;
            self.inner.invalidate_session(&peer, false).await;
        }
        for peer in reconnect_peers {
            self.inner.schedule_reconnect(peer).await;
        }
        Ok(())
    }

    pub async fn send_ip(&self, packet: impl Into<Bytes>) -> Result<(), SendError> {
        let packet = IpPacket::parse(packet.into()).map_err(SendError::Ip)?;
        let source = packet.source();
        let destination = packet.destination();
        let packet_len = packet.as_bytes().len();
        let peer_id = self
            .inner
            .routes
            .lock()
            .await
            .validate_outbound(&packet)
            .map_err(SendError::Ip)?;
        debug!(
            debug_marker = "vela-data",
            peer_id = %peer_id,
            source = ?source,
            destination = ?destination,
            packet_len,
            "outbound IP packet routed to peer"
        );
        let peer = self
            .inner
            .peers
            .lock()
            .await
            .get(&peer_id)
            .cloned()
            .ok_or(SendError::UnknownPeer)?;
        let active_session_before = peer.active.lock().await.is_some();
        let should_connect = !active_session_before && peer.attempt.lock().await.is_none();
        let result = self.inner.send_payload(&peer, packet.into_bytes()).await;
        let active_session_after = peer.active.lock().await.is_some();
        match &result {
            Ok(()) => debug!(
                debug_marker = "vela-data",
                peer_id = %peer_id,
                packet_len,
                active_session = active_session_after,
                connection_in_progress = !active_session_before && !should_connect,
                "outbound IP packet accepted by core"
            ),
            Err(error) => debug!(
                debug_marker = "vela-data",
                peer_id = %peer_id,
                packet_len,
                error = %error,
                "outbound IP packet rejected by core"
            ),
        }
        if result.is_ok() && should_connect {
            self.inner
                .emit(VelaEvent::PeerConnectionRequested(peer_id))
                .await;
            let node = self.clone();
            tokio::spawn(async move {
                debug!(
                    debug_marker = "vela-session",
                    peer_id = %peer_id,
                    "starting peer connection after queued IP packet"
                );
                match node.connect(peer_id).await {
                    Ok(_) => debug!(
                        debug_marker = "vela-session",
                        peer_id = %peer_id,
                        "peer connection completed"
                    ),
                    Err(error) => debug!(
                        debug_marker = "vela-session",
                        peer_id = %peer_id,
                        error = %error,
                        "peer connection failed"
                    ),
                }
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
            .register_with_incarnation(
                &self.inner.identity,
                self.inner.incarnation,
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
        debug!(
            debug_marker = "vela-session",
            peer_id = %peer_id,
            "starting peer connection"
        );
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
        let candidates = peer.info().candidates;
        if candidates.is_empty() {
            debug!(
                debug_marker = "vela-session",
                peer_id = %peer_id,
                "peer has no candidates"
            );
            return Err(ConnectError::NoCandidates);
        }
        debug!(
            debug_marker = "vela-session",
            peer_id = %peer_id,
            candidate_count = candidates.len(),
            "sending peer probes"
        );
        let mut nonce = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let session_id = random_session_id();
        {
            let mut attempt = peer.attempt.lock().await;
            *attempt = Some(Attempt {
                session_id,
                handshake: None,
                handshake_payload: None,
                handshake_path: None,
                last_handshake_at: None,
                started_at: unix_time(),
                timeout_at: unix_time().saturating_add(self.inner.config.connect_timeout.as_secs()),
                candidates: candidates
                    .iter()
                    .cloned()
                    .map(|candidate| PeerCandidateAttempt {
                        candidate,
                        state: PeerCandidateState::Pending,
                        last_sent_at: None,
                        responded_at: None,
                        error: None,
                    })
                    .collect(),
            });
        }
        peer.clear_failure();
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
                let address = candidate.address();
                match self
                    .inner
                    .send_packet(address, PacketType::Probe, session_id, 0, &payload)
                    .await
                {
                    Ok(()) => {
                        self.inner
                            .record_candidate_probe(&peer, session_id, address, None)
                            .await
                    }
                    Err(error) => {
                        self.inner
                            .record_candidate_probe(
                                &peer,
                                session_id,
                                address,
                                Some(error.to_string()),
                            )
                            .await;
                        debug!(
                            debug_marker = "vela-session",
                            peer_id = %peer_id,
                            target = %address,
                            session_id,
                            error = %error,
                            "peer probe send failed"
                        );
                    }
                }
            }
        };
        send_probes().await;
        let deadline = Instant::now() + self.inner.config.connect_timeout;
        let mut next_probe = Instant::now() + Duration::from_millis(250);
        // The remote side may win the simultaneous probe race and replace our
        // attempt. Keep waiting for that attempt to establish the session so
        // the caller observes the shared connection rather than Superseded.
        let mut superseded = false;
        loop {
            if peer.active.lock().await.is_some() {
                return Ok(PeerHandle {
                    node: self.clone(),
                    peer_id,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let current = {
                    let mut attempt = peer.attempt.lock().await;
                    if attempt
                        .as_ref()
                        .is_some_and(|value| value.session_id == session_id)
                    {
                        *attempt = None;
                        true
                    } else {
                        false
                    }
                };
                if !current {
                    return Err(ConnectError::Superseded);
                }
                peer.record_failure("connection attempt timed out");
                self.inner.emit(VelaEvent::PeerUnreachable(peer_id)).await;
                debug!(
                    debug_marker = "vela-session",
                    peer_id = %peer_id,
                    "peer connection timed out"
                );
                return Err(ConnectError::Timeout);
            }
            let current_attempt = peer.attempt.lock().await;
            if !current_attempt
                .as_ref()
                .is_some_and(|value| value.session_id == session_id)
            {
                if current_attempt.is_some() {
                    superseded = true;
                    next_probe = deadline;
                } else if !superseded {
                    return Err(ConnectError::Superseded);
                }
            }
            drop(current_attempt);
            if !superseded && Instant::now() >= next_probe {
                send_probes().await;
                next_probe = Instant::now() + Duration::from_millis(250);
                continue;
            }
            let wait_for_probe = if superseded {
                remaining
            } else {
                next_probe.saturating_duration_since(Instant::now())
            };
            let wait_for = remaining.min(wait_for_probe);
            if timeout(wait_for, peer.notify.notified()).await.is_err() {
                continue;
            }
            if peer.active.lock().await.is_none() && Instant::now() >= deadline {
                let current = {
                    let mut attempt = peer.attempt.lock().await;
                    if attempt
                        .as_ref()
                        .is_some_and(|value| value.session_id == session_id)
                    {
                        *attempt = None;
                        true
                    } else {
                        false
                    }
                };
                if !current {
                    return Err(ConnectError::Superseded);
                }
                peer.record_failure("connection attempt timed out");
                self.inner.emit(VelaEvent::PeerUnreachable(peer_id)).await;
                return Err(ConnectError::Timeout);
            }
        }
    }

    pub async fn next_event(&self) -> Option<VelaEvent> {
        let mut receiver = self.inner.event_rx.lock().await;
        receiver.as_mut()?.recv().await
    }

    /// Returns a redacted, read-only view of every peer's direct transport
    /// state. Credentials and public keys are intentionally omitted because
    /// this view is suitable for a local dashboard.
    pub async fn peer_statuses(&self) -> Vec<PeerRuntimeStatus> {
        let peers = self
            .inner
            .peers
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut statuses = Vec::with_capacity(peers.len());
        for peer in peers {
            let info = peer.info();
            let active = peer.active.lock().await;
            let attempt = peer.attempt.lock().await;
            let reconnect = peer.reconnect.lock().await;
            let failure = peer
                .last_failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            let (
                state,
                active_path,
                active_path_type,
                connected_at,
                path_changed_at,
                path_history,
                last_rx_at,
                last_rtt_ms,
                tx_bytes,
                rx_bytes,
            ) = if let Some(session) = active.as_ref() {
                (
                    PeerRuntimeState::Connected,
                    Some(session.path),
                    Some(candidate_type(&info.candidates, session.path).to_owned()),
                    Some(session.created_at_unix),
                    session.path_changed_at,
                    peer.path_history
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone(),
                    Some(unix_time().saturating_sub(session.last_rx.elapsed().as_secs())),
                    session.last_rtt_ms,
                    session.tx_bytes.load(Ordering::Relaxed),
                    session.rx_bytes.load(Ordering::Relaxed),
                )
            } else if attempt.is_some() || reconnect.requested || reconnect.running {
                (
                    PeerRuntimeState::Connecting,
                    None,
                    None,
                    None,
                    None,
                    Vec::new(),
                    None,
                    None,
                    0,
                    0,
                )
            } else if failure.is_some() {
                (
                    PeerRuntimeState::Unreachable,
                    None,
                    None,
                    None,
                    None,
                    Vec::new(),
                    None,
                    None,
                    0,
                    0,
                )
            } else {
                (
                    PeerRuntimeState::Idle,
                    None,
                    None,
                    None,
                    None,
                    Vec::new(),
                    None,
                    None,
                    0,
                    0,
                )
            };
            let attempt_status = attempt.as_ref().map(|attempt| PeerAttemptStatus {
                phase: if attempt.handshake.is_some() {
                    PeerAttemptPhase::Handshaking
                } else {
                    PeerAttemptPhase::Probing
                },
                started_at: attempt.started_at,
                timeout_at: attempt.timeout_at,
                retry_count: reconnect.attempts,
                candidates: attempt.candidates.clone(),
            });
            let attempt_status = attempt_status.or_else(|| {
                reconnect.requested.then_some(PeerAttemptStatus {
                    phase: PeerAttemptPhase::Retrying,
                    started_at: failure
                        .as_ref()
                        .map_or_else(unix_time, |failure| failure.occurred_at),
                    timeout_at: 0,
                    retry_count: reconnect.attempts,
                    candidates: info
                        .candidates
                        .iter()
                        .cloned()
                        .map(|candidate| PeerCandidateAttempt {
                            candidate,
                            state: PeerCandidateState::Pending,
                            last_sent_at: None,
                            responded_at: None,
                            error: None,
                        })
                        .collect(),
                })
            });
            statuses.push(PeerRuntimeStatus {
                node_id: info.node_id,
                online: peer.online.load(Ordering::Acquire),
                state,
                candidates: info.candidates,
                virtual_ipv4: info.virtual_ipv4,
                virtual_ipv6: info.virtual_ipv6,
                capabilities: info.capabilities,
                active_path,
                active_path_type,
                connected_at,
                path_changed_at,
                path_history: if active.is_some() {
                    path_history
                } else {
                    peer.path_history
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone()
                },
                last_rx_at,
                last_rtt_ms,
                tx_bytes,
                rx_bytes,
                attempt: attempt_status,
                last_failure: failure,
            });
        }
        statuses.sort_by_key(|status| status.node_id);
        statuses
    }
}

struct Inner {
    identity: Identity,
    incarnation: u64,
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
    stopping: AtomicBool,
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
                        debug!(
                            debug_marker = "vela-udp",
                            source = %source,
                            packet_len = length,
                            "received UDP datagram"
                        );
                        if let Some(transaction) = stun_transaction_id(&buffer[..length]) {
                            debug!(
                                debug_marker = "vela-stun",
                                source = %source,
                                packet_len = length,
                                "received STUN response"
                            );
                            let mut waiters = self.stun_waiters.lock().await;
                            let matching = waiters
                                .get(&transaction)
                                .is_some_and(|(_, target, _)| *target == source);
                            if matching {
                                if let Some((_, _, sender)) = waiters.remove(&transaction) {
                                    let _ = sender.send((buffer[..length].to_vec(), source));
                                }
                            } else if waiters.contains_key(&transaction) {
                                debug!(
                                    debug_marker = "vela-stun",
                                    source = %source,
                                    "ignored STUN response from an unexpected source"
                                );
                            }
                            continue;
                        }
                        if let Err(error) = self.handle_packet(&buffer[..length], source).await {
                            debug!(
                                debug_marker = "vela-udp",
                                error = %error,
                                %source,
                                "dropping invalid Vela packet"
                            );
                        }
                    }
                    Err(error) => {
                        if self.stopping.load(Ordering::Acquire) {
                            break;
                        }
                        warn!(%error, "Vela UDP receive loop stopped");
                        self.stun_waiters.lock().await.clear();
                        self.emit(VelaEvent::TransportFailed {
                            family: self.socket.failure_family(),
                            error: error.to_string(),
                        }).await;
                        self.shutdown.notify_waiters();
                        self.socket.shutdown().await;
                        break;
                    }
                }
            }
        }
    }

    async fn keepalive_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(self.config.keepalive_interval);
        let dead_after = self
            .config
            .keepalive_interval
            .checked_mul(3)
            .unwrap_or(Duration::MAX);
        loop {
            tokio::select! {
                _ = self.shutdown.notified() => break,
                _ = interval.tick() => {
                    let peers = self.peers.lock().await.values().cloned().collect::<Vec<_>>();
                    for peer in peers {
                        let peer_info = peer.info();
                        let membership_expired = self
                            .config
                            .server_public_key
                            .is_some_and(|server_key| {
                                validate_peer_membership(&peer_info, Some(server_key)).is_err()
                            });
                        if unix_time() >= self.snapshot_expires_at.load(Ordering::Acquire)
                            || membership_expired
                        {
                            self.invalidate_session(&peer, true).await;
                            continue;
                        }
                        let (keepalive, rekey_path, dead) = {
                            let mut active = peer.active.lock().await;
                            let Some(session) = active.as_mut() else {
                                continue;
                            };
                            if session.last_rx.elapsed() >= dead_after {
                                (None, None, true)
                            } else if session.needs_rekey() {
                                let path = session.path;
                                active.take();
                                (None, Some(path), false)
                            } else {
                                let sequence = session.tx_sequence.fetch_add(1, Ordering::Relaxed);
                                let mut nonce = [0; KEEPALIVE_NONCE_LEN];
                                rand::rngs::OsRng.fill_bytes(&mut nonce);
                                let packet = encrypt_payload(
                                    session,
                                    PacketType::KeepAlive,
                                    sequence,
                                    &nonce,
                                )
                                .ok()
                                .map(|payload| {
                                    session.pending_keepalive = Some((nonce, Instant::now()));
                                    (session.path, session.session_id, sequence, payload)
                                });
                                (packet, None, false)
                            }
                        };
                        if dead {
                            self.invalidate_session(&peer, true).await;
                            self.schedule_reconnect(peer).await;
                            continue;
                        }
                        if let Some((path, session_id, sequence, payload)) = keepalive {
                            let _ = self.send_packet(path, PacketType::KeepAlive, session_id, sequence, &payload).await;
                        }
                        if let Some(path) = rekey_path {
                            *peer.attempt.lock().await = None;
                            if self.identity.public().node_id < peer_info.node_id {
                                let session_id = random_session_id();
                                *peer.attempt.lock().await = Some(Attempt {
                                    session_id,
                                    handshake: None,
                                    handshake_payload: None,
                                    handshake_path: None,
                                    last_handshake_at: None,
                                    started_at: unix_time(),
                                    timeout_at: unix_time().saturating_add(
                                        self.config.connect_timeout.as_secs(),
                                    ),
                                    candidates: peer_info
                                        .candidates
                                        .iter()
                                        .cloned()
                                        .map(|candidate| PeerCandidateAttempt {
                                            candidate,
                                            state: PeerCandidateState::Pending,
                                            last_sent_at: None,
                                            responded_at: None,
                                            error: None,
                                        })
                                        .collect(),
                                });
                                let _ = self.start_initiator(&peer, path, session_id).await;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn invalidate_session(&self, peer: &Arc<PeerState>, request_reconnect: bool) {
        let disconnected = peer.active.lock().await.take().is_some();
        let had_attempt = peer.attempt.lock().await.take().is_some();
        peer.queue.lock().await.clear();
        if request_reconnect && (disconnected || had_attempt) {
            let mut reconnect = peer.reconnect.lock().await;
            reconnect.requested = true;
            reconnect.attempts = 0;
        }
        peer.notify.notify_waiters();
        if disconnected {
            self.emit(VelaEvent::PeerDisconnected(peer.info().node_id))
                .await;
        }
    }

    async fn schedule_reconnect(self: &Arc<Self>, peer: Arc<PeerState>) {
        if !self.started.load(Ordering::Acquire)
            || self.stopping.load(Ordering::Acquire)
            || !peer.online.load(Ordering::Acquire)
        {
            return;
        }
        let mut reconnect = peer.reconnect.lock().await;
        if !reconnect.requested || reconnect.running || reconnect.attempts >= MAX_RECONNECT_ATTEMPTS
        {
            return;
        }
        reconnect.running = true;
        drop(reconnect);
        self.emit(VelaEvent::PeerReconnectRequested(peer.info().node_id))
            .await;
        let inner = Arc::clone(self);
        tokio::spawn(async move {
            inner.reconnect_loop(peer).await;
        });
    }

    async fn reconnect_loop(self: Arc<Self>, peer: Arc<PeerState>) {
        loop {
            let delay = {
                let mut reconnect = peer.reconnect.lock().await;
                if !reconnect.requested
                    || self.stopping.load(Ordering::Acquire)
                    || !peer.online.load(Ordering::Acquire)
                    || reconnect.attempts >= MAX_RECONNECT_ATTEMPTS
                {
                    reconnect.running = false;
                    return;
                }
                let attempt = reconnect.attempts;
                reconnect.attempts += 1;
                if attempt == 0 {
                    Duration::ZERO
                } else {
                    let multiplier = 1u32 << u32::from(attempt.saturating_sub(1));
                    self.config
                        .reconnect_backoff
                        .saturating_mul(multiplier)
                        .min(Duration::from_secs(30))
                }
            };
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            if self.stopping.load(Ordering::Acquire) || !peer.online.load(Ordering::Acquire) {
                peer.reconnect.lock().await.running = false;
                return;
            }
            let current = self.peers.lock().await.get(&peer.info().node_id).cloned();
            if current
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(current, &peer))
            {
                peer.reconnect.lock().await.running = false;
                return;
            }
            let node = VelaNode {
                inner: Arc::clone(&self),
            };
            match node.connect(peer.info().node_id).await {
                Ok(_) => {
                    let mut reconnect = peer.reconnect.lock().await;
                    reconnect.requested = false;
                    reconnect.running = false;
                    reconnect.attempts = 0;
                    return;
                }
                Err(error) => {
                    peer.record_failure(error.to_string());
                    debug!(
                        debug_marker = "vela-session",
                        peer_id = %peer.info().node_id,
                        error = %error,
                        "automatic peer reconnect attempt failed"
                    );
                }
            }
        }
    }

    async fn handle_packet(&self, input: &[u8], source: SocketAddr) -> Result<(), CoreError> {
        if unix_time() >= self.snapshot_expires_at.load(Ordering::Acquire) {
            return Err(CoreError::SnapshotExpired);
        }
        let packet = WirePacket::decode(input)?;
        debug!(
            debug_marker = "vela-udp",
            source = %source,
            packet_type = ?packet.header.packet_type,
            session_id = packet.header.session_id,
            sequence = packet.header.sequence,
            wire_len = input.len(),
            "decoded inbound Vela packet"
        );
        match packet.header.packet_type {
            PacketType::Probe => self.handle_probe(packet, source).await,
            PacketType::ProbeResponse => self.handle_probe_response(packet, source).await,
            PacketType::Handshake => self.handle_handshake(packet, source).await,
            PacketType::Data
            | PacketType::KeepAlive
            | PacketType::KeepAliveAck
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
        let peer_info = peer.info();
        validate_peer_membership(&peer_info, self.config.server_public_key)?;
        verify_probe(&probe, &peer_info)?;
        info!(
            debug_marker = "vela-session",
            peer_id = %probe.sender,
            source = %source,
            session_id = probe.session_id,
            "received authenticated peer connection probe"
        );
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
                    handshake_payload: None,
                    handshake_path: None,
                    last_handshake_at: None,
                    started_at: unix_time(),
                    timeout_at: unix_time().saturating_add(self.config.connect_timeout.as_secs()),
                    candidates: peer_info
                        .candidates
                        .iter()
                        .cloned()
                        .map(|candidate| PeerCandidateAttempt {
                            candidate,
                            state: PeerCandidateState::Pending,
                            last_sent_at: None,
                            responded_at: None,
                            error: None,
                        })
                        .collect(),
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
        let peer_info = peer.info();
        validate_peer_membership(&peer_info, self.config.server_public_key)?;
        verify_probe(&probe, &peer_info)?;
        let attempt = peer.attempt.lock().await;
        let attempt_session_id = attempt.as_ref().map(|value| value.session_id);
        if attempt_session_id != Some(probe.session_id) {
            debug!(
                debug_marker = "vela-session",
                peer_id = %probe.sender,
                source = %source,
                response_session_id = probe.session_id,
                attempt_session_id = ?attempt_session_id,
                "ignoring probe response without a matching connection attempt"
            );
            return Ok(());
        }
        drop(attempt);
        self.record_candidate_response(&peer, probe.session_id, source)
            .await;
        debug!(
            debug_marker = "vela-session",
            peer_id = %probe.sender,
            source = %source,
            session_id = probe.session_id,
            "accepted probe response for connection attempt"
        );
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
        let peer_id = peer.info().node_id;
        if peer.active.lock().await.is_some() {
            debug!(
                debug_marker = "vela-session",
                peer_id = %peer_id,
                path = %path,
                session_id,
                "skipping Noise handshake because peer session is already active"
            );
            return Ok(());
        }
        let mut attempt = peer.attempt.lock().await;
        let Some(attempt_value) = attempt.as_mut() else {
            debug!(
                debug_marker = "vela-session",
                peer_id = %peer_id,
                path = %path,
                session_id,
                "skipping Noise handshake because connection attempt is gone"
            );
            return Ok(());
        };
        if attempt_value.session_id != session_id {
            debug!(
                debug_marker = "vela-session",
                peer_id = %peer_id,
                path = %path,
                session_id,
                attempt_session_id = attempt_value.session_id,
                "skipping Noise handshake because session id is stale"
            );
            return Ok(());
        }
        let peer_info = peer.info();
        let (payload, new_handshake) = match (
            attempt_value.handshake.is_some(),
            attempt_value.handshake_payload.clone(),
        ) {
            (true, Some(payload)) => {
                let recently_sent = attempt_value
                    .handshake_path
                    .is_some_and(|previous_path| previous_path == path)
                    && attempt_value
                        .last_handshake_at
                        .is_some_and(|sent_at| sent_at.elapsed() < HANDSHAKE_RETRY_INTERVAL);
                if recently_sent {
                    debug!(
                        debug_marker = "vela-session",
                        peer_id = %peer_id,
                        path = %path,
                        session_id,
                        "skipping Noise handshake retry because the same path was tried recently"
                    );
                    return Ok(());
                }
                debug!(
                    debug_marker = "vela-session",
                    peer_id = %peer_id,
                    path = %path,
                    previous_path = ?attempt_value.handshake_path,
                    session_id,
                    "retrying Noise handshake on candidate path"
                );
                (payload, None)
            }
            _ => {
                debug!(
                    debug_marker = "vela-session",
                    peer_id = %peer_id,
                    path = %path,
                    session_id,
                    "creating Noise handshake"
                );
                let mut handshake =
                    NoiseHandshake::initiator(&self.identity, &peer_info.noise_public)?;
                let message = handshake.write_message(&self.handshake_context().await?)?;
                let mut payload = Vec::with_capacity(33 + message.len());
                payload.push(1);
                payload.extend_from_slice(self.identity.public().node_id.as_bytes());
                payload.extend_from_slice(&message);
                (payload, Some(handshake))
            }
        };
        if let Err(error) = self
            .send_packet(path, PacketType::Handshake, session_id, 0, &payload)
            .await
        {
            peer.record_failure(format!("handshake send failed: {error}"));
            debug!(
                debug_marker = "vela-session",
                peer_id = %peer_id,
                path = %path,
                session_id,
                error = %error,
                "Noise handshake send failed; keeping attempt retryable"
            );
            return Err(error);
        }
        if let Some(handshake) = new_handshake {
            attempt_value.handshake = Some(handshake);
            attempt_value.handshake_payload = Some(payload);
        }
        attempt_value.handshake_path = Some(path);
        attempt_value.last_handshake_at = Some(Instant::now());
        drop(attempt);
        debug!(
            debug_marker = "vela-session",
            peer_id = %peer_id,
            path = %path,
            session_id,
            "Noise handshake sent; awaiting response or retry"
        );
        self.emit(VelaEvent::PeerConnecting(peer_info.node_id))
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
        let peer_info = peer.info();
        validate_peer_membership(&peer_info, self.config.server_public_key)?;
        debug!(
            debug_marker = "vela-session",
            peer_id = %sender,
            source = %source,
            session_id = packet.header.session_id,
            role,
            payload_len = packet.payload.len(),
            "received Noise handshake"
        );
        if peer
            .active
            .lock()
            .await
            .as_ref()
            .is_some_and(|session| session.session_id == packet.header.session_id)
        {
            debug!(
                debug_marker = "vela-session",
                peer_id = %sender,
                source = %source,
                session_id = packet.header.session_id,
                "ignoring Noise handshake because peer session is already active"
            );
            return Ok(());
        }
        if role == 1 {
            if self.identity.public().node_id < sender {
                debug!(
                    debug_marker = "vela-session",
                    peer_id = %sender,
                    source = %source,
                    session_id = packet.header.session_id,
                    "ignoring initiator handshake because local node is the initiator"
                );
                return Ok(());
            }
            let mut handshake = NoiseHandshake::responder(&self.identity)?;
            let context = handshake.read_message(&packet.payload[33..])?;
            self.validate_handshake_context(&context, sender, &peer_info)
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
            if peer.active.lock().await.is_some() {
                self.invalidate_session(&peer, false).await;
            }
            self.establish(
                &peer,
                packet.header.session_id,
                source,
                keys.cipher(false),
                &peer_info,
            )
            .await;
        } else if role == 2 {
            if self.identity.public().node_id > sender {
                debug!(
                    debug_marker = "vela-session",
                    peer_id = %sender,
                    source = %source,
                    session_id = packet.header.session_id,
                    "ignoring responder handshake because local node is the responder"
                );
                return Ok(());
            }
            let mut attempt = peer.attempt.lock().await;
            if attempt.as_ref().map(|value| value.session_id) != Some(packet.header.session_id) {
                debug!(
                    debug_marker = "vela-session",
                    peer_id = %sender,
                    source = %source,
                    response_session_id = packet.header.session_id,
                    attempt_session_id = ?attempt.as_ref().map(|value| value.session_id),
                    "ignoring Noise handshake response without a matching connection attempt"
                );
                return Ok(());
            }
            let Some(mut handshake) = attempt.as_mut().and_then(|value| value.handshake.take())
            else {
                debug!(
                    debug_marker = "vela-session",
                    peer_id = %sender,
                    source = %source,
                    session_id = packet.header.session_id,
                    "ignoring Noise handshake response because no initiator state is available"
                );
                return Ok(());
            };
            let context = handshake.read_message(&packet.payload[33..])?;
            self.validate_handshake_context(&context, sender, &peer_info)
                .await?;
            let keys = handshake.into_session()?;
            drop(attempt);
            if peer.active.lock().await.is_some() {
                self.invalidate_session(&peer, false).await;
            }
            self.establish(
                &peer,
                packet.header.session_id,
                source,
                keys.cipher(true),
                &peer_info,
            )
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
            let peer_info = peer.info();
            let mut active = peer.active.lock().await;
            let Some(session) = active.as_mut() else {
                continue;
            };
            if session.session_id != packet.header.session_id {
                continue;
            }
            debug!(
                debug_marker = "vela-data",
                peer_id = %peer_info.node_id,
                source = %source,
                packet_type = ?packet.header.packet_type,
                session_id = packet.header.session_id,
                sequence = packet.header.sequence,
                encrypted_len = packet.payload.len(),
                "matched inbound packet to active session"
            );
            if let Some(server_key) = self.config.server_public_key {
                if validate_peer_membership(&peer_info, Some(server_key)).is_err() {
                    active.take();
                    drop(active);
                    *peer.attempt.lock().await = None;
                    peer.queue.lock().await.clear();
                    self.emit(VelaEvent::PeerDisconnected(peer_info.node_id))
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
            session.last_rx = Instant::now();
            let path_changed = session.path != source;
            session.path = source;
            if path_changed {
                session.path_changed_at = Some(unix_time());
                peer.record_path(source, &peer_info.candidates);
            }
            session
                .rx_bytes
                .fetch_add(packet.payload.len() as u64, Ordering::Relaxed);
            let mut events = Vec::new();
            if path_changed {
                events.push(VelaEvent::PathChanged(peer_info.node_id, source));
            }
            let mut response: Option<(PacketType, SocketAddr, u64, u64, Vec<u8>)> = None;
            match packet.header.packet_type {
                PacketType::Data => {
                    let ip_packet = IpPacket::parse(plaintext).map_err(CoreError::Ip)?;
                    let destination = ip_packet.destination();
                    debug!(
                        debug_marker = "vela-data",
                        peer_id = %peer_info.node_id,
                        source_ip = ?ip_packet.source(),
                        destination = ?destination,
                        packet_len = ip_packet.as_bytes().len(),
                        "decrypted inbound IP packet"
                    );
                    if !self.routes.lock().await.is_local(destination) {
                        return Err(CoreError::Ip(vela_ip::IpError::DestinationUnknown(
                            destination,
                        )));
                    }
                    self.observe(TrafficSample {
                        peer: Some(peer_info.node_id),
                        direction: TrafficDirection::Received,
                        path: source,
                        payload_bytes: ip_packet.as_bytes().len(),
                        encrypted_bytes: packet.payload.len(),
                        wire_bytes: input_wire_len(&packet),
                    });
                    events.push(VelaEvent::IpPacket {
                        peer: peer_info.node_id,
                        packet: ip_packet,
                    });
                }
                PacketType::KeepAlive => {
                    if plaintext.len() != KEEPALIVE_NONCE_LEN {
                        return Err(CoreError::InvalidKeepAlive);
                    }
                    let sequence = session.tx_sequence.fetch_add(1, Ordering::Relaxed);
                    let encrypted =
                        encrypt_payload(session, PacketType::KeepAliveAck, sequence, &plaintext)?;
                    response = Some((
                        PacketType::KeepAliveAck,
                        session.path,
                        session.session_id,
                        sequence,
                        encrypted,
                    ));
                }
                PacketType::KeepAliveAck => {
                    if plaintext.len() != KEEPALIVE_NONCE_LEN {
                        return Err(CoreError::InvalidKeepAlive);
                    }
                    if session
                        .pending_keepalive
                        .as_ref()
                        .is_some_and(|(nonce, _)| nonce.as_slice() == plaintext.as_slice())
                    {
                        if let Some((_, sent_at)) = session.pending_keepalive.take() {
                            session.last_rtt_ms = u64::try_from(sent_at.elapsed().as_millis())
                                .ok()
                                .or(Some(u64::MAX));
                        }
                    }
                }
                PacketType::DiagnosticPing => {
                    if plaintext.len() != DIAGNOSTIC_NONCE_LEN {
                        return Err(CoreError::InvalidDiagnosticPing);
                    }
                    let sequence = session.tx_sequence.fetch_add(1, Ordering::Relaxed);
                    let encrypted =
                        encrypt_payload(session, PacketType::DiagnosticPong, sequence, &plaintext)?;
                    response = Some((
                        PacketType::DiagnosticPong,
                        session.path,
                        session.session_id,
                        sequence,
                        encrypted,
                    ));
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
            if let Some((packet_type, path, session_id, sequence, payload)) = response {
                self.send_packet(path, packet_type, session_id, sequence, &payload)
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
        expected_peer: &PeerInfo,
    ) {
        let mut active = peer.active.lock().await;
        if active.is_some() || peer.info() != *expected_peer {
            return;
        }
        *active = Some(ActiveSession {
            session_id,
            path,
            cipher,
            tx_sequence: AtomicU64::new(1),
            replay: ReplayWindow::default(),
            ping_waiters: HashMap::new(),
            pending_keepalive: None,
            last_rx: Instant::now(),
            created_at_unix: unix_time(),
            created_at: Instant::now(),
            path_changed_at: None,
            last_rtt_ms: None,
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
        });
        drop(active);
        peer.record_path(path, &expected_peer.candidates);
        peer.clear_failure();
        *peer.attempt.lock().await = None;
        let mut reconnect = peer.reconnect.lock().await;
        reconnect.requested = false;
        reconnect.running = false;
        reconnect.attempts = 0;
        drop(reconnect);
        peer.notify.notify_waiters();
        let peer_id = peer.info().node_id;
        debug!(
            debug_marker = "vela-session",
            peer_id = %peer_id,
            path = %path,
            session_id,
            "encrypted peer session established"
        );
        self.emit(VelaEvent::PeerConnected(peer_id)).await;
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
            self.invalidate_session(peer, true).await;
            return Err(SendError::SnapshotExpired);
        }
        let packet = IpPacket::parse(payload.clone()).map_err(SendError::Ip)?;
        let routed_peer = self
            .routes
            .lock()
            .await
            .validate_outbound(&packet)
            .map_err(SendError::Ip)?;
        if routed_peer != peer.info().node_id {
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
            debug!(
                debug_marker = "vela-data",
                peer_id = %peer.info().node_id,
                queued_packets = queue.len(),
                "queued IP packet until peer session is established"
            );
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
        debug!(
            debug_marker = "vela-data",
            peer_id = %peer.info().node_id,
            path = %session.path,
            session_id = session.session_id,
            sequence,
            packet_len = payload.len(),
            wire_len = packet.len(),
            "sent encrypted IP packet"
        );
        session
            .tx_bytes
            .fetch_add(payload.len() as u64, Ordering::Relaxed);
        self.observe(TrafficSample {
            peer: Some(peer.info().node_id),
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
        debug!(
            debug_marker = "vela-udp",
            target = %target,
            packet_type = ?packet_type,
            session_id,
            sequence,
            wire_len = packet.len(),
            "sent Vela UDP packet"
        );
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

    async fn record_candidate_probe(
        &self,
        peer: &Arc<PeerState>,
        session_id: u64,
        address: SocketAddr,
        error: Option<String>,
    ) {
        let mut attempt = peer.attempt.lock().await;
        let Some(attempt) = attempt
            .as_mut()
            .filter(|attempt| attempt.session_id == session_id)
        else {
            return;
        };
        let Some(candidate) = attempt
            .candidates
            .iter_mut()
            .find(|candidate| candidate.candidate.address() == address)
        else {
            return;
        };
        candidate.last_sent_at = Some(unix_time());
        candidate.error = error.clone();
        candidate.state = if error.is_some() {
            PeerCandidateState::Failed
        } else {
            PeerCandidateState::Sent
        };
    }

    async fn record_candidate_response(
        &self,
        peer: &Arc<PeerState>,
        session_id: u64,
        address: SocketAddr,
    ) {
        let mut attempt = peer.attempt.lock().await;
        let Some(attempt) = attempt
            .as_mut()
            .filter(|attempt| attempt.session_id == session_id)
        else {
            return;
        };
        let Some(candidate) = attempt
            .candidates
            .iter_mut()
            .find(|candidate| candidate.candidate.address() == address)
        else {
            return;
        };
        candidate.state = PeerCandidateState::Responded;
        candidate.responded_at = Some(unix_time());
        candidate.error = None;
    }

    async fn handshake_context(&self) -> Result<Vec<u8>, CoreError> {
        let network_id = *self.network_id.lock().await;
        let ipv4 = *self.local_ipv4.lock().await;
        let ipv6 = *self.local_ipv6.lock().await;
        let generation = self.snapshot_generation.load(Ordering::Acquire);
        Ok(encode_handshake_context(
            network_id,
            self.identity.public().node_id,
            self.incarnation,
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
        let expected_generation = self.snapshot_generation.load(Ordering::Acquire);
        let valid = context.network_id == expected_network_id
            && context.generation == expected_generation
            && context.node_id == sender
            && context.node_id == peer.node_id
            && context.incarnation == peer.incarnation
            && context.virtual_ipv4 == peer.virtual_ipv4
            && context.virtual_ipv6 == peer.virtual_ipv6;
        if !valid {
            debug!(
                debug_marker = "vela-session",
                peer_id = %sender,
                context_generation = context.generation,
                expected_generation,
                context_node_id = %context.node_id,
                expected_node_id = %peer.node_id,
                context_incarnation = context.incarnation,
                expected_incarnation = peer.incarnation,
                context_virtual_ipv4 = ?context.virtual_ipv4,
                expected_virtual_ipv4 = ?peer.virtual_ipv4,
                context_virtual_ipv6 = ?context.virtual_ipv6,
                expected_virtual_ipv6 = ?peer.virtual_ipv6,
                network_id_matches = context.network_id == expected_network_id,
                "rejecting Noise handshake context"
            );
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

#[derive(Clone, Debug, Serialize)]
pub struct PeerRuntimeStatus {
    pub node_id: NodeId,
    pub online: bool,
    pub state: PeerRuntimeState,
    pub candidates: Vec<Candidate>,
    pub virtual_ipv4: Option<Ipv4Addr>,
    pub virtual_ipv6: Option<Ipv6Addr>,
    pub capabilities: Vec<PeerCapability>,
    pub active_path: Option<SocketAddr>,
    pub active_path_type: Option<String>,
    pub connected_at: Option<u64>,
    pub path_changed_at: Option<u64>,
    pub path_history: Vec<PeerPathChange>,
    pub last_rx_at: Option<u64>,
    pub last_rtt_ms: Option<u64>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub attempt: Option<PeerAttemptStatus>,
    pub last_failure: Option<PeerFailureStatus>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerPathChange {
    pub path: SocketAddr,
    pub candidate_type: String,
    pub changed_at: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRuntimeState {
    Idle,
    Connecting,
    Connected,
    Unreachable,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerAttemptStatus {
    pub phase: PeerAttemptPhase,
    pub started_at: u64,
    pub timeout_at: u64,
    pub retry_count: u8,
    pub candidates: Vec<PeerCandidateAttempt>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerAttemptPhase {
    Probing,
    Handshaking,
    Retrying,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerCandidateAttempt {
    pub candidate: Candidate,
    pub state: PeerCandidateState,
    pub last_sent_at: Option<u64>,
    pub responded_at: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerCandidateState {
    Pending,
    Sent,
    Responded,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct PeerFailureStatus {
    pub reason: String,
    pub occurred_at: u64,
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
            self.node
                .inner
                .emit(VelaEvent::PeerConnectionRequested(self.peer_id))
                .await;
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
    PeerConnectionRequested(NodeId),
    PeerConnected(NodeId),
    PeerDisconnected(NodeId),
    PeerReconnectRequested(NodeId),
    PeerUnreachable(NodeId),
    PathChanged(NodeId, SocketAddr),
    TransportFailed {
        family: Option<AddressFamily>,
        error: String,
    },
    IpPacket {
        peer: NodeId,
        packet: IpPacket,
    },
}

struct PeerState {
    info: StdMutex<PeerInfo>,
    online: AtomicBool,
    last_failure: StdMutex<Option<PeerFailureStatus>>,
    path_history: StdMutex<Vec<PeerPathChange>>,
    connect: Mutex<()>,
    attempt: Mutex<Option<Attempt>>,
    active: Mutex<Option<ActiveSession>>,
    reconnect: Mutex<ReconnectState>,
    notify: Notify,
    queue: Mutex<VecDeque<Bytes>>,
}

impl PeerState {
    fn new(info: PeerInfo) -> Self {
        Self::with_online(info, true)
    }

    fn with_online(info: PeerInfo, online: bool) -> Self {
        Self {
            info: StdMutex::new(info),
            online: AtomicBool::new(online),
            last_failure: StdMutex::new(None),
            path_history: StdMutex::new(Vec::new()),
            connect: Mutex::new(()),
            attempt: Mutex::new(None),
            active: Mutex::new(None),
            reconnect: Mutex::new(ReconnectState::default()),
            notify: Notify::new(),
            queue: Mutex::new(VecDeque::new()),
        }
    }

    fn info(&self) -> PeerInfo {
        self.info
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn update_info(&self, info: PeerInfo) {
        *self
            .info
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = info;
    }

    fn clear_failure(&self) {
        *self
            .last_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    fn record_failure(&self, reason: impl Into<String>) {
        *self
            .last_failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(PeerFailureStatus {
            reason: reason.into(),
            occurred_at: unix_time(),
        });
    }

    fn record_path(&self, path: SocketAddr, candidates: &[Candidate]) {
        let mut history = self
            .path_history
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if history.last().is_some_and(|previous| previous.path == path) {
            return;
        }
        history.push(PeerPathChange {
            path,
            candidate_type: candidate_type(candidates, path).to_owned(),
            changed_at: unix_time(),
        });
        if history.len() > 32 {
            history.remove(0);
        }
    }
}

#[derive(Default)]
struct ReconnectState {
    requested: bool,
    running: bool,
    attempts: u8,
}

async fn can_retain_session(peer: &Arc<PeerState>, next: &PeerInfo) -> bool {
    let previous = peer.info();
    if previous.node_id != next.node_id
        || previous.incarnation != next.incarnation
        || previous.signing_public != next.signing_public
        || previous.noise_public != next.noise_public
        || previous.virtual_ipv4 != next.virtual_ipv4
        || previous.virtual_ipv6 != next.virtual_ipv6
    {
        return false;
    }
    let active = peer.active.lock().await;
    if let Some(session) = active.as_ref() {
        return previous.candidates == next.candidates
            || next
                .candidates
                .iter()
                .any(|candidate| candidate.address() == session.path);
    }
    drop(active);
    let attempt = peer.attempt.lock().await;
    attempt.is_none() || previous.candidates == next.candidates
}

struct Attempt {
    session_id: u64,
    handshake: Option<NoiseHandshake>,
    handshake_payload: Option<Vec<u8>>,
    handshake_path: Option<SocketAddr>,
    last_handshake_at: Option<Instant>,
    started_at: u64,
    timeout_at: u64,
    candidates: Vec<PeerCandidateAttempt>,
}

const HANDSHAKE_RETRY_INTERVAL: Duration = Duration::from_millis(250);

struct ActiveSession {
    session_id: u64,
    path: SocketAddr,
    cipher: SessionCipher,
    tx_sequence: AtomicU64,
    replay: ReplayWindow,
    ping_waiters: HashMap<[u8; DIAGNOSTIC_NONCE_LEN], oneshot::Sender<SocketAddr>>,
    pending_keepalive: Option<([u8; KEEPALIVE_NONCE_LEN], Instant)>,
    last_rx: Instant,
    created_at_unix: u64,
    created_at: Instant,
    path_changed_at: Option<u64>,
    last_rtt_ms: Option<u64>,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

const KEEPALIVE_NONCE_LEN: usize = 16;
const MAX_RECONNECT_ATTEMPTS: u8 = 5;

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

const HANDSHAKE_CONTEXT_MAGIC: &[u8] = b"VELA-HS-v2";

struct HandshakeContext {
    network_id: [u8; 16],
    generation: u64,
    node_id: NodeId,
    incarnation: u64,
    virtual_ipv4: Option<Ipv4Addr>,
    virtual_ipv6: Option<Ipv6Addr>,
}

fn encode_handshake_context(
    network_id: [u8; 16],
    node_id: NodeId,
    incarnation: u64,
    virtual_ipv4: Option<Ipv4Addr>,
    virtual_ipv6: Option<Ipv6Addr>,
    generation: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + 16 + 8 + 32 + 8 + 1 + 4 + 1 + 16);
    out.extend_from_slice(HANDSHAKE_CONTEXT_MAGIC);
    out.extend_from_slice(&network_id);
    out.extend_from_slice(&generation.to_be_bytes());
    out.extend_from_slice(node_id.as_bytes());
    out.extend_from_slice(&incarnation.to_be_bytes());
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
    if bytes.len() != magic_len + 16 + 8 + 32 + 8 + 1 + 4 + 1 + 16
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
    let incarnation = u64::from_be_bytes(bytes[offset..offset + 8].try_into().ok()?);
    offset += 8;
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
        incarnation,
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

fn candidate_type(candidates: &[Candidate], address: SocketAddr) -> &'static str {
    candidates
        .iter()
        .find(|candidate| candidate.address() == address)
        .map_or("peer_reflexive", |candidate| match candidate {
            Candidate::Host(_) => "host",
            Candidate::ServerReflexive(_) => "server_reflexive",
            Candidate::PeerReflexive(_) => "peer_reflexive",
        })
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
    #[error("failed to bind {family} UDP socket on port {port}: {source}")]
    DatagramBind {
        family: AddressFamily,
        port: u16,
        #[source]
        source: io::Error,
    },
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
    #[error("invalid keepalive payload")]
    InvalidKeepAlive,
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
    #[error("connection attempt was superseded by a newer peer state")]
    Superseded,
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
    use async_trait::async_trait;
    use vela_crypto::ServerSigner;
    use vela_proto::{Candidate, Ipv4Cidr, NetworkSnapshot};

    struct DropKeepAliveAckProvider {
        host_candidates: Vec<Candidate>,
    }

    struct DropKeepAliveAckSocket {
        inner: Arc<dyn DatagramSocket>,
    }

    #[async_trait]
    impl DatagramProvider for DropKeepAliveAckProvider {
        async fn bind(&self, options: BindOptions) -> Result<Arc<dyn DatagramSocket>, CoreError> {
            let inner = TokioDatagramProvider::new(self.host_candidates.clone())
                .bind(options)
                .await?;
            Ok(Arc::new(DropKeepAliveAckSocket { inner }))
        }

        fn local_candidates(&self) -> Vec<Candidate> {
            self.host_candidates.clone()
        }
    }

    #[async_trait]
    impl DatagramSocket for DropKeepAliveAckSocket {
        async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> io::Result<usize> {
            if WirePacket::decode(bytes).ok().is_some_and(|packet| {
                matches!(
                    packet.header.packet_type,
                    PacketType::KeepAlive | PacketType::KeepAliveAck
                )
            }) {
                return Ok(bytes.len());
            }
            self.inner.send_to(bytes, target).await
        }

        async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            self.inner.recv_from(buffer).await
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.inner.local_addr()
        }

        fn local_addrs(&self) -> io::Result<Vec<SocketAddr>> {
            self.inner.local_addrs()
        }

        async fn shutdown(&self) {
            self.inner.shutdown().await;
        }

        fn failure_family(&self) -> Option<AddressFamily> {
            self.inner.failure_family()
        }
    }

    fn peer_info(
        identity: &Identity,
        incarnation: u64,
        address: SocketAddr,
        virtual_ipv4: Ipv4Addr,
    ) -> PeerInfo {
        let public = identity.public();
        PeerInfo {
            node_id: public.node_id,
            incarnation,
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
    fn selected_interface_host_candidates_use_the_matching_socket_port() {
        let Some(interface) = get_if_addrs()
            .unwrap()
            .into_iter()
            .find(|interface| !interface.is_loopback() && !interface.is_link_local())
        else {
            return;
        };
        let family = AddressFamily::of(SocketAddr::new(interface.ip(), 0));
        let local_addrs = match family {
            AddressFamily::Ipv4 => vec!["0.0.0.0:45101".parse().unwrap()],
            AddressFamily::Ipv6 => vec!["[::]:45102".parse().unwrap()],
        };
        let candidates = host_candidates(&local_addrs, &[(family, interface.name.clone())]);
        assert!(candidates.contains(&Candidate::Host(SocketAddr::new(
            interface.ip(),
            local_addrs[0].port(),
        ))));
    }

    #[tokio::test]
    async fn provider_binds_ipv4_and_ipv6_sockets_with_the_same_explicit_port() {
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let provider =
            TokioDatagramProvider::new(vec![Candidate::Host("127.0.0.1:1".parse().unwrap())]);
        let socket = provider.bind(BindOptions { port }).await.unwrap();
        let addrs = socket.local_addrs().unwrap();
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)));
        assert_eq!(addrs[1], SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)));
        socket.shutdown().await;
    }

    #[tokio::test]
    async fn provider_uses_fresh_ports_after_a_partial_explicit_bind_failure() {
        let ipv6_blocker = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        ipv6_blocker.set_only_v6(true).unwrap();
        ipv6_blocker
            .bind(&"[::]:0".parse::<SocketAddr>().unwrap().into())
            .unwrap();
        let port = ipv6_blocker
            .local_addr()
            .unwrap()
            .as_socket()
            .unwrap()
            .port();
        let provider =
            TokioDatagramProvider::new(vec![Candidate::Host("127.0.0.1:1".parse().unwrap())]);
        let error = match provider.bind(BindOptions { port }).await {
            Ok(_) => panic!("the occupied IPv6 port unexpectedly bound"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            CoreError::DatagramBind {
                family: AddressFamily::Ipv6,
                ..
            }
        ));
        drop(ipv6_blocker);
        std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).unwrap();
    }

    #[tokio::test]
    async fn provider_retries_both_families_with_fresh_ports_after_preferred_failure() {
        let occupied = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let provider = TokioDatagramProvider::with_preferred_ports(
            vec![Candidate::Host("127.0.0.1:1".parse().unwrap())],
            [Some(occupied_port), Some(occupied_port)],
        );
        let socket = provider.bind(BindOptions { port: 0 }).await.unwrap();
        let addrs = socket.local_addrs().unwrap();
        assert_ne!(addrs[0].port(), occupied_port);
        assert_ne!(addrs[1].port(), 0);
        socket.shutdown().await;
    }

    #[tokio::test]
    async fn immediate_shutdown_does_not_emit_a_transport_failure() {
        let node = VelaNode::builder()
            .datagram_provider(Arc::new(TokioDatagramProvider::new(vec![Candidate::Host(
                "127.0.0.1:1".parse().unwrap(),
            )])))
            .config(NodeConfig::default())
            .build()
            .await
            .unwrap();
        node.start().await.unwrap();
        node.shutdown().await;
        assert!(
            timeout(Duration::from_millis(50), node.next_event())
                .await
                .is_err()
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
                port: address_a.port(),
            },
            connect_timeout: Duration::from_secs(2),
            virtual_ipv4: Some(Ipv4Addr::new(10, 254, 0, 1)),
            ..NodeConfig::default()
        };
        let config_b = NodeConfig {
            bind: BindOptions {
                port: address_b.port(),
            },
            connect_timeout: Duration::from_secs(2),
            virtual_ipv4: Some(Ipv4Addr::new(10, 254, 0, 2)),
            ..NodeConfig::default()
        };
        let node_a = VelaNode::builder()
            .identity(identity_a.clone())
            .incarnation(1)
            .datagram_provider(provider_a)
            .config(config_a)
            .build()
            .await
            .unwrap();
        let node_b = VelaNode::builder()
            .identity(identity_b.clone())
            .incarnation(2)
            .datagram_provider(provider_b)
            .config(config_b)
            .build()
            .await
            .unwrap();
        node_a
            .register_peer(peer_info(
                &identity_b,
                2,
                address_b,
                Ipv4Addr::new(10, 254, 0, 2),
            ))
            .await
            .unwrap();
        node_b
            .register_peer(peer_info(
                &identity_a,
                1,
                address_a,
                Ipv4Addr::new(10, 254, 0, 1),
            ))
            .await
            .unwrap();
        node_a.start().await.unwrap();
        node_b.start().await.unwrap();
        let a_id = node_a.node_id();
        let b_id = node_b.node_id();
        let (result_a, result_b) = tokio::join!(node_a.connect(b_id), node_b.connect(a_id));
        let handle_a = result_a.unwrap();
        result_b.unwrap();
        let diagnostic = handle_a
            .diagnostic_ping(3, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(diagnostic.peer, b_id);
        assert_eq!(diagnostic.path, address_b);
        assert_eq!(diagnostic.rtts.len(), 3);

        while timeout(Duration::from_millis(5), node_a.next_event())
            .await
            .is_ok()
        {}
        node_a
            .register_peer(peer_info(
                &identity_b,
                2,
                address_b,
                Ipv4Addr::new(10, 254, 0, 2),
            ))
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_millis(20), node_a.next_event())
                .await
                .is_err()
        );

        node_a
            .apply_snapshot(NetworkSnapshot {
                network_id: [0; 16],
                generation: 1,
                virtual_ipv4: Some(Ipv4Cidr {
                    address: Ipv4Addr::new(10, 254, 0, 0),
                    prefix_len: 16,
                }),
                virtual_ipv6: None,
                doh_servers: Vec::new(),
                stun_servers: Vec::new(),
                peers: vec![
                    peer_info(&identity_a, 1, address_a, Ipv4Addr::new(10, 254, 0, 1)),
                    peer_info(&identity_b, 2, address_b, Ipv4Addr::new(10, 254, 0, 2)),
                ],
                online_peers: vec![a_id],
                expires_at: u64::MAX,
                signature: Vec::new(),
            })
            .await
            .unwrap();
        let diagnostic_after_snapshot = handle_a
            .diagnostic_ping(1, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(diagnostic_after_snapshot.peer, b_id);
        assert_eq!(diagnostic_after_snapshot.path, address_b);

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
    async fn peer_restart_with_new_address_and_incarnation_reconnects_automatically() {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let address_a: SocketAddr = "127.0.0.1:45121".parse().unwrap();
        let address_b: SocketAddr = "127.0.0.1:45122".parse().unwrap();
        let address_b_restarted: SocketAddr = "127.0.0.1:45123".parse().unwrap();
        let virtual_a = Ipv4Addr::new(10, 254, 0, 21);
        let virtual_b = Ipv4Addr::new(10, 254, 0, 22);

        let config = |port| NodeConfig {
            bind: BindOptions { port },
            connect_timeout: Duration::from_millis(300),
            reconnect_backoff: Duration::from_millis(10),
            virtual_ipv4: Some(if port == address_a.port() {
                virtual_a
            } else {
                virtual_b
            }),
            ..NodeConfig::default()
        };
        let node_a = VelaNode::builder()
            .identity(identity_a.clone())
            .incarnation(1)
            .datagram_provider(Arc::new(TokioDatagramProvider::new(vec![Candidate::Host(
                address_a,
            )])))
            .config(config(address_a.port()))
            .build()
            .await
            .unwrap();
        let node_b = VelaNode::builder()
            .identity(identity_b.clone())
            .incarnation(2)
            .datagram_provider(Arc::new(TokioDatagramProvider::new(vec![Candidate::Host(
                address_b,
            )])))
            .config(config(address_b.port()))
            .build()
            .await
            .unwrap();
        node_a
            .register_peer(peer_info(&identity_b, 2, address_b, virtual_b))
            .await
            .unwrap();
        node_b
            .register_peer(peer_info(&identity_a, 1, address_a, virtual_a))
            .await
            .unwrap();
        node_a.start().await.unwrap();
        node_b.start().await.unwrap();
        let peer_id = node_b.node_id();
        let handle = node_a.connect(peer_id).await.unwrap();

        while timeout(Duration::from_millis(5), node_a.next_event())
            .await
            .is_ok()
        {}

        node_b.shutdown().await;
        let node_b_restarted = VelaNode::builder()
            .identity(identity_b.clone())
            .incarnation(3)
            .datagram_provider(Arc::new(TokioDatagramProvider::new(vec![Candidate::Host(
                address_b_restarted,
            )])))
            .config(config(address_b_restarted.port()))
            .build()
            .await
            .unwrap();
        node_b_restarted
            .register_peer(peer_info(&identity_a, 1, address_a, virtual_a))
            .await
            .unwrap();
        let snapshot = NetworkSnapshot {
            network_id: [0; 16],
            generation: 1,
            virtual_ipv4: Some(Ipv4Cidr {
                address: Ipv4Addr::new(10, 254, 0, 0),
                prefix_len: 16,
            }),
            virtual_ipv6: None,
            doh_servers: Vec::new(),
            stun_servers: Vec::new(),
            peers: vec![
                peer_info(&identity_a, 1, address_a, virtual_a),
                peer_info(&identity_b, 3, address_b_restarted, virtual_b),
            ],
            online_peers: vec![node_a.node_id(), peer_id],
            expires_at: u64::MAX,
            signature: Vec::new(),
        };
        node_b_restarted
            .apply_snapshot(snapshot.clone())
            .await
            .unwrap();
        node_b_restarted.start().await.unwrap();
        node_a.apply_snapshot(snapshot).await.unwrap();

        timeout(Duration::from_secs(2), async {
            loop {
                if matches!(node_a.next_event().await, Some(VelaEvent::PeerConnected(id)) if id == peer_id) {
                    break;
                }
            }
        })
        .await
        .unwrap();
        let diagnostic = handle
            .diagnostic_ping(1, Duration::from_secs(1))
            .await
            .unwrap();
        assert_eq!(diagnostic.path, address_b_restarted);

        node_a.shutdown().await;
        node_b_restarted.shutdown().await;
    }

    #[tokio::test]
    async fn missing_keepalive_ack_marks_session_dead_and_reconnects() {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let address_a: SocketAddr = "127.0.0.1:45131".parse().unwrap();
        let address_b: SocketAddr = "127.0.0.1:45132".parse().unwrap();
        let virtual_a = Ipv4Addr::new(10, 254, 0, 31);
        let virtual_b = Ipv4Addr::new(10, 254, 0, 32);
        let config = |port, virtual_ipv4| NodeConfig {
            bind: BindOptions { port },
            keepalive_interval: Duration::from_millis(20),
            connect_timeout: Duration::from_millis(300),
            reconnect_backoff: Duration::from_millis(10),
            virtual_ipv4: Some(virtual_ipv4),
            ..NodeConfig::default()
        };
        let node_a = VelaNode::builder()
            .identity(identity_a.clone())
            .incarnation(1)
            .datagram_provider(Arc::new(TokioDatagramProvider::new(vec![Candidate::Host(
                address_a,
            )])))
            .config(config(address_a.port(), virtual_a))
            .build()
            .await
            .unwrap();
        let node_b = VelaNode::builder()
            .identity(identity_b.clone())
            .incarnation(2)
            .datagram_provider(Arc::new(DropKeepAliveAckProvider {
                host_candidates: vec![Candidate::Host(address_b)],
            }))
            .config(config(address_b.port(), virtual_b))
            .build()
            .await
            .unwrap();
        node_a
            .register_peer(peer_info(&identity_b, 2, address_b, virtual_b))
            .await
            .unwrap();
        node_b
            .register_peer(peer_info(&identity_a, 1, address_a, virtual_a))
            .await
            .unwrap();
        node_a.start().await.unwrap();
        node_b.start().await.unwrap();
        let peer_id = node_b.node_id();
        node_a.connect(peer_id).await.unwrap();

        while timeout(Duration::from_millis(5), node_a.next_event())
            .await
            .is_ok()
        {}

        timeout(Duration::from_secs(2), async {
            let mut disconnected = false;
            let mut reconnect_requested = false;
            loop {
                match node_a.next_event().await {
                    Some(VelaEvent::PeerDisconnected(id)) if id == peer_id => {
                        disconnected = true;
                    }
                    Some(VelaEvent::PeerReconnectRequested(id)) if id == peer_id => {
                        reconnect_requested = true;
                    }
                    Some(VelaEvent::PeerConnected(id))
                        if id == peer_id && disconnected && reconnect_requested =>
                    {
                        break;
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap();

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
            .incarnation(1)
            .datagram_provider(Arc::new(TokioDatagramProvider::new(Vec::new())))
            .config(NodeConfig {
                bind: BindOptions { port: 0 },
                virtual_ipv4: Some(Ipv4Addr::new(10, 254, 0, 3)),
                ..NodeConfig::default()
            })
            .build()
            .await
            .unwrap();
        let node_b = VelaNode::builder()
            .identity(identity_b.clone())
            .incarnation(2)
            .datagram_provider(Arc::new(TokioDatagramProvider::new(Vec::new())))
            .config(NodeConfig {
                bind: BindOptions { port: 0 },
                virtual_ipv4: Some(Ipv4Addr::new(10, 254, 0, 4)),
                ..NodeConfig::default()
            })
            .build()
            .await
            .unwrap();
        assert_eq!(node_a.local_addrs().unwrap().len(), 2);
        assert_eq!(node_b.local_addrs().unwrap().len(), 2);
        let Some(address_a) =
            node_a
                .local_candidates()
                .into_iter()
                .find_map(|candidate| match candidate {
                    Candidate::Host(address) if address.is_ipv6() => Some(address),
                    _ => None,
                })
        else {
            return;
        };
        let Some(address_b) =
            node_b
                .local_candidates()
                .into_iter()
                .find_map(|candidate| match candidate {
                    Candidate::Host(address) if address.is_ipv6() => Some(address),
                    _ => None,
                })
        else {
            return;
        };
        node_a
            .register_peer(peer_info(
                &identity_b,
                2,
                address_b,
                Ipv4Addr::new(10, 254, 0, 4),
            ))
            .await
            .unwrap();
        node_b
            .register_peer(peer_info(
                &identity_a,
                1,
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
                incarnation: 1,
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
            .incarnation(1)
            .datagram_provider(Arc::new(TokioDatagramProvider::new(vec![Candidate::Host(
                address,
            )])))
            .config(NodeConfig {
                bind: BindOptions {
                    port: address.port(),
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
                online_peers: Vec::new(),
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
