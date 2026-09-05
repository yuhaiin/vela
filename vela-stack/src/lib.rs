//! Tokio-owned userspace IP stack for Vela.
//!
//! The stack deliberately has one owner task. smoltcp sockets are not shared
//! between application tasks; public handles send small commands to that
//! owner, which keeps polling, socket state, and Vela packet I/O serialized.

use bytes::{Bytes, BytesMut};
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{icmp, raw, tcp, udp},
    storage::{PacketBuffer, PacketMetadata},
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Cidr, Ipv6Cidr},
};
use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};
use vela_core::{CoreError, DEFAULT_VIRTUAL_MTU, VelaEvent, VelaNode};

const DEFAULT_MTU: usize = DEFAULT_VIRTUAL_MTU;
const DEFAULT_SOCKET_BUFFER: usize = 64 * 1024;
const DEVICE_QUEUE_LIMIT: usize = 256;
const EPHEMERAL_PORT_START: u16 = 49152;
const EPHEMERAL_PORT_END: u16 = 65535;
const STACK_POLL_MIN_INTERVAL: Duration = Duration::from_millis(1);
const STACK_POLL_IDLE_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Clone, Debug)]
pub struct StackConfig {
    pub ipv4: Option<(Ipv4Addr, u8)>,
    pub ipv6: Option<(Ipv6Addr, u8)>,
    pub mtu: usize,
    pub socket_buffer: usize,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            ipv4: None,
            ipv6: None,
            mtu: DEFAULT_MTU,
            socket_buffer: DEFAULT_SOCKET_BUFFER,
        }
    }
}

impl StackConfig {
    pub fn ipv4(address: Ipv4Addr) -> Self {
        Self {
            ipv4: Some((address, 10)),
            ..Self::default()
        }
    }
}

#[derive(Clone)]
pub struct VelaStack {
    commands: mpsc::Sender<Command>,
}

impl VelaStack {
    pub fn attach(node: VelaNode, config: StackConfig) -> Result<Self, StackError> {
        if config.mtu < 576 {
            return Err(StackError::InvalidConfig("MTU must be at least 576"));
        }
        if config.ipv4.is_some_and(|(_, prefix_len)| prefix_len > 32)
            || config.ipv6.is_some_and(|(_, prefix_len)| prefix_len > 128)
        {
            return Err(StackError::InvalidConfig("invalid IP prefix length"));
        }
        if config.ipv4.is_none() && config.ipv6.is_none() {
            return Err(StackError::InvalidConfig(
                "at least one local IP is required",
            ));
        }
        let (commands, receiver) = mpsc::channel(256);
        let stack = Self { commands };
        tokio::spawn(run_stack(node, config, stack.commands.clone(), receiver));
        Ok(stack)
    }

    /// Injects one complete IP packet received from an external L3 adapter.
    pub async fn inject_ip(&self, packet: impl Into<Bytes>) -> Result<(), StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::Inject {
                packet: packet.into(),
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }

    /// Alias for [`VelaStack::inject_ip`].
    pub async fn send_ip(&self, packet: impl Into<Bytes>) -> Result<(), StackError> {
        self.inject_ip(packet).await
    }

    /// Stops the userspace stack and the Vela node it owns.
    pub async fn shutdown(&self) -> Result<(), StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::Shutdown { response })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }

    pub async fn dial_tcp(&self, remote: SocketAddr) -> Result<VelaTcpStream, StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::DialTcp { remote, response })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }

    /// Tailscale-style TCP entry point for library consumers.
    pub async fn dial(&self, remote: SocketAddr) -> Result<VelaTcpStream, StackError> {
        self.dial_tcp(remote).await
    }

    pub async fn listen_tcp(&self, local: SocketAddr) -> Result<VelaTcpListener, StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::ListenTcp { local, response })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }

    /// Tailscale-style TCP listener entry point for library consumers.
    pub async fn listen(&self, local: SocketAddr) -> Result<VelaTcpListener, StackError> {
        self.listen_tcp(local).await
    }

    pub async fn bind_udp(&self, local: SocketAddr) -> Result<VelaUdpSocket, StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::BindUdp { local, response })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }

    /// Tailscale-style packet listener entry point for library consumers.
    pub async fn listen_packet(&self, local: SocketAddr) -> Result<VelaUdpSocket, StackError> {
        self.bind_udp(local).await
    }

    pub async fn raw_socket(
        &self,
        version: IpVersion,
        protocol: u8,
    ) -> Result<VelaRawSocket, StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::BindRaw {
                version,
                protocol,
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }

    pub async fn bind_icmp(&self, identifier: u16) -> Result<VelaIcmpSocket, StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::BindIcmp {
                identifier,
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Clone)]
pub struct VelaTcpStream {
    commands: mpsc::Sender<Command>,
    id: u64,
}

impl VelaTcpStream {
    pub async fn send(&self, data: &[u8]) -> Result<usize, StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::TcpSend {
                id: self.id,
                data: Bytes::copy_from_slice(data),
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }

    pub async fn recv(&self, max_len: usize) -> Result<Bytes, StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::TcpRecv {
                id: self.id,
                max_len,
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }

    pub async fn shutdown(&self) -> Result<(), StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::TcpShutdown {
                id: self.id,
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }
}

pub struct VelaTcpListener {
    commands: mpsc::Sender<Command>,
    id: u64,
}

impl VelaTcpListener {
    pub async fn accept(&self) -> Result<(VelaTcpStream, SocketAddr), StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::TcpAccept {
                id: self.id,
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }
}

#[derive(Clone)]
pub struct VelaUdpSocket {
    commands: mpsc::Sender<Command>,
    id: u64,
}

impl VelaUdpSocket {
    pub async fn send_to(&self, data: &[u8], target: SocketAddr) -> Result<usize, StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::UdpSend {
                id: self.id,
                data: Bytes::copy_from_slice(data),
                target,
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }

    pub async fn recv_from(&self, max_len: usize) -> Result<(Bytes, SocketAddr), StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::UdpRecv {
                id: self.id,
                max_len,
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }
}

#[derive(Clone)]
pub struct VelaRawSocket {
    commands: mpsc::Sender<Command>,
    id: u64,
}

pub type TcpStream = VelaTcpStream;
pub type TcpListener = VelaTcpListener;
pub type UdpSocket = VelaUdpSocket;
pub type RawSocket = VelaRawSocket;

#[derive(Clone)]
pub struct VelaIcmpSocket {
    commands: mpsc::Sender<Command>,
    id: u64,
}

impl VelaIcmpSocket {
    pub async fn send_to(&self, payload: &[u8], target: IpAddr) -> Result<(), StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::IcmpSend {
                id: self.id,
                payload: Bytes::copy_from_slice(payload),
                target,
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }

    pub async fn recv(&self, max_len: usize) -> Result<(Bytes, IpAddr), StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::IcmpRecv {
                id: self.id,
                max_len,
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }
}

impl VelaRawSocket {
    pub async fn send(&self, packet: &[u8]) -> Result<(), StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::RawSend {
                id: self.id,
                packet: Bytes::copy_from_slice(packet),
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }

    pub async fn recv(&self, max_len: usize) -> Result<Bytes, StackError> {
        let (response, receiver) = oneshot::channel();
        self.commands
            .send(Command::RawRecv {
                id: self.id,
                max_len,
                response,
            })
            .await
            .map_err(|_| StackError::Closed)?;
        receiver.await.map_err(|_| StackError::Closed)?
    }
}

enum Command {
    Shutdown {
        response: oneshot::Sender<Result<(), StackError>>,
    },
    Inject {
        packet: Bytes,
        response: oneshot::Sender<Result<(), StackError>>,
    },
    DialTcp {
        remote: SocketAddr,
        response: oneshot::Sender<Result<VelaTcpStream, StackError>>,
    },
    ListenTcp {
        local: SocketAddr,
        response: oneshot::Sender<Result<VelaTcpListener, StackError>>,
    },
    BindUdp {
        local: SocketAddr,
        response: oneshot::Sender<Result<VelaUdpSocket, StackError>>,
    },
    BindRaw {
        version: IpVersion,
        protocol: u8,
        response: oneshot::Sender<Result<VelaRawSocket, StackError>>,
    },
    BindIcmp {
        identifier: u16,
        response: oneshot::Sender<Result<VelaIcmpSocket, StackError>>,
    },
    TcpSend {
        id: u64,
        data: Bytes,
        response: oneshot::Sender<Result<usize, StackError>>,
    },
    TcpRecv {
        id: u64,
        max_len: usize,
        response: oneshot::Sender<Result<Bytes, StackError>>,
    },
    TcpShutdown {
        id: u64,
        response: oneshot::Sender<Result<(), StackError>>,
    },
    TcpAccept {
        id: u64,
        response: oneshot::Sender<Result<(VelaTcpStream, SocketAddr), StackError>>,
    },
    UdpSend {
        id: u64,
        data: Bytes,
        target: SocketAddr,
        response: oneshot::Sender<Result<usize, StackError>>,
    },
    UdpRecv {
        id: u64,
        max_len: usize,
        response: oneshot::Sender<Result<(Bytes, SocketAddr), StackError>>,
    },
    RawSend {
        id: u64,
        packet: Bytes,
        response: oneshot::Sender<Result<(), StackError>>,
    },
    RawRecv {
        id: u64,
        max_len: usize,
        response: oneshot::Sender<Result<Bytes, StackError>>,
    },
    IcmpSend {
        id: u64,
        payload: Bytes,
        target: IpAddr,
        response: oneshot::Sender<Result<(), StackError>>,
    },
    IcmpRecv {
        id: u64,
        max_len: usize,
        response: oneshot::Sender<Result<(Bytes, IpAddr), StackError>>,
    },
}

struct VirtualDevice {
    rx: VecDeque<Bytes>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl VirtualDevice {
    fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }

    fn push_rx(&mut self, packet: Bytes) -> Result<(), StackError> {
        if packet.len() > self.mtu {
            return Err(StackError::PacketTooLarge);
        }
        if self.rx.len() >= DEVICE_QUEUE_LIMIT {
            return Err(StackError::QueueFull);
        }
        self.rx.push_back(packet);
        Ok(())
    }
}

struct VirtualRxToken {
    packet: Bytes,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

struct VirtualTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    mtu: usize,
}

impl TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        if len <= self.mtu && self.queue.len() < DEVICE_QUEUE_LIMIT {
            self.queue.push_back(packet);
        }
        result
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((
            VirtualRxToken { packet },
            VirtualTxToken {
                queue: &mut self.tx,
                mtu: self.mtu,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            queue: &mut self.tx,
            mtu: self.mtu,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

struct StackRuntime {
    commands: mpsc::Receiver<Command>,
    sender: mpsc::Sender<Command>,
    node: VelaNode,
    interface: Interface,
    device: VirtualDevice,
    sockets: SocketSet<'static>,
    next_id: u64,
    tcp: HashMap<u64, TcpState>,
    listeners: HashMap<u64, ListenerState>,
    udp: HashMap<u64, UdpState>,
    raw: HashMap<u64, RawState>,
    icmp: HashMap<u64, IcmpState>,
    next_port: u16,
    started: std::time::Instant,
    socket_buffer: usize,
}

struct TcpState {
    handle: SocketHandle,
    pending_connect: Option<oneshot::Sender<Result<VelaTcpStream, StackError>>>,
    pending_send: Option<(Bytes, oneshot::Sender<Result<usize, StackError>>)>,
    pending_recv: Option<(usize, oneshot::Sender<Result<Bytes, StackError>>)>,
}

struct ListenerState {
    handle: SocketHandle,
    local: SocketAddr,
    pending_accept: Option<oneshot::Sender<Result<(VelaTcpStream, SocketAddr), StackError>>>,
    accepted: VecDeque<(u64, SocketAddr)>,
}

struct UdpState {
    handle: SocketHandle,
    pending_recv: Option<PendingUdpRecv>,
}

struct RawState {
    handle: SocketHandle,
    pending_recv: Option<(usize, oneshot::Sender<Result<Bytes, StackError>>)>,
}

struct IcmpState {
    handle: SocketHandle,
    pending_recv: Option<PendingIcmpRecv>,
}

type PendingUdpRecv = (
    usize,
    oneshot::Sender<Result<(Bytes, SocketAddr), StackError>>,
);
type PendingIcmpRecv = (usize, oneshot::Sender<Result<(Bytes, IpAddr), StackError>>);

async fn run_stack(
    node: VelaNode,
    config: StackConfig,
    sender: mpsc::Sender<Command>,
    commands: mpsc::Receiver<Command>,
) {
    let runtime = match StackRuntime::new(node, config, sender, commands) {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "userspace Vela stack failed to initialize");
            return;
        }
    };
    runtime.run().await;
}

impl StackRuntime {
    fn new(
        node: VelaNode,
        config: StackConfig,
        sender: mpsc::Sender<Command>,
        commands: mpsc::Receiver<Command>,
    ) -> Result<Self, StackError> {
        let mut device = VirtualDevice::new(config.mtu);
        let mut interface = Interface::new(
            InterfaceConfig::new(HardwareAddress::Ip),
            &mut device,
            SmolInstant::from_millis(0),
        );
        interface.update_ip_addrs(|addresses| {
            if let Some((address, prefix_len)) = config.ipv4 {
                let _ = addresses.push(IpCidr::Ipv4(Ipv4Cidr::new(address, prefix_len)));
            }
            if let Some((address, prefix_len)) = config.ipv6 {
                let _ = addresses.push(IpCidr::Ipv6(Ipv6Cidr::new(address, prefix_len)));
            }
        });
        Ok(Self {
            commands,
            sender,
            node,
            interface,
            device,
            sockets: SocketSet::new(Vec::new()),
            next_id: 1,
            tcp: HashMap::new(),
            listeners: HashMap::new(),
            udp: HashMap::new(),
            raw: HashMap::new(),
            icmp: HashMap::new(),
            next_port: EPHEMERAL_PORT_START,
            started: std::time::Instant::now(),
            socket_buffer: config.socket_buffer,
        })
    }

    async fn run(mut self) {
        loop {
            let poll_delay = self.poll_delay();
            tokio::select! {
                command = self.commands.recv() => {
                    let Some(command) = command else { break };
                    if self.handle_command(command) {
                        break;
                    }
                }
                event = self.node.next_event() => {
                    match event {
                        Some(VelaEvent::IpPacket { packet, .. }) => {
                            let _ = self.device.push_rx(packet.into_bytes());
                        }
                        Some(VelaEvent::TransportFailed { family, error }) => {
                            tracing::error!(
                                debug_marker = "vela-udp",
                                ?family,
                                %error,
                                "Vela UDP transport failed"
                            );
                            break;
                        }
                        Some(_) => {}
                        None => break,
                    }
                }
                _ = tokio::time::sleep(poll_delay) => {
                    self.poll();
                }
            }
            self.complete_pending();
            self.flush_device().await;
        }
        self.node.shutdown().await;
    }

    fn handle_command(&mut self, command: Command) -> bool {
        match command {
            Command::Shutdown { response } => {
                let _ = response.send(Ok(()));
                return true;
            }
            Command::Inject { packet, response } => {
                let result = self.device.push_rx(packet);
                let _ = response.send(result);
            }
            Command::DialTcp { remote, response } => {
                let id = self.next_id();
                let local_port = match self.allocate_tcp_port() {
                    Ok(port) => port,
                    Err(error) => {
                        let _ = response.send(Err(error));
                        return false;
                    }
                };
                let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; self.socket_buffer]),
                    tcp::SocketBuffer::new(vec![0; self.socket_buffer]),
                );
                let result = socket
                    .connect(
                        self.interface.context(),
                        remote,
                        smoltcp::wire::IpListenEndpoint {
                            addr: None,
                            port: local_port,
                        },
                    )
                    .map_err(|error| StackError::Socket(error.to_string()));
                if result.is_err() {
                    let _ = response.send(result.map(|_| VelaTcpStream {
                        commands: self.commands_sender(),
                        id,
                    }));
                    return false;
                }
                let handle = self.sockets.add(socket);
                self.tcp.insert(
                    id,
                    TcpState {
                        handle,
                        pending_connect: Some(response),
                        pending_send: None,
                        pending_recv: None,
                    },
                );
            }
            Command::ListenTcp { local, response } => {
                let id = self.next_id();
                let mut socket = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; self.socket_buffer]),
                    tcp::SocketBuffer::new(vec![0; self.socket_buffer]),
                );
                let result = socket
                    .listen(local)
                    .map_err(|error| StackError::Socket(error.to_string()));
                if result.is_err() {
                    let _ = response.send(result.map(|_| VelaTcpListener {
                        commands: self.commands_sender(),
                        id,
                    }));
                    return false;
                }
                let handle = self.sockets.add(socket);
                self.listeners.insert(
                    id,
                    ListenerState {
                        handle,
                        local,
                        pending_accept: None,
                        accepted: VecDeque::new(),
                    },
                );
                let _ = response.send(Ok(VelaTcpListener {
                    commands: self.commands_sender(),
                    id,
                }));
            }
            Command::BindUdp { local, response } => {
                let id = self.next_id();
                let mut socket = udp::Socket::new(
                    udp::PacketBuffer::new(
                        vec![PacketMetadata::EMPTY; 64],
                        vec![0; self.socket_buffer],
                    ),
                    udp::PacketBuffer::new(
                        vec![PacketMetadata::EMPTY; 64],
                        vec![0; self.socket_buffer],
                    ),
                );
                let result = socket
                    .bind(local)
                    .map_err(|error| StackError::Socket(error.to_string()));
                if result.is_err() {
                    let _ = response.send(result.map(|_| VelaUdpSocket {
                        commands: self.commands_sender(),
                        id,
                    }));
                    return false;
                }
                let handle = self.sockets.add(socket);
                self.udp.insert(
                    id,
                    UdpState {
                        handle,
                        pending_recv: None,
                    },
                );
                let _ = response.send(Ok(VelaUdpSocket {
                    commands: self.commands_sender(),
                    id,
                }));
            }
            Command::BindRaw {
                version,
                protocol,
                response,
            } => {
                let id = self.next_id();
                let ip_version = match version {
                    IpVersion::V4 => smoltcp::wire::IpVersion::Ipv4,
                    IpVersion::V6 => smoltcp::wire::IpVersion::Ipv6,
                };
                let socket = raw::Socket::new(
                    ip_version,
                    IpProtocol::from(protocol),
                    raw_packet_buffer(self.socket_buffer),
                    raw_packet_buffer(self.socket_buffer),
                );
                let handle = self.sockets.add(socket);
                self.raw.insert(
                    id,
                    RawState {
                        handle,
                        pending_recv: None,
                    },
                );
                let _ = response.send(Ok(VelaRawSocket {
                    commands: self.commands_sender(),
                    id,
                }));
            }
            Command::BindIcmp {
                identifier,
                response,
            } => {
                let id = self.next_id();
                let mut socket = icmp::Socket::new(
                    icmp::PacketBuffer::new(
                        vec![icmp::PacketMetadata::EMPTY; 64],
                        vec![0; self.socket_buffer],
                    ),
                    icmp::PacketBuffer::new(
                        vec![icmp::PacketMetadata::EMPTY; 64],
                        vec![0; self.socket_buffer],
                    ),
                );
                let result = socket
                    .bind(icmp::Endpoint::Ident(identifier))
                    .map_err(|error| StackError::Socket(error.to_string()));
                if result.is_err() {
                    let _ = response.send(result.map(|_| VelaIcmpSocket {
                        commands: self.commands_sender(),
                        id,
                    }));
                    return false;
                }
                let handle = self.sockets.add(socket);
                self.icmp.insert(
                    id,
                    IcmpState {
                        handle,
                        pending_recv: None,
                    },
                );
                let _ = response.send(Ok(VelaIcmpSocket {
                    commands: self.commands_sender(),
                    id,
                }));
            }
            Command::TcpSend { id, data, response } => {
                let Some(state) = self.tcp.get_mut(&id) else {
                    let _ = response.send(Err(StackError::UnknownSocket));
                    return false;
                };
                if state.pending_send.is_some() {
                    let _ = response.send(Err(StackError::OperationPending));
                    return false;
                }
                let socket = self.sockets.get_mut::<tcp::Socket>(state.handle);
                if socket.can_send() {
                    let result = socket
                        .send_slice(&data)
                        .map_err(|error| StackError::Socket(error.to_string()));
                    let _ = response.send(result);
                } else {
                    state.pending_send = Some((data, response));
                }
            }
            Command::TcpRecv {
                id,
                max_len,
                response,
            } => {
                let Some(state) = self.tcp.get_mut(&id) else {
                    let _ = response.send(Err(StackError::UnknownSocket));
                    return false;
                };
                if state.pending_recv.is_some() {
                    let _ = response.send(Err(StackError::OperationPending));
                    return false;
                }
                let socket = self.sockets.get_mut::<tcp::Socket>(state.handle);
                if socket.can_recv() {
                    let mut data = BytesMut::zeroed(max_len);
                    let result = socket
                        .recv_slice(&mut data)
                        .map(|length| {
                            data.truncate(length);
                            data.freeze()
                        })
                        .map_err(|error| StackError::Socket(error.to_string()));
                    let _ = response.send(result);
                } else if !socket.may_recv() {
                    let _ = response.send(Ok(Bytes::new()));
                } else {
                    state.pending_recv = Some((max_len, response));
                }
            }
            Command::TcpShutdown { id, response } => {
                let Some(state) = self.tcp.get(&id) else {
                    let _ = response.send(Err(StackError::UnknownSocket));
                    return false;
                };
                self.sockets.get_mut::<tcp::Socket>(state.handle).close();
                let _ = response.send(Ok(()));
            }
            Command::TcpAccept { id, response } => {
                let Some(state) = self.listeners.get_mut(&id) else {
                    let _ = response.send(Err(StackError::UnknownSocket));
                    return false;
                };
                if state.pending_accept.is_some() {
                    let _ = response.send(Err(StackError::OperationPending));
                    return false;
                }
                if let Some((stream_id, remote)) = state.accepted.pop_front() {
                    let _ = response.send(Ok((
                        VelaTcpStream {
                            commands: self.commands_sender(),
                            id: stream_id,
                        },
                        remote,
                    )));
                } else {
                    state.pending_accept = Some(response);
                }
            }
            Command::UdpSend {
                id,
                data,
                target,
                response,
            } => {
                let Some(state) = self.udp.get_mut(&id) else {
                    let _ = response.send(Err(StackError::UnknownSocket));
                    return false;
                };
                let socket = self.sockets.get_mut::<udp::Socket>(state.handle);
                let result = socket
                    .send_slice(&data, target)
                    .map(|_| data.len())
                    .map_err(|error| StackError::Socket(error.to_string()));
                let _ = response.send(result);
            }
            Command::UdpRecv {
                id,
                max_len,
                response,
            } => {
                let Some(state) = self.udp.get_mut(&id) else {
                    let _ = response.send(Err(StackError::UnknownSocket));
                    return false;
                };
                if state.pending_recv.is_some() {
                    let _ = response.send(Err(StackError::OperationPending));
                    return false;
                }
                let socket = self.sockets.get_mut::<udp::Socket>(state.handle);
                if socket.can_recv() {
                    let mut data = BytesMut::zeroed(max_len);
                    let result = match socket.recv_slice(&mut data) {
                        Ok((length, meta)) => socket_addr(meta.endpoint)
                            .map(|address| {
                                data.truncate(length);
                                (data.freeze(), address)
                            })
                            .ok_or_else(|| StackError::Socket("invalid UDP endpoint".into())),
                        Err(error) => Err(StackError::Socket(error.to_string())),
                    };
                    let _ = response.send(result);
                } else {
                    state.pending_recv = Some((max_len, response));
                }
            }
            Command::RawSend {
                id,
                packet,
                response,
            } => {
                let Some(state) = self.raw.get_mut(&id) else {
                    let _ = response.send(Err(StackError::UnknownSocket));
                    return false;
                };
                let socket = self.sockets.get_mut::<raw::Socket>(state.handle);
                let result = socket
                    .send_slice(&packet)
                    .map_err(|error| StackError::Socket(error.to_string()));
                let _ = response.send(result);
            }
            Command::RawRecv {
                id,
                max_len,
                response,
            } => {
                let Some(state) = self.raw.get_mut(&id) else {
                    let _ = response.send(Err(StackError::UnknownSocket));
                    return false;
                };
                if state.pending_recv.is_some() {
                    let _ = response.send(Err(StackError::OperationPending));
                    return false;
                }
                let socket = self.sockets.get_mut::<raw::Socket>(state.handle);
                if socket.can_recv() {
                    let mut data = BytesMut::zeroed(max_len);
                    let result = socket
                        .recv_slice(&mut data)
                        .map(|length| {
                            data.truncate(length);
                            data.freeze()
                        })
                        .map_err(|error| StackError::Socket(error.to_string()));
                    let _ = response.send(result);
                } else {
                    state.pending_recv = Some((max_len, response));
                }
            }
            Command::IcmpSend {
                id,
                payload,
                target,
                response,
            } => {
                let Some(state) = self.icmp.get_mut(&id) else {
                    let _ = response.send(Err(StackError::UnknownSocket));
                    return false;
                };
                let socket = self.sockets.get_mut::<icmp::Socket>(state.handle);
                let result = socket
                    .send_slice(&payload, smoltcp_ip_address(target))
                    .map_err(|error| StackError::Socket(error.to_string()));
                let _ = response.send(result);
            }
            Command::IcmpRecv {
                id,
                max_len,
                response,
            } => {
                let Some(state) = self.icmp.get_mut(&id) else {
                    let _ = response.send(Err(StackError::UnknownSocket));
                    return false;
                };
                if state.pending_recv.is_some() {
                    let _ = response.send(Err(StackError::OperationPending));
                    return false;
                }
                let socket = self.sockets.get_mut::<icmp::Socket>(state.handle);
                if socket.recv_queue() != 0 {
                    let mut data = BytesMut::zeroed(max_len);
                    let result = match socket.recv_slice(&mut data) {
                        Ok((length, source)) => {
                            data.truncate(length);
                            Ok((data.freeze(), std_ip_address(source)))
                        }
                        Err(error) => Err(StackError::Socket(error.to_string())),
                    };
                    let _ = response.send(result);
                } else {
                    state.pending_recv = Some((max_len, response));
                }
            }
        }
        false
    }

    fn poll(&mut self) {
        let now = SmolInstant::from_millis(self.started.elapsed().as_millis() as i64);
        let _ = self
            .interface
            .poll(now, &mut self.device, &mut self.sockets);
    }

    fn poll_delay(&mut self) -> Duration {
        if !self.device.rx.is_empty() || !self.device.tx.is_empty() {
            return STACK_POLL_MIN_INTERVAL;
        }
        let now = SmolInstant::from_millis(self.started.elapsed().as_millis() as i64);
        let delay = self
            .interface
            .poll_delay(now, &self.sockets)
            .map(|delay| Duration::from_millis(delay.total_millis()))
            .unwrap_or(STACK_POLL_IDLE_INTERVAL);
        delay.clamp(STACK_POLL_MIN_INTERVAL, STACK_POLL_IDLE_INTERVAL)
    }

    fn allocate_tcp_port(&mut self) -> Result<u16, StackError> {
        let port_count = usize::from(EPHEMERAL_PORT_END - EPHEMERAL_PORT_START) + 1;
        for _ in 0..port_count {
            let candidate = self.next_port;
            self.next_port = if candidate == EPHEMERAL_PORT_END {
                EPHEMERAL_PORT_START
            } else {
                candidate + 1
            };
            let listener_uses_port = self
                .listeners
                .values()
                .any(|state| state.local.port() == candidate);
            let tcp_uses_port = self.tcp.values().any(|state| {
                let socket = self.sockets.get::<tcp::Socket>(state.handle);
                socket.state() != tcp::State::Closed
                    && socket
                        .local_endpoint()
                        .is_some_and(|endpoint| endpoint.port == candidate)
            });
            if !listener_uses_port && !tcp_uses_port {
                return Ok(candidate);
            }
        }
        Err(StackError::NoEphemeralPort)
    }

    fn complete_pending(&mut self) {
        let commands = self.commands_sender();
        for (id, state) in &mut self.tcp {
            let socket = self.sockets.get_mut::<tcp::Socket>(state.handle);
            if let Some(response) = state.pending_connect.take() {
                if socket.state() == tcp::State::Established {
                    let _ = response.send(Ok(VelaTcpStream {
                        commands: commands.clone(),
                        id: *id,
                    }));
                } else {
                    state.pending_connect = Some(response);
                }
            }
            if let Some((data, response)) = state.pending_send.take() {
                if socket.can_send() {
                    let result = socket
                        .send_slice(&data)
                        .map_err(|error| StackError::Socket(error.to_string()));
                    let _ = response.send(result);
                } else {
                    state.pending_send = Some((data, response));
                }
            }
            if let Some((max_len, response)) = state.pending_recv.take() {
                if socket.can_recv() {
                    let mut data = BytesMut::zeroed(max_len);
                    let result = socket
                        .recv_slice(&mut data)
                        .map(|length| {
                            data.truncate(length);
                            data.freeze()
                        })
                        .map_err(|error| StackError::Socket(error.to_string()));
                    let _ = response.send(result);
                } else if !socket.may_recv() {
                    let _ = response.send(Ok(Bytes::new()));
                } else {
                    state.pending_recv = Some((max_len, response));
                }
            }
        }
        let listener_ids = self.listeners.keys().copied().collect::<Vec<_>>();
        for id in listener_ids {
            let stream_id = self.next_id();
            let Some(state) = self.listeners.get_mut(&id) else {
                continue;
            };
            let socket = self.sockets.get_mut::<tcp::Socket>(state.handle);
            if socket.state() != tcp::State::Established {
                continue;
            }
            let remote = socket.remote_endpoint().and_then(socket_addr);
            let Some(remote) = remote else {
                continue;
            };
            let old_handle = state.handle;
            let replacement = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; self.socket_buffer]),
                tcp::SocketBuffer::new(vec![0; self.socket_buffer]),
            );
            let mut replacement = replacement;
            if replacement.listen(state.local).is_err() {
                continue;
            }
            let replacement_handle = self.sockets.add(replacement);
            self.tcp.insert(
                stream_id,
                TcpState {
                    handle: old_handle,
                    pending_connect: None,
                    pending_send: None,
                    pending_recv: None,
                },
            );
            state.handle = replacement_handle;
            if let Some(response) = state.pending_accept.take() {
                let _ = response.send(Ok((
                    VelaTcpStream {
                        commands: commands.clone(),
                        id: stream_id,
                    },
                    remote,
                )));
            } else {
                state.accepted.push_back((stream_id, remote));
            }
        }
        for state in self.udp.values_mut() {
            if let Some((max_len, response)) = state.pending_recv.take() {
                let socket = self.sockets.get_mut::<udp::Socket>(state.handle);
                if socket.can_recv() {
                    let mut data = BytesMut::zeroed(max_len);
                    let result = match socket.recv_slice(&mut data) {
                        Ok((length, meta)) => socket_addr(meta.endpoint)
                            .map(|address| {
                                data.truncate(length);
                                (data.freeze(), address)
                            })
                            .ok_or_else(|| StackError::Socket("invalid UDP endpoint".into())),
                        Err(error) => Err(StackError::Socket(error.to_string())),
                    };
                    let _ = response.send(result);
                } else {
                    state.pending_recv = Some((max_len, response));
                }
            }
        }
        for state in self.raw.values_mut() {
            if let Some((max_len, response)) = state.pending_recv.take() {
                let socket = self.sockets.get_mut::<raw::Socket>(state.handle);
                if socket.can_recv() {
                    let mut data = BytesMut::zeroed(max_len);
                    let result = socket
                        .recv_slice(&mut data)
                        .map(|length| {
                            data.truncate(length);
                            data.freeze()
                        })
                        .map_err(|error| StackError::Socket(error.to_string()));
                    let _ = response.send(result);
                } else {
                    state.pending_recv = Some((max_len, response));
                }
            }
        }
        for state in self.icmp.values_mut() {
            if let Some((max_len, response)) = state.pending_recv.take() {
                let socket = self.sockets.get_mut::<icmp::Socket>(state.handle);
                if socket.recv_queue() != 0 {
                    let mut data = BytesMut::zeroed(max_len);
                    let result = match socket.recv_slice(&mut data) {
                        Ok((length, source)) => {
                            data.truncate(length);
                            Ok((data.freeze(), std_ip_address(source)))
                        }
                        Err(error) => Err(StackError::Socket(error.to_string())),
                    };
                    let _ = response.send(result);
                } else {
                    state.pending_recv = Some((max_len, response));
                }
            }
        }
    }

    async fn flush_device(&mut self) {
        while let Some(packet) = self.device.tx.pop_front() {
            if let Err(error) = self.node.send_ip(packet).await {
                tracing::debug!(%error, "userspace stack dropped an unroutable packet");
            }
        }
    }

    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    fn commands_sender(&self) -> mpsc::Sender<Command> {
        self.sender.clone()
    }
}

fn raw_packet_buffer(size: usize) -> PacketBuffer<'static, ()> {
    PacketBuffer::new(vec![PacketMetadata::EMPTY; 64], vec![0; size])
}

fn socket_addr(endpoint: smoltcp::wire::IpEndpoint) -> Option<SocketAddr> {
    match endpoint.addr {
        IpAddress::Ipv4(address) => Some(SocketAddr::new(IpAddr::V4(address), endpoint.port)),
        IpAddress::Ipv6(address) => Some(SocketAddr::new(IpAddr::V6(address), endpoint.port)),
    }
}

fn smoltcp_ip_address(address: IpAddr) -> IpAddress {
    match address {
        IpAddr::V4(address) => IpAddress::Ipv4(address),
        IpAddr::V6(address) => IpAddress::Ipv6(address),
    }
}

fn std_ip_address(address: IpAddress) -> IpAddr {
    match address {
        IpAddress::Ipv4(address) => IpAddr::V4(address),
        IpAddress::Ipv6(address) => IpAddr::V6(address),
    }
}

#[derive(Debug, Error)]
pub enum StackError {
    #[error("userspace stack is closed")]
    Closed,
    #[error("invalid stack configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("stack socket error: {0}")]
    Socket(String),
    #[error("stack packet is too large")]
    PacketTooLarge,
    #[error("stack queue is full")]
    QueueFull,
    #[error("unknown userspace socket")]
    UnknownSocket,
    #[error("no free ephemeral TCP port")]
    NoEphemeralPort,
    #[error("another operation is already pending on this socket")]
    OperationPending,
    #[error("Vela core error: {0}")]
    Core(#[from] CoreError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::{
        phy::ChecksumCapabilities,
        wire::{Icmpv4Packet, Icmpv4Repr},
    };
    use std::sync::Arc;
    use vela_core::{BindOptions, NodeConfig, TokioDatagramProvider};
    use vela_crypto::Identity;
    use vela_proto::{Candidate, PeerInfo};

    fn peer(
        identity: &Identity,
        incarnation: u64,
        address: SocketAddr,
        virtual_address: Ipv4Addr,
    ) -> PeerInfo {
        let public = identity.public();
        PeerInfo {
            node_id: public.node_id,
            incarnation,
            signing_public: public.signing_public,
            noise_public: public.noise_public,
            candidates: vec![Candidate::Host(address)],
            virtual_ipv4: Some(virtual_address),
            virtual_ipv6: Some(virtual_v6(virtual_address)),
            credential: Vec::new(),
            capabilities: Vec::new(),
        }
    }

    async fn stacks(base_port: u16) -> (VelaStack, VelaStack) {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let address_a = SocketAddr::from(([127, 0, 0, 1], base_port));
        let address_b = SocketAddr::from(([127, 0, 0, 1], base_port + 1));
        let virtual_a = Ipv4Addr::new(10, 254, 0, 11);
        let virtual_b = Ipv4Addr::new(10, 254, 0, 12);
        let node_a = VelaNode::builder()
            .identity(identity_a.clone())
            .incarnation(1)
            .datagram_provider(Arc::new(TokioDatagramProvider::new(vec![Candidate::Host(
                address_a,
            )])))
            .config(NodeConfig {
                bind: BindOptions {
                    port: address_a.port(),
                },
                virtual_ipv4: Some(virtual_a),
                virtual_ipv6: Some(virtual_v6(virtual_a)),
                connect_timeout: Duration::from_secs(2),
                ..NodeConfig::default()
            })
            .build()
            .await
            .unwrap();
        let node_b = VelaNode::builder()
            .identity(identity_b.clone())
            .incarnation(2)
            .datagram_provider(Arc::new(TokioDatagramProvider::new(vec![Candidate::Host(
                address_b,
            )])))
            .config(NodeConfig {
                bind: BindOptions {
                    port: address_b.port(),
                },
                virtual_ipv4: Some(virtual_b),
                virtual_ipv6: Some(virtual_v6(virtual_b)),
                connect_timeout: Duration::from_secs(2),
                ..NodeConfig::default()
            })
            .build()
            .await
            .unwrap();
        node_a
            .register_peer(peer(&identity_b, 2, address_b, virtual_b))
            .await
            .unwrap();
        node_b
            .register_peer(peer(&identity_a, 1, address_a, virtual_a))
            .await
            .unwrap();
        node_a.start().await.unwrap();
        node_b.start().await.unwrap();
        let stack_a = VelaStack::attach(
            node_a,
            StackConfig {
                ipv4: Some((virtual_a, 10)),
                ipv6: Some((virtual_v6(virtual_a), 8)),
                ..StackConfig::default()
            },
        )
        .unwrap();
        let stack_b = VelaStack::attach(
            node_b,
            StackConfig {
                ipv4: Some((virtual_b, 10)),
                ipv6: Some((virtual_v6(virtual_b), 8)),
                ..StackConfig::default()
            },
        )
        .unwrap();
        (stack_a, stack_b)
    }

    #[tokio::test]
    async fn userspace_tcp_round_trip_uses_the_ip_data_plane() {
        let (stack_a, stack_b) = stacks(45111).await;
        let virtual_a = Ipv4Addr::new(10, 254, 0, 11);
        let virtual_b = Ipv4Addr::new(10, 254, 0, 12);
        let listener = stack_b
            .listen(SocketAddr::new(IpAddr::V4(virtual_b), 8080))
            .await
            .unwrap();
        let client = stack_a
            .dial(SocketAddr::new(IpAddr::V4(virtual_b), 8080))
            .await
            .unwrap();
        let (server, remote) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(remote.ip(), IpAddr::V4(virtual_a));
        client.send(b"hello over vela").await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), server.recv(64))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received[..], b"hello over vela");
    }

    #[tokio::test]
    async fn userspace_udp_round_trip_uses_virtual_addresses() {
        let (stack_a, stack_b) = stacks(45121).await;
        let virtual_a = Ipv4Addr::new(10, 254, 0, 11);
        let virtual_b = Ipv4Addr::new(10, 254, 0, 12);
        let receiver = stack_b
            .listen_packet(SocketAddr::new(IpAddr::V4(virtual_b), 9090))
            .await
            .unwrap();
        let sender = stack_a
            .listen_packet(SocketAddr::new(IpAddr::V4(virtual_a), 9091))
            .await
            .unwrap();
        assert_eq!(
            sender
                .send_to(b"udp over vela", receiver_addr(virtual_b, 9090))
                .await
                .unwrap(),
            13
        );
        let (received, source) =
            tokio::time::timeout(Duration::from_secs(2), receiver.recv_from(64))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, receiver_addr(virtual_a, 9091));
        assert_eq!(&received[..], b"udp over vela");

        let receiver_v6 = stack_b
            .listen_packet(SocketAddr::new(IpAddr::V6(virtual_v6(virtual_b)), 9092))
            .await
            .unwrap();
        let sender_v6 = stack_a
            .listen_packet(SocketAddr::new(IpAddr::V6(virtual_v6(virtual_a)), 9093))
            .await
            .unwrap();
        assert_eq!(
            sender_v6
                .send_to(
                    b"udp v6 over vela",
                    SocketAddr::new(IpAddr::V6(virtual_v6(virtual_b)), 9092),
                )
                .await
                .unwrap(),
            16
        );
        let (received, source) =
            tokio::time::timeout(Duration::from_secs(2), receiver_v6.recv_from(64))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            source,
            SocketAddr::new(IpAddr::V6(virtual_v6(virtual_a)), 9093)
        );
        assert_eq!(&received[..], b"udp v6 over vela");
    }

    #[tokio::test]
    async fn userspace_udp_allows_send_while_receive_is_pending() {
        let (stack_a, stack_b) = stacks(45125).await;
        let virtual_a = Ipv4Addr::new(10, 254, 0, 11);
        let virtual_b = Ipv4Addr::new(10, 254, 0, 12);
        let socket_a = stack_a
            .listen_packet(SocketAddr::new(IpAddr::V4(virtual_a), 9101))
            .await
            .unwrap();
        let socket_b = stack_b
            .listen_packet(SocketAddr::new(IpAddr::V4(virtual_b), 9100))
            .await
            .unwrap();
        let waiting = {
            let socket_b = socket_b.clone();
            tokio::spawn(async move {
                tokio::time::timeout(Duration::from_secs(2), socket_b.recv_from(64))
                    .await
                    .unwrap()
                    .unwrap()
            })
        };
        tokio::time::sleep(Duration::from_millis(5)).await;
        socket_b
            .send_to(b"reply", receiver_addr(virtual_a, 9101))
            .await
            .unwrap();
        socket_a
            .send_to(b"request", receiver_addr(virtual_b, 9100))
            .await
            .unwrap();
        let (received, source) = waiting.await.unwrap();
        assert_eq!(&received[..], b"request");
        assert_eq!(source, receiver_addr(virtual_a, 9101));
        let (received, source) =
            tokio::time::timeout(Duration::from_secs(2), socket_a.recv_from(64))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&received[..], b"reply");
        assert_eq!(source, receiver_addr(virtual_b, 9100));
    }

    #[tokio::test]
    async fn userspace_raw_socket_preserves_an_ip_packet() {
        let (stack_a, stack_b) = stacks(45131).await;
        let virtual_a = Ipv4Addr::new(10, 254, 0, 11);
        let virtual_b = Ipv4Addr::new(10, 254, 0, 12);
        let receiver = stack_b.raw_socket(IpVersion::V4, 99).await.unwrap();
        let sender = stack_a.raw_socket(IpVersion::V4, 99).await.unwrap();
        let packet = ipv4_packet(virtual_a, virtual_b, 99, b"raw over vela");
        sender.send(&packet).await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(2), receiver.recv(1200))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received[20..], b"raw over vela");
    }

    #[tokio::test]
    async fn userspace_icmp_socket_round_trip_uses_virtual_addresses() {
        let (stack_a, stack_b) = stacks(45141).await;
        let virtual_a = Ipv4Addr::new(10, 254, 0, 11);
        let virtual_b = Ipv4Addr::new(10, 254, 0, 12);
        let receiver = stack_b.bind_icmp(7).await.unwrap();
        let sender = stack_a.bind_icmp(7).await.unwrap();
        let packet = icmp_echo_request(7, 1, b"icmp over vela");
        sender
            .send_to(&packet, IpAddr::V4(virtual_b))
            .await
            .unwrap();
        let (received, source) = tokio::time::timeout(Duration::from_secs(2), receiver.recv(1200))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(source, IpAddr::V4(virtual_a));
        assert_eq!(&received[..], &packet[..]);
    }

    #[tokio::test]
    async fn userspace_stack_has_an_explicit_shutdown_lifecycle() {
        let (stack, _peer) = stacks(45151).await;
        stack.shutdown().await.unwrap();
        assert!(matches!(
            stack
                .send_ip(ipv4_packet(
                    Ipv4Addr::new(10, 254, 0, 11),
                    Ipv4Addr::new(10, 254, 0, 12),
                    17,
                    b"after shutdown",
                ))
                .await,
            Err(StackError::Closed)
        ));
    }

    fn receiver_addr(address: Ipv4Addr, port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(address), port)
    }

    fn virtual_v6(address: Ipv4Addr) -> Ipv6Addr {
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, u16::from(address.octets()[3]))
    }

    fn ipv4_packet(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut packet = vec![0; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..].copy_from_slice(payload);
        let checksum = ipv4_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet
    }

    fn ipv4_checksum(header: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in header.chunks_exact(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        !(sum as u16).wrapping_add((sum >> 16) as u16)
    }

    fn icmp_echo_request(identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
        let repr = Icmpv4Repr::EchoRequest {
            ident: identifier,
            seq_no: sequence,
            data,
        };
        let mut packet = vec![0; repr.buffer_len()];
        repr.emit(
            &mut Icmpv4Packet::new_unchecked(&mut packet),
            &ChecksumCapabilities::default(),
        );
        packet
    }
}
