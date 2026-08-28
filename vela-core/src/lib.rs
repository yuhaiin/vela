//! Embeddable direct UDP peer transport.
//!
//! The core owns peer/session state and Tokio tasks. Hosts can provide the
//! actual direct UDP socket through [`DatagramProvider`] to select an
//! interface, source address, routing domain or platform-specific socket
//! options without making Vela know about those details.

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use rand::RngCore;
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    sync::{
        Arc,
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
};
use vela_proto::{
    Candidate, Header, NodeId, PacketType, PeerInfo, ProtoError, PublicPeerInfo, WirePacket,
};

#[derive(Clone, Debug)]
pub struct BindOptions {
    pub local_addr: SocketAddr,
}

impl Default for BindOptions {
    fn default() -> Self {
        Self {
            local_addr: "0.0.0.0:0".parse().expect("valid default socket address"),
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
}

pub struct TokioDatagramProvider {
    pub host_candidates: Vec<Candidate>,
}

impl TokioDatagramProvider {
    pub fn new(host_candidates: Vec<Candidate>) -> Self {
        Self { host_candidates }
    }
}

#[async_trait]
impl DatagramProvider for TokioDatagramProvider {
    async fn bind(&self, options: BindOptions) -> Result<Arc<dyn DatagramSocket>, CoreError> {
        Ok(Arc::new(TokioDatagramSocket {
            socket: UdpSocket::bind(options.local_addr).await?,
        }))
    }

    fn local_candidates(&self) -> Vec<Candidate> {
        self.host_candidates.clone()
    }
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
    socket: Arc<dyn DatagramSocket>,
}

#[async_trait]
impl vela_stun::StunSocket for StunSocketAdapter {
    async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.socket.send_to(bytes, target).await
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buffer).await
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
        let inner = Arc::new(Inner {
            identity,
            socket,
            provider,
            config: self.config,
            observer: self.observer,
            peers: Mutex::new(HashMap::new()),
            event_tx,
            event_rx: Mutex::new(Some(event_rx)),
            shutdown: Notify::new(),
            started: AtomicBool::new(false),
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
        if candidates.is_empty() {
            self.local_addr()
                .map(|address| vec![Candidate::Host(address)])
                .unwrap_or_default()
        } else {
            candidates
        }
    }

    pub async fn gather_server_reflexive_candidates(
        &self,
        config: &vela_stun::StunConfig,
    ) -> Result<Vec<Candidate>, CoreError> {
        let socket = StunSocketAdapter {
            socket: Arc::clone(&self.inner.socket),
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
        self.inner
            .peers
            .lock()
            .await
            .insert(info.node_id, Arc::new(PeerState::new(info)));
        Ok(())
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
        for peer in &registration.peers {
            self.register_peer(peer.clone()).await?;
        }
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
        let peer = self
            .inner
            .peers
            .lock()
            .await
            .get(&peer_id)
            .cloned()
            .ok_or(ConnectError::UnknownPeer)?;
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
                        let mut active = peer.active.lock().await;
                        if let Some(session) = active.as_mut() {
                            let sequence = session.tx_sequence.fetch_add(1, Ordering::Relaxed);
                            if let Ok(payload) = encrypt_payload(session, PacketType::KeepAlive, sequence, &[]) {
                                let _ = self.send_packet(session.path, PacketType::KeepAlive, session.session_id, sequence, &payload).await;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn handle_packet(&self, input: &[u8], source: SocketAddr) -> Result<(), CoreError> {
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
        verify_probe(&probe, &peer.info)?;
        add_candidate(&peer, Candidate::PeerReflexive(source)).await;
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
            if attempt.as_ref().map(|value| value.session_id) != Some(probe.session_id) {
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
        let message = handshake.write_message(&[])?;
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
        if peer.active.lock().await.is_some() {
            return Ok(());
        }
        if role == 1 {
            if self.identity.public().node_id < sender {
                return Ok(());
            }
            let mut handshake = NoiseHandshake::responder(&self.identity)?;
            handshake.read_message(&packet.payload[33..])?;
            let response = handshake.write_message(&[])?;
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
            handshake.read_message(&packet.payload[33..])?;
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
                    self.observe(TrafficSample {
                        peer: Some(peer.info.node_id),
                        direction: TrafficDirection::Received,
                        path: source,
                        payload_bytes: plaintext.len(),
                        encrypted_bytes: packet.payload.len(),
                        wire_bytes: input_wire_len(&packet),
                    });
                    events.push(VelaEvent::Packet {
                        peer: peer.info.node_id,
                        payload: Bytes::from(plaintext),
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

    pub async fn send(&self, payload: Bytes) -> Result<(), SendError> {
        let peer = self
            .node
            .inner
            .peers
            .lock()
            .await
            .get(&self.peer_id)
            .cloned()
            .ok_or(SendError::UnknownPeer)?;
        self.node.inner.send_payload(&peer, payload).await
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
    Packet { peer: NodeId, payload: Bytes },
}

struct PeerState {
    info: PeerInfo,
    attempt: Mutex<Option<Attempt>>,
    active: Mutex<Option<ActiveSession>>,
    notify: Notify,
    queue: Mutex<VecDeque<Bytes>>,
}

impl PeerState {
    fn new(info: PeerInfo) -> Self {
        Self {
            info,
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
}

#[derive(Default)]
struct ReplayWindow {
    highest: Option<u64>,
    bits: u64,
}

impl ReplayWindow {
    fn accept(&mut self, sequence: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.bits = 1;
            return true;
        };
        if sequence > highest {
            let shift = sequence - highest;
            self.bits = if shift >= 64 {
                1
            } else {
                (self.bits << shift) | 1
            };
            self.highest = Some(sequence);
            true
        } else {
            let distance = highest - sequence;
            if distance >= 64 || (self.bits & (1 << distance)) != 0 {
                return false;
            }
            self.bits |= 1 << distance;
            true
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

async fn add_candidate(peer: &Arc<PeerState>, candidate: Candidate) {
    if !peer
        .info
        .candidates
        .iter()
        .any(|old| old.address() == candidate.address())
    { /* candidate exchange is immutable in MVP; source is used for this attempt */
    }
}
fn validate_peer_info(info: &PeerInfo) -> Result<(), CoreError> {
    if NodeId::new(*blake3::hash(&info.signing_public).as_bytes()) != info.node_id {
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
    #[error("peer is not connected")]
    NotConnected,
    #[error("peer send queue is full")]
    QueueFull,
    #[error("packet is larger than configured max payload")]
    PacketTooLarge,
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
    use vela_proto::Candidate;

    fn peer_info(identity: &Identity, address: SocketAddr) -> PeerInfo {
        let public = identity.public();
        PeerInfo {
            node_id: public.node_id,
            signing_public: public.signing_public,
            noise_public: public.noise_public,
            candidates: vec![Candidate::Host(address)],
            credential: Vec::new(),
            capabilities: Vec::new(),
        }
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
            ..NodeConfig::default()
        };
        let config_b = NodeConfig {
            bind: BindOptions {
                local_addr: address_b,
            },
            connect_timeout: Duration::from_secs(2),
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
            .register_peer(peer_info(&identity_b, address_b))
            .await
            .unwrap();
        node_b
            .register_peer(peer_info(&identity_a, address_a))
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
        handle_a
            .send(Bytes::from_static(b"hello from A"))
            .await
            .unwrap();
        let event = timeout(Duration::from_secs(1), async {
            loop {
                if let Some(event @ VelaEvent::Packet { .. }) = node_b.next_event().await {
                    break event;
                }
            }
        })
        .await
        .unwrap();
        assert!(
            matches!(event, VelaEvent::Packet { peer, ref payload } if peer == a_id && payload.as_ref() == b"hello from A")
        );
        node_a.shutdown().await;
        node_b.shutdown().await;
    }
}
