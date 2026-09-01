use async_trait::async_trait;
use bytes::Bytes;
use std::{
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{runtime::Builder, sync::Notify};
use vela_core::{BindOptions, DatagramProvider, DatagramSocket, NodeConfig, SendError, VelaNode};
use vela_crypto::Identity;
use vela_proto::{Candidate, PeerInfo};

const LIMITS: &[usize] = &[32, 64, 128, 256, 512, 1024];
const OFFERED_PACKETS: usize = 2048;
const ROUNDS: usize = 5;
const PACKET_SIZE: usize = 1200;
const LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 1);
const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 254, 0, 2);

struct BenchmarkSocket {
    probe_sent: Arc<Notify>,
}

#[async_trait]
impl DatagramSocket for BenchmarkSocket {
    async fn send_to(&self, bytes: &[u8], _target: SocketAddr) -> io::Result<usize> {
        self.probe_sent.notify_one();
        Ok(bytes.len())
    }

    async fn recv_from(&self, _buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from(([127, 0, 0, 1], 0)))
    }
}

struct BenchmarkProvider {
    probe_sent: Arc<Notify>,
}

#[async_trait]
impl DatagramProvider for BenchmarkProvider {
    async fn bind(
        &self,
        _options: BindOptions,
    ) -> Result<Arc<dyn DatagramSocket>, vela_core::CoreError> {
        Ok(Arc::new(BenchmarkSocket {
            probe_sent: Arc::clone(&self.probe_sent),
        }))
    }

    fn local_candidates(&self) -> Vec<Candidate> {
        Vec::new()
    }
}

struct Measurement {
    accepted: usize,
    dropped: usize,
    elapsed: Duration,
}

fn main() {
    let runtime = Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("benchmark runtime must build");

    println!(
        "peer queue benchmark: {}-byte packets, {} offered per round, {} rounds",
        PACKET_SIZE, OFFERED_PACKETS, ROUNDS
    );
    println!(
        "{:<8} {:>10} {:>10} {:>14} {:>14} {:>12}",
        "limit", "accepted", "dropped", "buffer bound", "ns/call", "M calls/s"
    );

    for &limit in LIMITS {
        let measurements = runtime.block_on(async {
            let mut measurements = Vec::with_capacity(ROUNDS);
            for _ in 0..ROUNDS {
                measurements.push(run_round(limit).await);
            }
            measurements
        });
        let accepted = measurements.iter().map(|m| m.accepted).sum::<usize>();
        let dropped = measurements.iter().map(|m| m.dropped).sum::<usize>();
        let elapsed = measurements.iter().map(|m| m.elapsed).sum::<Duration>();
        let calls = (accepted + dropped) as f64;
        let ns_per_call = elapsed.as_secs_f64() * 1e9 / calls;
        let calls_per_second = calls / elapsed.as_secs_f64() / 1e6;
        println!(
            "{:<8} {:>10} {:>10} {:>11} KiB {:>14.1} {:>12.2}",
            limit,
            accepted,
            dropped,
            limit * PACKET_SIZE / 1024,
            ns_per_call,
            calls_per_second
        );
    }
}

async fn run_round(limit: usize) -> Measurement {
    let probe_sent = Arc::new(Notify::new());
    let identity = Identity::generate();
    let remote_identity = Identity::generate();
    let peer = peer_info(&remote_identity);
    let node = VelaNode::builder()
        .identity(identity)
        .datagram_provider(Arc::new(BenchmarkProvider {
            probe_sent: Arc::clone(&probe_sent),
        }))
        .config(NodeConfig {
            bind: BindOptions { port: 0 },
            max_payload_size: PACKET_SIZE,
            per_peer_queue_limit: limit,
            virtual_mtu: PACKET_SIZE,
            virtual_ipv4: Some(LOCAL_IP),
            connect_timeout: Duration::from_secs(30),
            ..NodeConfig::default()
        })
        .build()
        .await
        .expect("benchmark node must build");
    node.register_peer(peer)
        .await
        .expect("benchmark peer must register");
    node.start().await.expect("benchmark node must start");

    let peer_id = remote_identity.public().node_id;
    let connect_task = {
        let node = node.clone();
        tokio::spawn(async move {
            let _ = node.connect(peer_id).await;
        })
    };
    probe_sent.notified().await;

    let packet = ipv4_packet(PACKET_SIZE);
    let start = Instant::now();
    let mut accepted = 0;
    let mut dropped = 0;
    for _ in 0..OFFERED_PACKETS {
        match node.send_ip(std::hint::black_box(packet.clone())).await {
            Ok(()) => accepted += 1,
            Err(SendError::QueueFull) => dropped += 1,
            Err(error) => panic!("unexpected benchmark send error: {error}"),
        }
    }
    let elapsed = start.elapsed();

    connect_task.abort();
    let _ = connect_task.await;
    node.shutdown().await;

    Measurement {
        accepted,
        dropped,
        elapsed,
    }
}

fn peer_info(identity: &Identity) -> PeerInfo {
    let public = identity.public();
    PeerInfo {
        node_id: public.node_id,
        signing_public: public.signing_public,
        noise_public: public.noise_public,
        candidates: vec![Candidate::Host(SocketAddr::from(([127, 0, 0, 1], 9)))],
        virtual_ipv4: Some(REMOTE_IP),
        virtual_ipv6: None,
        credential: Vec::new(),
        capabilities: Vec::new(),
    }
}

fn ipv4_packet(size: usize) -> Bytes {
    assert!(size >= 20 && size <= u16::MAX as usize);
    let mut packet = vec![0; size];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&LOCAL_IP.octets());
    packet[16..20].copy_from_slice(&REMOTE_IP.octets());
    let mut checksum = 0u32;
    for chunk in packet[..20].chunks_exact(2) {
        checksum = checksum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
        while checksum > u32::from(u16::MAX) {
            checksum = (checksum & u32::from(u16::MAX)) + (checksum >> 16);
        }
    }
    packet[10..12].copy_from_slice(&(!(checksum as u16)).to_be_bytes());
    Bytes::from(packet)
}
