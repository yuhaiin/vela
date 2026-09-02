use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tokio::{net::TcpListener, time::sleep};
use vela_coord::CoordServer;
use vela_coord_client::CoordinationClient;
use vela_core::{
    BindOptions, NodeConfig, PeerReceiveStats, TokioDatagramProvider, TransportReceiveStats,
    VelaEvent, VelaNode,
};
use vela_crypto::Identity;
use vela_proto::{Candidate, ControlMessage, NodeId};

const DEFAULT_PORT: u16 = 41_000;
const DEFAULT_PACKET_SIZE: usize = 1_200;

#[derive(Debug, Parser)]
#[command(name = "vela-e2e-bench")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Server(ServerArgs),
    Peer(PeerArgs),
}

#[derive(Debug, Args)]
struct ServerArgs {
    #[arg(long)]
    run_dir: PathBuf,
    #[arg(long)]
    bind: SocketAddr,
    #[arg(long, default_value_t = 3600)]
    invite_ttl: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, ValueEnum)]
enum PeerRole {
    Sender,
    Receiver,
}

#[derive(Debug, Args)]
struct PeerArgs {
    #[arg(long)]
    run_dir: PathBuf,
    #[arg(long, value_parser = ["a", "b"])]
    name: String,
    #[arg(long)]
    role: PeerRole,
    #[arg(long)]
    server: String,
    #[arg(long)]
    advertise_ip: Ipv4Addr,
    #[arg(long, default_value_t = DEFAULT_PORT)]
    port: u16,
    #[arg(long, default_value_t = DEFAULT_PACKET_SIZE)]
    packet_size: usize,
    #[arg(long, default_value_t = 5)]
    duration_seconds: u64,
    #[arg(long, default_value_t = 2)]
    drain_seconds: u64,
}

#[derive(Debug, Serialize)]
struct PeerResult {
    name: String,
    role: PeerRole,
    packet_size: usize,
    elapsed_ms: u128,
    accepted_packets: u64,
    send_errors: u64,
    received_packets: u64,
    accepted_bytes: u64,
    received_bytes: u64,
    receive: Option<PeerReceiveStats>,
    transport_receive: TransportReceiveStats,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
    match Cli::parse().command {
        Command::Server(args) => run_server(args).await?,
        Command::Peer(args) => run_peer(args).await?,
    }
    Ok(())
}

async fn run_server(args: ServerArgs) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(&args.run_dir)?;
    let server = CoordServer::open(
        args.run_dir.join("coord.db"),
        args.run_dir.join("server.key"),
        "e2e-benchmark",
    )?;
    let invite_a = server.create_invite(args.invite_ttl)?;
    let invite_b = server.create_invite(args.invite_ttl)?;
    let info = format!(
        "server_key={}\ninvite_a={}\ninvite_b={}\n",
        BASE64.encode(server.server_public_key()),
        invite_a,
        invite_b,
    );
    let listener = TcpListener::bind(args.bind).await?;
    fs::write(args.run_dir.join("server.info"), info)?;
    println!("server_ready bind={}", args.bind);
    server.serve(listener).await?;
    Ok(())
}

async fn run_peer(args: PeerArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.packet_size < 576 || args.packet_size > u16::MAX as usize {
        return Err("packet size must be between 576 and 65535".into());
    }
    let info = wait_for_file(&args.run_dir.join("server.info"), Duration::from_secs(30)).await?;
    let values = read_key_values(&info)?;
    let server_key = BASE64.decode(required(&values, "server_key")?)?;
    let server_key: [u8; 32] = server_key
        .try_into()
        .map_err(|_| "server key must decode to 32 bytes")?;
    let invite = required(
        &values,
        if args.name == "a" {
            "invite_a"
        } else {
            "invite_b"
        },
    )?;
    let state_dir = args.run_dir.join(&args.name);
    fs::create_dir_all(&state_dir)?;
    let identity = Identity::load_or_generate(state_dir.join("identity"))?;
    let incarnation = rand::random::<u64>().max(1);
    let candidate = Candidate::Host(SocketAddr::from((args.advertise_ip, args.port)));
    let mut client = connect_control(&args.server, server_key).await?;
    let registration = client
        .register_with_incarnation(
            &identity,
            incarnation,
            Some(invite),
            None,
            vec![candidate.clone()],
        )
        .await?;
    let local = registration
        .snapshot
        .peers
        .iter()
        .find(|peer| peer.node_id == identity.public().node_id)
        .ok_or("registration snapshot does not contain this peer")?;
    let local_ipv4 = local
        .virtual_ipv4
        .ok_or("registration snapshot does not assign a virtual IPv4 address")?;
    let node = VelaNode::builder()
        .identity(identity)
        .incarnation(incarnation)
        .datagram_provider(std::sync::Arc::new(TokioDatagramProvider::new(vec![
            candidate,
        ])))
        .config(NodeConfig {
            bind: BindOptions { port: args.port },
            max_payload_size: args.packet_size,
            per_peer_queue_limit: 4096,
            network_id: registration.snapshot.network_id,
            server_public_key: Some(server_key),
            virtual_ipv4: local.virtual_ipv4,
            virtual_ipv6: local.virtual_ipv6,
            virtual_mtu: args.packet_size,
            ..NodeConfig::default()
        })
        .build()
        .await?;
    node.apply_snapshot(registration.snapshot).await?;
    let remote_id = wait_for_remote(&mut client, node.node_id()).await?;
    let remote = client.lookup_peer(remote_id).await?;
    eprintln!(
        "peer={} local={} remote={}",
        args.name,
        node.node_id(),
        remote_id
    );
    if let Some(snapshot) = take_latest_snapshot(&mut client).await? {
        node.apply_snapshot(snapshot).await?;
    }
    node.register_peer(remote).await?;
    node.start().await?;
    fs::write(
        args.run_dir.join(format!("connected-{}", args.name)),
        node.node_id().to_string(),
    )?;
    if args.role == PeerRole::Sender {
        if let Err(error) =
            tokio::time::timeout(Duration::from_secs(15), node.connect(remote_id)).await?
        {
            eprintln!("peer={} connect_error={error}", args.name);
            for status in node.peer_statuses().await {
                eprintln!(
                    "peer={} status={} candidates={:?} active_path={:?} attempt={:?}",
                    args.name,
                    status.node_id,
                    status.candidates,
                    status.active_path,
                    status.attempt,
                );
            }
            return Err(error.into());
        }
    }
    let mut result = match args.role {
        PeerRole::Sender => run_sender(&args, &node, remote_id, local_ipv4).await?,
        PeerRole::Receiver => run_receiver(&args, &node).await?,
    };
    result.receive = node
        .peer_statuses()
        .await
        .into_iter()
        .find(|status| status.node_id == remote_id)
        .map(|status| status.receive);
    result.transport_receive = node.transport_receive_stats();
    fs::write(
        args.run_dir.join(format!("{}.result", args.name)),
        serde_json::to_string(&result)?,
    )?;
    println!(
        "{}_result elapsed_ms={} accepted={} send_errors={} received={} accepted_bytes={} received_bytes={}",
        args.name,
        result.elapsed_ms,
        result.accepted_packets,
        result.send_errors,
        result.received_packets,
        result.accepted_bytes,
        result.received_bytes,
    );
    node.shutdown().await;
    Ok(())
}

async fn run_sender(
    args: &PeerArgs,
    node: &VelaNode,
    remote_id: NodeId,
    local_ipv4: Ipv4Addr,
) -> Result<PeerResult, Box<dyn std::error::Error>> {
    wait_for_file(&args.run_dir.join("connected-b"), Duration::from_secs(15)).await?;
    let destination = node
        .peer_statuses()
        .await
        .into_iter()
        .find(|status| status.node_id == remote_id)
        .and_then(|status| status.virtual_ipv4)
        .ok_or("remote peer has no virtual IPv4 address")?;
    let packet = udp_packet(args.packet_size, local_ipv4, destination);
    fs::write(args.run_dir.join("start"), "start")?;
    let deadline = Instant::now() + Duration::from_secs(args.duration_seconds);
    let started = Instant::now();
    let mut accepted_packets = 0;
    let mut send_errors = 0;
    while Instant::now() < deadline {
        match node.send_ip(packet.clone()).await {
            Ok(()) => accepted_packets += 1,
            Err(_) => send_errors += 1,
        }
    }
    let elapsed = started.elapsed();
    Ok(PeerResult {
        name: args.name.clone(),
        role: args.role,
        packet_size: args.packet_size,
        elapsed_ms: elapsed.as_millis(),
        accepted_packets,
        send_errors,
        received_packets: 0,
        accepted_bytes: accepted_packets * args.packet_size as u64,
        received_bytes: 0,
        receive: None,
        transport_receive: TransportReceiveStats::default(),
    })
}

async fn run_receiver(
    args: &PeerArgs,
    node: &VelaNode,
) -> Result<PeerResult, Box<dyn std::error::Error>> {
    wait_for_file(&args.run_dir.join("start"), Duration::from_secs(15)).await?;
    let started = Instant::now();
    let deadline = started
        + Duration::from_secs(args.duration_seconds)
        + Duration::from_secs(args.drain_seconds);
    let mut received_packets = 0;
    let mut events = Vec::with_capacity(64);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        let received =
            tokio::time::timeout(remaining, node.next_event_batch(&mut events, 64)).await;
        if received.ok().is_none_or(|count| count == 0) {
            break;
        }
        for event in events.drain(..) {
            if let VelaEvent::IpPacket { packet, .. } = event {
                if packet.as_bytes().len() == args.packet_size
                    && packet.as_bytes().first() == Some(&0x45)
                    && packet.as_bytes().get(9) == Some(&17)
                {
                    received_packets += 1;
                }
            }
        }
    }
    let elapsed = started.elapsed();
    Ok(PeerResult {
        name: args.name.clone(),
        role: args.role,
        packet_size: args.packet_size,
        elapsed_ms: elapsed.as_millis(),
        accepted_packets: 0,
        send_errors: 0,
        received_packets,
        accepted_bytes: 0,
        received_bytes: received_packets * args.packet_size as u64,
        receive: None,
        transport_receive: TransportReceiveStats::default(),
    })
}

async fn connect_control(
    server: &str,
    server_key: [u8; 32],
) -> Result<CoordinationClient, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match CoordinationClient::connect(server).await {
            Ok(mut client) => {
                client.trust_server_key(server_key);
                return Ok(client);
            }
            Err(error) if Instant::now() < deadline => {
                eprintln!("coordination connection retry: {error}");
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}

async fn wait_for_remote(
    client: &mut CoordinationClient,
    local_id: NodeId,
) -> Result<NodeId, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let peers = client.list_peers().await?;
        if let Some(peer) = peers.into_iter().find(|peer| peer.node_id != local_id) {
            return Ok(peer.node_id);
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for the other peer to register".into());
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn take_latest_snapshot(
    client: &mut CoordinationClient,
) -> Result<Option<vela_proto::NetworkSnapshot>, Box<dyn std::error::Error>> {
    let mut latest = None;
    for _ in 0..8 {
        let message = match tokio::time::timeout(Duration::from_millis(25), client.recv()).await {
            Ok(message) => message?,
            Err(_) => break,
        };
        if let ControlMessage::Snapshot { snapshot } = message {
            latest = Some(snapshot);
        }
    }
    Ok(latest)
}

async fn wait_for_file(
    path: &Path,
    timeout: Duration,
) -> Result<String, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        match fs::read_to_string(path) {
            Ok(value) => return Ok(value),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {}", path.display()).into());
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn read_key_values(
    value: &str,
) -> Result<std::collections::HashMap<String, String>, Box<dyn std::error::Error>> {
    value
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("invalid key-value line: {line}"))?;
            Ok((key.to_owned(), value.to_owned()))
        })
        .collect()
}

fn required<'a>(
    values: &'a std::collections::HashMap<String, String>,
    key: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("server info is missing {key}").into())
}

fn udp_packet(size: usize, source: Ipv4Addr, destination: Ipv4Addr) -> Bytes {
    let mut packet = vec![0u8; size];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    packet[20..22].copy_from_slice(&41_001u16.to_be_bytes());
    packet[22..24].copy_from_slice(&41_002u16.to_be_bytes());
    packet[24..26].copy_from_slice(&((size - 20) as u16).to_be_bytes());
    let checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    Bytes::from(packet)
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}
