use std::{env, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};
use vela_coord::CoordServer;
use vela_crypto::Identity;
use vela_diagnostic::{DiagnosticControl, DiagnosticPeer, PeerState};
use vela_proto::NodeId;

fn usage() -> ! {
    eprintln!(
        "Usage:\n  vela-cli identity <path>\n  vela-cli server --bind <addr> --db <path> --signer <path> --tenant <name> [--cert <path> --key <path>]\n  vela-cli invite --db <path> --signer <path> --tenant <name> [--ttl <seconds>]\n  vela-cli peers --db <path> --signer <path> --tenant <name>\n  vela-cli revoke <node-id> --db <path> --signer <path> --tenant <name>\n  vela-cli peer register --state <dir> --server <url> --server-key <base64> --invite <token> [--bind <addr>] [--stun <addr>]\n  vela-cli peer run --state <dir> [--bind <addr>] [--stun <addr>]\n  vela-cli peer up --state <dir> [--tun <name>] [--mtu <bytes>] [--bind <addr>] [--stun <addr>]\n  vela-cli peer list --state <dir> [--json]\n  vela-cli peer ping <node-id> --state <dir> [--count <n>] [--timeout <duration>] [--json]"
    );
    eprintln!("  vela-cli peer status --state <dir> [--json]");
    std::process::exit(2);
}

fn option(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find_map(|pair| (pair[0] == name).then(|| pair[1].clone()))
}

fn required(args: &[String], name: &str) -> String {
    option(args, name).unwrap_or_else(|| {
        eprintln!("missing {name}");
        usage()
    })
}

fn options(args: &[String], name: &str) -> Vec<String> {
    args.windows(2)
        .filter(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
        .collect()
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let (number, multiplier) = if let Some(value) = value.strip_suffix("ms") {
        (value, 1)
    } else if let Some(value) = value.strip_suffix('s') {
        (value, 1000)
    } else {
        return Err(format!("duration must end in ms or s: {value}"));
    };
    let millis = number
        .parse::<u64>()
        .map_err(|_| format!("invalid duration: {value}"))?
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration is too large: {value}"))?;
    Ok(Duration::from_millis(millis))
}

fn decode_server_key(value: &str) -> Result<[u8; 32], String> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .map_err(|_| "invalid base64 server key".to_owned())?;
    bytes
        .try_into()
        .map_err(|_| "server key must decode to 32 bytes".to_owned())
}

fn bind_option(args: &[String]) -> Result<Option<SocketAddr>, Box<dyn std::error::Error>> {
    option(args, "--bind")
        .map(|value| value.parse().map_err(Into::into))
        .transpose()
}

async fn run_peer_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let Some(subcommand) = args.first() else {
        usage();
    };
    let args = &args[1..];
    match subcommand.as_str() {
        "register" => {
            let state_dir = required(args, "--state");
            let server = required(args, "--server");
            let server_key = decode_server_key(&required(args, "--server-key"))?;
            let invite = required(args, "--invite");
            let bind = bind_option(args)?.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap());
            let stun = options(args, "--stun")
                .into_iter()
                .map(|value| value.parse())
                .collect::<Result<Vec<SocketAddr>, _>>()?;
            let state =
                vela_diagnostic::register(&state_dir, server, server_key, &invite, bind, stun)
                    .await?;
            let identity = Identity::load(PeerState::identity_path(&state_dir))?;
            println!("registered {}", identity.public().node_id);
            println!("state saved in {}", state_dir);
            let _ = state;
        }
        "run" => {
            let state_dir = required(args, "--state");
            let stun_values = options(args, "--stun");
            let stun = if stun_values.is_empty() {
                None
            } else {
                Some(
                    stun_values
                        .into_iter()
                        .map(|value| value.parse())
                        .collect::<Result<Vec<SocketAddr>, _>>()?,
                )
            };
            let peer = DiagnosticPeer::open(&state_dir, bind_option(args)?, stun).await?;
            println!(
                "peer {} ready on {}",
                peer.node_id(),
                peer.node.local_addr()?
            );
            peer.run().await?;
        }
        "up" => {
            #[cfg(not(target_os = "linux"))]
            {
                let _ = args;
                return Err("peer up currently requires Linux TUN support".into());
            }
            #[cfg(target_os = "linux")]
            {
                let state_dir = required(args, "--state");
                let stun_values = options(args, "--stun");
                let stun = if stun_values.is_empty() {
                    None
                } else {
                    Some(
                        stun_values
                            .into_iter()
                            .map(|value| value.parse())
                            .collect::<Result<Vec<SocketAddr>, _>>()?,
                    )
                };
                let peer = DiagnosticPeer::open(&state_dir, bind_option(args)?, stun).await?;
                let snapshot = peer
                    .state
                    .snapshot
                    .clone()
                    .ok_or("state has no network snapshot; register first")?;
                let tun_name = option(args, "--tun").unwrap_or_else(|| "vela0".into());
                let mtu = option(args, "--mtu")
                    .map(|value| value.parse::<usize>())
                    .transpose()?
                    .unwrap_or(1200);
                let tun = vela_tun::TunDevice::open(vela_tun::TunConfig {
                    name: tun_name,
                    mtu,
                })?;
                let routes = vela_tun::RouteManager::for_interface(tun.name()).await?;
                routes.set_mtu(mtu).await?;
                let local_peer = snapshot
                    .peers
                    .iter()
                    .find(|value| value.node_id == peer.node_id())
                    .ok_or("snapshot does not contain this node")?;
                if let (Some(address), Some(cidr)) =
                    (local_peer.virtual_ipv4, snapshot.virtual_ipv4)
                {
                    routes
                        .add_local_address(address.into(), cidr.prefix_len)
                        .await?;
                }
                if let (Some(address), Some(cidr)) =
                    (local_peer.virtual_ipv6, snapshot.virtual_ipv6)
                {
                    routes
                        .add_local_address(address.into(), cidr.prefix_len)
                        .await?;
                }
                let _leases =
                    vela_tun::install_snapshot_routes(&routes, &snapshot, peer.node_id()).await?;
                println!("peer {} up on TUN {}", peer.node_id(), tun.name());
                run_tun_peer(peer, tun, routes, _leases).await?;
            }
        }
        "list" => {
            let state_dir = required(args, "--state");
            let mut control = DiagnosticControl::open(&state_dir).await?;
            let peers = control.list_peers().await?;
            if args.iter().any(|arg| arg == "--json") {
                println!("{}", serde_json::to_string_pretty(&peers)?);
            } else {
                for peer in peers {
                    println!(
                        "{}\t{}\t{:?}",
                        peer.node_id,
                        if peer.online { "online" } else { "offline" },
                        peer.capabilities
                    );
                }
            }
        }
        "status" => {
            let state_dir = required(args, "--state");
            let mut control = DiagnosticControl::open(&state_dir).await?;
            let status = control.status().await?;
            if args.iter().any(|arg| arg == "--json") {
                println!("{}", serde_json::to_string_pretty(&status)?);
            } else {
                println!("node\t{}", status.node_id);
                println!("server\t{}", status.server);
                println!("bind\t{}", status.bind);
                println!("candidates\t{:?}", status.candidates);
                println!("peers\t{}", status.peers.len());
            }
        }
        "ping" => {
            let target = args
                .first()
                .ok_or_else(|| "missing target node id".to_owned())?
                .parse::<NodeId>()?;
            let state_dir = required(args, "--state");
            let count = option(args, "--count")
                .map(|value| value.parse())
                .transpose()?
                .unwrap_or(1);
            let timeout = option(args, "--timeout")
                .map(|value| parse_duration(&value))
                .transpose()?
                .unwrap_or_else(|| Duration::from_secs(8));
            let mut peer = DiagnosticPeer::open(&state_dir, None, None).await?;
            let report = peer.ping(target, count, timeout).await?;
            if args.iter().any(|arg| arg == "--json") {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!(
                    "direct ping {} via {} ({}) connect={}ms rtt={:?}ms",
                    report.target,
                    report.path,
                    report.candidate_type,
                    report.connect_ms,
                    report.rtts_ms
                );
            }
        }
        _ => usage(),
    }
    Ok(())
}

#[cfg(target_os = "linux")]
async fn run_tun_peer(
    mut peer: DiagnosticPeer,
    tun: vela_tun::TunDevice,
    routes: vela_tun::RouteManager,
    mut leases: Vec<vela_tun::RouteLease>,
) -> Result<(), Box<dyn std::error::Error>> {
    let node = peer.node.clone();
    let mut refresh = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! {
            packet = tun.recv() => {
                node.send_ip(packet?).await?;
            }
            event = node.next_event() => {
                match event {
                    Some(vela_core::VelaEvent::IpPacket { packet, .. }) => tun.send(packet.as_bytes()).await?,
                    Some(_) => {}
                    None => return Err("Vela node stopped".into()),
                }
            }
            message = peer.client.recv() => {
                match message? {
                    vela_proto::ControlMessage::ConnectSignal { from, to } if to == peer.node_id() => {
                        let info = peer.client.verify_public_peer(from)?;
                        node.register_peer(info).await?;
                    }
                    vela_proto::ControlMessage::Snapshot { snapshot } => {
                        node.apply_snapshot(snapshot.clone()).await?;
                        for lease in leases.drain(..) {
                            let _ = lease.release().await;
                        }
                        let local = snapshot
                            .peers
                            .iter()
                            .find(|value| value.node_id == peer.node_id())
                            .ok_or("snapshot does not contain this node")?;
                        if let (Some(address), Some(cidr)) = (local.virtual_ipv4, snapshot.virtual_ipv4) {
                            routes.add_local_address(address.into(), cidr.prefix_len).await?;
                        }
                        if let (Some(address), Some(cidr)) = (local.virtual_ipv6, snapshot.virtual_ipv6) {
                            routes.add_local_address(address.into(), cidr.prefix_len).await?;
                        }
                        leases = vela_tun::install_snapshot_routes(&routes, &snapshot, peer.node_id()).await?;
                        peer.state.snapshot = Some(snapshot);
                    }
                    vela_proto::ControlMessage::Revoke { node_id } if node_id == peer.node_id() => {
                        for lease in leases.drain(..) {
                            let _ = lease.release().await;
                        }
                        peer.node.shutdown().await;
                        return Err("peer membership was revoked".into());
                    }
                    _ => {}
                }
            }
            _ = tokio::signal::ctrl_c() => {
                for lease in leases.drain(..) {
                    let _ = lease.release().await;
                }
                peer.node.shutdown().await;
                return Ok(());
            }
            tick = refresh.tick() => {
                let _ = tick;
                peer.refresh_candidates().await?;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().cloned().unwrap_or_default();
    if command.is_empty() {
        usage();
    }
    args.remove(0);
    match command.as_str() {
        "identity" => {
            let path = args.first().map(PathBuf::from).unwrap_or_else(|| usage());
            let identity = Identity::load_or_generate(&path)?;
            println!("{}", identity.public().node_id);
        }
        "server" => {
            let bind = SocketAddr::from_str(&required(&args, "--bind"))?;
            let db = required(&args, "--db");
            let signer = required(&args, "--signer");
            let tenant = required(&args, "--tenant");
            let server = CoordServer::open(db, signer, tenant)?;
            println!(
                "coordination server public key: {}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    server.server_public_key()
                )
            );
            match (option(&args, "--cert"), option(&args, "--key")) {
                (Some(cert), Some(key)) => server.serve_tls(bind, cert, key).await?,
                (None, None) => {
                    server
                        .serve(tokio::net::TcpListener::bind(bind).await?)
                        .await?
                }
                _ => {
                    eprintln!("--cert and --key must be provided together");
                    usage();
                }
            }
        }
        "invite" => {
            let server = CoordServer::open(
                required(&args, "--db"),
                required(&args, "--signer"),
                required(&args, "--tenant"),
            )?;
            let ttl = option(&args, "--ttl")
                .and_then(|value| value.parse().ok())
                .unwrap_or(3600);
            println!("{}", server.create_invite(ttl)?);
        }
        "peers" => {
            let server = CoordServer::open(
                required(&args, "--db"),
                required(&args, "--signer"),
                required(&args, "--tenant"),
            )?;
            for peer in server.list_peers()? {
                println!("{peer}");
            }
        }
        "revoke" => {
            let node_id = args
                .first()
                .and_then(|value| value.parse().ok())
                .unwrap_or_else(|| {
                    eprintln!("missing node id");
                    usage()
                });
            let server = CoordServer::open(
                required(&args, "--db"),
                required(&args, "--signer"),
                required(&args, "--tenant"),
            )?;
            server.revoke_peer(node_id).await?;
        }
        "peer" => run_peer_command(&args).await?,
        _ => usage(),
    }
    Ok(())
}
