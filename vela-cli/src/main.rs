use std::{env, io::Read, net::SocketAddr, path::PathBuf, str::FromStr, time::Duration};
use vela_coord::CoordServer;
use vela_crypto::Identity;
use vela_diagnostic::{DiagnosticControl, DiagnosticPeer, PeerState};
use vela_proto::NodeId;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

fn usage() -> ! {
    eprintln!(
        "Usage:\n  vela-cli identity <path>\n  vela-cli server --path <dir> --bind <addr> --tenant <name> [--doh <https-url>] [--stun <host:port>] [--admin-password-stdin]\n  vela-cli invite --path <dir> --tenant <name> [--ttl <seconds>]\n  vela-cli peers --path <dir> --tenant <name>\n  vela-cli revoke <node-id> --path <dir> --tenant <name>\n  vela-cli admin password reset --path <dir> [--password-stdin]\n  vela-cli peer register --state <dir> --server <url> --server-key <base64> --invite <token> [--bind <addr>] [--stun <host:port>]\n  vela-cli peer run --state <dir> [--bind <addr>] [--stun <host:port>]\n  vela-cli peer up --state <dir> [--tun <name>] [--mtu <bytes>] [--bind <addr>] [--stun <host:port>]\n  vela-cli peer list --state <dir> [--json]\n  vela-cli peer ping <node-id> --state <dir> [--count <n>] [--timeout <duration>] [--json]\n\nServer path defaults: <path>/vela.db, <path>/server.key, <path>/admin.credentials.\nThe server DoH/STUN settings can also be changed from the admin web page.\nLegacy --db/--signer and --admin-credentials overrides are still accepted."
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn release_route_leases(leases: &mut Vec<vela_tun::RouteLease>) {
    let pending = std::mem::take(leases);
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, async move {
        for lease in pending {
            let _ = lease.release().await;
        }
    })
    .await
    .is_err()
    {
        tracing::warn!(
            timeout = ?SHUTDOWN_TIMEOUT,
            "timed out while releasing TUN routes during shutdown"
        );
    }
}

fn coordination_paths(args: &[String]) -> (PathBuf, PathBuf, PathBuf) {
    let path = option(args, "--path").map(PathBuf::from);
    let database = option(args, "--db")
        .map(PathBuf::from)
        .or_else(|| path.as_ref().map(|path| path.join("vela.db")))
        .unwrap_or_else(|| {
            eprintln!("missing --path");
            usage()
        });
    let signer = option(args, "--signer")
        .map(PathBuf::from)
        .or_else(|| path.as_ref().map(|path| path.join("server.key")))
        .unwrap_or_else(|| {
            eprintln!("missing --path");
            usage()
        });
    let credentials = option(args, "--admin-credentials")
        .map(PathBuf::from)
        .or_else(|| path.map(|path| path.join("admin.credentials")))
        .unwrap_or_else(|| database.with_extension("admin-credentials"));
    (database, signer, credentials)
}

fn open_coordination_server(args: &[String]) -> Result<CoordServer, Box<dyn std::error::Error>> {
    let (database, signer, credentials) = coordination_paths(args);
    Ok(CoordServer::open_with_admin_credentials_and_network_config(
        database,
        signer,
        required(args, "--tenant"),
        credentials,
        options(args, "--doh"),
        options(args, "--stun"),
    )?)
}

fn password_from_stdin(args: &[String]) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if !args
        .iter()
        .any(|arg| arg == "--password-stdin" || arg == "--admin-password-stdin")
    {
        return Ok(None);
    }
    let mut password = String::new();
    std::io::stdin().read_to_string(&mut password)?;
    let password = password.trim_end_matches(['\r', '\n']).to_owned();
    if password.is_empty() {
        return Err("password stdin was empty".into());
    }
    Ok(Some(password))
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
            let bind = bind_option(args)?.unwrap_or_else(|| "[::]:0".parse().unwrap());
            let stun = options(args, "--stun");
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
                Some(stun_values)
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
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            {
                let _ = args;
                return Err("peer up is unsupported on this platform".into());
            }
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            {
                let state_dir = required(args, "--state");
                let stun_values = options(args, "--stun");
                let stun = if stun_values.is_empty() {
                    None
                } else {
                    Some(stun_values)
                };
                let peer = DiagnosticPeer::open(&state_dir, bind_option(args)?, stun).await?;
                let snapshot = peer
                    .state
                    .snapshot
                    .clone()
                    .ok_or("state has no network snapshot; register first")?;
                let tun_name = option(args, "--tun").unwrap_or_else(|| {
                    if cfg!(target_os = "macos") {
                        String::new()
                    } else {
                        "vela0".into()
                    }
                });
                let mtu = option(args, "--mtu")
                    .map(|value| value.parse::<usize>())
                    .transpose()?
                    .unwrap_or(1200);
                let tun = vela_tun::TunDevice::open(vela_tun::TunConfig {
                    name: tun_name,
                    mtu,
                })?;
                let routes = vela_tun::RouteManager::for_tun(&tun).await?;
                routes.set_mtu(mtu).await?;
                let mut leases = Vec::new();
                apply_tun_snapshot(&peer, &routes, &mut leases, &snapshot).await?;
                println!("peer {} up on TUN {}", peer.node_id(), tun.name());
                run_tun_peer(peer, tun, routes, leases).await?;
            }
        }
        "list" => {
            let state_dir = required(args, "--state");
            let mut control = DiagnosticControl::open(&state_dir).await?;
            let peers = control.list_peers().await?;
            if args.iter().any(|arg| arg == "--json") {
                println!("{}", serde_json::to_string_pretty(&peers)?);
            } else {
                println!("name\tnode\tstatus\tipv4\tipv6\tcapabilities");
                for peer in peers {
                    let name = if peer.name.is_empty() {
                        "-"
                    } else {
                        peer.name.as_str()
                    };
                    let ipv4 = peer
                        .virtual_ipv4
                        .map_or_else(|| "-".to_owned(), |address| address.to_string());
                    let ipv6 = peer
                        .virtual_ipv6
                        .map_or_else(|| "-".to_owned(), |address| address.to_string());
                    println!(
                        "{}\t{}\t{}\t{}\t{}\t{:?}",
                        name,
                        peer.node_id,
                        if peer.online { "online" } else { "offline" },
                        ipv4,
                        ipv6,
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
                println!("doh_servers\t{:?}", status.doh_servers);
                println!("stun_servers\t{:?}", status.stun_servers);
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn apply_tun_snapshot(
    peer: &DiagnosticPeer,
    routes: &vela_tun::RouteManager,
    leases: &mut Vec<vela_tun::RouteLease>,
    snapshot: &vela_proto::NetworkSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    for lease in leases.drain(..) {
        let _ = lease.release().await;
    }
    let local = snapshot
        .peers
        .iter()
        .find(|value| value.node_id == peer.node_id())
        .ok_or("snapshot does not contain this node")?;
    if let (Some(address), Some(cidr)) = (local.virtual_ipv4, snapshot.virtual_ipv4) {
        routes
            .add_local_address(address.into(), cidr.prefix_len)
            .await?;
    }
    if let (Some(address), Some(cidr)) = (local.virtual_ipv6, snapshot.virtual_ipv6) {
        routes
            .add_local_address(address.into(), cidr.prefix_len)
            .await?;
    }
    *leases = vela_tun::install_snapshot_routes(routes, snapshot, peer.node_id()).await?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run_tun_peer(
    mut peer: DiagnosticPeer,
    tun: vela_tun::TunDevice,
    routes: vela_tun::RouteManager,
    mut leases: Vec<vela_tun::RouteLease>,
) -> Result<(), Box<dyn std::error::Error>> {
    let node = peer.node.clone();
    let mut refresh = tokio::time::interval(Duration::from_secs(60));
    let mut control_connected = true;
    let mut reconnect_backoff = Duration::from_secs(1);
    let mut reconnect_sleep = Box::pin(tokio::time::sleep(Duration::ZERO));
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            packet = tun.recv() => {
                match node.send_ip(packet?).await {
                    Ok(()) => {}
                    Err(vela_core::SendError::Ip(error)) => {
                        tracing::debug!(error = %error, "dropping invalid or unrouted packet from TUN");
                    }
                    Err(vela_core::SendError::QueueFull) => {
                        tracing::debug!("dropping packet because the peer send queue is full");
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            event = node.next_event() => {
                match event {
                    Some(vela_core::VelaEvent::IpPacket { packet, .. }) => tun.send(packet.as_bytes()).await?,
                    Some(_) => {}
                    None => return Err("Vela node stopped".into()),
                }
            }
            message = peer.client.recv(), if control_connected => {
                match message {
                    Ok(vela_proto::ControlMessage::ConnectSignal { from, to }) if to == peer.node_id() => {
                        let info = peer.client.verify_public_peer(from)?;
                        node.register_peer(info).await?;
                    }
                    Ok(vela_proto::ControlMessage::Snapshot { snapshot }) => {
                        let refresh_candidates = peer.apply_snapshot(snapshot.clone()).await?;
                        apply_tun_snapshot(&peer, &routes, &mut leases, &snapshot).await?;
                        if refresh_candidates {
                            if let Err(error) = peer.refresh_candidates().await {
                                if !DiagnosticPeer::is_retryable_control_error(&error) {
                                    return Err(error.into());
                                }
                                tracing::warn!(error = %error, "coordination refresh failed; retrying");
                                control_connected = false;
                                reconnect_sleep.as_mut().reset(
                                    tokio::time::Instant::now() + reconnect_backoff,
                                );
                            }
                        }
                    }
                    Ok(vela_proto::ControlMessage::Revoke { node_id }) if node_id == peer.node_id() => {
                        for lease in leases.drain(..) {
                            let _ = lease.release().await;
                        }
                        peer.node.shutdown().await;
                        return Err("peer membership was revoked".into());
                    }
                    Err(error) => {
                        let error = vela_diagnostic::DiagnosticError::Coordination(error);
                        if !DiagnosticPeer::is_retryable_control_error(&error) {
                            return Err(error.into());
                        }
                        tracing::warn!(error = %error, "coordination connection lost; retrying");
                        control_connected = false;
                        reconnect_sleep.as_mut().reset(
                            tokio::time::Instant::now() + reconnect_backoff,
                        );
                    }
                    _ => {}
                }
            }
            _ = &mut ctrl_c => {
                peer.node.shutdown().await;
                release_route_leases(&mut leases).await;
                return Ok(());
            }
            tick = refresh.tick(), if control_connected => {
                let _ = tick;
                if let Err(error) = peer.refresh_candidates().await {
                    if !DiagnosticPeer::is_retryable_control_error(&error) {
                        return Err(error.into());
                    }
                    tracing::warn!(error = %error, "coordination refresh failed; retrying");
                    control_connected = false;
                    reconnect_sleep.as_mut().reset(
                        tokio::time::Instant::now() + reconnect_backoff,
                    );
                }
            }
            _ = &mut reconnect_sleep, if !control_connected => {
                match peer.reconnect().await {
                    Ok(snapshot) => {
                        apply_tun_snapshot(&peer, &routes, &mut leases, &snapshot).await?;
                        control_connected = true;
                        reconnect_backoff = Duration::from_secs(1);
                    }
                    Err(error) if DiagnosticPeer::is_retryable_control_error(&error) => {
                        tracing::warn!(error = %error, backoff = ?reconnect_backoff, "coordination reconnect failed");
                        reconnect_sleep.as_mut().reset(
                            tokio::time::Instant::now() + reconnect_backoff,
                        );
                        reconnect_backoff = reconnect_backoff
                            .saturating_mul(2)
                            .min(Duration::from_secs(30));
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async_main());
    runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
    result
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Rustls crypto provider already installed");

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
            let tenant = required(&args, "--tenant");
            let (database, signer, credentials) = coordination_paths(&args);
            if let Some(password) = password_from_stdin(&args)? {
                CoordServer::reset_admin_password(&credentials, Some(&password))?;
            }
            let server = CoordServer::open_with_admin_credentials_and_network_config(
                database,
                signer,
                tenant,
                credentials,
                options(&args, "--doh"),
                options(&args, "--stun"),
            )?;
            println!(
                "coordination server public key: {}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    server.server_public_key()
                )
            );
            server
                .serve(tokio::net::TcpListener::bind(bind).await?)
                .await?;
        }
        "invite" => {
            let server = open_coordination_server(&args)?;
            let ttl = option(&args, "--ttl")
                .and_then(|value| value.parse().ok())
                .unwrap_or(3600);
            println!("{}", server.create_invite(ttl)?);
        }
        "peers" => {
            let server = open_coordination_server(&args)?;
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
            let server = open_coordination_server(&args)?;
            server.revoke_peer(node_id).await?;
        }
        "admin" => {
            if args.first().map(String::as_str) != Some("password")
                || args.get(1).map(String::as_str) != Some("reset")
            {
                usage();
            }
            let (_, _, credentials) = coordination_paths(&args);
            let password = password_from_stdin(&args)?.unwrap_or_default();
            let password = CoordServer::reset_admin_password(
                credentials,
                (!password.is_empty()).then_some(password.as_str()),
            )?;
            println!("admin username: admin");
            println!("admin password: {password}");
            println!("restart the server to load the new password");
        }
        "peer" => run_peer_command(&args).await?,
        _ => usage(),
    }
    Ok(())
}
