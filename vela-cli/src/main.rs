use std::{
    collections::HashSet, env, io::Read, net::SocketAddr, path::PathBuf, str::FromStr,
    time::Duration,
};
use vela_coord::CoordServer;
use vela_crypto::Identity;
use vela_diagnostic::{DiagnosticControl, DiagnosticError, DiagnosticPeer, PeerState};
use vela_proto::{NetworkSnapshot, NodeId};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

fn usage() -> ! {
    eprintln!(
        "Usage:\n  vela-cli identity <path>\n  vela-cli server --path <dir> --bind <addr> --tenant <name> [--doh <https-url>] [--stun <host:port>] [--admin-password-stdin]\n  vela-cli invite --path <dir> --tenant <name> [--ttl <seconds>]\n  vela-cli peers --path <dir> --tenant <name>\n  vela-cli revoke <node-id> --path <dir> --tenant <name>\n  vela-cli admin password reset --path <dir> [--password-stdin]\n  vela-cli peer register --state <dir> --server <url> --server-key <base64> --invite <token> [--port <port>] [--stun <host:port>]\n  vela-cli peer run --state <dir> [--port <port>] [--stun <host:port>]\n  vela-cli peer up --state <dir> [--tun <name>] [--mtu <bytes>] [--port <port>] [--stun <host:port>]\n  vela-cli peer list --state <dir> [--json]\n  vela-cli peer ping <node-id> --state <dir> [--count <n>] [--timeout <duration>] [--json]\n\nServer path defaults: <path>/vela.db, <path>/server.key, <path>/admin.credentials.\nThe server DoH/STUN settings can also be changed from the admin web page.\nLegacy --db/--signer and --admin-credentials overrides are still accepted."
    );
    eprintln!(
        "  vela-cli peer dashboard --state <dir> [--bind <addr>] [--port <port>] [--stun <host:port>]"
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

fn port_option(args: &[String]) -> Result<Option<u16>, Box<dyn std::error::Error>> {
    option(args, "--port")
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
            let port = port_option(args)?.unwrap_or(0);
            let stun = options(args, "--stun");
            let state =
                vela_diagnostic::register(&state_dir, server, server_key, &invite, port, stun)
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
            let peer = DiagnosticPeer::open(&state_dir, port_option(args)?, stun).await?;
            println!(
                "peer {} ready on {:?}",
                peer.node_id(),
                peer.node.local_addrs()?
            );
            peer.run().await?;
        }
        "dashboard" => {
            let state_dir = required(args, "--state");
            let stun_values = options(args, "--stun");
            let stun = if stun_values.is_empty() {
                None
            } else {
                Some(stun_values)
            };
            let bind = option(args, "--bind")
                .unwrap_or_else(|| "127.0.0.1:7001".to_owned())
                .parse::<SocketAddr>()?;
            let peer = DiagnosticPeer::open(&state_dir, port_option(args)?, stun).await?;
            println!(
                "peer {} dashboard available at http://{}",
                peer.node_id(),
                bind
            );
            peer.run_with_dashboard(bind).await?;
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
                let peer = DiagnosticPeer::open(&state_dir, port_option(args)?, stun).await?;
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
                println!("local_addrs\t{:?}", status.local_addrs);
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
    tracing::debug!(
        debug_marker = "vela-tun",
        node_id = %peer.node_id(),
        generation = snapshot.generation,
        peer_count = snapshot.peers.len(),
        "applying network snapshot to TUN"
    );
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
    tracing::debug!(
        debug_marker = "vela-tun",
        node_id = %peer.node_id(),
        local_ipv4 = ?local.virtual_ipv4,
        local_ipv6 = ?local.virtual_ipv6,
        installed_route_leases = leases.len(),
        "TUN addresses and peer routes installed"
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TunSendDisposition {
    Drop,
    Reconnect,
    Fatal,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn tun_send_disposition(error: &vela_core::SendError) -> TunSendDisposition {
    match error {
        vela_core::SendError::Ip(_) | vela_core::SendError::QueueFull => TunSendDisposition::Drop,
        vela_core::SendError::SnapshotExpired => TunSendDisposition::Reconnect,
        _ => TunSendDisposition::Fatal,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run_tun_peer(
    peer: DiagnosticPeer,
    tun: vela_tun::TunDevice,
    routes: vela_tun::RouteManager,
    mut leases: Vec<vela_tun::RouteLease>,
) -> Result<(), Box<dyn std::error::Error>> {
    let node = peer.node.clone();
    let mut peer = Some(peer);
    let mut refresh = tokio::time::interval(vela_diagnostic::CANDIDATE_REFRESH_INTERVAL);
    let mut control_connected = true;
    let mut pending_reconnects = HashSet::new();
    let mut reconnect_backoff = Duration::from_secs(1);
    let mut reconnect_sleep = Box::pin(tokio::time::sleep(Duration::ZERO));
    let mut reconnect_task: Option<
        tokio::task::JoinHandle<(DiagnosticPeer, Result<NetworkSnapshot, DiagnosticError>)>,
    > = None;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);
    loop {
        tokio::select! {
            packet = tun.recv() => {
                let packet = packet?;
                let packet_len = packet.len();
                tracing::debug!(
                    debug_marker = "vela-tun",
                    packet_len,
                    "received packet from TUN"
                );
                match node.send_ip(packet).await {
                    Ok(()) => tracing::debug!(
                        debug_marker = "vela-tun",
                        packet_len,
                        "handed TUN packet to Vela core"
                    ),
                    Err(vela_core::SendError::Ip(error)) => {
                        tracing::debug!(
                            debug_marker = "vela-tun",
                            packet_len,
                            error = %error,
                            "dropping invalid or unrouted packet from TUN"
                        );
                    }
                    Err(vela_core::SendError::QueueFull) => {
                        tracing::debug!(
                            debug_marker = "vela-tun",
                            packet_len,
                            "dropping packet because the peer send queue is full"
                        );
                    }
                    Err(error)
                        if tun_send_disposition(&error) == TunSendDisposition::Reconnect =>
                    {
                        if control_connected {
                            tracing::warn!(
                                debug_marker = "vela-tun",
                                packet_len,
                                error = %error,
                                "network snapshot expired; reconnecting to coordination service"
                            );
                            control_connected = false;
                            reconnect_sleep
                                .as_mut()
                                .reset(tokio::time::Instant::now());
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            debug_marker = "vela-tun",
                            packet_len,
                            error = %error,
                            "fatal error while sending TUN packet"
                        );
                        return Err(error.into());
                    }
                }
            }
            event = node.next_event() => {
                match event {
                    Some(vela_core::VelaEvent::IpPacket { peer, packet }) => {
                        tracing::debug!(
                            debug_marker = "vela-tun",
                            peer_id = %peer,
                            source = ?packet.source(),
                            destination = ?packet.destination(),
                            packet_len = packet.as_bytes().len(),
                            "received decrypted IP packet; writing to TUN"
                        );
                        tun.send(packet.as_bytes()).await?;
                    }
                    Some(vela_core::VelaEvent::PeerConnecting(peer)) => tracing::debug!(
                        debug_marker = "vela-session",
                        peer_id = %peer,
                        "peer session connecting"
                    ),
                    Some(vela_core::VelaEvent::PeerConnected(peer)) => tracing::info!(
                        debug_marker = "vela-session",
                        peer_id = %peer,
                        "peer session connected"
                    ),
                    Some(vela_core::VelaEvent::PeerDisconnected(peer)) => tracing::warn!(
                        debug_marker = "vela-session",
                        peer_id = %peer,
                        "peer session disconnected"
                    ),
                    Some(vela_core::VelaEvent::PeerReconnectRequested(peer_id)) => {
                        if !control_connected {
                            pending_reconnects.insert(peer_id);
                            continue;
                        }
                        let control_peer = peer.as_mut().expect("control peer is available");
                        if let Err(error) = control_peer.request_peer_connection(peer_id).await {
                            if !DiagnosticPeer::is_retryable_control_error(&error) {
                                return Err(error.into());
                            }
                            pending_reconnects.insert(peer_id);
                            tracing::warn!(
                                debug_marker = "vela-control",
                                peer_id = %peer_id,
                                error = %error,
                                "failed to signal peer for bilateral reconnect; retrying coordination"
                            );
                            control_connected = false;
                            reconnect_sleep.as_mut().reset(
                                tokio::time::Instant::now() + reconnect_backoff,
                            );
                        }
                    }
                    Some(vela_core::VelaEvent::PeerUnreachable(peer)) => tracing::warn!(
                        debug_marker = "vela-session",
                        peer_id = %peer,
                        "peer is unreachable"
                    ),
                    Some(vela_core::VelaEvent::PathChanged(peer, path)) => tracing::info!(
                        debug_marker = "vela-session",
                        peer_id = %peer,
                        path = %path,
                        "peer path changed"
                    ),
                    Some(vela_core::VelaEvent::TransportFailed { family, error }) => {
                        return Err(format!("UDP transport failed ({family:?}): {error}").into());
                    }
                    None => return Err("Vela node stopped".into()),
                }
            }
            message = async {
                peer.as_mut()
                    .expect("control peer is available")
                    .client
                    .recv()
                    .await
            }, if control_connected && peer.is_some() => {
                match message {
                    Ok(vela_proto::ControlMessage::ConnectSignal { from, to }) if to == node.node_id() => {
                        tracing::debug!(
                            debug_marker = "vela-control",
                            from = %from.node_id,
                            "received peer connect signal"
                        );
                        let control_peer = peer.as_mut().expect("control peer is available");
                        let info = control_peer.client.verify_public_peer(from)?;
                        let peer_id = info.node_id;
                        node.register_peer(info).await?;
                        let connect_node = node.clone();
                        tokio::spawn(async move {
                            if let Err(error) = connect_node.connect(peer_id).await {
                                tracing::warn!(
                                    debug_marker = "vela-session",
                                    peer_id = %peer_id,
                                    error = %error,
                                    "peer connection triggered by coordination signal failed"
                                );
                            }
                        });
                    }
                    Ok(vela_proto::ControlMessage::Snapshot { snapshot }) => {
                        tracing::debug!(
                            debug_marker = "vela-control",
                            generation = snapshot.generation,
                            peer_count = snapshot.peers.len(),
                            "received network snapshot"
                        );
                        let control_peer = peer.as_mut().expect("control peer is available");
                        let refresh_candidates = control_peer.apply_snapshot(snapshot.clone()).await?;
                        apply_tun_snapshot(control_peer, &routes, &mut leases, &snapshot).await?;
                        if refresh_candidates {
                            if let Err(error) = control_peer.refresh_candidates().await {
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
                    Ok(vela_proto::ControlMessage::Revoke { node_id }) if node_id == node.node_id() => {
                        for lease in leases.drain(..) {
                            let _ = lease.release().await;
                        }
                        node.shutdown().await;
                        return Err("peer membership was revoked".into());
                    }
                    Err(error) => {
                        let error = vela_diagnostic::DiagnosticError::Coordination(error);
                        if !DiagnosticPeer::is_retryable_control_error(&error) {
                            return Err(error.into());
                        }
                        tracing::warn!(
                            debug_marker = "vela-control",
                            error = %error,
                            "coordination connection lost; retrying while keeping data plane alive"
                        );
                        control_connected = false;
                        reconnect_sleep.as_mut().reset(
                            tokio::time::Instant::now() + reconnect_backoff,
                        );
                    }
                    _ => {}
                }
            }
            _ = &mut ctrl_c => {
                tracing::info!(debug_marker = "vela-lifecycle", "shutdown requested");
                node.shutdown().await;
                release_route_leases(&mut leases).await;
                return Ok(());
            }
            tick = refresh.tick(), if control_connected && peer.is_some() => {
                let _ = tick;
                let control_peer = peer.as_mut().expect("control peer is available");
                if let Err(error) = control_peer.refresh_candidates().await {
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
            _ = &mut reconnect_sleep, if !control_connected && reconnect_task.is_none() => {
                let mut reconnect_peer = peer.take().expect("control peer is available");
                let reconnect_node_id = node.node_id();
                tracing::info!(
                    debug_marker = "vela-control",
                    node_id = %reconnect_node_id,
                    "starting coordination reconnect in background"
                );
                reconnect_task = Some(tokio::spawn(async move {
                    let result = reconnect_peer.reconnect().await;
                    (reconnect_peer, result)
                }));
            }
            reconnect_result = async {
                reconnect_task
                    .as_mut()
                    .expect("reconnect task is available")
                    .await
            }, if reconnect_task.is_some() => {
                let (reconnected_peer, result) = reconnect_result
                    .map_err(|error| format!("coordination reconnect task failed: {error}"))?;
                peer = Some(reconnected_peer);
                match result {
                    Ok(snapshot) => {
                        tracing::info!(
                            debug_marker = "vela-control",
                            generation = snapshot.generation,
                            "coordination reconnected"
                        );
                        let control_peer = peer.as_ref().expect("control peer is available");
                        apply_tun_snapshot(control_peer, &routes, &mut leases, &snapshot).await?;
                        reconnect_task = None;
                        control_connected = true;
                        reconnect_backoff = Duration::from_secs(1);
                        let pending = std::mem::take(&mut pending_reconnects);
                        for peer_id in pending {
                            let control_peer = peer.as_mut().expect("control peer is available");
                            if let Err(error) = control_peer.request_peer_connection(peer_id).await {
                                if !DiagnosticPeer::is_retryable_control_error(&error) {
                                    return Err(error.into());
                                }
                                pending_reconnects.insert(peer_id);
                                tracing::warn!(
                                    debug_marker = "vela-control",
                                    peer_id = %peer_id,
                                    error = %error,
                                    "failed to flush bilateral reconnect signal"
                                );
                                control_connected = false;
                                reconnect_sleep.as_mut().reset(
                                    tokio::time::Instant::now() + reconnect_backoff,
                                );
                                break;
                            }
                        }
                    }
                    Err(error) if DiagnosticPeer::is_retryable_control_error(&error) => {
                        tracing::warn!(
                            debug_marker = "vela-control",
                            error = %error,
                            backoff = ?reconnect_backoff,
                            "coordination reconnect failed; data plane remains running"
                        );
                        reconnect_task = None;
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
    init_tracing();
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

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(filter)
        .try_init();
}

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
mod tests {
    use super::*;

    #[test]
    fn expired_snapshot_requests_coordination_reconnect() {
        assert_eq!(
            tun_send_disposition(&vela_core::SendError::SnapshotExpired),
            TunSendDisposition::Reconnect
        );
    }

    #[test]
    fn legacy_peer_bind_argument_is_ignored() {
        let args = vec!["--bind".to_owned(), "192.0.2.10:40000".to_owned()];
        assert_eq!(port_option(&args).unwrap(), None);
        let args = vec!["--port".to_owned(), "40000".to_owned()];
        assert_eq!(port_option(&args).unwrap(), Some(40000));
    }
}
