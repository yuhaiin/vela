use clap::{ArgAction, Args, Parser, Subcommand};
use std::{
    collections::{HashMap, HashSet},
    io::Read,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use vela_coord::CoordServer;
use vela_crypto::Identity;
use vela_diagnostic::{LocalControlClient, PeerState, RuntimeProcess};
use vela_proto::NodeId;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Parser)]
#[command(name = "vela-cli", version, about = "Vela coordination and peer tools")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Identity(IdentityArgs),
    Server(ServerArgs),
    Invite(InviteArgs),
    Peers(ServerPathArgs),
    Revoke(RevokeArgs),
    Admin(AdminArgs),
    Peer {
        #[command(subcommand)]
        command: PeerCommand,
    },
}

#[derive(Debug, Args)]
struct IdentityArgs {
    path: PathBuf,
}

#[derive(Debug, Args)]
struct ServerPathArgs {
    #[arg(long)]
    path: Option<PathBuf>,
    #[arg(long)]
    db: Option<PathBuf>,
    #[arg(long)]
    signer: Option<PathBuf>,
    #[arg(long = "admin-credentials")]
    admin_credentials: Option<PathBuf>,
    #[arg(long)]
    tenant: String,
    #[arg(long = "doh", action = ArgAction::Append)]
    doh: Vec<String>,
    #[arg(long = "stun", action = ArgAction::Append)]
    stun: Vec<String>,
}

#[derive(Debug, Args)]
struct ServerArgs {
    #[command(flatten)]
    paths: ServerPathArgs,
    #[arg(long)]
    bind: SocketAddr,
    #[arg(long = "admin-password-stdin")]
    admin_password_stdin: bool,
}

#[derive(Debug, Args)]
struct InviteArgs {
    #[command(flatten)]
    paths: ServerPathArgs,
    #[arg(long, default_value_t = 3600)]
    ttl: u64,
}

#[derive(Debug, Args)]
struct RevokeArgs {
    node_id: NodeId,
    #[command(flatten)]
    paths: ServerPathArgs,
}

#[derive(Debug, Args)]
struct AdminArgs {
    #[command(subcommand)]
    command: AdminCommand,
}

#[derive(Debug, Subcommand)]
enum AdminCommand {
    Password(AdminPasswordArgs),
}

#[derive(Debug, Args)]
struct AdminPasswordArgs {
    #[command(subcommand)]
    command: AdminPasswordCommand,
}

#[derive(Debug, Subcommand)]
enum AdminPasswordCommand {
    Reset(AdminResetArgs),
}

#[derive(Debug, Args)]
struct AdminResetArgs {
    #[arg(long)]
    path: PathBuf,
    #[arg(long)]
    password_stdin: bool,
}

#[derive(Debug, Subcommand)]
enum PeerCommand {
    Register(PeerRegisterArgs),
    Up(PeerUpArgs),
    List(PeerStateArgs),
    Status(PeerStateArgs),
    Ping(PeerPingArgs),
}

#[derive(Debug, Args)]
struct PeerRegisterArgs {
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    server: String,
    #[arg(long = "server-key")]
    server_key: String,
    #[arg(long)]
    invite: String,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long = "stun", action = ArgAction::Append)]
    stun: Vec<String>,
}

#[derive(Debug, Args)]
struct PeerUpArgs {
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    tun: Option<String>,
    #[arg(long, default_value_t = 1200)]
    mtu: usize,
    #[arg(long, default_value = "127.0.0.1:7001")]
    bind: SocketAddr,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long = "stun", action = ArgAction::Append)]
    stun: Vec<String>,
}

#[derive(Debug, Args)]
struct PeerStateArgs {
    #[arg(long)]
    state: PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct PeerPingArgs {
    target: NodeId,
    #[arg(long)]
    state: PathBuf,
    #[arg(long, default_value_t = 1, value_parser = parse_ping_count)]
    count: usize,
    #[arg(long, default_value = "8s", value_parser = parse_ping_timeout)]
    timeout: Duration,
    #[arg(long)]
    json: bool,
}

fn invalid_input(message: impl Into<String>) -> Box<dyn std::error::Error> {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into()).into()
}

fn parse_duration(value: &str) -> Result<Duration, String> {
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1u64)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1000u64)
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

fn parse_ping_count(value: &str) -> Result<usize, String> {
    let count = value
        .parse::<usize>()
        .map_err(|_| format!("invalid ping count: {value}"))?;
    if (1..=vela_diagnostic::MAX_PING_COUNT).contains(&count) {
        Ok(count)
    } else {
        Err(format!(
            "ping count must be between 1 and {}",
            vela_diagnostic::MAX_PING_COUNT
        ))
    }
}

fn parse_ping_timeout(value: &str) -> Result<Duration, String> {
    let timeout = parse_duration(value)?;
    if !(vela_diagnostic::MIN_PING_TIMEOUT..=vela_diagnostic::MAX_PING_TIMEOUT).contains(&timeout) {
        return Err(format!(
            "ping timeout must be between {:?} and {:?}",
            vela_diagnostic::MIN_PING_TIMEOUT,
            vela_diagnostic::MAX_PING_TIMEOUT
        ));
    }
    Ok(timeout)
}

fn decode_server_key(value: &str) -> Result<[u8; 32], String> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, value)
        .map_err(|_| "invalid base64 server key".to_owned())?;
    bytes
        .try_into()
        .map_err(|_| "server key must decode to 32 bytes".to_owned())
}

fn coordination_paths(
    paths: &ServerPathArgs,
) -> Result<(PathBuf, PathBuf, PathBuf), Box<dyn std::error::Error>> {
    let database = paths
        .db
        .clone()
        .or_else(|| paths.path.as_ref().map(|path| path.join("vela.db")))
        .ok_or_else(|| invalid_input("missing --path or --db"))?;
    let signer = paths
        .signer
        .clone()
        .or_else(|| paths.path.as_ref().map(|path| path.join("server.key")))
        .ok_or_else(|| invalid_input("missing --path or --signer"))?;
    let credentials = paths
        .admin_credentials
        .clone()
        .or_else(|| {
            paths
                .path
                .as_ref()
                .map(|path| path.join("admin.credentials"))
        })
        .unwrap_or_else(|| database.with_extension("admin-credentials"));
    Ok((database, signer, credentials))
}

fn open_coordination_server(
    paths: &ServerPathArgs,
) -> Result<CoordServer, Box<dyn std::error::Error>> {
    let (database, signer, credentials) = coordination_paths(paths)?;
    Ok(CoordServer::open_with_admin_credentials_and_network_config(
        database,
        signer,
        paths.tenant.clone(),
        credentials,
        paths.doh.clone(),
        paths.stun.clone(),
    )?)
}

fn read_password(enabled: bool) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if !enabled {
        return Ok(None);
    }
    let mut password = String::new();
    std::io::stdin().read_to_string(&mut password)?;
    let password = password.trim_end_matches(['\r', '\n']).to_owned();
    if password.is_empty() {
        return Err(invalid_input("password stdin was empty"));
    }
    Ok(Some(password))
}

async fn run_command(command: Command) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Command::Identity(args) => {
            let identity = Identity::load_or_generate(args.path)?;
            println!("{}", identity.public().node_id);
        }
        Command::Server(args) => {
            let (database, signer, credentials) = coordination_paths(&args.paths)?;
            if let Some(password) = read_password(args.admin_password_stdin)? {
                CoordServer::reset_admin_password(&credentials, Some(&password))?;
            }
            let server = CoordServer::open_with_admin_credentials_and_network_config(
                database,
                signer,
                args.paths.tenant,
                credentials,
                args.paths.doh,
                args.paths.stun,
            )?;
            println!(
                "coordination server public key: {}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    server.server_public_key()
                )
            );
            server
                .serve(tokio::net::TcpListener::bind(args.bind).await?)
                .await?;
        }
        Command::Invite(args) => {
            let server = open_coordination_server(&args.paths)?;
            println!("{}", server.create_invite(args.ttl)?);
        }
        Command::Peers(args) => {
            let server = open_coordination_server(&args)?;
            for peer in server.list_peers()? {
                println!("{peer}");
            }
        }
        Command::Revoke(args) => {
            let server = open_coordination_server(&args.paths)?;
            server.revoke_peer(args.node_id).await?;
        }
        Command::Admin(args) => run_admin_command(args).await?,
        Command::Peer { command } => run_peer_command(command).await?,
    }
    Ok(())
}

async fn run_admin_command(args: AdminArgs) -> Result<(), Box<dyn std::error::Error>> {
    match args.command {
        AdminCommand::Password(args) => match args.command {
            AdminPasswordCommand::Reset(args) => {
                let credentials = args.path.join("admin.credentials");
                let password = read_password(args.password_stdin)?;
                let password = CoordServer::reset_admin_password(credentials, password.as_deref())?;
                println!("admin username: admin");
                println!("admin password: {password}");
                println!("restart the server to load the new password");
            }
        },
    }
    Ok(())
}

async fn run_peer_command(command: PeerCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        PeerCommand::Register(args) => {
            let server_key = decode_server_key(&args.server_key)?;
            let state = vela_diagnostic::register(
                &args.state,
                args.server,
                server_key,
                &args.invite,
                args.port.unwrap_or(0),
                args.stun,
            )
            .await?;
            let identity = Identity::load(PeerState::identity_path(&args.state))?;
            println!("registered {}", identity.public().node_id);
            println!("state saved in {}", args.state.display());
            let _ = state;
        }
        PeerCommand::Up(args) => run_peer_up(args).await?,
        PeerCommand::List(args) => {
            let control = LocalControlClient::open(&args.state).await?;
            let peers = control.peers().await?;
            if args.json {
                println!("{}", serde_json::to_string_pretty(&peers)?);
            } else {
                print_peer_table(&peers);
            }
        }
        PeerCommand::Status(args) => {
            let control = LocalControlClient::open(&args.state).await?;
            let status = control.status().await?;
            if args.json {
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
        PeerCommand::Ping(args) => {
            let control = LocalControlClient::open(&args.state).await?;
            let report = control.ping(args.target, args.count, args.timeout).await?;
            if args.json {
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
    }
    Ok(())
}

fn print_peer_table(peers: &[vela_proto::PeerSummary]) {
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

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn run_peer_up(_args: PeerUpArgs) -> Result<(), Box<dyn std::error::Error>> {
    Err("peer up is unsupported on this platform".into())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run_peer_up(args: PeerUpArgs) -> Result<(), Box<dyn std::error::Error>> {
    let process = vela_diagnostic::DiagnosticRuntime::open_with_mtu(
        &args.state,
        args.port,
        (!args.stun.is_empty()).then_some(args.stun),
        args.bind,
        args.mtu,
    )
    .await?;
    let snapshot = process
        .io
        .snapshots
        .borrow()
        .clone()
        .ok_or_else(|| invalid_input("state has no network snapshot; register first"))?;
    let tun_name = args.tun.unwrap_or_else(|| {
        if cfg!(target_os = "macos") {
            String::new()
        } else {
            "vela0".to_owned()
        }
    });
    let tun = match vela_tun::TunDevice::open(vela_tun::TunConfig {
        name: tun_name,
        mtu: args.mtu,
    }) {
        Ok(tun) => tun,
        Err(error) => {
            stop_process(process).await;
            return Err(error.into());
        }
    };
    let routes = match vela_tun::RouteManager::for_tun(&tun).await {
        Ok(routes) => routes,
        Err(error) => {
            stop_process(process).await;
            return Err(error.into());
        }
    };
    if let Err(error) = routes.set_mtu(args.mtu).await {
        stop_process(process).await;
        return Err(error.into());
    }
    let mut leases = HashMap::new();
    if let Err(error) =
        apply_tun_snapshot(process.handle.node_id(), &routes, &mut leases, &snapshot).await
    {
        release_route_leases(&mut leases).await;
        stop_process(process).await;
        return Err(error);
    }
    let endpoint = process.handle.endpoint().address.map_or_else(
        || "unavailable".to_owned(),
        |address| format!("http://{address}"),
    );
    println!(
        "peer {} up on TUN {}; dashboard available at {}",
        process.handle.node_id(),
        tun.name(),
        endpoint
    );
    run_tun_peer(process, tun, routes, leases).await
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn stop_process(process: RuntimeProcess) {
    process.handle.stop();
    let _ = process.task.await;
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn release_route_leases(leases: &mut HashMap<IpAddr, vela_tun::RouteLease>) {
    let pending = std::mem::take(leases);
    if tokio::time::timeout(SHUTDOWN_TIMEOUT, async move {
        for lease in pending.into_values() {
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

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn apply_tun_snapshot(
    node_id: NodeId,
    routes: &vela_tun::RouteManager,
    leases: &mut HashMap<IpAddr, vela_tun::RouteLease>,
    snapshot: &vela_proto::NetworkSnapshot,
) -> Result<(), Box<dyn std::error::Error>> {
    snapshot
        .validate()
        .map_err(|error| invalid_input(format!("invalid network snapshot: {error}")))?;
    let local = snapshot
        .peers
        .iter()
        .find(|peer| peer.node_id == node_id)
        .ok_or_else(|| invalid_input("snapshot does not contain this node"))?;
    tracing::debug!(
        debug_marker = "vela-tun",
        node_id = %node_id,
        generation = snapshot.generation,
        peer_count = snapshot.peers.len(),
        "applying network snapshot to TUN"
    );
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

    // Host routes belong to the signed server membership. `online_peers` only
    // describes the current control-plane presence and must not create route
    // churn when a peer disconnects or reconnects.
    let desired = vela_tun::snapshot_route_addresses(snapshot, node_id)?
        .into_iter()
        .collect::<HashSet<_>>();
    let missing = desired
        .iter()
        .copied()
        .filter(|address| !leases.contains_key(address))
        .collect::<Vec<_>>();
    for address in missing {
        let lease = routes.claim_host_route(address).await?;
        leases.insert(address, lease);
    }
    let stale = leases
        .keys()
        .copied()
        .filter(|address| !desired.contains(address))
        .collect::<Vec<_>>();
    for address in stale {
        if let Some(lease) = leases.remove(&address) {
            let _ = lease.release().await;
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
async fn run_tun_peer(
    process: RuntimeProcess,
    tun: vela_tun::TunDevice,
    routes: vela_tun::RouteManager,
    mut leases: HashMap<IpAddr, vela_tun::RouteLease>,
) -> Result<(), Box<dyn std::error::Error>> {
    let vela_diagnostic::RuntimeProcess {
        handle,
        io,
        mut task,
    } = process;
    let tun = Arc::new(tun);
    let tun_reader = Arc::clone(&tun);
    let reader_handle = handle.clone();
    let mut tun_to_vela = tokio::spawn(async move {
        loop {
            let packet = tun_reader.recv().await.map_err(|error| error.to_string())?;
            let packet_len = packet.len();
            match reader_handle.send_ip(packet).await {
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
                    "dropping TUN packet after a transient Vela send failure"
                ),
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), String>(())
    });
    let tun_writer = Arc::clone(&tun);
    let mut vela_to_tun = tokio::spawn(async move {
        let mut packets = io.packets;
        while let Some((_peer, packet)) = packets.recv().await {
            tun_writer
                .send(packet.as_bytes())
                .await
                .map_err(|error| error.to_string())?;
        }
        Err::<(), _>("peer runtime packet channel closed".to_owned())
    });
    let mut snapshots = io.snapshots;
    let ctrl_c = tokio::signal::ctrl_c();
    tokio::pin!(ctrl_c);

    let mut runtime_result = None;
    let loop_result: Result<(), Box<dyn std::error::Error>> = loop {
        tokio::select! {
            result = &mut task => {
                runtime_result = Some(match result {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => Err(Box::new(error) as Box<dyn std::error::Error>),
                    Err(error) => Err(Box::new(error) as Box<dyn std::error::Error>),
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
                    break Err(invalid_input("peer runtime snapshot channel closed"));
                }
                if let Some(snapshot) = snapshots.borrow().clone() {
                    if let Err(error) = apply_tun_snapshot(
                        handle.node_id(),
                        &routes,
                        &mut leases,
                        &snapshot,
                    ).await {
                        break Err(error);
                    }
                }
            }
            _ = &mut ctrl_c => {
                tracing::info!(debug_marker = "vela-lifecycle", "shutdown requested");
                break Ok(());
            }
        }
    };

    tun_to_vela.abort();
    vela_to_tun.abort();
    if runtime_result.is_none() {
        handle.stop();
        runtime_result = Some(
            task.await
                .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })?
                .map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) }),
        );
    }
    release_route_leases(&mut leases).await;
    loop_result.and(runtime_result.expect("runtime result is set"))
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_env_filter(filter)
        .try_init();
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        init_tracing();
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Rustls crypto provider already installed");
        run_command(Cli::parse().command).await
    });
    runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removed_peer_commands_are_rejected() {
        assert!(Cli::try_parse_from(["vela-cli", "peer", "run", "--state", "state"]).is_err());
        assert!(
            Cli::try_parse_from(["vela-cli", "peer", "dashboard", "--state", "state"]).is_err()
        );
    }

    #[test]
    fn ping_limits_are_parsed_at_the_cli_boundary() {
        assert_eq!(parse_ping_count("32"), Ok(32));
        assert!(parse_ping_count("33").is_err());
        assert_eq!(parse_ping_timeout("100ms"), Ok(Duration::from_millis(100)));
        assert!(parse_ping_timeout("99ms").is_err());
        assert!(parse_ping_timeout("61s").is_err());
    }
}
