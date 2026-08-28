use std::{env, net::SocketAddr, path::PathBuf, str::FromStr};
use vela_coord::CoordServer;
use vela_crypto::Identity;

fn usage() -> ! {
    eprintln!(
        "Usage:\n  vela-cli identity <path>\n  vela-cli server --bind <addr> --db <path> --signer <path> --tenant <name> [--cert <path> --key <path>]\n  vela-cli invite --db <path> --signer <path> --tenant <name> [--ttl <seconds>]\n  vela-cli peers --db <path> --signer <path> --tenant <name>\n  vela-cli revoke <node-id> --db <path> --signer <path> --tenant <name>"
    );
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
        _ => usage(),
    }
    Ok(())
}
