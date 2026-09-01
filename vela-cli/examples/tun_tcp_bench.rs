use clap::{Args, Parser, Subcommand};
use std::{path::PathBuf, time::Instant};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const BUFFER_SIZE: usize = 64 * 1024;
const ONE_GIB: u64 = 1 << 30;

#[derive(Debug, Parser)]
#[command(name = "tun-tcp-bench")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Server(ServerArgs),
    Client(ClientArgs),
}

#[derive(Debug, Args)]
struct ServerArgs {
    #[arg(long)]
    bind: String,
    #[arg(long)]
    file: PathBuf,
    #[arg(long)]
    ready: PathBuf,
}

#[derive(Debug, Args)]
struct ClientArgs {
    #[arg(long)]
    connect: String,
    #[arg(long, default_value_t = ONE_GIB)]
    bytes: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Command::Server(args) => run_server(args).await?,
        Command::Client(args) => run_client(args).await?,
    }
    Ok(())
}

async fn run_server(args: ServerArgs) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(&args.bind).await?;
    tokio::fs::write(&args.ready, b"ready").await?;
    println!("tcp_server_ready bind={}", args.bind);
    let (mut stream, peer) = listener.accept().await?;
    let mut file = File::open(args.file).await?;
    let started = Instant::now();
    let bytes = tokio::io::copy(&mut file, &mut stream).await?;
    stream.shutdown().await?;
    println!(
        "tcp_server_done peer={} bytes={} elapsed_ms={} mbps={:.2}",
        peer,
        bytes,
        started.elapsed().as_millis(),
        megabits_per_second(bytes, started.elapsed()),
    );
    Ok(())
}

async fn run_client(args: ClientArgs) -> Result<(), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let mut stream = TcpStream::connect(&args.connect).await?;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut bytes = 0u64;
    while bytes < args.bytes {
        let remaining = args.bytes - bytes;
        let read_size = remaining.min(buffer.len() as u64) as usize;
        let length = stream.read(&mut buffer[..read_size]).await?;
        if length == 0 {
            return Err(format!("TCP stream ended after {bytes} of {} bytes", args.bytes).into());
        }
        bytes += length as u64;
    }
    let elapsed = started.elapsed();
    println!(
        "tcp_client_done bytes={} elapsed_ms={} mbps={:.2}",
        bytes,
        elapsed.as_millis(),
        megabits_per_second(bytes, elapsed),
    );
    Ok(())
}

fn megabits_per_second(bytes: u64, elapsed: std::time::Duration) -> f64 {
    bytes as f64 * 8.0 / elapsed.as_secs_f64() / 1_000_000.0
}
