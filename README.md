# Vela

Vela is an embeddable, relay-free, encrypted peer datagram transport for Rust.
It does not create TUN/TAP devices, change kernel routes, or carry data through
the coordination server.

## Current implementation

The workspace currently contains:

- `vela-proto`: versioned JSON control messages and a bounds-checked binary data header.
- `vela-crypto`: Ed25519 identity, X25519 Noise `IK`, signed membership credentials, and ChaCha20-Poly1305 datagrams.
- `vela-stun`: client-side STUN Binding transactions.
- `vela-coord-client`: WebSocket control-plane client with server-key credential verification.
- `vela-core`: Tokio peer state machine with injectable direct UDP `DatagramProvider`, signed probes, path migration, replay-window checks, and traffic observation.
- `vela-diagnostic`: registered, relay-free peer diagnostics with authenticated direct Echo/Pong tests.
- `vela-coord`: single-tenant coordination server with SQLite authorization state and in-memory online sessions.
- `vela-cli`: identity, server, invite, peer-list, revoke, and diagnostic peer commands.

The default server listener is plain WebSocket for local development. The
server also exposes `serve_tls` and the CLI accepts `--cert`/`--key` for direct
Rustls termination.

The wire parser has a cargo-fuzz target at `fuzz/fuzz_targets/wire_packet.rs`.
It is intentionally outside the workspace and can be run with cargo-fuzz.

An embedded host can select its own direct socket provider:

```rust,no_run
use std::sync::Arc;
use vela_core::{BindOptions, NodeConfig, TokioDatagramProvider, VelaNode};
use vela_crypto::Identity;

# async fn run() -> Result<(), Box<dyn std::error::Error>> {
let provider = Arc::new(TokioDatagramProvider::new(Vec::new()));
let node = VelaNode::builder()
    .identity(Identity::load_or_generate("./node.key")?)
    .datagram_provider(provider)
    .config(NodeConfig {
        bind: BindOptions { local_addr: "0.0.0.0:0".parse()? },
        ..NodeConfig::default()
    })
    .build()
    .await?;
node.start().await?;
# Ok(())
# }
```

## Quick start

```text
cargo test --workspace

cargo run -p vela-cli -- server \
  --bind 0.0.0.0:7000 \
  --db ./vela.db \
  --signer ./server.key \
  --tenant my-network

cargo run -p vela-cli -- invite \
  --db ./vela.db \
  --signer ./server.key \
  --tenant my-network

# Use the server's printed public key and an invite token for each diagnostic peer.
cargo run -p vela-cli -- peer register \
  --state ./peer-a \
  --server ws://127.0.0.1:7000/ws \
  --server-key <base64-server-key> \
  --invite <invite-token> \
  --bind 192.0.2.10:0

cargo run -p vela-cli -- peer run --state ./peer-a
cargo run -p vela-cli -- peer list --state ./peer-a --json
cargo run -p vela-cli -- peer status --state ./peer-a --json
cargo run -p vela-cli -- peer ping vela:<node-id-hex> --state ./peer-a --count 3 --json
```

`peer run` is a diagnostic peer process, not a server or relay. The
coordination server only exchanges registration and candidate information;
the Probe, Noise handshake, and encrypted Echo/Pong packets travel directly
between peer UDP sockets. `--stun <ip:port>` can be repeated during register
or run to publish server-reflexive candidates.

For an embedded node, create a `TokioDatagramProvider` or implement
`DatagramProvider` in the host. The host provider is the intended place for
interface selection, source-address binding, routing marks and platform
specific socket options. Vela requires the provider to expose a real direct
UDP send/receive path; a SOCKS/HTTP proxy is not silently treated as direct
P2P.

## Security status

The protocol reserves a `CryptoPolicy` for a future hybrid X25519 + ML-KEM
handshake. `PreferHybrid` currently uses the classical suite because the
hybrid suite is not yet implemented; `RequireHybrid` fails closed. This is an
explicit MVP limitation, not an automatic downgrade.

The peer state directory stores the identity, server key, membership
credential, and published candidates. Identity and state files are written
with mode `0600`; production deployments should still protect them with
filesystem permissions and backups. The coordination server must be exposed
through TLS, either with the built-in Rustls listener or a trusted TLS
terminator.
