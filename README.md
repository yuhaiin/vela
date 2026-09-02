# Vela

Vela is an embeddable, relay-free, encrypted layer-3 peer network for Rust.
It forwards complete IPv4/IPv6 packets directly between authenticated peers.
Linux, macOS, and Windows can expose the network through a TUN device; library
users can instead use the userspace stack without changing kernel routes.

## Current implementation

The workspace currently contains:

- `vela-proto`: versioned JSON control messages and a bounds-checked binary data header.
- `vela-crypto`: Ed25519 identity, X25519 Noise `IK`, signed membership credentials, and ChaCha20-Poly1305 datagrams.
- `vela-dns`: DNS-over-HTTPS resolver for control-plane and candidate endpoints.
- `vela-stun`: client-side STUN Binding transactions.
- `vela-coord-client`: WebSocket control-plane client with server-key credential verification.
- `vela-ip`: strict IPv4/IPv6 packet validation and exact host-route selection.
- `vela-core`: shared encrypted IP data plane with direct UDP probing, Noise sessions, path migration, replay-window checks, snapshot replacement, and traffic observation.
- `vela-stack`: Tokio-owned `smoltcp` userspace TCP/UDP/ICMP/raw-IP stack with `dial`, `listen`, and `listen_packet` entry points.
- `vela-tun`: platform TUN adapters plus managed `/32` and `/128` route leases
  (Linux netlink, macOS route sockets, and Windows IP Helper).
- `vela-diagnostic`: registered, relay-free peer diagnostics with authenticated direct Echo/Pong tests.
- `vela-coord`: single-tenant coordination server with SQLite authorization state, signed network snapshots, stable virtual addresses, and in-memory online sessions.
- `vela-cli`: identity, server, invite, peer-list, revoke, diagnostic peer, and
  Linux/macOS/Windows TUN peer commands.

The coordination server listener is plain HTTP/WebSocket. Public deployments
should put it behind a TLS terminator such as Cloudflare Tunnel.

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
        bind: BindOptions { port: 0 },
        ..NodeConfig::default()
    })
    .build()
    .await?;
node.start().await?;
# Ok(())
# }
```

For process-local networking, attach `vela-stack` after the node has been
started and use the virtual address directly:

```rust,no_run
use vela_stack::{StackConfig, VelaStack};

# async fn run(node: vela_core::VelaNode) -> Result<(), Box<dyn std::error::Error>> {
let stack = VelaStack::attach(node, StackConfig::ipv4("10.254.0.11".parse()?))?;
let listener = stack.listen("10.254.0.11:8080".parse()?).await?;
let connection = stack.dial("10.254.0.12:8080".parse()?).await?;
connection.send(b"hello").await?;
let (server, _remote) = listener.accept().await?;
let _data = server.recv(4096).await?;
# Ok(())
# }
```

`vela-stack` owns the `VelaNode` event stream, so an application should not
consume `node.next_event()` concurrently with the attached stack. Use
`VelaNode::send_ip` and `VelaEvent::IpPacket` when integrating a custom L3
adapter instead.

## Quick start

```text
cargo test --workspace

cargo run -p vela-cli -- server \
  --path ./vela-server \
  --bind 0.0.0.0:7000 \
  --tenant my-network
# Optional initial values; both can also be changed in /admin.
#   --doh https://doh.pub --stun stun.nextcloud.com:3478

# The first server start prints a generated admin password once.
# Open http://127.0.0.1:7000/admin and use it to manage peers.
# To set it explicitly instead: cat <password-file> | ... server ... --admin-password-stdin

cargo run -p vela-cli -- invite --path ./vela-server --tenant my-network

# Use the server's printed public key and an invite token for each diagnostic peer.
cargo run -p vela-cli -- peer register \
  --state ./peer-a \
  --server ws://127.0.0.1:7000/ws \
  --server-key <base64-server-key> \
  --invite <invite-token> \
  --port 0

# `peer up` starts the only peer runtime, the TUN adapter, and the dashboard.
cargo run -p vela-cli -- peer up --state ./peer-a --mtu 1200
# The following commands connect to the already-running peer up service.
cargo run -p vela-cli -- peer list --state ./peer-a --json
cargo run -p vela-cli -- peer status --state ./peer-a --json
cargo run -p vela-cli -- peer ping vela:<node-id-hex> --state ./peer-a --count 3 --json

# Reset the admin password if it was lost. The server must be restarted after this.
cargo run -p vela-cli -- admin password reset --path ./vela-server
```

The coordination server exposes a plain HTTP/WebSocket admin service at
`/admin`, `/api/v1`, and `/download/vela-cli`. The page uses the current
`window.location.origin`, so it works behind a Cloudflare Tunnel without a
separate frontend build or Node.js runtime. Admin sessions are held in memory
for 24 hours and the browser stores the session token in `localStorage` until
it expires.

Creating an invite in the admin page produces a one-time download command for
the same `vela-cli` executable, a peer registration command, and a TUN startup
command. The CLI download is protected by its own `X-Vela-Download-Token` and
does not expose the admin session token.

`peer up` is a diagnostic peer process, not a server or relay. The
coordination server only exchanges registration and candidate information;
the Probe, Noise handshake, and encrypted Echo/Pong packets travel directly
between peer UDP sockets. Hostname resolution does not use the system resolver:
peers use the built-in DoH endpoint `https://doh.pub` by default for the
coordination endpoint and STUN hostnames. `--stun <host:port>` can be repeated
during register or up to publish server-reflexive candidates; hostnames are
resolved through DoH on every refresh. The server may be started with repeated
`--doh <https-url>` and `--stun <host:port>` options, or both settings can be
edited in `/admin`; changes are persisted, signed into snapshots, and pushed to
online peers dynamically.

`peer up` runs the peer lifecycle together with a read-only local HTTP dashboard
at `127.0.0.1:7001` (use `--bind` to change it). Its dashboard API is
`/api/v1/dashboard` and is polled by the page once per second. On Unix,
`peer status`, `peer list`, and `peer ping` use the authenticated service
through `control.sock`; on Windows they use the authenticated loopback HTTP
endpoint recorded in `control.json`. They never load the full peer state or create another
coordinator client. Coordinator online state and direct UDP state are deliberately separate;
candidate lists show advertised addresses, while `active path` shows the address actually used
by the encrypted session.
The peer transport always creates one IPv4-only and one IPv6-only UDP socket.
`--port <port>` selects the same local port for both sockets; omitting it lets
the operating system choose an ephemeral port independently for each family.
On restart, the last successful IPv4 and IPv6 ports are tried first and both
families fall back to fresh ports together if that pair is unavailable. The
peer transport no longer uses `--bind`; that option selects the dashboard HTTP
address. The sockets and their automatically
collected host candidates use each family's main-table
default-route interface, so addresses from unrelated VPN, container, or
virtual interfaces are not advertised. If a family has no default route, its
socket remains usable but no host candidate is published for that family; STUN
can still discover a server-reflexive candidate.

On Linux, macOS, and Windows, `peer up` creates a layer-3 TUN interface, assigns
the stable virtual address from the signed network snapshot, installs one host
route for every remote peer record in that snapshot (including offline peers),
and bridges complete IP packets to the encrypted direct data plane. A peer's
online status affects connection attempts only; it never removes its route.
Routes are updated incrementally and are removed only when the server snapshot
no longer contains that peer or when the local peer process shuts down. Linux
needs access to `/dev/net/tun` and `CAP_NET_ADMIN`;
macOS needs permission to create and configure `utun` interfaces; Windows uses
Wintun and requires `wintun.dll` matching the binary architecture beside the
executable, plus Administrator privileges. The default interface name is
`vela0` on Linux/Windows and `utun0` on macOS. Routes are reference-counted.

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
filesystem permissions and backups. The coordination server speaks plain
HTTP/WebSocket by default. For public deployment, put it behind a trusted TLS
terminator such as Cloudflare Tunnel; the admin page automatically derives
`ws://` or `wss://` from the current browser origin.
