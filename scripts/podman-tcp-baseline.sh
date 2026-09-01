#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/vela-tcp-baseline.XXXXXX")
network="vela-tcp-baseline-$$"
image="docker.io/library/debian:bookworm-slim"
tcp_bin="$repo_dir/target/release/examples/tun_tcp_bench"
server_name="${network}-server"
client_name="${network}-client"

cleanup() {
    podman rm -f "$client_name" "$server_name" >/dev/null 2>&1 || true
    podman network rm "$network" >/dev/null 2>&1 || true
    rm -rf "$run_dir"
}
trap cleanup EXIT

cargo build --release -p vela-cli --example tun_tcp_bench
fallocate -l 1G "$run_dir/download.bin"
podman network create --subnet 10.252.0.0/24 --gateway 10.252.0.1 "$network" >/dev/null
podman run -d --name "$server_name" --network "$network" --ip 10.252.0.2 \
    -v "$run_dir:/bench" -v "$tcp_bin:/usr/local/bin/tun_tcp_bench:ro" "$image" \
    /usr/local/bin/tun_tcp_bench server --bind 0.0.0.0:41000 --file /bench/download.bin --ready /bench/ready >/dev/null
for _ in $(seq 1 100); do
    [[ -s "$run_dir/ready" ]] && break
    sleep 0.1
done
[[ -s "$run_dir/ready" ]]
podman run --rm --name "$client_name" --network "$network" \
    -v "$tcp_bin:/usr/local/bin/tun_tcp_bench:ro" "$image" \
    /usr/local/bin/tun_tcp_bench client --connect 10.252.0.2:41000 --bytes 1073741824
