#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/vela-tun-e2e.XXXXXX")
network="vela-tun-e2e-$$"
image="docker.io/library/debian:bookworm-slim"
coord_bin="$repo_dir/target/release/examples/e2e_bench"
cli_bin="$repo_dir/target/release/vela-cli"
tcp_bin="$repo_dir/target/release/examples/tun_tcp_bench"
bench_bytes="${BENCH_BYTES:-1073741824}"
server_name="${network}-server"
peer_a_name="${network}-peer-a"
peer_b_name="${network}-peer-b"
file_path="$run_dir/download.bin"

cleanup() {
    podman rm -f "$peer_a_name" "$peer_b_name" "$server_name" >/dev/null 2>&1 || true
    podman network rm "$network" >/dev/null 2>&1 || true
    rm -rf "$run_dir"
}
trap cleanup EXIT

if [[ ! "$bench_bytes" =~ ^[0-9]+$ || "$bench_bytes" -eq 0 ]]; then
    echo "BENCH_BYTES must be a positive integer" >&2
    exit 2
fi

refresh_peer_logs() {
    podman logs "$peer_a_name" >"$run_dir/peer-a.log" 2>&1 || true
    podman logs "$peer_b_name" >"$run_dir/peer-b.log" 2>&1 || true
}

cargo build --release \
    -p vela-core --example e2e_bench \
    -p vela-cli --bin vela-cli \
    -p vela-cli --example tun_tcp_bench
fallocate -l "$bench_bytes" "$file_path"

podman network create --subnet 10.253.0.0/24 --gateway 10.253.0.1 "$network" >/dev/null

podman run -d --name "$server_name" --network "$network" --ip 10.253.0.2 \
    -v "$run_dir:/bench" -v "$coord_bin:/usr/local/bin/vela-e2e:ro" "$image" \
    /usr/local/bin/vela-e2e server --run-dir /bench --bind 0.0.0.0:7000 >/dev/null

for _ in $(seq 1 100); do
    [[ -s "$run_dir/server.info" ]] && break
    sleep 0.1
done
[[ -s "$run_dir/server.info" ]]

podman run -d --name "$peer_b_name" --network "$network" --ip 10.253.0.4 \
    --device /dev/net/tun --cap-add NET_ADMIN \
    -e RUST_LOG="${RUST_LOG:-info}" \
    -v "$run_dir:/bench" -v "$cli_bin:/usr/local/bin/vela-cli:ro" \
    -v "$tcp_bin:/usr/local/bin/tun_tcp_bench:ro" "$image" \
    sh -c '\
        server_key=$(sed -n "s/^server_key=//p" /bench/server.info) && \
        invite=$(sed -n "s/^invite_b=//p" /bench/server.info) && \
        /usr/local/bin/vela-cli peer register --state /bench/b --server ws://10.253.0.2:7000/ws --server-key "$server_key" --invite "$invite" --port 41000 && \
        exec /usr/local/bin/vela-cli peer up --state /bench/b --tun vela0 --mtu 1200 --bind 0.0.0.0:7001 --port 41000' \
    >/dev/null

podman run -d --name "$peer_a_name" --network "$network" --ip 10.253.0.3 \
    --device /dev/net/tun --cap-add NET_ADMIN \
    -e RUST_LOG="${RUST_LOG:-info}" \
    -v "$run_dir:/bench" -v "$cli_bin:/usr/local/bin/vela-cli:ro" \
    -v "$tcp_bin:/usr/local/bin/tun_tcp_bench:ro" "$image" \
    sh -c '\
        server_key=$(sed -n "s/^server_key=//p" /bench/server.info) && \
        invite=$(sed -n "s/^invite_a=//p" /bench/server.info) && \
        /usr/local/bin/vela-cli peer register --state /bench/a --server ws://10.253.0.2:7000/ws --server-key "$server_key" --invite "$invite" --port 41000 && \
        exec /usr/local/bin/vela-cli peer up --state /bench/a --tun vela0 --mtu 1200 --bind 0.0.0.0:7001 --port 41000' \
    >/dev/null

for _ in $(seq 1 200); do
    refresh_peer_logs
    if rg -q 'up on TUN' "$run_dir/peer-a.log" "$run_dir/peer-b.log" 2>/dev/null; then
        if rg -q 'up on TUN' "$run_dir/peer-a.log" && rg -q 'up on TUN' "$run_dir/peer-b.log"; then
            break
        fi
    fi
    sleep 0.1
done
refresh_peer_logs
if ! rg -q 'up on TUN' "$run_dir/peer-a.log" || ! rg -q 'up on TUN' "$run_dir/peer-b.log"; then
    echo "TUN peers failed to become ready" >&2
    echo "--- peer-a ---" >&2
    sed -n '1,160p' "$run_dir/peer-a.log" "$run_dir/peer-b.log" >&2 || true
    echo "--- peer-b ---" >&2
    sed -n '1,160p' "$run_dir/peer-b.log" >&2 || true
    podman inspect "$peer_a_name" "$peer_b_name" \
        --format '{{.Name}} status={{.State.Status}} exit={{.State.ExitCode}} error={{.State.Error}}' >&2 || true
    exit 1
fi

a_id=$($cli_bin identity "$run_dir/a/identity")
b_id=$($cli_bin identity "$run_dir/b/identity")
a_json_id=$(printf '%s' "${a_id#vela:}" | xxd -r -p | base64 -w0)
b_json_id=$(printf '%s' "${b_id#vela:}" | xxd -r -p | base64 -w0)
a_ip=$(jq -r --arg id "$a_json_id" '.snapshot.peers[] | select(.node_id == $id) | .virtual_ipv4' "$run_dir/a/state.json")
b_ip=$(jq -r --arg id "$b_json_id" '.snapshot.peers[] | select(.node_id == $id) | .virtual_ipv4' "$run_dir/b/state.json")
[[ -n "$a_ip" && "$a_ip" != "null" && -n "$b_ip" && "$b_ip" != "null" ]]

podman exec -d "$peer_b_name" /usr/local/bin/tun_tcp_bench server \
    --bind "$b_ip:41000" --file /bench/download.bin --ready /bench/tcp-server.ready >/dev/null
for _ in $(seq 1 100); do
    [[ -s "$run_dir/tcp-server.ready" ]] && break
    sleep 0.1
done
[[ -s "$run_dir/tcp-server.ready" ]]

read_tcp_retransmits() {
    podman exec "$1" awk '
        $1 == "Tcp:" && $2 == "RtoAlgorithm" {
            for (field_index = 1; field_index <= NF; field_index++) {
                if ($field_index == "RetransSegs") {
                    retrans_index = field_index
                }
            }
            next
        }
        $1 == "Tcp:" && retrans_index {
            print $retrans_index
            exit
        }
    ' /proc/net/snmp
}

tcp_retransmits_before=$(read_tcp_retransmits "$peer_a_name")
tcp_retransmits_before_remote=$(read_tcp_retransmits "$peer_b_name")
echo "tun_tcp_benchmark local_ip=$a_ip remote_ip=$b_ip bytes=$bench_bytes"
client_result=$(podman exec "$peer_a_name" /usr/local/bin/tun_tcp_bench client \
    --connect "$b_ip:41000" --bytes "$bench_bytes")
printf '%s\n' "$client_result"
tcp_retransmits_after=$(read_tcp_retransmits "$peer_a_name")
tcp_retransmits_after_remote=$(read_tcp_retransmits "$peer_b_name")
if [[ "$tcp_retransmits_before" =~ ^[0-9]+$ && "$tcp_retransmits_after" =~ ^[0-9]+$ ]]; then
    echo "tcp_retransmits_local=$((tcp_retransmits_after - tcp_retransmits_before))"
fi
if [[ "$tcp_retransmits_before_remote" =~ ^[0-9]+$ && "$tcp_retransmits_after_remote" =~ ^[0-9]+$ ]]; then
    echo "tcp_retransmits_remote=$((tcp_retransmits_after_remote - tcp_retransmits_before_remote))"
fi
