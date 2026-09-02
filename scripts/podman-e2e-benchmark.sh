#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/vela-e2e.XXXXXX")
network="vela-e2e-${PPID}"
image="docker.io/library/debian:bookworm-slim"
build_profile="${BUILD_PROFILE:-debug}"
case "$build_profile" in
    debug)
        build_args=()
        target_dir="$repo_dir/target/debug"
        ;;
    release)
        build_args=(--release)
        target_dir="$repo_dir/target/release"
        ;;
    *)
        echo "BUILD_PROFILE must be debug or release" >&2
        exit 2
        ;;
esac
bench_bin="$target_dir/examples/e2e_bench"
server_name="${network}-server"
peer_a_name="${network}-peer-a"
peer_b_name="${network}-peer-b"

cleanup() {
    podman rm -f "$peer_a_name" "$peer_b_name" "$server_name" >/dev/null 2>&1 || true
    podman network rm "$network" >/dev/null 2>&1 || true
    rm -rf "$run_dir"
}
trap cleanup EXIT

cargo build "${build_args[@]}" -p vela-core --example e2e_bench
podman network create --subnet 10.253.0.0/24 --gateway 10.253.0.1 "$network" >/dev/null

podman run -d --name "$server_name" --network "$network" --ip 10.253.0.2 \
    -v "$run_dir:/bench" -v "$bench_bin:/usr/local/bin/vela-e2e:ro" "$image" \
    /usr/local/bin/vela-e2e server --run-dir /bench --bind 0.0.0.0:7000 >/dev/null

for _ in $(seq 1 100); do
    [[ -s "$run_dir/server.info" ]] && break
    sleep 0.1
done
[[ -s "$run_dir/server.info" ]]

podman run --rm --name "$peer_b_name" --network "$network" --ip 10.253.0.4 \
    -e RUST_LOG="${RUST_LOG:-info}" \
    -v "$run_dir:/bench" -v "$bench_bin:/usr/local/bin/vela-e2e:ro" "$image" \
    /usr/local/bin/vela-e2e peer --run-dir /bench --name b --role receiver \
    --server ws://10.253.0.2:7000/ws --advertise-ip 10.253.0.4 >"$run_dir/peer-b.log" 2>&1 &
peer_b_pid=$!

podman run --rm --name "$peer_a_name" --network "$network" --ip 10.253.0.3 \
    -e RUST_LOG="${RUST_LOG:-info}" \
    -v "$run_dir:/bench" -v "$bench_bin:/usr/local/bin/vela-e2e:ro" "$image" \
    /usr/local/bin/vela-e2e peer --run-dir /bench --name a --role sender \
    --server ws://10.253.0.2:7000/ws --advertise-ip 10.253.0.3 >"$run_dir/peer-a.log" 2>&1 &
peer_a_pid=$!

set +e
wait "$peer_a_pid"
peer_a_status=$?
wait "$peer_b_pid"
peer_b_status=$?
set -e
if [[ "$peer_a_status" -ne 0 || "$peer_b_status" -ne 0 ]]; then
    echo "peer benchmark failed: sender=$peer_a_status receiver=$peer_b_status" >&2
    rg 'connect_error|received Noise|rejecting Noise|established|invalid handshake|received UDP datagram|sent Vela UDP packet' \
        "$run_dir/peer-a.log" "$run_dir/peer-b.log" >&2 || true
    exit 1
fi
cat "$run_dir/a.result"
cat "$run_dir/b.result"
