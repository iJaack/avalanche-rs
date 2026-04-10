#!/bin/bash
# Production benchmark: avalanche-rs vs AvalancheGo
# Runs each node from empty Fuji state for a fixed duration and records:
# - first peer handshake time
# - final RSS and peak RSS
# - final P-Chain / C-Chain heights and peer count
# - common RPC latency slice
set -euo pipefail

AVALANCHE_RS="${AVALANCHE_RS:-./target/release/avalanche-rs}"
AVALANCHE_GO_VERSION="${AVALANCHE_GO_VERSION:-v1.14.2}"
AVALANCHE_GO_ARCHIVE="${AVALANCHE_GO_ARCHIVE:-/tmp/avalanchego-macos-${AVALANCHE_GO_VERSION}.zip}"
AVALANCHE_GO_DIR="${AVALANCHE_GO_DIR:-/tmp/avalanchego-${AVALANCHE_GO_VERSION}}"
AVALANCHE_GO="${AVALANCHE_GO:-}"
BOOTSTRAP_IP="${BOOTSTRAP_IP:-52.29.72.46:9651}"
BOOTSTRAP_ID="${BOOTSTRAP_ID:-NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg}"
DURATION="${DURATION:-300}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-30}"
RESULT_MAX_TIME="${RESULT_MAX_TIME:-3}"
LATENCY_MAX_TIME="${LATENCY_MAX_TIME:-2}"
LATENCY_SAMPLES="${LATENCY_SAMPLES:-3}"
RESULTS_FILE="${RESULTS_FILE:-./docs/benchmarks/$(date -u +%Y-%m-%d)-fuji-${DURATION}s.md}"
RAW_DIR="${RAW_DIR:-./docs/benchmarks/raw}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
EXISTING_RS_ENV_FILE="${EXISTING_RS_ENV_FILE:-}"
EXISTING_GO_ENV_FILE="${EXISTING_GO_ENV_FILE:-}"

mkdir -p "$(dirname "$RESULTS_FILE")" "$RAW_DIR"

require_bin() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required binary: $1" >&2
    exit 1
  fi
}

require_bin curl
require_bin jq
require_bin unzip

if [ ! -x "$AVALANCHE_RS" ]; then
  echo "missing avalanche-rs binary at $AVALANCHE_RS" >&2
  exit 1
fi

download_avalanchego() {
  if [ -n "$AVALANCHE_GO" ] && [ -x "$AVALANCHE_GO" ]; then
    return
  fi

  local asset_url
  asset_url="https://github.com/ava-labs/avalanchego/releases/download/${AVALANCHE_GO_VERSION}/avalanchego-macos-${AVALANCHE_GO_VERSION}.zip"

  if [ ! -f "$AVALANCHE_GO_ARCHIVE" ]; then
    echo "Downloading AvalancheGo ${AVALANCHE_GO_VERSION}..."
    curl -L --fail --silent --show-error -o "$AVALANCHE_GO_ARCHIVE" "$asset_url"
  fi

  rm -rf "$AVALANCHE_GO_DIR"
  mkdir -p "$AVALANCHE_GO_DIR"
  unzip -q -o "$AVALANCHE_GO_ARCHIVE" -d "$AVALANCHE_GO_DIR"

  AVALANCHE_GO="$(find "$AVALANCHE_GO_DIR" -type f -name avalanchego | head -1)"
  if [ -z "$AVALANCHE_GO" ] || [ ! -x "$AVALANCHE_GO" ]; then
    echo "failed to locate avalanchego binary under $AVALANCHE_GO_DIR" >&2
    exit 1
  fi
}

wait_for_log_pattern() {
  local file="$1"
  local pattern="$2"
  local timeout_secs="$3"
  local start_ns="$4"
  local deadline
  deadline=$((SECONDS + timeout_secs))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if grep -qE "$pattern" "$file" 2>/dev/null; then
      local now_ns
      now_ns="$(date +%s%N)"
      echo $(((now_ns - start_ns) / 1000000))
      return 0
    fi
    sleep 0.1
  done
  echo "NA"
}

wait_for_http() {
  local url="$1"
  local timeout_secs="$2"
  local deadline
  deadline=$((SECONDS + timeout_secs))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if curl -s --max-time 2 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

start_rss_sampler() {
  local pid="$1"
  local outfile="$2"
  local duration="$3"
  local interval="$4"
  (
    local elapsed=0
    while [ "$elapsed" -le "$duration" ]; do
      if ps -p "$pid" >/dev/null 2>&1; then
        local rss
        rss="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo 0)"
        echo "${elapsed},${rss:-0}" >> "$outfile"
      else
        break
      fi
      sleep "$interval"
      elapsed=$((elapsed + interval))
    done
  ) &
  echo $!
}

jsonrpc_time_ms() {
  local url="$1"
  local payload="$2"
  local total=0
  local samples=0
  local i
  i=1
  while [ "$i" -le "$LATENCY_SAMPLES" ]; do
    local seconds
    seconds="$(curl -s --connect-timeout 1 --max-time "$LATENCY_MAX_TIME" -o /tmp/bench-rpc-body.$$ -w '%{time_total}' \
      -H 'content-type: application/json' \
      --data "$payload" "$url" || true)"
    if [ -s /tmp/bench-rpc-body.$$ ]; then
      total="$(awk -v a="$total" -v b="$seconds" 'BEGIN { printf "%.6f", a + b }')"
      samples=$((samples + 1))
    fi
    i=$((i + 1))
  done
  rm -f /tmp/bench-rpc-body.$$
  if [ "$samples" -eq 0 ]; then
    echo "NA"
  else
    awk -v total="$total" -v samples="$samples" 'BEGIN { printf "%.1f", (total / samples) * 1000 }'
  fi
}

jsonrpc_result() {
  local url="$1"
  local payload="$2"
  curl -s --connect-timeout 1 --max-time "$RESULT_MAX_TIME" -H 'content-type: application/json' --data "$payload" "$url" || true
}

http_time_ms() {
  local url="$1"
  local total=0
  local samples=0
  local i
  i=1
  while [ "$i" -le "$LATENCY_SAMPLES" ]; do
    local seconds
    seconds="$(curl -s --connect-timeout 1 --max-time "$LATENCY_MAX_TIME" -o /tmp/bench-http-body.$$ -w '%{time_total}' "$url" || true)"
    if [ -s /tmp/bench-http-body.$$ ]; then
      total="$(awk -v a="$total" -v b="$seconds" 'BEGIN { printf "%.6f", a + b }')"
      samples=$((samples + 1))
    fi
    i=$((i + 1))
  done
  rm -f /tmp/bench-http-body.$$
  if [ "$samples" -eq 0 ]; then
    echo "NA"
  else
    awk -v total="$total" -v samples="$samples" 'BEGIN { printf "%.1f", (total / samples) * 1000 }'
  fi
}

sleep_remaining_from_start() {
  local start_ns="$1"
  local duration_secs="$2"
  local now_ns
  now_ns="$(date +%s%N)"
  local elapsed_ns=$((now_ns - start_ns))
  local target_ns=$((duration_secs * 1000000000))
  if [ "$elapsed_ns" -lt "$target_ns" ]; then
    local remaining_ns=$((target_ns - elapsed_ns))
    awk -v ns="$remaining_ns" 'BEGIN { printf "%.3f", ns / 1000000000 }' | {
      read -r sleep_secs
      sleep "$sleep_secs"
    }
  fi
}

json_field() {
  local input="$1"
  local filter="$2"
  if [ -z "$input" ]; then
    echo "null"
    return
  fi
  printf '%s' "$input" | jq -r "$filter" 2>/dev/null || echo "null"
}

extract_peak_rss_kb() {
  local sample_file="$1"
  if [ ! -s "$sample_file" ]; then
    echo "0"
    return
  fi
  awk -F, 'NR > 1 { if ($2 + 0 > peak) peak = $2 + 0 } END { print peak + 0 }' "$sample_file"
}

run_avalanche_rs() {
  local env_file="$1"
  local log_file="$RAW_DIR/${RUN_ID}-avalanche-rs.log"
  local sample_file="$RAW_DIR/${RUN_ID}-avalanche-rs-rss.csv"
  local http_port=29650
  local staking_port=29651

  rm -rf /tmp/bench-rs
  : > "$sample_file"
  echo "elapsed_seconds,rss_kb" > "$sample_file"

  RUST_LOG=info "$AVALANCHE_RS" \
    --network-id 5 \
    --data-dir /tmp/bench-rs \
    --bootstrap-ips "$BOOTSTRAP_IP" \
    --staking-port "$staking_port" \
    --http-port "$http_port" \
    > "$log_file" 2>&1 &
  local pid=$!
  local start_ns
  start_ns="$(date +%s%N)"
  local sampler_pid
  sampler_pid="$(start_rss_sampler "$pid" "$sample_file" "$DURATION" "$SAMPLE_INTERVAL")"

  local handshake_ms
  handshake_ms="$(wait_for_log_pattern "$log_file" "Handshake complete|TLS handshake complete" 60 "$start_ns")"
  wait_for_http "http://127.0.0.1:${http_port}/ext/health" 120 || true

  sleep_remaining_from_start "$start_ns" "$DURATION"

  local c_url="http://127.0.0.1:${http_port}/ext/bc/C/rpc"
  local p_url="http://127.0.0.1:${http_port}/ext/bc/P"
  local info_url="http://127.0.0.1:${http_port}/ext/info"
  local health_url="http://127.0.0.1:${http_port}/ext/health"
  local metrics_url="http://127.0.0.1:${http_port}/metrics"

  local block_number_json
  block_number_json="$(jsonrpc_result "$c_url" '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}')"
  local chain_id_json
  chain_id_json="$(jsonrpc_result "$c_url" '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":2}')"
  local gas_price_json
  gas_price_json="$(jsonrpc_result "$c_url" '{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":3}')"
  local p_height_json
  p_height_json="$(jsonrpc_result "$p_url" '{"jsonrpc":"2.0","method":"platform.getHeight","params":{},"id":4}')"
  local peers_json
  peers_json="$(jsonrpc_result "$info_url" '{"jsonrpc":"2.0","method":"info.peers","params":{},"id":5}')"
  local bootstrapped_json
  bootstrapped_json="$(jsonrpc_result "$info_url" '{"jsonrpc":"2.0","method":"info.isBootstrapped","params":{"chain":"P"},"id":6}')"
  local health_json
  health_json="$(curl -s --connect-timeout 1 --max-time "$RESULT_MAX_TIME" "$health_url" || true)"

  local final_rss
  final_rss="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo 0)"
  local peak_rss
  peak_rss="$(extract_peak_rss_kb "$sample_file")"

  local eth_block_number
  eth_block_number="$(json_field "$block_number_json" '.result // "null"')"
  local eth_chain_id
  eth_chain_id="$(json_field "$chain_id_json" '.result // "null"')"
  local eth_gas_price
  eth_gas_price="$(json_field "$gas_price_json" '.result // "null"')"
  local p_height
  p_height="$(json_field "$p_height_json" '.result.height // .height // .result // "null"')"
  local peer_count
  peer_count="$(json_field "$peers_json" '((.result.peers // .peers // []) | length) // 0')"
  local bootstrapped
  bootstrapped="$(json_field "$bootstrapped_json" 'if (.result | type == "object") and (.result | has("isBootstrapped")) then .result.isBootstrapped elif has("isBootstrapped") then .isBootstrapped elif has("result") then .result else "null" end')"
  local healthy
  healthy="$(json_field "$health_json" 'if has("healthy") then .healthy elif (.result | type == "object") and (.result | has("healthy")) then .result.healthy else "null" end')"

  local eth_block_ms
  eth_block_ms="$(jsonrpc_time_ms "$c_url" '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":11}')"
  local eth_chain_ms
  eth_chain_ms="$(jsonrpc_time_ms "$c_url" '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":12}')"
  local eth_gas_ms
  eth_gas_ms="$(jsonrpc_time_ms "$c_url" '{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":13}')"
  local p_height_ms
  p_height_ms="$(jsonrpc_time_ms "$p_url" '{"jsonrpc":"2.0","method":"platform.getHeight","params":{},"id":14}')"
  local health_ms
  health_ms="$(http_time_ms "$health_url")"
  local metrics_ms
  metrics_ms="$(http_time_ms "$metrics_url")"

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  wait "$sampler_pid" 2>/dev/null || true

  cat > "$env_file" <<EOF
NAME=avalanche-rs
VERSION=$(git rev-parse --short HEAD)
HANDSHAKE_MS=$handshake_ms
FINAL_RSS_KB=$final_rss
PEAK_RSS_KB=$peak_rss
P_HEIGHT=$p_height
C_HEIGHT=$eth_block_number
PEER_COUNT=$peer_count
BOOTSTRAPPED=$bootstrapped
HEALTHY=$healthy
ETH_CHAIN_ID=$eth_chain_id
ETH_GAS_PRICE=$eth_gas_price
LAT_ETH_BLOCK_MS=$eth_block_ms
LAT_ETH_CHAIN_MS=$eth_chain_ms
LAT_ETH_GAS_MS=$eth_gas_ms
LAT_P_HEIGHT_MS=$p_height_ms
LAT_HEALTH_MS=$health_ms
LAT_METRICS_MS=$metrics_ms
LOG_FILE=$log_file
RSS_FILE=$sample_file
BIN_KB=$(du -k "$AVALANCHE_RS" | cut -f1)
EOF
}

run_avalanchego() {
  local env_file="$1"
  local log_file="$RAW_DIR/${RUN_ID}-avalanchego.log"
  local sample_file="$RAW_DIR/${RUN_ID}-avalanchego-rss.csv"
  local http_port=29660
  local staking_port=29661

  rm -rf /tmp/bench-go
  mkdir -p /tmp/bench-go
  : > "$sample_file"
  echo "elapsed_seconds,rss_kb" > "$sample_file"

  "$AVALANCHE_GO" \
    --network-id=fuji \
    --data-dir=/tmp/bench-go \
    --staking-port="$staking_port" \
    --http-port="$http_port" \
    --log-level=info \
    --bootstrap-ips="$BOOTSTRAP_IP" \
    --bootstrap-ids="$BOOTSTRAP_ID" \
    > "$log_file" 2>&1 &
  local pid=$!
  local start_ns
  start_ns="$(date +%s%N)"
  local sampler_pid
  sampler_pid="$(start_rss_sampler "$pid" "$sample_file" "$DURATION" "$SAMPLE_INTERVAL")"

  local handshake_ms
  handshake_ms="$(wait_for_log_pattern "$log_file" "connected to|handshake" 120 "$start_ns")"
  wait_for_http "http://127.0.0.1:${http_port}/ext/health" 180 || true

  sleep_remaining_from_start "$start_ns" "$DURATION"

  local c_url="http://127.0.0.1:${http_port}/ext/bc/C/rpc"
  local p_url="http://127.0.0.1:${http_port}/ext/bc/P"
  local info_url="http://127.0.0.1:${http_port}/ext/info"
  local health_url="http://127.0.0.1:${http_port}/ext/health"
  local metrics_url="http://127.0.0.1:${http_port}/ext/metrics"
  if ! curl -s --max-time 3 "$metrics_url" >/dev/null 2>&1; then
    metrics_url="http://127.0.0.1:${http_port}/metrics"
  fi

  local block_number_json
  block_number_json="$(jsonrpc_result "$c_url" '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}')"
  local chain_id_json
  chain_id_json="$(jsonrpc_result "$c_url" '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":2}')"
  local gas_price_json
  gas_price_json="$(jsonrpc_result "$c_url" '{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":3}')"
  local p_height_json
  p_height_json="$(jsonrpc_result "$p_url" '{"jsonrpc":"2.0","method":"platform.getHeight","params":{},"id":4}')"
  local peers_json
  peers_json="$(jsonrpc_result "$info_url" '{"jsonrpc":"2.0","method":"info.peers","params":{},"id":5}')"
  local bootstrapped_json
  bootstrapped_json="$(jsonrpc_result "$info_url" '{"jsonrpc":"2.0","method":"info.isBootstrapped","params":{"chain":"P"},"id":6}')"
  local health_json
  health_json="$(curl -s --connect-timeout 1 --max-time "$RESULT_MAX_TIME" "$health_url" || true)"

  local final_rss
  final_rss="$(ps -o rss= -p "$pid" 2>/dev/null | tr -d ' ' || echo 0)"
  local peak_rss
  peak_rss="$(extract_peak_rss_kb "$sample_file")"

  local eth_block_number
  eth_block_number="$(json_field "$block_number_json" '.result // "null"')"
  local eth_chain_id
  eth_chain_id="$(json_field "$chain_id_json" '.result // "null"')"
  local eth_gas_price
  eth_gas_price="$(json_field "$gas_price_json" '.result // "null"')"
  local p_height
  p_height="$(json_field "$p_height_json" '.result.height // .height // .result // "null"')"
  local peer_count
  peer_count="$(json_field "$peers_json" '((.result.peers // .peers // []) | length) // 0')"
  local bootstrapped
  bootstrapped="$(json_field "$bootstrapped_json" 'if (.result | type == "object") and (.result | has("isBootstrapped")) then .result.isBootstrapped elif has("isBootstrapped") then .isBootstrapped elif has("result") then .result else "null" end')"
  local healthy
  healthy="$(json_field "$health_json" 'if has("healthy") then .healthy elif (.result | type == "object") and (.result | has("healthy")) then .result.healthy else "null" end')"

  local eth_block_ms
  eth_block_ms="$(jsonrpc_time_ms "$c_url" '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":11}')"
  local eth_chain_ms
  eth_chain_ms="$(jsonrpc_time_ms "$c_url" '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":12}')"
  local eth_gas_ms
  eth_gas_ms="$(jsonrpc_time_ms "$c_url" '{"jsonrpc":"2.0","method":"eth_gasPrice","params":[],"id":13}')"
  local p_height_ms
  p_height_ms="$(jsonrpc_time_ms "$p_url" '{"jsonrpc":"2.0","method":"platform.getHeight","params":{},"id":14}')"
  local health_ms
  health_ms="$(http_time_ms "$health_url")"
  local metrics_ms
  metrics_ms="$(http_time_ms "$metrics_url")"

  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  wait "$sampler_pid" 2>/dev/null || true

  cat > "$env_file" <<EOF
NAME=avalanchego
VERSION=$AVALANCHE_GO_VERSION
HANDSHAKE_MS=$handshake_ms
FINAL_RSS_KB=$final_rss
PEAK_RSS_KB=$peak_rss
P_HEIGHT=$p_height
C_HEIGHT=$eth_block_number
PEER_COUNT=$peer_count
BOOTSTRAPPED=$bootstrapped
HEALTHY=$healthy
ETH_CHAIN_ID=$eth_chain_id
ETH_GAS_PRICE=$eth_gas_price
LAT_ETH_BLOCK_MS=$eth_block_ms
LAT_ETH_CHAIN_MS=$eth_chain_ms
LAT_ETH_GAS_MS=$eth_gas_ms
LAT_P_HEIGHT_MS=$p_height_ms
LAT_HEALTH_MS=$health_ms
LAT_METRICS_MS=$metrics_ms
LOG_FILE=$log_file
RSS_FILE=$sample_file
BIN_KB=$(du -k "$AVALANCHE_GO" | cut -f1)
EOF
}

emit_markdown() {
  local rs_env="$1"
  local go_env="$2"
  eval "$rs_env"
  local rs_name="$NAME"
  local rs_version="$VERSION"
  local rs_handshake="$HANDSHAKE_MS"
  local rs_final_rss="$FINAL_RSS_KB"
  local rs_peak_rss="$PEAK_RSS_KB"
  local rs_p_height="$P_HEIGHT"
  local rs_c_height="$C_HEIGHT"
  local rs_peer_count="$PEER_COUNT"
  local rs_bootstrapped="$BOOTSTRAPPED"
  local rs_healthy="$HEALTHY"
  local rs_chain_id="$ETH_CHAIN_ID"
  local rs_gas_price="$ETH_GAS_PRICE"
  local rs_eth_block_ms="$LAT_ETH_BLOCK_MS"
  local rs_eth_chain_ms="$LAT_ETH_CHAIN_MS"
  local rs_eth_gas_ms="$LAT_ETH_GAS_MS"
  local rs_p_height_ms="$LAT_P_HEIGHT_MS"
  local rs_health_ms="$LAT_HEALTH_MS"
  local rs_metrics_ms="$LAT_METRICS_MS"
  local rs_log="$LOG_FILE"
  local rs_rss="$RSS_FILE"
  local rs_bin_kb="$BIN_KB"

  eval "$go_env"
  local go_name="$NAME"
  local go_version="$VERSION"
  local go_handshake="$HANDSHAKE_MS"
  local go_final_rss="$FINAL_RSS_KB"
  local go_peak_rss="$PEAK_RSS_KB"
  local go_p_height="$P_HEIGHT"
  local go_c_height="$C_HEIGHT"
  local go_peer_count="$PEER_COUNT"
  local go_bootstrapped="$BOOTSTRAPPED"
  local go_healthy="$HEALTHY"
  local go_chain_id="$ETH_CHAIN_ID"
  local go_gas_price="$ETH_GAS_PRICE"
  local go_eth_block_ms="$LAT_ETH_BLOCK_MS"
  local go_eth_chain_ms="$LAT_ETH_CHAIN_MS"
  local go_eth_gas_ms="$LAT_ETH_GAS_MS"
  local go_p_height_ms="$LAT_P_HEIGHT_MS"
  local go_health_ms="$LAT_HEALTH_MS"
  local go_metrics_ms="$LAT_METRICS_MS"
  local go_log="$LOG_FILE"
  local go_rss="$RSS_FILE"
  local go_bin_kb="$BIN_KB"

  cat > "$RESULTS_FILE" <<EOF
# Benchmark: avalanche-rs vs AvalancheGo ${go_version}

- Date (UTC): $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Network: Fuji testnet
- Duration: ${DURATION}s per implementation
- Hardware: $(uname -sm)
- Bootstrap IP: ${BOOTSTRAP_IP}
- Bootstrap ID: ${BOOTSTRAP_ID}
- avalanche-rs commit: ${rs_version}
- AvalancheGo version: ${go_version}

## Cold Start Sync

| Metric | avalanche-rs | AvalancheGo ${go_version} |
|--------|-------------|---------------------------|
| Binary size | ${rs_bin_kb} KB | ${go_bin_kb} KB |
| First peer handshake | ${rs_handshake} ms | ${go_handshake} ms |
| Final RSS | ${rs_final_rss} KB | ${go_final_rss} KB |
| Peak RSS | ${rs_peak_rss} KB | ${go_peak_rss} KB |
| P-Chain height | ${rs_p_height} | ${go_p_height} |
| C-Chain block number | ${rs_c_height} | ${go_c_height} |
| Peer count (\`info.peers\`) | ${rs_peer_count} | ${go_peer_count} |
| P-Chain bootstrapped | ${rs_bootstrapped} | ${go_bootstrapped} |
| Health endpoint healthy | ${rs_healthy} | ${go_healthy} |

## Shared RPC Latency Slice

Average of ${LATENCY_SAMPLES} requests after the 5-minute run.

| Endpoint | avalanche-rs | AvalancheGo ${go_version} |
|----------|-------------|---------------------------|
| \`eth_blockNumber\` | ${rs_eth_block_ms} ms | ${go_eth_block_ms} ms |
| \`eth_chainId\` | ${rs_eth_chain_ms} ms | ${go_eth_chain_ms} ms |
| \`eth_gasPrice\` | ${rs_eth_gas_ms} ms | ${go_eth_gas_ms} ms |
| \`platform.getHeight\` | ${rs_p_height_ms} ms | ${go_p_height_ms} ms |
| \`GET /ext/health\` | ${rs_health_ms} ms | ${go_health_ms} ms |
| \`GET /metrics\` | ${rs_metrics_ms} ms | ${go_metrics_ms} ms |

## Shared RPC Values At End Of Run

| Value | avalanche-rs | AvalancheGo ${go_version} |
|-------|-------------|---------------------------|
| \`eth_chainId\` | ${rs_chain_id} | ${go_chain_id} |
| \`eth_gasPrice\` | ${rs_gas_price} | ${go_gas_price} |

## Raw Artifacts

- avalanche-rs log: \`${rs_log}\`
- avalanche-rs RSS samples: \`${rs_rss}\`
- AvalancheGo log: \`${go_log}\`
- AvalancheGo RSS samples: \`${go_rss}\`

## Scope Notes

- This benchmark is a real 5-minute cold-start comparison against the shared Fuji production surface.
- It measures sync progress, resource usage, health, and a shared RPC slice. It does not attempt to benchmark every non-overlapping feature family one-by-one inside the same 5-minute window.
- Both runs start from empty local state and are executed sequentially on the same host.
EOF
}

download_avalanchego

RS_ENV_FILE="$RAW_DIR/${RUN_ID}-avalanche-rs.env"
GO_ENV_FILE="$RAW_DIR/${RUN_ID}-avalanchego.env"
if [ -n "$EXISTING_RS_ENV_FILE" ] && [ -f "$EXISTING_RS_ENV_FILE" ]; then
  RS_ENV="$(cat "$EXISTING_RS_ENV_FILE")"
else
  run_avalanche_rs "$RS_ENV_FILE"
  RS_ENV="$(cat "$RS_ENV_FILE")"
fi
if [ -n "$EXISTING_GO_ENV_FILE" ] && [ -f "$EXISTING_GO_ENV_FILE" ]; then
  GO_ENV="$(cat "$EXISTING_GO_ENV_FILE")"
else
  run_avalanchego "$GO_ENV_FILE"
  GO_ENV="$(cat "$GO_ENV_FILE")"
fi
emit_markdown "$RS_ENV" "$GO_ENV"

echo "Saved benchmark results to $RESULTS_FILE"
cat "$RESULTS_FILE"
