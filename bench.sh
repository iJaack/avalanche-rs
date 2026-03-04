#!/bin/bash
# Benchmark: avalanche-rs vs AvalancheGo
# Measures: startup time, handshake time, bootstrap time, blocks synced, memory usage
set -e

AVALANCHE_RS="./target/release/avalanche-rs"
AVALANCHE_GO="/tmp/avalanchego"
BOOTSTRAP_IP="52.29.72.46:9651"
DURATION=60  # seconds per test
RESULTS_FILE="/tmp/bench-results-$(date +%s).md"

echo "# Benchmark: avalanche-rs vs AvalancheGo" > "$RESULTS_FILE"
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# --- Test 1: avalanche-rs ---
echo "=== Testing avalanche-rs ==="
rm -rf /tmp/bench-rs
RUST_LOG=info $AVALANCHE_RS \
  --network-id 5 --data-dir /tmp/bench-rs \
  --bootstrap-ips "$BOOTSTRAP_IP" \
  --staking-port 29651 --http-port 29650 > /tmp/bench-rs.log 2>&1 &
RS_PID=$!
RS_START=$(date +%s%N)

# Wait for first peer connection
for i in $(seq 1 60); do
  if grep -q "Handshake complete" /tmp/bench-rs.log 2>/dev/null; then
    RS_HANDSHAKE=$(date +%s%N)
    break
  fi
  sleep 0.1
done

# Wait for bootstrap complete
for i in $(seq 1 600); do
  if grep -q "Bootstrap P-Chain complete" /tmp/bench-rs.log 2>/dev/null; then
    RS_BOOTSTRAP=$(date +%s%N)
    break
  fi
  sleep 0.1
done

sleep $DURATION
RS_MEM=$(ps -o rss= -p $RS_PID 2>/dev/null || echo 0)
RS_BLOCKS=$(grep "total blocks stored" /tmp/bench-rs.log | tail -1 | grep -oE '[0-9]+ total' | head -1 | cut -d' ' -f1)
RS_PEERS=$(grep "TLS handshake complete" /tmp/bench-rs.log | wc -l | tr -d ' ')
RS_CHAIN_LEN=$(grep "blocks linked from tip" /tmp/bench-rs.log | tail -1 | grep -oE '[0-9]+ blocks' | head -1 | cut -d' ' -f1)
kill $RS_PID 2>/dev/null; wait $RS_PID 2>/dev/null

RS_HANDSHAKE_MS=$(( (${RS_HANDSHAKE:-$RS_START} - RS_START) / 1000000 ))
RS_BOOTSTRAP_MS=$(( (${RS_BOOTSTRAP:-$RS_START} - RS_START) / 1000000 ))

echo "avalanche-rs: handshake=${RS_HANDSHAKE_MS}ms, bootstrap=${RS_BOOTSTRAP_MS}ms, blocks=${RS_BLOCKS:-0}, peers=${RS_PEERS}, chain=${RS_CHAIN_LEN:-0}, mem=${RS_MEM}KB"

# --- Test 2: AvalancheGo ---
echo "=== Testing AvalancheGo ==="
rm -rf /tmp/bench-go
mkdir -p /tmp/bench-go

$AVALANCHE_GO --network-id=fuji \
  --data-dir=/tmp/bench-go \
  --staking-port=29661 --http-port=29660 \
  --log-level=info \
  --staking-enabled=false \
  --bootstrap-ips="$BOOTSTRAP_IP" \
  --bootstrap-ids="NodeID-7Xhw2mDxuDS44j42TCB6U5579esbSt3Lg" > /tmp/bench-go.log 2>&1 &
GO_PID=$!
GO_START=$(date +%s%N)

# Wait for first peer connection
for i in $(seq 1 120); do
  if grep -qE "connected to|handshake" /tmp/bench-go.log 2>/dev/null; then
    GO_HANDSHAKE=$(date +%s%N)
    break
  fi
  sleep 0.1
done

# Wait for bootstrap indication
for i in $(seq 1 600); do
  if grep -qiE "bootstrapp|accepted frontier" /tmp/bench-go.log 2>/dev/null; then
    GO_BOOTSTRAP=$(date +%s%N)
    break
  fi
  sleep 0.1
done

sleep $DURATION
GO_MEM=$(ps -o rss= -p $GO_PID 2>/dev/null || echo 0)
kill $GO_PID 2>/dev/null; wait $GO_PID 2>/dev/null

GO_HANDSHAKE_MS=$(( (${GO_HANDSHAKE:-$GO_START} - GO_START) / 1000000 ))
GO_BOOTSTRAP_MS=$(( (${GO_BOOTSTRAP:-$GO_START} - GO_START) / 1000000 ))

echo "AvalancheGo: handshake=${GO_HANDSHAKE_MS}ms, bootstrap=${GO_BOOTSTRAP_MS}ms, mem=${GO_MEM}KB"

# --- Results ---
cat >> "$RESULTS_FILE" << RESULTS
| Metric | avalanche-rs | AvalancheGo |
|--------|-------------|-------------|
| Handshake time | ${RS_HANDSHAKE_MS}ms | ${GO_HANDSHAKE_MS}ms |
| Bootstrap time | ${RS_BOOTSTRAP_MS}ms | ${GO_BOOTSTRAP_MS}ms |
| P-Chain blocks | ${RS_BLOCKS:-0} | N/A (full sync) |
| Peers connected | ${RS_PEERS} | N/A |
| Chain walk length | ${RS_CHAIN_LEN:-0} | N/A |
| Memory (RSS) | ${RS_MEM}KB | ${GO_MEM}KB |
| Binary size | $(du -k "$AVALANCHE_RS" | cut -f1)KB | $(du -k "$AVALANCHE_GO" | cut -f1)KB |
RESULTS

echo ""
echo "=== Results saved to $RESULTS_FILE ==="
cat "$RESULTS_FILE"
