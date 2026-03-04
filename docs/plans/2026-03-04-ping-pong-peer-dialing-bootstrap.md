# Ping/Pong Keepalive + Peer Dialing + Bootstrap Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add proper 30s ping/pong keepalive, dial discovered peers from PeerList, and implement P-Chain bootstrap message exchange.

**Architecture:** Restructure the message loop to use `tokio::select!` with three concurrent arms: a 30s ping interval, a 60s pong timeout, and message reading. Peer dialing spawns `connect_and_handshake` tasks for up to 10 new peers tracked in a shared `HashSet`. Bootstrap follows the 5-step AvalancheGo protocol: GetAcceptedFrontier → AcceptedFrontier → GetAccepted → Accepted → GetAncestors → Ancestors. Add `GetAncestors` and `Ancestors` variants to `NetworkMessage` + proto mapping to replace the current aliases through `Get`/`Put`.

**Tech Stack:** Rust, tokio, prost, existing `NetworkMessage` enum, `PeerManager`, `connect_and_handshake`

---

### Task 1: Add `GetAncestors` and `Ancestors` NetworkMessage variants

**Files:**
- Modify: `src/network/mod.rs` (around line 162 — after `Accepted`)
- Modify: `src/proto/mod.rs` (around line 497 — `GetAncestors`/`Ancestors` proto mappings)

**Step 1: Write the failing tests**

Add these tests to `src/network/mod.rs` test block (which is near the end of the file):

```rust
#[test]
fn test_get_ancestors_roundtrip() {
    use crate::network::{ChainId, BlockId, NetworkMessage};
    let msg = NetworkMessage::GetAncestors {
        chain_id: ChainId([0xBB; 32]),
        request_id: 7,
        deadline: 5_000_000_000,
        container_id: BlockId([0xCC; 32]),
        max_containers_size: 2_000_000,
    };
    let encoded = msg.encode_proto().unwrap();
    let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
    match decoded {
        NetworkMessage::GetAncestors { request_id, max_containers_size, .. } => {
            assert_eq!(request_id, 7);
            assert_eq!(max_containers_size, 2_000_000);
        }
        other => panic!("expected GetAncestors, got {:?}", other.name()),
    }
}

#[test]
fn test_ancestors_roundtrip() {
    use crate::network::{ChainId, NetworkMessage};
    let msg = NetworkMessage::Ancestors {
        chain_id: ChainId([0x11; 32]),
        request_id: 8,
        containers: vec![vec![1, 2, 3], vec![4, 5, 6]],
    };
    let encoded = msg.encode_proto().unwrap();
    let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
    match decoded {
        NetworkMessage::Ancestors { request_id, containers, .. } => {
            assert_eq!(request_id, 8);
            assert_eq!(containers.len(), 2);
        }
        other => panic!("expected Ancestors, got {:?}", other.name()),
    }
}
```

**Step 2: Run tests to verify they fail**

```bash
cargo test test_get_ancestors_roundtrip test_ancestors_roundtrip 2>&1 | tail -20
```
Expected: compile error — variants don't exist yet.

**Step 3: Add the variants to `NetworkMessage` enum in `src/network/mod.rs`**

Find the `Accepted` variant (around line 157–161) and add after it:

```rust
    GetAncestors {
        chain_id: ChainId,
        request_id: u32,
        deadline: u64,
        container_id: BlockId,
        max_containers_size: u32,
    },
    Ancestors {
        chain_id: ChainId,
        request_id: u32,
        containers: Vec<Vec<u8>>,
    },
```

**Step 4: Add `name()` arms in `impl NetworkMessage`**

Find the `name()` match block and add:

```rust
            Self::GetAncestors { .. } => "GetAncestors",
            Self::Ancestors { .. } => "Ancestors",
```

**Step 5: Update `to_proto()` in `src/proto/mod.rs`**

Find where `NetworkMessage::Get` is encoded (around line 277) and add before it:

```rust
            NetworkMessage::GetAncestors {
                chain_id,
                request_id,
                deadline,
                container_id,
                max_containers_size,
            } => ProtoOneOf::GetAncestors(pb::GetAncestors {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                deadline: *deadline,
                container_id: Bytes::copy_from_slice(&container_id.0),
                max_containers_size: *max_containers_size,
            }),

            NetworkMessage::Ancestors {
                chain_id,
                request_id,
                containers,
            } => ProtoOneOf::Ancestors(pb::Ancestors {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                containers: containers.iter().map(|c| Bytes::copy_from_slice(c)).collect(),
            }),
```

**Step 6: Update `from_proto_oneof()` in `src/proto/mod.rs`**

Replace the existing `GetAncestors` and `Ancestors` arms (around lines 497–511) that currently map to `Get`/`Put`:

```rust
            ProtoOneOf::GetAncestors(g) => Ok(NetworkMessage::GetAncestors {
                chain_id: bytes_to_chain_id(&g.chain_id),
                request_id: g.request_id,
                deadline: g.deadline,
                container_id: bytes_to_block_id(&g.container_id),
                max_containers_size: g.max_containers_size,
            }),
            ProtoOneOf::Ancestors(a) => Ok(NetworkMessage::Ancestors {
                chain_id: bytes_to_chain_id(&a.chain_id),
                request_id: a.request_id,
                containers: a.containers.iter().map(|c| c.to_vec()).collect(),
            }),
```

**Step 7: Run tests**

```bash
cargo test 2>&1 | tail -10
```
Expected: all 273+ tests pass.

**Step 8: Commit**

```bash
git add src/network/mod.rs src/proto/mod.rs
git commit -m "feat: add GetAncestors/Ancestors NetworkMessage variants"
```

---

### Task 2: Restructure message loop — ping/pong keepalive with tokio::select!

**Files:**
- Modify: `src/main.rs` (lines 646–717, the `Entering message loop` section)

**Context:** The current loop uses a 120s read timeout as a hack to send pings. We need:
- Send Ping every 30s regardless of traffic
- Track whether we received a Pong after each Ping
- Close connection after 60s without a Pong (i.e., if we sent a Ping and didn't get a Pong within the next 30s interval)

**Step 1: Write a unit test for ping timeout logic**

Add to `src/proto/mod.rs` tests (these test encode/decode behavior used in the loop):

```rust
#[test]
fn test_ping_uptime_100() {
    let ping = NetworkMessage::Ping { uptime: 100 };
    let encoded = ping.encode_proto().unwrap();
    let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
    match decoded {
        NetworkMessage::Ping { uptime } => assert_eq!(uptime, 100),
        other => panic!("expected Ping, got {:?}", other.name()),
    }
}

#[test]
fn test_pong_decode() {
    let pong = NetworkMessage::Pong { uptime: 0 };
    let encoded = pong.encode_proto().unwrap();
    let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
    assert!(matches!(decoded, NetworkMessage::Pong { .. }));
}
```

**Step 2: Run tests to confirm they pass immediately**

```bash
cargo test test_ping_uptime_100 test_pong_decode 2>&1 | tail -10
```
Expected: PASS (encode/decode already works).

**Step 3: Replace the message loop in `src/main.rs`**

Find the `// 6. Keep connection alive — read messages in a loop` comment (around line 646) and replace everything from that comment through the `warn!("Peer {} disconnected"...)` line (line 722) with:

```rust
    // 6. Keep connection alive — read messages in a loop
    info!("Entering message loop with {}", addr);

    let ping_interval = Duration::from_secs(30);
    let pong_timeout = Duration::from_secs(60);
    let mut ping_timer = tokio::time::interval(ping_interval);
    ping_timer.tick().await; // consume the immediate first tick
    let mut last_ping_sent: Option<Instant> = None;
    let mut pong_received_since_last_ping = true; // start true so first ping isn't rejected

    loop {
        let mut len_buf = [0u8; 4];
        tokio::select! {
            // Arm 1: periodic ping
            _ = ping_timer.tick() => {
                // Check if we haven't received a pong since last ping
                if let Some(t) = last_ping_sent {
                    if !pong_received_since_last_ping && t.elapsed() > pong_timeout {
                        warn!("No Pong from {} within {}s, closing", addr, pong_timeout.as_secs());
                        break;
                    }
                }
                let ping = NetworkMessage::Ping { uptime: 100 };
                if let Ok(encoded) = ping.encode_proto() {
                    match tls_stream.write_all(&encoded).await {
                        Ok(_) => {
                            let _ = tls_stream.flush().await;
                            last_ping_sent = Some(Instant::now());
                            pong_received_since_last_ping = false;
                            debug!("Sent Ping to {}", addr);
                        }
                        Err(e) => {
                            warn!("Failed to send Ping to {}: {}", addr, e);
                            break;
                        }
                    }
                }
            }

            // Arm 2: incoming message
            result = tls_stream.read_exact(&mut len_buf) => {
                match result {
                    Ok(_) => {
                        let msg_len = u32::from_be_bytes(len_buf) as usize;
                        if msg_len > 16 * 1024 * 1024 {
                            warn!("Message too large from {}: {} bytes", addr, msg_len);
                            break;
                        }
                        let mut msg_data = vec![0u8; msg_len];
                        match tls_stream.read_exact(&mut msg_data).await {
                            Ok(_) => {
                                let mut full = Vec::with_capacity(4 + msg_len);
                                full.extend_from_slice(&len_buf);
                                full.extend_from_slice(&msg_data);
                                match NetworkMessage::decode_proto(&full) {
                                    Ok(msg) => {
                                        debug!("Received {} from {} ({} bytes)", msg.name(), addr, msg_len);
                                        match &msg {
                                            NetworkMessage::Ping { uptime } => {
                                                let pong = NetworkMessage::Pong { uptime: *uptime };
                                                if let Ok(encoded) = pong.encode_proto() {
                                                    let _ = tls_stream.write_all(&encoded).await;
                                                    let _ = tls_stream.flush().await;
                                                    debug!("Sent Pong to {}", addr);
                                                }
                                            }
                                            NetworkMessage::Pong { .. } => {
                                                pong_received_since_last_ping = true;
                                                debug!("Received Pong from {}", addr);
                                            }
                                            NetworkMessage::PeerList { peers } => {
                                                let new_peers = {
                                                    let mut pm = node.peer_manager.write().await;
                                                    pm.process_peer_list(peers)
                                                };
                                                if !new_peers.is_empty() {
                                                    info!("Discovered {} new peers via {}", new_peers.len(), addr);
                                                    // Dial up to 10 new peers concurrently
                                                    dial_new_peers(new_peers, node.clone()).await;
                                                }
                                            }
                                            NetworkMessage::GetAcceptedFrontier { chain_id, request_id, .. } => {
                                                // Respond with empty frontier (we have nothing yet)
                                                let response = NetworkMessage::AcceptedFrontier {
                                                    chain_id: chain_id.clone(),
                                                    request_id: *request_id,
                                                    container_id: crate::network::BlockId::zero(),
                                                };
                                                if let Ok(encoded) = response.encode_proto() {
                                                    let _ = tls_stream.write_all(&encoded).await;
                                                    let _ = tls_stream.flush().await;
                                                }
                                            }
                                            _ => {
                                                debug!("Unhandled message {} from {}", msg.name(), addr);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        debug!("Failed to decode message from {}: {}", addr, e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Read error from {}: {}", addr, e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Connection to {} closed: {}", addr, e);
                        break;
                    }
                }
            }
        }
    }
```

**Step 4: Build to confirm no compile errors**

```bash
cargo build 2>&1 | tail -20
```
Expected: errors about `dial_new_peers` (not yet defined) — that's fine.

**Step 5: Run all tests**

```bash
cargo test --lib 2>&1 | tail -10
```
Expected: all 273+ tests pass (message loop changes don't affect lib tests).

---

### Task 3: Add `dial_new_peers` helper — dial discovered peers

**Files:**
- Modify: `src/main.rs` (add function after `connect_to_bootstrap_nodes`)

**Context:** After receiving a PeerList in the message loop, we need to connect to up to 10 new peers. We track already-connected IPs in the `PeerManager` to avoid duplicates.

**Step 1: Write a test for PeerManager duplicate tracking**

The `PeerManager::process_peer_list` already returns only new peers. Add a test for this behavior in `src/network/mod.rs`:

```rust
#[test]
fn test_process_peer_list_deduplication() {
    use std::net::SocketAddr;
    let config = NetworkConfig::default();
    let my_id = NodeId([0u8; 20]);
    let mut pm = PeerManager::new(config, my_id);

    let peers = vec![PeerInfo {
        node_id: NodeId([1u8; 20]),
        ip_addr: vec![10, 0, 0, 1],
        ip_port: 9651,
        cert_bytes: vec![],
        timestamp: 0,
        signature: vec![],
    }];

    let new1 = pm.process_peer_list(&peers);
    assert_eq!(new1.len(), 1, "first time should discover 1 new peer");

    // Add the peer to the manager
    let addr: SocketAddr = "10.0.0.1:9651".parse().unwrap();
    let mut peer = Peer::new(NodeId([1u8; 20]), addr);
    peer.state = PeerState::Connected;
    let _ = pm.add_peer(peer);

    let new2 = pm.process_peer_list(&peers);
    assert_eq!(new2.len(), 0, "already-known peer should not be returned");
}
```

**Step 2: Run the test**

```bash
cargo test test_process_peer_list_deduplication 2>&1 | tail -20
```
Expected: PASS if `process_peer_list` checks connected peers, or FAIL if it doesn't. Either way, verify then continue.

**Step 3: Add `dial_new_peers` to `src/main.rs`**

Add this function after `connect_to_bootstrap_nodes` (around line 395):

```rust
/// Dial up to 10 new peers discovered via PeerList.
/// Skips peers we can't parse as a SocketAddr.
async fn dial_new_peers(new_peers: Vec<crate::network::PeerInfo>, node: Arc<NodeState>) {
    let to_dial: Vec<_> = new_peers
        .into_iter()
        .take(10)
        .filter_map(|p| {
            // Convert raw IP bytes + port to SocketAddr
            let ip = match p.ip_addr.len() {
                4 => {
                    let arr: [u8; 4] = p.ip_addr.try_into().ok()?;
                    std::net::IpAddr::V4(std::net::Ipv4Addr::from(arr))
                }
                16 => {
                    let arr: [u8; 16] = p.ip_addr.try_into().ok()?;
                    std::net::IpAddr::V6(std::net::Ipv6Addr::from(arr))
                }
                _ => return None,
            };
            if p.ip_port == 0 {
                return None;
            }
            Some(std::net::SocketAddr::new(ip, p.ip_port))
        })
        .collect();

    for addr in to_dial {
        let node = node.clone();
        tokio::spawn(async move {
            info!("Dialing discovered peer {}", addr);
            if let Err(e) = connect_and_handshake(addr, node).await {
                debug!("Discovered peer {} failed: {}", addr, e);
            }
        });
    }
}
```

**Step 4: Build**

```bash
cargo build 2>&1 | tail -10
```
Expected: compiles cleanly.

**Step 5: Run all tests**

```bash
cargo test --lib 2>&1 | tail -10
```
Expected: 273+ tests pass.

**Step 6: Commit**

```bash
git add src/main.rs src/network/mod.rs
git commit -m "feat: add peer dialing and proper 30s ping/pong keepalive"
```

---

### Task 4: Bootstrap chain state — P-Chain GetAcceptedFrontier sequence

**Files:**
- Modify: `src/main.rs` (add `bootstrap_p_chain` function, call it after handshake)

**Context:** After a successful handshake with a peer, we initiate a bootstrap sequence for the P-Chain. The P-Chain uses `chain_id = [0u8; 32]` (all zeros). We use a simple `AtomicU32` request ID counter. We don't validate blocks yet — just log what we receive.

**Step 1: Write tests for bootstrap message encoding**

Add to `src/proto/mod.rs` tests:

```rust
#[test]
fn test_get_accepted_frontier_roundtrip() {
    let msg = NetworkMessage::GetAcceptedFrontier {
        chain_id: ChainId([0u8; 32]), // P-Chain
        request_id: 1,
        deadline: 5_000_000_000,
    };
    let encoded = msg.encode_proto().unwrap();
    let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
    match decoded {
        NetworkMessage::GetAcceptedFrontier { chain_id, request_id, .. } => {
            assert_eq!(chain_id.0, [0u8; 32]);
            assert_eq!(request_id, 1);
        }
        other => panic!("expected GetAcceptedFrontier, got {:?}", other.name()),
    }
}

#[test]
fn test_get_ancestors_bootstrap() {
    let container_id = BlockId([0xAA; 32]);
    let msg = NetworkMessage::GetAncestors {
        chain_id: ChainId([0u8; 32]),
        request_id: 5,
        deadline: 5_000_000_000,
        container_id: container_id.clone(),
        max_containers_size: 2_000_000,
    };
    let encoded = msg.encode_proto().unwrap();
    let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
    match decoded {
        NetworkMessage::GetAncestors { request_id, container_id: cid, .. } => {
            assert_eq!(request_id, 5);
            assert_eq!(cid.0, [0xAA; 32]);
        }
        other => panic!("expected GetAncestors, got {:?}", other.name()),
    }
}
```

**Step 2: Run tests**

```bash
cargo test test_get_accepted_frontier_roundtrip test_get_ancestors_bootstrap 2>&1 | tail -10
```
Expected: PASS.

**Step 3: Add `bootstrap_p_chain` function to `src/main.rs`**

Add this function after `dial_new_peers` (before `run_rpc_server`):

```rust
/// Bootstrap P-Chain state from a connected peer.
/// Implements: GetAcceptedFrontier → AcceptedFrontier → GetAccepted → Accepted → GetAncestors → Ancestors.
/// Logs what we receive; does not yet validate or apply blocks.
async fn bootstrap_p_chain<S>(
    stream: &mut S,
    addr: std::net::SocketAddr,
    request_id_base: u32,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use crate::network::{BlockId, ChainId};

    let p_chain_id = ChainId([0u8; 32]);
    let deadline_ns = 5_000_000_000u64; // 5 seconds in nanoseconds

    // Step 1: GetAcceptedFrontier
    let req = NetworkMessage::GetAcceptedFrontier {
        chain_id: p_chain_id.clone(),
        request_id: request_id_base,
        deadline: deadline_ns,
    };
    if let Ok(encoded) = req.encode_proto() {
        if let Err(e) = stream.write_all(&encoded).await {
            warn!("bootstrap: failed to send GetAcceptedFrontier to {}: {}", addr, e);
            return;
        }
        let _ = stream.flush().await;
        info!("bootstrap: sent GetAcceptedFrontier (req={}) to {}", request_id_base, addr);
    }

    // Step 2: Wait for AcceptedFrontier
    let frontier_block_id = loop {
        match read_one_message(stream, addr, 30).await {
            Ok(NetworkMessage::AcceptedFrontier { request_id, container_id, .. })
                if request_id == request_id_base =>
            {
                info!("bootstrap: AcceptedFrontier from {} — tip={}", addr, container_id);
                break container_id;
            }
            Ok(NetworkMessage::Ping { uptime }) => {
                // Respond to pings while waiting
                let pong = NetworkMessage::Pong { uptime };
                if let Ok(enc) = pong.encode_proto() {
                    let _ = stream.write_all(&enc).await;
                    let _ = stream.flush().await;
                }
            }
            Ok(other) => {
                debug!("bootstrap: ignoring {} while waiting for AcceptedFrontier", other.name());
            }
            Err(e) => {
                warn!("bootstrap: error waiting for AcceptedFrontier from {}: {}", addr, e);
                return;
            }
        }
    };

    if frontier_block_id.0 == [0u8; 32] {
        info!("bootstrap: peer {} has empty frontier — nothing to bootstrap", addr);
        return;
    }

    // Step 3: GetAccepted
    let req = NetworkMessage::GetAccepted {
        chain_id: p_chain_id.clone(),
        request_id: request_id_base + 1,
        deadline: deadline_ns,
        container_ids: vec![frontier_block_id.clone()],
    };
    if let Ok(encoded) = req.encode_proto() {
        if let Err(e) = stream.write_all(&encoded).await {
            warn!("bootstrap: failed to send GetAccepted to {}: {}", addr, e);
            return;
        }
        let _ = stream.flush().await;
        info!("bootstrap: sent GetAccepted (req={}) to {}", request_id_base + 1, addr);
    }

    // Step 4: Wait for Accepted
    let accepted_ids = loop {
        match read_one_message(stream, addr, 30).await {
            Ok(NetworkMessage::Accepted { request_id, container_ids, .. })
                if request_id == request_id_base + 1 =>
            {
                info!("bootstrap: Accepted from {} — {} block IDs", addr, container_ids.len());
                break container_ids;
            }
            Ok(NetworkMessage::Ping { uptime }) => {
                let pong = NetworkMessage::Pong { uptime };
                if let Ok(enc) = pong.encode_proto() {
                    let _ = stream.write_all(&enc).await;
                    let _ = stream.flush().await;
                }
            }
            Ok(other) => {
                debug!("bootstrap: ignoring {} while waiting for Accepted", other.name());
            }
            Err(e) => {
                warn!("bootstrap: error waiting for Accepted from {}: {}", addr, e);
                return;
            }
        }
    };

    if accepted_ids.is_empty() {
        info!("bootstrap: peer {} accepted no blocks from our set", addr);
        return;
    }

    // Step 5: GetAncestors for the first accepted block
    let target = &accepted_ids[0];
    let req = NetworkMessage::GetAncestors {
        chain_id: p_chain_id.clone(),
        request_id: request_id_base + 2,
        deadline: deadline_ns,
        container_id: target.clone(),
        max_containers_size: 2_000_000,
    };
    if let Ok(encoded) = req.encode_proto() {
        if let Err(e) = stream.write_all(&encoded).await {
            warn!("bootstrap: failed to send GetAncestors to {}: {}", addr, e);
            return;
        }
        let _ = stream.flush().await;
        info!("bootstrap: sent GetAncestors (req={}) for block {} to {}", request_id_base + 2, target, addr);
    }

    // Step 6: Wait for Ancestors
    loop {
        match read_one_message(stream, addr, 30).await {
            Ok(NetworkMessage::Ancestors { request_id, containers, .. })
                if request_id == request_id_base + 2 =>
            {
                info!(
                    "bootstrap: Ancestors from {} — {} containers, total {} bytes",
                    addr,
                    containers.len(),
                    containers.iter().map(|c| c.len()).sum::<usize>()
                );
                for (i, c) in containers.iter().enumerate() {
                    debug!("  container[{}]: {} bytes", i, c.len());
                }
                break;
            }
            Ok(NetworkMessage::Ping { uptime }) => {
                let pong = NetworkMessage::Pong { uptime };
                if let Ok(enc) = pong.encode_proto() {
                    let _ = stream.write_all(&enc).await;
                    let _ = stream.flush().await;
                }
            }
            Ok(other) => {
                debug!("bootstrap: ignoring {} while waiting for Ancestors", other.name());
            }
            Err(e) => {
                warn!("bootstrap: error waiting for Ancestors from {}: {}", addr, e);
                break;
            }
        }
    }
}
```

**Step 4: Call `bootstrap_p_chain` at end of `connect_and_handshake`**

In `connect_and_handshake`, find the comment `// 6. Keep connection alive` (around line 646).
Just before it, add:

```rust
    // 5b. Attempt P-Chain bootstrap
    // Use a fixed request_id base; in production this should be from a global counter.
    let bootstrap_request_base: u32 = rand::thread_rng().gen::<u16>() as u32 * 10;
    bootstrap_p_chain(&mut tls_stream, addr, bootstrap_request_base).await;
```

Add this import at the top of `src/main.rs` if not already there:
```rust
use rand::Rng;
```
(It's already imported.)

**Step 5: Build**

```bash
cargo build 2>&1 | tail -20
```
Expected: clean build.

**Step 6: Run all tests**

```bash
cargo test --lib 2>&1 | tail -10
```
Expected: 273+ tests pass.

**Step 7: Commit**

```bash
git add src/main.rs src/proto/mod.rs
git commit -m "feat: implement P-Chain bootstrap sequence (GetAcceptedFrontier → Ancestors)"
```

---

### Task 5: Final integration — build release + run full test suite

**Step 1: Release build**

```bash
cargo build --release 2>&1 | tail -5
```
Expected: Finished release ... in N.Ns

**Step 2: Run all lib tests**

```bash
cargo test --lib 2>&1 | tail -10
```
Expected: test result: ok. 280+ passed; 0 failed

**Step 3: Run doc tests if any**

```bash
cargo test 2>&1 | tail -10
```

**Step 4: Notify**

```bash
openclaw system event --text "Done: avalanche-rs ping/pong + peer dialing + bootstrap implemented" --mode now
```

**Step 5: Final commit if needed**

```bash
git status
```
If clean, done. If there are any loose changes:
```bash
git add -p
git commit -m "chore: final integration cleanup"
```

---

## Summary of Changes

| File | Change |
|------|--------|
| `src/network/mod.rs` | Add `GetAncestors`, `Ancestors` variants; `name()` arms; test for dedup |
| `src/proto/mod.rs` | Map `GetAncestors`/`Ancestors` proto ↔ new variants; add tests |
| `src/main.rs` | Restructure message loop to `tokio::select!` with 30s ping interval + 60s pong timeout; add `dial_new_peers`; add `bootstrap_p_chain` |
