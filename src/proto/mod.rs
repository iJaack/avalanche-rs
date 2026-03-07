//! Protobuf wire format for the Avalanche P2P protocol.
//!
//! Wraps prost-generated types from `reference/p2p.proto` and provides
//! conversions to/from the higher-level `NetworkMessage` enum used in
//! `src/network/mod.rs`.

use bytes::Bytes;
use prost::Message as ProstMessage;
use rand::Rng;

/// Generated protobuf types (compiled by build.rs from proto/p2p/p2p.proto).
pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/p2p.rs"));
}

// Re-export key generated types for convenience.
pub use pb::{
    message::Message as ProtoOneOf, BloomFilter as ProtoBloomFilter,
    ClaimedIpPort as ProtoClaimedIpPort, Client as ProtoClient, Handshake as ProtoHandshake,
    Message as ProtoMessage, Ping as ProtoPing, Pong as ProtoPong,
};

use crate::network::{BlockId, ChainId, NetworkError, NetworkMessage, NodeId, PeerInfo};

// ---------------------------------------------------------------------------
// Compression helpers
// ---------------------------------------------------------------------------

/// Compress a serialized protobuf `Message` with zstd and wrap it in the
/// `compressed_zstd` oneof variant.
pub fn compress_message(raw: &[u8]) -> Result<Vec<u8>, NetworkError> {
    let compressed =
        zstd::encode_all(raw, 3).map_err(|e| NetworkError::Serialization(e.to_string()))?;
    let wrapper = ProtoMessage {
        message: Some(ProtoOneOf::CompressedZstd(Bytes::from(compressed))),
    };
    Ok(wrapper.encode_to_vec())
}

/// If the outer message is `compressed_zstd`, decompress and re-parse.
/// Otherwise returns the inner oneof directly.
pub fn decompress_message(data: &[u8]) -> Result<ProtoOneOf, NetworkError> {
    let outer =
        ProtoMessage::decode(data).map_err(|e| NetworkError::Serialization(e.to_string()))?;
    let inner = outer
        .message
        .ok_or_else(|| NetworkError::Serialization("empty protobuf message".into()))?;

    match inner {
        ProtoOneOf::CompressedZstd(zstd_bytes) => {
            let decompressed = zstd::decode_all(zstd_bytes.as_ref())
                .map_err(|e| NetworkError::Serialization(format!("zstd decompress: {e}")))?;
            let inner_msg = ProtoMessage::decode(decompressed.as_slice())
                .map_err(|e| NetworkError::Serialization(e.to_string()))?;
            inner_msg
                .message
                .ok_or_else(|| NetworkError::Serialization("empty inner message".into()))
        }
        other => Ok(other),
    }
}

// ---------------------------------------------------------------------------
// NetworkMessage  →  Protobuf bytes  (encode)
// ---------------------------------------------------------------------------

impl NetworkMessage {
    /// Encode to Avalanche protobuf wire format (length-prefixed).
    /// Messages that benefit from compression (Put, Ancestors, AppResponse,
    /// etc.) are zstd-compressed automatically.
    pub fn encode_proto(&self) -> Result<Vec<u8>, NetworkError> {
        let proto_msg = self.to_proto()?;
        let raw = proto_msg.encode_to_vec();

        // Compress large / bulk-data messages
        let final_bytes = if self.should_compress() {
            compress_message(&raw)?
        } else {
            raw
        };

        // 4-byte big-endian length prefix (matches AvalancheGo framing)
        let len = (final_bytes.len() as u32).to_be_bytes();
        let mut buf = Vec::with_capacity(4 + final_bytes.len());
        buf.extend_from_slice(&len);
        buf.extend_from_slice(&final_bytes);
        Ok(buf)
    }

    /// Decode from length-prefixed Avalanche protobuf wire format.
    pub fn decode_proto(data: &[u8]) -> Result<Self, NetworkError> {
        if data.len() < 4 {
            return Err(NetworkError::Serialization("message too short".into()));
        }
        let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + len {
            return Err(NetworkError::Serialization(format!(
                "expected {} bytes, got {}",
                len,
                data.len() - 4,
            )));
        }
        let payload = &data[4..4 + len];
        let inner = decompress_message(payload)?;
        Self::from_proto_oneof(inner)
    }

    fn should_compress(&self) -> bool {
        matches!(
            self,
            NetworkMessage::Put { .. }
                | NetworkMessage::PushQuery { .. }
                | NetworkMessage::AppRequest { .. }
                | NetworkMessage::AppResponse { .. }
                | NetworkMessage::AppGossip { .. }
        )
    }

    /// Convert to a prost `ProtoMessage`.
    pub fn to_proto(&self) -> Result<ProtoMessage, NetworkError> {
        let oneof = match self {
            NetworkMessage::Ping { uptime } => ProtoOneOf::Ping(pb::Ping { uptime: *uptime }),
            NetworkMessage::Pong { .. } => ProtoOneOf::Pong(pb::Pong {}),

            NetworkMessage::Version {
                network_id,
                node_id: _,
                my_time,
                ip_addr,
                ip_port,
                my_version,
                my_version_time: _,
                sig,
                tracked_subnets,
            } => {
                let (major, minor, patch) = parse_version(my_version);

                // Latest activated upgrade time — must match what the network expects.
                // AvalancheGo uses this to check compatibility.
                // Granite is the latest activated upgrade on both networks.
                // Fortuna (ACP-181/204/226) activated 2025-03-13 but Granite is later.
                let upgrade_time = crate::fortuna::latest_upgrade_time(*network_id);

                // Build a minimal bloom filter (empty filter with random salt)
                // AvalancheGo expects this field to be present
                let bloom_salt: [u8; 8] = rand::thread_rng().gen();
                let known_peers_bloom = Some(pb::BloomFilter {
                    filter: Bytes::from(vec![0u8; 8]), // empty bloom = we know nobody
                    salt: Bytes::copy_from_slice(&bloom_salt),
                });

                ProtoOneOf::Handshake(pb::Handshake {
                    network_id: *network_id,
                    my_time: *my_time,
                    ip_addr: Bytes::copy_from_slice(ip_addr),
                    ip_port: *ip_port as u32,
                    upgrade_time,
                    ip_signing_time: *my_time,
                    ip_node_id_sig: Bytes::copy_from_slice(sig),
                    tracked_subnets: tracked_subnets
                        .iter()
                        .map(|s| Bytes::copy_from_slice(&s.0))
                        .collect(),
                    client: Some(pb::Client {
                        name: "avalanchego".into(), // identify as compatible client
                        major,
                        minor,
                        patch,
                    }),
                    supported_acps: vec![],
                    objected_acps: vec![],
                    known_peers: known_peers_bloom,
                    // BLS signature is provided via the sig field which now carries
                    // the TLS sig. We'll need a separate field for BLS...
                    // For now, embed a placeholder that gets overridden in main.rs
                    ip_bls_sig: Bytes::new(),
                    all_subnets: true, // track all subnets
                })
            }

            NetworkMessage::PeerList { peers } => {
                let claimed: Vec<pb::ClaimedIpPort> = peers
                    .iter()
                    .map(|p| pb::ClaimedIpPort {
                        x509_certificate: Bytes::copy_from_slice(&p.cert_bytes),
                        ip_addr: Bytes::copy_from_slice(&p.ip_addr),
                        ip_port: p.ip_port as u32,
                        timestamp: p.timestamp,
                        signature: Bytes::copy_from_slice(&p.signature),
                        tx_id: Bytes::new(),
                    })
                    .collect();
                ProtoOneOf::PeerList(pb::PeerList {
                    claimed_ip_ports: claimed,
                })
            }

            NetworkMessage::PeerListAck { .. } => {
                // PeerListAck maps to GetPeerList in the proto
                ProtoOneOf::GetPeerList(pb::GetPeerList {
                    known_peers: None,
                    all_subnets: false,
                })
            }

            NetworkMessage::GetStateSummaryFrontier {
                chain_id,
                request_id,
                deadline,
            } => ProtoOneOf::GetStateSummaryFrontier(pb::GetStateSummaryFrontier {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                deadline: *deadline,
            }),

            NetworkMessage::StateSummaryFrontier {
                chain_id,
                request_id,
                summary,
            } => ProtoOneOf::StateSummaryFrontier(pb::StateSummaryFrontier {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                summary: Bytes::copy_from_slice(summary),
            }),

            NetworkMessage::GetAcceptedFrontier {
                chain_id,
                request_id,
                deadline,
            } => ProtoOneOf::GetAcceptedFrontier(pb::GetAcceptedFrontier {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                deadline: *deadline,
            }),

            NetworkMessage::AcceptedFrontier {
                chain_id,
                request_id,
                container_id,
            } => ProtoOneOf::AcceptedFrontier(pb::AcceptedFrontier {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                container_id: Bytes::copy_from_slice(&container_id.0),
            }),

            NetworkMessage::GetAccepted {
                chain_id,
                request_id,
                deadline,
                container_ids,
            } => ProtoOneOf::GetAccepted(pb::GetAccepted {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                deadline: *deadline,
                container_ids: container_ids
                    .iter()
                    .map(|id| Bytes::copy_from_slice(&id.0))
                    .collect(),
            }),

            NetworkMessage::Accepted {
                chain_id,
                request_id,
                container_ids,
            } => ProtoOneOf::Accepted(pb::Accepted {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                container_ids: container_ids
                    .iter()
                    .map(|id| Bytes::copy_from_slice(&id.0))
                    .collect(),
            }),

            NetworkMessage::GetAncestors {
                chain_id,
                request_id,
                deadline,
                container_id,
                max_containers_size: _,
            } => ProtoOneOf::GetAncestors(pb::GetAncestors {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                deadline: *deadline,
                container_id: Bytes::copy_from_slice(&container_id.0),
                engine_type: 0,
            }),

            NetworkMessage::Ancestors {
                chain_id,
                request_id,
                containers,
            } => ProtoOneOf::Ancestors(pb::Ancestors {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                containers: containers
                    .iter()
                    .map(|c| Bytes::copy_from_slice(c))
                    .collect(),
            }),

            NetworkMessage::Get {
                chain_id,
                request_id,
                deadline,
                container_id,
            } => ProtoOneOf::Get(pb::Get {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                deadline: *deadline,
                container_id: Bytes::copy_from_slice(&container_id.0),
            }),

            NetworkMessage::Put {
                chain_id,
                request_id,
                container,
            } => ProtoOneOf::Put(pb::Put {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                container: Bytes::copy_from_slice(container),
            }),

            NetworkMessage::PushQuery {
                chain_id,
                request_id,
                deadline,
                container,
            } => ProtoOneOf::PushQuery(pb::PushQuery {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                deadline: *deadline,
                container: Bytes::copy_from_slice(container),
                requested_height: 0,
            }),

            NetworkMessage::PullQuery {
                chain_id,
                request_id,
                deadline,
                container_id,
            } => ProtoOneOf::PullQuery(pb::PullQuery {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                deadline: *deadline,
                container_id: Bytes::copy_from_slice(&container_id.0),
                requested_height: 0,
            }),

            NetworkMessage::Chits {
                chain_id,
                request_id,
                preferred_id,
                preferred_id_at_height,
                accepted_id,
            } => ProtoOneOf::Chits(pb::Chits {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                preferred_id: Bytes::copy_from_slice(&preferred_id.0),
                accepted_id: Bytes::copy_from_slice(&accepted_id.0),
                preferred_id_at_height: Bytes::copy_from_slice(&preferred_id_at_height.0),
                accepted_height: 0,
            }),

            NetworkMessage::AppRequest {
                chain_id,
                request_id,
                deadline,
                app_bytes,
            } => ProtoOneOf::AppRequest(pb::AppRequest {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                deadline: *deadline,
                app_bytes: Bytes::copy_from_slice(app_bytes),
            }),

            NetworkMessage::AppResponse {
                chain_id,
                request_id,
                app_bytes,
            } => ProtoOneOf::AppResponse(pb::AppResponse {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                request_id: *request_id,
                app_bytes: Bytes::copy_from_slice(app_bytes),
            }),

            NetworkMessage::AppGossip {
                chain_id,
                app_bytes,
            } => ProtoOneOf::AppGossip(pb::AppGossip {
                chain_id: Bytes::copy_from_slice(&chain_id.0),
                app_bytes: Bytes::copy_from_slice(app_bytes),
            }),
        };

        Ok(ProtoMessage {
            message: Some(oneof),
        })
    }

    /// Convert from a protobuf oneof variant to `NetworkMessage`.
    pub fn from_proto_oneof(oneof: ProtoOneOf) -> Result<Self, NetworkError> {
        match oneof {
            ProtoOneOf::Ping(p) => Ok(NetworkMessage::Ping { uptime: p.uptime }),
            ProtoOneOf::Pong(_) => Ok(NetworkMessage::Pong { uptime: 0 }),

            ProtoOneOf::Handshake(h) => {
                let version = if let Some(c) = &h.client {
                    format!("avalanche/{}.{}.{}", c.major, c.minor, c.patch)
                } else {
                    "avalanche/0.0.0".into()
                };
                // Derive a placeholder NodeId from the IP + port for now;
                // proper NodeID derivation from TLS cert is in Phase 2.
                let mut nid = [0u8; 20];
                let addr_bytes = h.ip_addr.as_ref();
                let copy_len = addr_bytes.len().min(20);
                nid[..copy_len].copy_from_slice(&addr_bytes[..copy_len]);

                Ok(NetworkMessage::Version {
                    network_id: h.network_id,
                    node_id: NodeId(nid),
                    my_time: h.my_time,
                    ip_addr: h.ip_addr.to_vec(),
                    ip_port: h.ip_port as u16,
                    my_version: version,
                    my_version_time: h.ip_signing_time,
                    sig: h.ip_node_id_sig.to_vec(),
                    tracked_subnets: h
                        .tracked_subnets
                        .iter()
                        .map(|b| {
                            let mut arr = [0u8; 32];
                            let len = b.len().min(32);
                            arr[..len].copy_from_slice(&b[..len]);
                            ChainId(arr)
                        })
                        .collect(),
                })
            }

            ProtoOneOf::PeerList(pl) => {
                let peers = pl
                    .claimed_ip_ports
                    .into_iter()
                    .map(|c| {
                        // Derive NodeId from certificate hash (SHA-256 first 20 bytes)
                        use sha2::{Digest, Sha256};
                        let cert_hash = Sha256::digest(&c.x509_certificate);
                        let mut nid = [0u8; 20];
                        nid.copy_from_slice(&cert_hash[..20]);
                        PeerInfo {
                            node_id: NodeId(nid),
                            ip_addr: c.ip_addr.to_vec(),
                            ip_port: c.ip_port as u16,
                            cert_bytes: c.x509_certificate.to_vec(),
                            timestamp: c.timestamp,
                            signature: c.signature.to_vec(),
                        }
                    })
                    .collect();
                Ok(NetworkMessage::PeerList { peers })
            }

            ProtoOneOf::GetPeerList(_) => Ok(NetworkMessage::PeerListAck { peer_ids: vec![] }),

            ProtoOneOf::GetStateSummaryFrontier(g) => Ok(NetworkMessage::GetStateSummaryFrontier {
                chain_id: bytes_to_chain_id(&g.chain_id),
                request_id: g.request_id,
                deadline: g.deadline,
            }),
            ProtoOneOf::StateSummaryFrontier(s) => Ok(NetworkMessage::StateSummaryFrontier {
                chain_id: bytes_to_chain_id(&s.chain_id),
                request_id: s.request_id,
                summary: s.summary.to_vec(),
            }),
            ProtoOneOf::GetAcceptedStateSummary(g) => {
                // Map to GetStateSummaryFrontier for simplicity
                Ok(NetworkMessage::GetStateSummaryFrontier {
                    chain_id: bytes_to_chain_id(&g.chain_id),
                    request_id: g.request_id,
                    deadline: g.deadline,
                })
            }
            ProtoOneOf::AcceptedStateSummary(a) => Ok(NetworkMessage::StateSummaryFrontier {
                chain_id: bytes_to_chain_id(&a.chain_id),
                request_id: a.request_id,
                summary: if a.summary_ids.is_empty() {
                    vec![]
                } else {
                    a.summary_ids[0].to_vec()
                },
            }),

            ProtoOneOf::GetAcceptedFrontier(g) => Ok(NetworkMessage::GetAcceptedFrontier {
                chain_id: bytes_to_chain_id(&g.chain_id),
                request_id: g.request_id,
                deadline: g.deadline,
            }),
            ProtoOneOf::AcceptedFrontier(a) => Ok(NetworkMessage::AcceptedFrontier {
                chain_id: bytes_to_chain_id(&a.chain_id),
                request_id: a.request_id,
                container_id: bytes_to_block_id(&a.container_id),
            }),

            ProtoOneOf::GetAccepted(g) => Ok(NetworkMessage::GetAccepted {
                chain_id: bytes_to_chain_id(&g.chain_id),
                request_id: g.request_id,
                deadline: g.deadline,
                container_ids: g
                    .container_ids
                    .iter()
                    .map(|b| bytes_to_block_id(b))
                    .collect(),
            }),
            ProtoOneOf::Accepted(a) => Ok(NetworkMessage::Accepted {
                chain_id: bytes_to_chain_id(&a.chain_id),
                request_id: a.request_id,
                container_ids: a
                    .container_ids
                    .iter()
                    .map(|b| bytes_to_block_id(b))
                    .collect(),
            }),

            ProtoOneOf::GetAncestors(g) => Ok(NetworkMessage::GetAncestors {
                chain_id: bytes_to_chain_id(&g.chain_id),
                request_id: g.request_id,
                deadline: g.deadline,
                container_id: bytes_to_block_id(&g.container_id),
                max_containers_size: 2_000_000,
            }),
            ProtoOneOf::Ancestors(a) => Ok(NetworkMessage::Ancestors {
                chain_id: bytes_to_chain_id(&a.chain_id),
                request_id: a.request_id,
                containers: a.containers.iter().map(|c| c.to_vec()).collect(),
            }),

            ProtoOneOf::Get(g) => Ok(NetworkMessage::Get {
                chain_id: bytes_to_chain_id(&g.chain_id),
                request_id: g.request_id,
                deadline: g.deadline,
                container_id: bytes_to_block_id(&g.container_id),
            }),
            ProtoOneOf::Put(p) => Ok(NetworkMessage::Put {
                chain_id: bytes_to_chain_id(&p.chain_id),
                request_id: p.request_id,
                container: p.container.to_vec(),
            }),
            ProtoOneOf::PushQuery(p) => Ok(NetworkMessage::PushQuery {
                chain_id: bytes_to_chain_id(&p.chain_id),
                request_id: p.request_id,
                deadline: p.deadline,
                container: p.container.to_vec(),
            }),
            ProtoOneOf::PullQuery(p) => Ok(NetworkMessage::PullQuery {
                chain_id: bytes_to_chain_id(&p.chain_id),
                request_id: p.request_id,
                deadline: p.deadline,
                container_id: bytes_to_block_id(&p.container_id),
            }),
            ProtoOneOf::Chits(c) => Ok(NetworkMessage::Chits {
                chain_id: bytes_to_chain_id(&c.chain_id),
                request_id: c.request_id,
                preferred_id: bytes_to_block_id(&c.preferred_id),
                preferred_id_at_height: bytes_to_block_id(&c.preferred_id_at_height),
                accepted_id: bytes_to_block_id(&c.accepted_id),
            }),

            ProtoOneOf::AppRequest(a) => Ok(NetworkMessage::AppRequest {
                chain_id: bytes_to_chain_id(&a.chain_id),
                request_id: a.request_id,
                deadline: a.deadline,
                app_bytes: a.app_bytes.to_vec(),
            }),
            ProtoOneOf::AppResponse(a) => Ok(NetworkMessage::AppResponse {
                chain_id: bytes_to_chain_id(&a.chain_id),
                request_id: a.request_id,
                app_bytes: a.app_bytes.to_vec(),
            }),
            ProtoOneOf::AppGossip(a) => Ok(NetworkMessage::AppGossip {
                chain_id: bytes_to_chain_id(&a.chain_id),
                app_bytes: a.app_bytes.to_vec(),
            }),
            ProtoOneOf::AppError(e) => Err(NetworkError::InvalidMessage(format!(
                "AppError: code={}, msg={}",
                e.error_code, e.error_message
            ))),
            ProtoOneOf::CompressedZstd(_) => Err(NetworkError::Serialization(
                "unexpected nested compression".into(),
            )),
            ProtoOneOf::Simplex(_) => {
                // Simplex consensus messages — not yet implemented
                Err(NetworkError::InvalidMessage(
                    "simplex not yet supported".into(),
                ))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bytes_to_chain_id(b: &[u8]) -> ChainId {
    let mut arr = [0u8; 32];
    let len = b.len().min(32);
    arr[..len].copy_from_slice(&b[..len]);
    ChainId(arr)
}

fn bytes_to_block_id(b: &[u8]) -> BlockId {
    let mut arr = [0u8; 32];
    let len = b.len().min(32);
    arr[..len].copy_from_slice(&b[..len]);
    BlockId(arr)
}

fn parse_version(v: &str) -> (u32, u32, u32) {
    // Parse "avalanche/1.2.3" or "1.2.3"
    let ver = v.split('/').last().unwrap_or(v);
    let parts: Vec<u32> = ver.split('.').filter_map(|s| s.parse().ok()).collect();
    (
        parts.first().copied().unwrap_or(0),
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ping_roundtrip() {
        let msg = NetworkMessage::Ping { uptime: 9500 };
        let encoded = msg.encode_proto().unwrap();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::Ping { uptime } => assert_eq!(uptime, 9500),
            other => panic!("expected Ping, got {:?}", other),
        }
    }

    #[test]
    fn test_pong_roundtrip() {
        let msg = NetworkMessage::Pong { uptime: 100 };
        let encoded = msg.encode_proto().unwrap();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        assert!(matches!(decoded, NetworkMessage::Pong { .. }));
    }

    #[test]
    fn test_version_handshake_roundtrip() {
        let msg = NetworkMessage::Version {
            network_id: 1,
            node_id: NodeId([1u8; 20]),
            my_time: 1234567890,
            ip_addr: vec![127, 0, 0, 1],
            ip_port: 9651,
            my_version: "avalanche/1.11.3".into(),
            my_version_time: 1234567890,
            sig: vec![0xAA; 64],
            tracked_subnets: vec![],
        };
        let encoded = msg.encode_proto().unwrap();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::Version {
                network_id,
                ip_port,
                my_version,
                ..
            } => {
                assert_eq!(network_id, 1);
                assert_eq!(ip_port, 9651);
                assert!(my_version.contains("1.11.3"));
            }
            other => panic!("expected Version, got {:?}", other),
        }
    }

    #[test]
    fn test_put_compressed_roundtrip() {
        let chain_id = ChainId([0xCC; 32]);
        let container = vec![0xDE; 1024]; // Large enough to benefit from compression
        let msg = NetworkMessage::Put {
            chain_id: chain_id.clone(),
            request_id: 42,
            container: container.clone(),
        };
        let encoded = msg.encode_proto().unwrap();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::Put {
                chain_id: cid,
                request_id,
                container: c,
            } => {
                assert_eq!(cid.0, chain_id.0);
                assert_eq!(request_id, 42);
                assert_eq!(c, container);
            }
            other => panic!("expected Put, got {:?}", other),
        }
    }

    #[test]
    fn test_get_accepted_roundtrip() {
        let chain_id = ChainId([0x11; 32]);
        let ids: Vec<BlockId> = (0..5).map(|i| BlockId([i; 32])).collect();
        let msg = NetworkMessage::GetAccepted {
            chain_id: chain_id.clone(),
            request_id: 99,
            deadline: 5_000_000_000,
            container_ids: ids.clone(),
        };
        let encoded = msg.encode_proto().unwrap();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::GetAccepted {
                request_id,
                container_ids,
                ..
            } => {
                assert_eq!(request_id, 99);
                assert_eq!(container_ids.len(), 5);
                assert_eq!(container_ids[0].0, [0u8; 32]);
                assert_eq!(container_ids[4].0, [4u8; 32]);
            }
            other => panic!("expected GetAccepted, got {:?}", other),
        }
    }

    #[test]
    fn test_chits_roundtrip() {
        let msg = NetworkMessage::Chits {
            chain_id: ChainId([0xAA; 32]),
            request_id: 77,
            preferred_id: BlockId([1u8; 32]),
            preferred_id_at_height: BlockId([2u8; 32]),
            accepted_id: BlockId([3u8; 32]),
        };
        let encoded = msg.encode_proto().unwrap();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::Chits {
                request_id,
                preferred_id,
                accepted_id,
                ..
            } => {
                assert_eq!(request_id, 77);
                assert_eq!(preferred_id.0, [1u8; 32]);
                assert_eq!(accepted_id.0, [3u8; 32]);
            }
            other => panic!("expected Chits, got {:?}", other),
        }
    }

    #[test]
    fn test_app_request_compressed_roundtrip() {
        let msg = NetworkMessage::AppRequest {
            chain_id: ChainId([0; 32]),
            request_id: 1,
            deadline: 10_000_000_000,
            app_bytes: vec![0x42; 2048],
        };
        let encoded = msg.encode_proto().unwrap();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::AppRequest { app_bytes, .. } => {
                assert_eq!(app_bytes.len(), 2048);
                assert!(app_bytes.iter().all(|&b| b == 0x42));
            }
            other => panic!("expected AppRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_peer_list_roundtrip() {
        let peers = vec![PeerInfo {
            node_id: NodeId([5u8; 20]),
            ip_addr: vec![10, 0, 0, 1],
            ip_port: 9651,
            cert_bytes: vec![0xDE; 100],
            timestamp: 1700000000,
            signature: vec![0xAB; 64],
        }];
        let msg = NetworkMessage::PeerList {
            peers: peers.clone(),
        };
        let encoded = msg.encode_proto().unwrap();
        let decoded = NetworkMessage::decode_proto(&encoded).unwrap();
        match decoded {
            NetworkMessage::PeerList {
                peers: decoded_peers,
            } => {
                assert_eq!(decoded_peers.len(), 1);
                assert_eq!(decoded_peers[0].ip_port, 9651);
                assert_eq!(decoded_peers[0].cert_bytes.len(), 100);
            }
            other => panic!("expected PeerList, got {:?}", other),
        }
    }

    #[test]
    fn test_compression_reduces_size() {
        // A message with highly compressible data
        let msg = NetworkMessage::Put {
            chain_id: ChainId([0; 32]),
            request_id: 1,
            container: vec![0xAA; 4096],
        };
        let compressed = msg.encode_proto().unwrap();

        // Encode without compression for comparison
        let proto_msg = msg.to_proto().unwrap();
        let raw = proto_msg.encode_to_vec();
        let uncompressed_len = 4 + raw.len();

        assert!(
            compressed.len() < uncompressed_len,
            "compressed {} should be < uncompressed {}",
            compressed.len(),
            uncompressed_len
        );
    }

    #[test]
    fn test_parse_version_string() {
        assert_eq!(parse_version("avalanche/1.11.3"), (1, 11, 3));
        assert_eq!(parse_version("1.2.3"), (1, 2, 3));
        assert_eq!(parse_version(""), (0, 0, 0));
    }

    #[test]
    fn test_short_message_error() {
        let result = NetworkMessage::decode_proto(&[0, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_message_types_encode() {
        // Verify every NetworkMessage variant can be encoded to proto
        let chain = ChainId([0; 32]);
        let block = BlockId([0; 32]);
        let messages = vec![
            NetworkMessage::Ping { uptime: 100 },
            NetworkMessage::Pong { uptime: 100 },
            NetworkMessage::Version {
                network_id: 1,
                node_id: NodeId([0; 20]),
                my_time: 0,
                ip_addr: vec![],
                ip_port: 9651,
                my_version: "1.0.0".into(),
                my_version_time: 0,
                sig: vec![],
                tracked_subnets: vec![],
            },
            NetworkMessage::PeerList { peers: vec![] },
            NetworkMessage::PeerListAck { peer_ids: vec![] },
            NetworkMessage::GetStateSummaryFrontier {
                chain_id: chain.clone(),
                request_id: 0,
                deadline: 0,
            },
            NetworkMessage::StateSummaryFrontier {
                chain_id: chain.clone(),
                request_id: 0,
                summary: vec![],
            },
            NetworkMessage::GetAcceptedFrontier {
                chain_id: chain.clone(),
                request_id: 0,
                deadline: 0,
            },
            NetworkMessage::AcceptedFrontier {
                chain_id: chain.clone(),
                request_id: 0,
                container_id: block.clone(),
            },
            NetworkMessage::GetAccepted {
                chain_id: chain.clone(),
                request_id: 0,
                deadline: 0,
                container_ids: vec![],
            },
            NetworkMessage::Accepted {
                chain_id: chain.clone(),
                request_id: 0,
                container_ids: vec![],
            },
            NetworkMessage::Get {
                chain_id: chain.clone(),
                request_id: 0,
                deadline: 0,
                container_id: block.clone(),
            },
            NetworkMessage::Put {
                chain_id: chain.clone(),
                request_id: 0,
                container: vec![],
            },
            NetworkMessage::PushQuery {
                chain_id: chain.clone(),
                request_id: 0,
                deadline: 0,
                container: vec![],
            },
            NetworkMessage::PullQuery {
                chain_id: chain.clone(),
                request_id: 0,
                deadline: 0,
                container_id: block.clone(),
            },
            NetworkMessage::Chits {
                chain_id: chain.clone(),
                request_id: 0,
                preferred_id: block.clone(),
                preferred_id_at_height: block.clone(),
                accepted_id: block.clone(),
            },
            NetworkMessage::AppRequest {
                chain_id: chain.clone(),
                request_id: 0,
                deadline: 0,
                app_bytes: vec![],
            },
            NetworkMessage::AppResponse {
                chain_id: chain.clone(),
                request_id: 0,
                app_bytes: vec![],
            },
            NetworkMessage::AppGossip {
                chain_id: chain.clone(),
                app_bytes: vec![],
            },
        ];

        for msg in &messages {
            let encoded = msg
                .encode_proto()
                .expect(&format!("encode {:?}", msg.name()));
            let decoded =
                NetworkMessage::decode_proto(&encoded).expect(&format!("decode {:?}", msg.name()));
            assert_eq!(msg.name(), decoded.name());
        }
    }

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
            NetworkMessage::GetAcceptedFrontier {
                chain_id,
                request_id,
                ..
            } => {
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
            NetworkMessage::GetAncestors {
                request_id,
                container_id: cid,
                ..
            } => {
                assert_eq!(request_id, 5);
                assert_eq!(cid.0, [0xAA; 32]);
            }
            other => panic!("expected GetAncestors, got {:?}", other.name()),
        }
    }

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
}
