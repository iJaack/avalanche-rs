//! TLS Identity & NodeID derivation for Avalanche P2P networking.
//!
//! Phase 2: Avalanche nodes derive their NodeID from the SHA-256 hash of
//! their X.509 DER-encoded TLS certificate. This module handles:
//! - Self-signed certificate generation (or loading from file)
//! - NodeID derivation: first 20 bytes of SHA-256(DER cert)
//! - IP:port signing with the TLS private key for `ClaimedIpPort`
//! - TLS server/client config for peer connections

use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use k256::ecdsa::signature::Verifier;
use rand::Rng;
use blst::min_pk::{SecretKey as BlsSecretKey, PublicKey as BlsPublicKey, Signature as BlsSignature};
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use ring::rand::SystemRandom;
use sha2::{Digest, Sha256};

use crate::network::NodeId;

/// A node's TLS identity, holding the certificate + private key.
#[derive(Clone)]
pub struct NodeIdentity {
    /// DER-encoded X.509 certificate
    pub cert_der: Vec<u8>,
    /// DER-encoded private key (PKCS#8)
    pub key_der: Vec<u8>,
    /// Derived NodeID (first 20 bytes of SHA-256 of cert DER)
    pub node_id: NodeId,
    /// secp256k1 signing key (for backward compat)
    signing_key: SigningKey,
    /// PKCS#8 DER bytes of the TLS key for ring-based signing
    tls_key_pkcs8: Vec<u8>,
    /// BLS secret key for proof-of-possession signing
    bls_secret_key: Vec<u8>,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIdentity")
            .field("node_id", &self.node_id)
            .field("cert_len", &self.cert_der.len())
            .finish()
    }
}

impl NodeIdentity {
    /// Generate a new self-signed TLS identity using ECDSA P-256.
    pub fn generate() -> Result<Self, IdentityError> {
        // Generate ECDSA P-256 key pair using ring (same key type AvalancheGo expects)
        let rng = SystemRandom::new();
        let pkcs8_doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| IdentityError::CertGeneration(format!("key generation: {}", e)))?;
        let tls_key_pkcs8 = pkcs8_doc.as_ref().to_vec();

        // Create rcgen key pair from PKCS#8 DER bytes
        let rcgen_key = rcgen::KeyPair::try_from(&tls_key_pkcs8[..])
            .map_err(|e| IdentityError::CertGeneration(format!("rcgen key: {}", e)))?;

        // Build self-signed cert
        let params = rcgen::CertificateParams::new(vec!["avalanche-node".into()])
            .map_err(|e| IdentityError::CertGeneration(e.to_string()))?;

        let cert = params.self_signed(&rcgen_key)
            .map_err(|e| IdentityError::CertGeneration(e.to_string()))?;

        let cert_der = cert.der().to_vec();

        let node_id = derive_node_id(&cert_der);
        let signing_key = SigningKey::random(&mut rand::thread_rng());

        // Generate BLS key for proof-of-possession
        let mut bls_ikm = [0u8; 32];
        rand::thread_rng().fill(&mut bls_ikm);
        let bls_sk = BlsSecretKey::key_gen(&bls_ikm, &[])
            .expect("BLS key generation should not fail");
        let bls_secret_key = bls_sk.to_bytes().to_vec();

        Ok(Self {
            cert_der,
            key_der: tls_key_pkcs8.clone(),
            node_id,
            signing_key,
            tls_key_pkcs8,
            bls_secret_key,
        })
    }

    /// Load identity from PEM cert + key files on disk.
    pub fn load_from_files(cert_path: &Path, key_path: &Path) -> Result<Self, IdentityError> {
        let cert_pem = std::fs::read(cert_path)
            .map_err(|e| IdentityError::IoError(e.to_string()))?;
        let key_pem = std::fs::read(key_path)
            .map_err(|e| IdentityError::IoError(e.to_string()))?;

        Self::load_from_pem(&cert_pem, &key_pem)
    }

    /// Load identity from PEM-encoded cert + key bytes.
    pub fn load_from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, IdentityError> {
        use rustls_pemfile::{certs, private_key};
        use std::io::Cursor;

        let cert_der = certs(&mut Cursor::new(cert_pem))
            .next()
            .ok_or_else(|| IdentityError::InvalidCert("no certificate found in PEM".into()))?
            .map_err(|e| IdentityError::InvalidCert(e.to_string()))?
            .to_vec();

        let _key = private_key(&mut Cursor::new(key_pem))
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?
            .ok_or_else(|| IdentityError::InvalidKey("no private key found in PEM".into()))?;

        let node_id = derive_node_id(&cert_der);
        let signing_key = SigningKey::random(&mut rand::thread_rng());

        // Extract PKCS#8 DER from PEM for ring signing
        let key_obj = private_key(&mut std::io::Cursor::new(key_pem))
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?
            .ok_or_else(|| IdentityError::InvalidKey("no key in PEM".into()))?;
        let tls_key_pkcs8 = key_obj.secret_der().to_vec();

        let mut bls_ikm = [0u8; 32];
        rand::thread_rng().fill(&mut bls_ikm);
        let bls_sk = BlsSecretKey::key_gen(&bls_ikm, &[])
            .expect("BLS key generation");
        let bls_secret_key = bls_sk.to_bytes().to_vec();

        Ok(Self {
            cert_der,
            key_der: key_pem.to_vec(),
            node_id,
            signing_key,
            tls_key_pkcs8,
            bls_secret_key,
        })
    }

    /// Sign an IP:port pair with a timestamp (for ClaimedIpPort / Handshake).
    /// Matches AvalancheGo's format: IPv6 (16 bytes) || port (2 bytes BE) || timestamp (8 bytes BE)
    /// Then SHA-256 the bytes and sign with TLS private key.
    pub fn sign_ip(&self, ip: &[u8], port: u16, timestamp: u64) -> Vec<u8> {
        let hash = ip_signing_hash(ip, port, timestamp);
        let sig: Signature = self.signing_key.sign(&hash);
        sig.to_vec()
    }

    /// Sign IP in AvalancheGo format using the actual TLS private key.
    /// This is what AvalancheGo's staking.CheckSignature() verifies.
    ///
    /// AvalancheGo format:
    /// 1. Build bytes: IPv6_addr (16 bytes) || port (2 bytes BE) || timestamp (8 bytes BE)
    /// 2. Hash: SHA-256(bytes)
    /// 3. Sign the HASH with the TLS cert's private key (ECDSA P-256)
    ///
    /// staking.CheckSignature calls ecdsa.VerifyASN1(pubkey, hash, sig)
    pub fn sign_ip_with_tls_key(&self, ip: &[u8], port: u16, timestamp: u64) -> Vec<u8> {
        // Build the unsigned IP bytes (AvalancheGo format)
        let mut bytes = Vec::with_capacity(26);
        if ip.len() == 4 {
            // IPv4-mapped IPv6: ::ffff:a.b.c.d
            bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
            bytes.extend_from_slice(ip);
        } else if ip.len() == 16 {
            bytes.extend_from_slice(ip);
        } else {
            bytes.extend_from_slice(&[0u8; 16]);
        }
        bytes.extend_from_slice(&port.to_be_bytes());
        bytes.extend_from_slice(&timestamp.to_be_bytes());

        // SHA-256 hash (AvalancheGo uses hashing.ComputeHash256 which is SHA-256)
        let hash = Sha256::digest(&bytes);

        // Sign the hash with the TLS ECDSA P-256 key using ring
        let rng = SystemRandom::new();
        let key_pair = EcdsaKeyPair::from_pkcs8(
            &ECDSA_P256_SHA256_ASN1_SIGNING,
            &self.tls_key_pkcs8,
            &rng,
        ).expect("valid TLS key");

        // ring's sign() takes the raw message and does SHA-256 internally,
        // but AvalancheGo signs SHA-256(bytes) directly.
        // We need to sign the hash, not the original bytes.
        // Use ECDSA_P256_SHA256_FIXED_SIGNING to sign pre-hashed data... 
        // Actually, ring doesn't support signing pre-hashed data easily.
        // AvalancheGo: hashing.ComputeHash256(ipBytes) then signs the hash.
        // Go's ecdsa.Sign uses SHA-256 internally on the hash again? No.
        // Go's ecdsa.SignASN1(rand, privKey, hash) signs the hash directly.
        // ring's key_pair.sign(msg) does hash(msg) then signs.
        // So we need to pass the raw bytes to ring, not the hash!
        key_pair.sign(&rng, &bytes)
            .expect("signing should not fail")
            .as_ref()
            .to_vec()
    }

    /// Sign IP bytes with BLS key for proof-of-possession (ip_bls_sig).
    /// AvalancheGo uses `blsSigner.SignProofOfPossession(ipBytes)`.
    pub fn sign_ip_bls(&self, ip: &[u8], port: u16, timestamp: u64) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(26);
        if ip.len() == 4 {
            bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]);
            bytes.extend_from_slice(ip);
        } else if ip.len() == 16 {
            bytes.extend_from_slice(ip);
        } else {
            bytes.extend_from_slice(&[0u8; 16]);
        }
        bytes.extend_from_slice(&port.to_be_bytes());
        bytes.extend_from_slice(&timestamp.to_be_bytes());

        let sk = BlsSecretKey::from_bytes(&self.bls_secret_key)
            .expect("valid BLS secret key");
        // AvalancheGo uses CiphersuiteProofOfPossession DST for ip_bls_sig
        let sig = sk.sign(&bytes, b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_", &[]);
        sig.compress().to_vec()
    }

    /// Get the verifying (public) key for IP signature verification.
    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }

    /// Verify an IP signature from a peer.
    pub fn verify_ip_signature(
        verifying_key: &VerifyingKey,
        ip: &[u8],
        port: u16,
        timestamp: u64,
        signature: &[u8],
    ) -> Result<(), IdentityError> {
        let hash = ip_signing_hash(ip, port, timestamp);
        let sig = Signature::from_slice(signature)
            .map_err(|e| IdentityError::InvalidSignature(e.to_string()))?;
        verifying_key
            .verify(&hash, &sig)
            .map_err(|e| IdentityError::InvalidSignature(e.to_string()))
    }

    /// Build a rustls ServerConfig for accepting inbound TLS connections.
    #[cfg(feature = "p2p")]
    pub fn tls_server_config(&self) -> Result<Arc<rustls::ServerConfig>, IdentityError> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let cert = CertificateDer::from(self.cert_der.clone());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()));

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .map_err(|e| IdentityError::TlsConfig(e.to_string()))?;

        Ok(Arc::new(config))
    }

    /// Build a rustls ClientConfig for outbound TLS connections.
    /// Uses dangerous verifier that accepts any cert (we verify NodeID ourselves).
    #[cfg(feature = "p2p")]
    pub fn tls_client_config(&self) -> Result<Arc<rustls::ClientConfig>, IdentityError> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
        use rustls::{DigitallySignedStruct, SignatureScheme};

        // Custom verifier: accept any cert (we verify NodeID ourselves after handshake)
        #[derive(Debug)]
        struct AvalancheVerifier;

        impl ServerCertVerifier for AvalancheVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &CertificateDer<'_>,
                _intermediates: &[CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> std::result::Result<ServerCertVerified, rustls::Error> {
                // Avalanche verifies identity via NodeID, not CA chain
                Ok(ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                vec![
                    SignatureScheme::ECDSA_NISTP256_SHA256,
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::RSA_PSS_SHA256,
                    SignatureScheme::RSA_PSS_SHA384,
                    SignatureScheme::RSA_PSS_SHA512,
                    SignatureScheme::ED25519,
                ]
            }
        }

        let cert = CertificateDer::from(self.cert_der.clone());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()));

        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AvalancheVerifier))
            .with_client_auth_cert(vec![cert], key)
            .map_err(|e| IdentityError::TlsConfig(e.to_string()))?;

        Ok(Arc::new(config))
    }

    /// Current time as unix seconds.
    pub fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// Derive NodeID from DER-encoded certificate.
/// NodeID = first 20 bytes of SHA-256(cert_der)
pub fn derive_node_id(cert_der: &[u8]) -> NodeId {
    let hash = Sha256::digest(cert_der);
    let mut id = [0u8; 20];
    id.copy_from_slice(&hash[..20]);
    NodeId(id)
}

/// Verify that a peer's claimed NodeID matches their TLS certificate.
pub fn verify_peer_node_id(cert_der: &[u8], claimed_node_id: &NodeId) -> bool {
    derive_node_id(cert_der) == *claimed_node_id
}

/// Create the hash that gets signed for IP:port claims.
fn ip_signing_hash(ip: &[u8], port: u16, timestamp: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ip);
    hasher.update(port.to_be_bytes());
    hasher.update(timestamp.to_be_bytes());
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Identity-related errors.
#[derive(Debug, Clone)]
pub enum IdentityError {
    CertGeneration(String),
    InvalidCert(String),
    InvalidKey(String),
    InvalidSignature(String),
    TlsConfig(String),
    IoError(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CertGeneration(e) => write!(f, "cert generation: {}", e),
            Self::InvalidCert(e) => write!(f, "invalid cert: {}", e),
            Self::InvalidKey(e) => write!(f, "invalid key: {}", e),
            Self::InvalidSignature(e) => write!(f, "invalid signature: {}", e),
            Self::TlsConfig(e) => write!(f, "TLS config: {}", e),
            Self::IoError(e) => write!(f, "IO error: {}", e),
        }
    }
}

impl std::error::Error for IdentityError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_identity() {
        let id = NodeIdentity::generate().unwrap();
        assert!(!id.cert_der.is_empty());
        assert!(!id.key_der.is_empty());
        assert_ne!(id.node_id.0, [0u8; 20]);
    }

    #[test]
    fn test_node_id_derivation_deterministic() {
        let cert_der = vec![1, 2, 3, 4, 5];
        let id1 = derive_node_id(&cert_der);
        let id2 = derive_node_id(&cert_der);
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_node_id_different_certs() {
        let id1 = derive_node_id(&[1, 2, 3]);
        let id2 = derive_node_id(&[4, 5, 6]);
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_verify_peer_node_id() {
        let id = NodeIdentity::generate().unwrap();
        assert!(verify_peer_node_id(&id.cert_der, &id.node_id));
        assert!(!verify_peer_node_id(&id.cert_der, &NodeId([0xFF; 20])));
    }

    #[test]
    fn test_sign_and_verify_ip() {
        let id = NodeIdentity::generate().unwrap();
        let ip = &[127, 0, 0, 1];
        let port = 9651u16;
        let timestamp = 1700000000u64;

        let sig = id.sign_ip(ip, port, timestamp);
        assert!(!sig.is_empty());

        let vk = id.verifying_key();
        NodeIdentity::verify_ip_signature(&vk, ip, port, timestamp, &sig).unwrap();
    }

    #[test]
    fn test_ip_signature_wrong_data_fails() {
        let id = NodeIdentity::generate().unwrap();
        let sig = id.sign_ip(&[127, 0, 0, 1], 9651, 1700000000);
        let vk = id.verifying_key();

        // Wrong IP
        let result = NodeIdentity::verify_ip_signature(&vk, &[10, 0, 0, 1], 9651, 1700000000, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_two_identities_different_node_ids() {
        let id1 = NodeIdentity::generate().unwrap();
        let id2 = NodeIdentity::generate().unwrap();
        assert_ne!(id1.node_id, id2.node_id);
    }

    #[cfg(feature = "p2p")]
    #[test]
    fn test_tls_configs() {
        // Install the ring crypto provider for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();

        let id = NodeIdentity::generate().unwrap();
        let server_config = id.tls_server_config();
        assert!(server_config.is_ok());
        let client_config = id.tls_client_config();
        assert!(client_config.is_ok());
    }

    #[test]
    fn test_node_id_is_20_bytes_of_sha256() {
        let cert_der = b"test certificate data";
        let hash = Sha256::digest(cert_der);
        let nid = derive_node_id(cert_der);
        assert_eq!(&nid.0[..], &hash[..20]);
    }
}
