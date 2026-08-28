//! Vela identity, membership credentials, Noise handshakes and datagram AEAD.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce, Tag};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use snow::{Builder, HandshakeState, params::NoiseParams};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use vela_proto::NodeId;
use x25519_dalek::StaticSecret;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CryptoPolicy {
    PreferHybrid,
    RequireHybrid,
    ClassicalOnly,
}

#[derive(Clone)]
pub struct Identity {
    signing: SigningKey,
    noise_static: StaticSecret,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub node_id: NodeId,
    pub signing_public: [u8; 32],
    pub noise_public: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    signing_private: String,
    noise_private: String,
}

impl Identity {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
            noise_static: StaticSecret::random_from_rng(OsRng),
        }
    }

    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let path = path.as_ref();
        if path.exists() {
            return Self::load(path);
        }
        let identity = Self::generate();
        identity.save(path)?;
        Ok(identity)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let data = std::fs::read(path)?;
        let file: IdentityFile = serde_json::from_slice(&data)?;
        let signing_private = BASE64
            .decode(file.signing_private)
            .map_err(|_| CryptoError::InvalidKey)?;
        let noise_private = BASE64
            .decode(file.noise_private)
            .map_err(|_| CryptoError::InvalidKey)?;
        let signing_private: [u8; 32] = signing_private
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let noise_private: [u8; 32] = noise_private
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            signing: SigningKey::from_bytes(&signing_private),
            noise_static: StaticSecret::from(noise_private),
        })
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), CryptoError> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = IdentityFile {
            signing_private: BASE64.encode(self.signing.to_bytes()),
            noise_private: BASE64.encode(self.noise_static.to_bytes()),
        };
        let data = serde_json::to_vec_pretty(&file)?;
        let temporary = path.as_ref().with_extension("tmp");
        std::fs::write(&temporary, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(temporary, path)?;
        Ok(())
    }

    pub fn public(&self) -> PublicIdentity {
        let signing_public = self.signing.verifying_key().to_bytes();
        let node_id = NodeId::new(*blake3::hash(&signing_public).as_bytes());
        PublicIdentity {
            node_id,
            signing_public,
            noise_public: x25519_dalek::PublicKey::from(&self.noise_static).to_bytes(),
        }
    }

    pub fn signing_public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
    pub fn noise_private(&self) -> [u8; 32] {
        self.noise_static.to_bytes()
    }
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MembershipCredential {
    pub node_id: NodeId,
    pub signing_public: [u8; 32],
    pub noise_public: [u8; 32],
    pub tenant: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub server_key_id: [u8; 32],
    pub signature: Vec<u8>,
}

impl MembershipCredential {
    pub fn unsigned(
        identity: &PublicIdentity,
        tenant: impl Into<String>,
        expires_at: u64,
        server_key_id: [u8; 32],
    ) -> Self {
        Self {
            node_id: identity.node_id,
            signing_public: identity.signing_public,
            noise_public: identity.noise_public,
            tenant: tenant.into(),
            issued_at: unix_time(),
            expires_at,
            server_key_id,
            signature: vec![0; 64],
        }
    }

    pub fn sign(mut self, server: &ServerSigner) -> Self {
        self.signature = server.sign(&self.signing_bytes()).to_vec();
        self
    }

    pub fn verify(&self, server_public: &[u8; 32], now: u64) -> Result<(), CryptoError> {
        if self.expires_at < self.issued_at
            || self.expires_at < now
            || self.issued_at > now.saturating_add(60)
        {
            return Err(CryptoError::CredentialExpired);
        }
        if self.server_key_id != *blake3::hash(server_public).as_bytes() {
            return Err(CryptoError::InvalidSignature);
        }
        if self.node_id != NodeId::new(*blake3::hash(&self.signing_public).as_bytes()) {
            return Err(CryptoError::InvalidSignature);
        }
        let verifying =
            VerifyingKey::from_bytes(server_public).map_err(|_| CryptoError::InvalidKey)?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        verifying
            .verify(&self.signing_bytes(), &Signature::from_bytes(&signature))
            .map_err(|_| CryptoError::InvalidSignature)
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(32 + 32 + 32 + self.tenant.len() + 16 + 32);
        data.extend_from_slice(self.node_id.as_bytes());
        data.extend_from_slice(&self.signing_public);
        data.extend_from_slice(&self.noise_public);
        data.extend_from_slice(&(self.tenant.len() as u32).to_be_bytes());
        data.extend_from_slice(self.tenant.as_bytes());
        data.extend_from_slice(&self.issued_at.to_be_bytes());
        data.extend_from_slice(&self.expires_at.to_be_bytes());
        data.extend_from_slice(&self.server_key_id);
        data
    }
}

pub struct ServerSigner {
    signing: SigningKey,
}

impl ServerSigner {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }
    pub fn load_or_generate(path: impl AsRef<Path>) -> Result<Self, CryptoError> {
        let path = path.as_ref();
        if path.exists() {
            let data = std::fs::read(path)?;
            let bytes: [u8; 32] = BASE64
                .decode(data)
                .map_err(|_| CryptoError::InvalidKey)?
                .try_into()
                .map_err(|_| CryptoError::InvalidKey)?;
            Ok(Self {
                signing: SigningKey::from_bytes(&bytes),
            })
        } else {
            let signer = Self::generate();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, BASE64.encode(signer.signing.to_bytes()))?;
            Ok(signer)
        }
    }
    pub fn public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }
    pub fn key_id(&self) -> [u8; 32] {
        *blake3::hash(&self.public()).as_bytes()
    }
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

pub struct NoiseHandshake {
    state: HandshakeState,
}

impl NoiseHandshake {
    pub fn initiator(
        identity: &Identity,
        peer_noise_public: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|_| CryptoError::Noise)?;
        let state = Builder::new(params)
            .local_private_key(&identity.noise_private())
            .remote_public_key(peer_noise_public)
            .build_initiator()
            .map_err(|_| CryptoError::Noise)?;
        Ok(Self { state })
    }

    pub fn responder(identity: &Identity) -> Result<Self, CryptoError> {
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|_| CryptoError::Noise)?;
        let state = Builder::new(params)
            .local_private_key(&identity.noise_private())
            .build_responder()
            .map_err(|_| CryptoError::Noise)?;
        Ok(Self { state })
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0u8; 2048];
        let len = self
            .state
            .write_message(payload, &mut out)
            .map_err(|_| CryptoError::Noise)?;
        out.truncate(len);
        Ok(out)
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0u8; 2048];
        let len = self
            .state
            .read_message(message, &mut out)
            .map_err(|_| CryptoError::Noise)?;
        out.truncate(len);
        Ok(out)
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    pub fn into_session(self) -> Result<SessionKeys, CryptoError> {
        if !self.state.is_handshake_finished() {
            return Err(CryptoError::Noise);
        }
        let hash = self.state.get_handshake_hash().to_vec();
        let mut initiator = [0u8; 32];
        let mut responder = [0u8; 32];
        Hkdf::<Sha256>::new(Some(b"vela datagram session"), &hash)
            .expand(b"initiator", &mut initiator)
            .map_err(|_| CryptoError::Noise)?;
        Hkdf::<Sha256>::new(Some(b"vela datagram session"), &hash)
            .expand(b"responder", &mut responder)
            .map_err(|_| CryptoError::Noise)?;
        Ok(SessionKeys {
            initiator,
            responder,
        })
    }
}

#[derive(Clone)]
pub struct SessionKeys {
    pub initiator: [u8; 32],
    pub responder: [u8; 32],
}

impl SessionKeys {
    pub fn cipher(&self, initiator: bool) -> SessionCipher {
        let tx_key = if initiator {
            self.initiator
        } else {
            self.responder
        };
        let rx_key = if initiator {
            self.responder
        } else {
            self.initiator
        };
        SessionCipher {
            tx: ChaCha20Poly1305::new_from_slice(&tx_key).expect("fixed-size AEAD key"),
            rx: ChaCha20Poly1305::new_from_slice(&rx_key).expect("fixed-size AEAD key"),
        }
    }
}

#[derive(Clone)]
pub struct SessionCipher {
    tx: ChaCha20Poly1305,
    rx: ChaCha20Poly1305,
}

impl SessionCipher {
    pub fn encrypt(
        &self,
        sequence: u64,
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = nonce(sequence);
        let mut out = plaintext.to_vec();
        let tag = self
            .tx
            .encrypt_in_place_detached(&nonce, associated_data, &mut out)
            .map_err(|_| CryptoError::Aead)?;
        out.extend_from_slice(&tag);
        Ok(out)
    }

    pub fn decrypt(
        &self,
        sequence: u64,
        associated_data: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext_and_tag.len() < 16 {
            return Err(CryptoError::Aead);
        }
        let split = ciphertext_and_tag.len() - 16;
        let mut out = ciphertext_and_tag[..split].to_vec();
        let tag = Tag::from_slice(&ciphertext_and_tag[split..]);
        self.rx
            .decrypt_in_place_detached(&nonce(sequence), associated_data, &mut out, tag)
            .map_err(|_| CryptoError::Aead)?;
        Ok(out)
    }
}

fn nonce(sequence: u64) -> Nonce {
    let mut bytes = [0u8; 12];
    bytes[4..].copy_from_slice(&sequence.to_be_bytes());
    *Nonce::from_slice(&bytes)
}
fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("invalid key")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("credential expired or not yet valid")]
    CredentialExpired,
    #[error("Noise handshake failed")]
    Noise,
    #[error("AEAD operation failed")]
    Aead,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_node_id_is_stable() {
        let identity = Identity::generate();
        assert_eq!(
            identity.public().node_id.as_bytes(),
            blake3::hash(&identity.signing_public()).as_bytes()
        );
    }

    #[test]
    fn noise_and_datagram_cipher_round_trip() {
        let initiator_identity = Identity::generate();
        let responder_identity = Identity::generate();
        let mut initiator = NoiseHandshake::initiator(
            &initiator_identity,
            &responder_identity.public().noise_public,
        )
        .unwrap();
        let mut responder = NoiseHandshake::responder(&responder_identity).unwrap();
        let first = initiator.write_message(b"probe").unwrap();
        responder.read_message(&first).unwrap();
        let second = responder.write_message(b"reply").unwrap();
        initiator.read_message(&second).unwrap();
        assert!(initiator.is_finished() && responder.is_finished());
        let a = initiator.into_session().unwrap();
        let b = responder.into_session().unwrap();
        let ca = a.cipher(true);
        let cb = b.cipher(false);
        let encrypted = ca.encrypt(1, b"header", b"payload").unwrap();
        assert_eq!(cb.decrypt(1, b"header", &encrypted).unwrap(), b"payload");
    }

    #[test]
    fn membership_credential_binds_identity_and_server_key() {
        let identity = Identity::generate();
        let signer = ServerSigner::generate();
        let credential = MembershipCredential::unsigned(
            &identity.public(),
            "test",
            unix_time() + 60,
            signer.key_id(),
        )
        .sign(&signer);
        credential.verify(&signer.public(), unix_time()).unwrap();
        let other = ServerSigner::generate();
        assert!(credential.verify(&other.public(), unix_time()).is_err());
    }
}
