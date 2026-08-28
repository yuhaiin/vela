//! Versioned control and data-plane types shared by Vela clients and servers.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::{fmt, net::SocketAddr, str::FromStr};
use thiserror::Error;

pub const MAGIC: [u8; 4] = *b"VELA";
pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 26;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct NodeId(#[serde(with = "node_id_serde")] pub [u8; 32]);

impl NodeId {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vela:{}", hex_encode(&self.0))
    }
}

impl NodeId {
    pub fn short(&self) -> String {
        format!("vela:{}", hex_encode(&self.0[..8]))
    }
}

impl FromStr for NodeId {
    type Err = ProtoError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.strip_prefix("vela:").unwrap_or(value);
        let bytes = hex_decode(value)?;
        if bytes.len() != 32 {
            return Err(ProtoError::InvalidNodeId);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

mod node_id_serde {
    use super::*;

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&BASE64.encode(value))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes = BASE64.decode(value).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("NodeId must be 32 bytes"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Candidate {
    Host(SocketAddr),
    ServerReflexive(SocketAddr),
    PeerReflexive(SocketAddr),
}

impl Candidate {
    pub fn address(&self) -> SocketAddr {
        match self {
            Self::Host(addr) | Self::ServerReflexive(addr) | Self::PeerReflexive(addr) => *addr,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    Probe = 1,
    ProbeResponse = 2,
    Handshake = 3,
    Data = 4,
    KeepAlive = 5,
    DiagnosticPing = 6,
    DiagnosticPong = 7,
}

impl TryFrom<u8> for PacketType {
    type Error = ProtoError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Probe),
            2 => Ok(Self::ProbeResponse),
            3 => Ok(Self::Handshake),
            4 => Ok(Self::Data),
            5 => Ok(Self::KeepAlive),
            6 => Ok(Self::DiagnosticPing),
            7 => Ok(Self::DiagnosticPong),
            _ => Err(ProtoError::UnknownPacketType(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub version: u8,
    pub packet_type: PacketType,
    pub flags: u16,
    pub session_id: u64,
    pub sequence: u64,
    pub payload_len: u16,
}

impl Header {
    pub fn new(
        packet_type: PacketType,
        session_id: u64,
        sequence: u64,
        payload_len: usize,
    ) -> Result<Self, ProtoError> {
        let payload_len = u16::try_from(payload_len).map_err(|_| ProtoError::PayloadTooLarge)?;
        Ok(Self {
            version: PROTOCOL_VERSION,
            packet_type,
            flags: 0,
            session_id,
            sequence,
            payload_len,
        })
    }

    pub fn encode(&self, out: &mut BytesMut) {
        out.put_slice(&MAGIC);
        out.put_u8(self.version);
        out.put_u8(self.packet_type as u8);
        out.put_u16(self.flags);
        out.put_u64(self.session_id);
        out.put_u64(self.sequence);
        out.put_u16(self.payload_len);
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProtoError> {
        if input.len() < HEADER_LEN {
            return Err(ProtoError::Truncated);
        }
        if input[..4] != MAGIC {
            return Err(ProtoError::InvalidMagic);
        }
        let version = input[4];
        if version != PROTOCOL_VERSION {
            return Err(ProtoError::UnsupportedVersion(version));
        }
        let packet_type = PacketType::try_from(input[5])?;
        let flags = u16::from_be_bytes([input[6], input[7]]);
        let session_id = u64::from_be_bytes(input[8..16].try_into().expect("checked header"));
        let sequence = u64::from_be_bytes(input[16..24].try_into().expect("checked header"));
        let payload_len = u16::from_be_bytes([input[24], input[25]]);
        Ok(Self {
            version,
            packet_type,
            flags,
            session_id,
            sequence,
            payload_len,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WirePacket {
    pub header: Header,
    pub payload: Bytes,
}

impl WirePacket {
    pub fn encode(&self) -> Result<Bytes, ProtoError> {
        if self.payload.len() != self.header.payload_len as usize {
            return Err(ProtoError::LengthMismatch);
        }
        let mut out = BytesMut::with_capacity(HEADER_LEN + self.payload.len());
        self.header.encode(&mut out);
        out.extend_from_slice(&self.payload);
        Ok(out.freeze())
    }

    pub fn decode(input: &[u8]) -> Result<Self, ProtoError> {
        let header = Header::decode(input)?;
        let end = HEADER_LEN + header.payload_len as usize;
        if input.len() < end {
            return Err(ProtoError::Truncated);
        }
        if input.len() != end {
            return Err(ProtoError::TrailingBytes);
        }
        Ok(Self {
            header,
            payload: Bytes::copy_from_slice(&input[HEADER_LEN..end]),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicPeerInfo {
    pub node_id: NodeId,
    pub signing_public: String,
    pub noise_public: String,
    pub candidates: Vec<Candidate>,
    pub credential: String,
    pub capabilities: Vec<PeerCapability>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerCapability {
    DiagnosticPing,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerSummary {
    pub node_id: NodeId,
    pub online: bool,
    pub capabilities: Vec<PeerCapability>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub signing_public: [u8; 32],
    pub noise_public: [u8; 32],
    pub candidates: Vec<Candidate>,
    pub credential: Vec<u8>,
    pub capabilities: Vec<PeerCapability>,
}

impl TryFrom<PublicPeerInfo> for PeerInfo {
    type Error = ProtoError;

    fn try_from(value: PublicPeerInfo) -> Result<Self, Self::Error> {
        let signing_public = BASE64
            .decode(value.signing_public)
            .map_err(|_| ProtoError::InvalidEncoding)?;
        let noise_public = BASE64
            .decode(value.noise_public)
            .map_err(|_| ProtoError::InvalidEncoding)?;
        let credential = BASE64
            .decode(value.credential)
            .map_err(|_| ProtoError::InvalidEncoding)?;
        Ok(Self {
            node_id: value.node_id,
            signing_public: signing_public
                .try_into()
                .map_err(|_| ProtoError::InvalidEncoding)?,
            noise_public: noise_public
                .try_into()
                .map_err(|_| ProtoError::InvalidEncoding)?,
            candidates: value.candidates,
            credential,
            capabilities: value.capabilities,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlMessage {
    Register {
        node_id: NodeId,
        signing_public: String,
        noise_public: String,
        credential: String,
        invite_token: Option<String>,
        candidates: Vec<Candidate>,
        capabilities: Vec<PeerCapability>,
    },
    RegisterOk {
        credential: String,
        peers: Vec<PublicPeerInfo>,
    },
    UpdateCandidates {
        candidates: Vec<Candidate>,
    },
    LookupPeer {
        node_id: NodeId,
    },
    PeerInfo {
        peer: PublicPeerInfo,
    },
    ListPeers,
    ListPeersOk {
        peers: Vec<PeerSummary>,
    },
    ConnectSignal {
        from: PublicPeerInfo,
        to: NodeId,
    },
    Revoke {
        node_id: NodeId,
    },
    Error {
        code: String,
        message: String,
    },
    Ping {
        nonce: u64,
    },
    Pong {
        nonce: u64,
    },
}

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("truncated packet")]
    Truncated,
    #[error("invalid Vela magic")]
    InvalidMagic,
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown packet type {0}")]
    UnknownPacketType(u8),
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("packet length mismatch")]
    LengthMismatch,
    #[error("trailing bytes after packet")]
    TrailingBytes,
    #[error("invalid NodeId")]
    InvalidNodeId,
    #[error("invalid encoding")]
    InvalidEncoding,
    #[error("invalid hex: {0}")]
    Hex(String),
}

fn hex_encode(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ProtoError> {
    if value.len() % 2 != 0 {
        return Err(ProtoError::InvalidNodeId);
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16).map_err(|e| ProtoError::Hex(e.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_packet_round_trips() {
        let payload = Bytes::from_static(b"hello");
        let header = Header::new(PacketType::Data, 7, 9, payload.len()).unwrap();
        let packet = WirePacket { header, payload };
        let encoded = packet.encode().unwrap();
        assert_eq!(WirePacket::decode(&encoded).unwrap(), packet);
    }

    #[test]
    fn malformed_wire_packet_is_rejected() {
        assert!(matches!(
            WirePacket::decode(b"bad"),
            Err(ProtoError::Truncated)
        ));
        let mut bytes = vec![0; HEADER_LEN];
        bytes[..4].copy_from_slice(b"NOPE");
        assert!(matches!(
            WirePacket::decode(&bytes),
            Err(ProtoError::InvalidMagic)
        ));
    }
}
