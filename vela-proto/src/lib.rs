//! Versioned control and data-plane types shared by Vela clients and servers.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::{BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};
use thiserror::Error;

pub const MAGIC: [u8; 4] = *b"VELA";
pub const PROTOCOL_VERSION: u8 = 2;
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
    pub virtual_ipv4: Option<Ipv4Addr>,
    pub virtual_ipv6: Option<Ipv6Addr>,
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
    pub virtual_ipv4: Option<Ipv4Addr>,
    pub virtual_ipv6: Option<Ipv6Addr>,
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
            virtual_ipv4: value.virtual_ipv4,
            virtual_ipv6: value.virtual_ipv6,
            credential,
            capabilities: value.capabilities,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv4Cidr {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Ipv6Cidr {
    pub address: Ipv6Addr,
    pub prefix_len: u8,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkSnapshot {
    pub network_id: [u8; 16],
    pub generation: u64,
    pub virtual_ipv4: Option<Ipv4Cidr>,
    pub virtual_ipv6: Option<Ipv6Cidr>,
    pub peers: Vec<PeerInfo>,
    pub expires_at: u64,
    pub signature: Vec<u8>,
}

impl NetworkSnapshot {
    pub fn validate(&self) -> Result<(), ProtoError> {
        if self.generation == 0 {
            return Err(ProtoError::InvalidSnapshot(
                "generation must be non-zero".into(),
            ));
        }
        if let Some(cidr) = self.virtual_ipv4 {
            if cidr.prefix_len > 32 {
                return Err(ProtoError::InvalidSnapshot(
                    "invalid IPv4 prefix length".into(),
                ));
            }
            if !ipv4_in_network(cidr.address, cidr.address, cidr.prefix_len) {
                return Err(ProtoError::InvalidSnapshot(
                    "IPv4 network address is not canonical".into(),
                ));
            }
        }
        if let Some(cidr) = self.virtual_ipv6 {
            if cidr.prefix_len > 128 {
                return Err(ProtoError::InvalidSnapshot(
                    "invalid IPv6 prefix length".into(),
                ));
            }
            if !ipv6_in_network(cidr.address, cidr.address, cidr.prefix_len) {
                return Err(ProtoError::InvalidSnapshot(
                    "IPv6 network address is not canonical".into(),
                ));
            }
        }
        let mut node_ids = std::collections::HashSet::new();
        let mut ipv4 = std::collections::HashSet::new();
        let mut ipv6 = std::collections::HashSet::new();
        for peer in &self.peers {
            if !node_ids.insert(peer.node_id)
                || peer.node_id != NodeId::new(*blake3::hash(&peer.signing_public).as_bytes())
            {
                return Err(ProtoError::InvalidSnapshot(
                    "invalid or duplicate peer identity".into(),
                ));
            }
            if let Some(address) = peer.virtual_ipv4 {
                let valid_network = self
                    .virtual_ipv4
                    .is_some_and(|cidr| ipv4_in_network(cidr.address, address, cidr.prefix_len));
                if !ipv4.insert(address) || !valid_network {
                    return Err(ProtoError::InvalidSnapshot(
                        "invalid or duplicate virtual IPv4".into(),
                    ));
                }
            }
            if let Some(address) = peer.virtual_ipv6 {
                let valid_network = self
                    .virtual_ipv6
                    .is_some_and(|cidr| ipv6_in_network(cidr.address, address, cidr.prefix_len));
                if !ipv6.insert(address) || !valid_network {
                    return Err(ProtoError::InvalidSnapshot(
                        "invalid or duplicate virtual IPv6".into(),
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(b"VELA-NETWORK-SNAPSHOT-v1");
        out.extend_from_slice(&self.network_id);
        out.extend_from_slice(&self.generation.to_be_bytes());
        encode_ipv4_cidr(&mut out, self.virtual_ipv4);
        encode_ipv6_cidr(&mut out, self.virtual_ipv6);
        out.extend_from_slice(&(self.peers.len() as u32).to_be_bytes());
        let mut peers = self.peers.clone();
        peers.sort_by_key(|peer| peer.node_id);
        for peer in peers {
            out.extend_from_slice(peer.node_id.as_bytes());
            out.extend_from_slice(&peer.signing_public);
            out.extend_from_slice(&peer.noise_public);
            match peer.virtual_ipv4 {
                Some(address) => {
                    out.push(1);
                    out.extend_from_slice(&address.octets());
                }
                None => out.push(0),
            }
            match peer.virtual_ipv6 {
                Some(address) => {
                    out.push(1);
                    out.extend_from_slice(&address.octets());
                }
                None => out.push(0),
            }
            out.extend_from_slice(&(peer.candidates.len() as u32).to_be_bytes());
            for candidate in peer.candidates {
                encode_candidate(&mut out, candidate);
            }
            out.extend_from_slice(&(peer.credential.len() as u32).to_be_bytes());
            out.extend_from_slice(&peer.credential);
            out.extend_from_slice(&(peer.capabilities.len() as u32).to_be_bytes());
            for capability in peer.capabilities {
                out.push(capability as u8);
            }
        }
        out.extend_from_slice(&self.expires_at.to_be_bytes());
        out
    }
}

fn ipv4_in_network(network: Ipv4Addr, address: Ipv4Addr, prefix_len: u8) -> bool {
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    u32::from(network) & mask == u32::from(address) & mask
        && u32::from(network) & mask == u32::from(network)
}

fn ipv6_in_network(network: Ipv6Addr, address: Ipv6Addr, prefix_len: u8) -> bool {
    let network = u128::from_be_bytes(network.octets());
    let address = u128::from_be_bytes(address.octets());
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    network & mask == address & mask && network & mask == network
}

fn encode_ipv4_cidr(out: &mut Vec<u8>, cidr: Option<Ipv4Cidr>) {
    match cidr {
        Some(cidr) => {
            out.push(1);
            out.extend_from_slice(&cidr.address.octets());
            out.push(cidr.prefix_len);
        }
        None => out.push(0),
    }
}

fn encode_ipv6_cidr(out: &mut Vec<u8>, cidr: Option<Ipv6Cidr>) {
    match cidr {
        Some(cidr) => {
            out.push(1);
            out.extend_from_slice(&cidr.address.octets());
            out.push(cidr.prefix_len);
        }
        None => out.push(0),
    }
}

fn encode_candidate(out: &mut Vec<u8>, candidate: Candidate) {
    match candidate {
        Candidate::Host(address) => {
            out.push(0);
            encode_socket_address(out, address);
        }
        Candidate::ServerReflexive(address) => {
            out.push(1);
            encode_socket_address(out, address);
        }
        Candidate::PeerReflexive(address) => {
            out.push(2);
            encode_socket_address(out, address);
        }
    }
}

fn encode_socket_address(out: &mut Vec<u8>, address: SocketAddr) {
    match address.ip() {
        std::net::IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&address.port().to_be_bytes());
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
        snapshot: NetworkSnapshot,
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
    Snapshot {
        snapshot: NetworkSnapshot,
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
    #[error("invalid network snapshot: {0}")]
    InvalidSnapshot(String),
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
