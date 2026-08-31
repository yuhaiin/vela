//! Validated IPv4/IPv6 packets and the host-route table used by Vela.

use bytes::Bytes;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use thiserror::Error;
use vela_proto::NodeId;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IpPacket {
    bytes: Bytes,
    version: IpVersion,
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
}

impl IpPacket {
    pub fn parse(bytes: impl Into<Bytes>) -> Result<Self, IpError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(IpError::Truncated);
        }
        match bytes[0] >> 4 {
            4 => Self::parse_v4(bytes),
            6 => Self::parse_v6(bytes),
            version => Err(IpError::UnsupportedVersion(version)),
        }
    }

    fn parse_v4(bytes: Bytes) -> Result<Self, IpError> {
        if bytes.len() < 20 {
            return Err(IpError::Truncated);
        }
        let header_len = usize::from(bytes[0] & 0x0f) * 4;
        if header_len < 20 {
            return Err(IpError::InvalidHeaderLength);
        }
        if bytes.len() < header_len {
            return Err(IpError::Truncated);
        }
        let total_len = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
        if total_len < header_len {
            return Err(IpError::InvalidTotalLength);
        }
        if total_len != bytes.len() {
            return Err(IpError::LengthMismatch {
                declared: total_len,
                actual: bytes.len(),
            });
        }
        if checksum(&bytes[..header_len]) != 0 {
            return Err(IpError::InvalidChecksum);
        }
        Ok(Self {
            source: IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
            destination: IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
            protocol: bytes[9],
            version: IpVersion::V4,
            bytes,
        })
    }

    fn parse_v6(bytes: Bytes) -> Result<Self, IpError> {
        if bytes.len() < 40 {
            return Err(IpError::Truncated);
        }
        let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        let total_len = 40usize.saturating_add(payload_len);
        if total_len != bytes.len() {
            return Err(IpError::LengthMismatch {
                declared: total_len,
                actual: bytes.len(),
            });
        }
        let source =
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).expect("checked IPv6 source"));
        let destination =
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).expect("checked IPv6 destination"));
        Ok(Self {
            source: IpAddr::V6(source),
            destination: IpAddr::V6(destination),
            protocol: bytes[6],
            version: IpVersion::V6,
            bytes,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Bytes {
        self.bytes
    }

    pub fn version(&self) -> IpVersion {
        self.version
    }

    pub fn source(&self) -> IpAddr {
        self.source
    }

    pub fn destination(&self) -> IpAddr {
        self.destination
    }

    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    pub fn is_fragment(&self) -> bool {
        match self.version {
            IpVersion::V4 => {
                let flags_and_offset = u16::from_be_bytes([self.bytes[6], self.bytes[7]]);
                flags_and_offset & 0x3fff != 0
            }
            IpVersion::V6 => self.protocol == 44,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RouteTable {
    local: Vec<IpAddr>,
    routes: HashMap<IpAddr, NodeId>,
}

impl RouteTable {
    pub fn new(local: impl IntoIterator<Item = IpAddr>) -> Self {
        Self {
            local: local.into_iter().collect(),
            routes: HashMap::new(),
        }
    }

    pub fn set_local(&mut self, addresses: impl IntoIterator<Item = IpAddr>) {
        self.local = addresses.into_iter().collect();
    }

    pub fn insert(&mut self, address: IpAddr, peer: NodeId) {
        self.routes.insert(address, peer);
    }

    pub fn clear_routes(&mut self) {
        self.routes.clear();
    }

    pub fn remove(&mut self, address: &IpAddr) -> Option<NodeId> {
        self.routes.remove(address)
    }

    pub fn peer_for(&self, address: IpAddr) -> Option<NodeId> {
        self.routes.get(&address).copied()
    }

    pub fn is_local(&self, address: IpAddr) -> bool {
        self.local.contains(&address)
    }

    pub fn validate_outbound(&self, packet: &IpPacket) -> Result<NodeId, IpError> {
        if !self.is_local(packet.source()) {
            return Err(IpError::SourceNotLocal(packet.source()));
        }
        self.peer_for(packet.destination())
            .ok_or(IpError::DestinationUnknown(packet.destination()))
    }

    pub fn routes(&self) -> impl Iterator<Item = (IpAddr, NodeId)> + '_ {
        self.routes.iter().map(|(address, peer)| (*address, *peer))
    }
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum = sum.wrapping_add(u32::from(word));
        while sum > u32::from(u16::MAX) {
            sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
        }
    }
    !(sum as u16)
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum IpError {
    #[error("truncated IP packet")]
    Truncated,
    #[error("unsupported IP version {0}")]
    UnsupportedVersion(u8),
    #[error("invalid IP header length")]
    InvalidHeaderLength,
    #[error("invalid IP total length")]
    InvalidTotalLength,
    #[error("IP packet length mismatch: declared {declared}, actual {actual}")]
    LengthMismatch { declared: usize, actual: usize },
    #[error("invalid IPv4 header checksum")]
    InvalidChecksum,
    #[error("IP source address is not local: {0}")]
    SourceNotLocal(IpAddr),
    #[error("IP destination has no route: {0}")]
    DestinationUnknown(IpAddr),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr, payload: &[u8]) -> Bytes {
        let mut packet = vec![0u8; 20 + payload.len()];
        packet[0] = 0x45;
        let length = packet.len() as u16;
        packet[2..4].copy_from_slice(&length.to_be_bytes());
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..].copy_from_slice(payload);
        let checksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        Bytes::from(packet)
    }

    #[test]
    fn validates_ipv4_and_exposes_route_fields() {
        let packet = IpPacket::parse(ipv4_packet(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            b"payload",
        ))
        .unwrap();
        assert_eq!(packet.version(), IpVersion::V4);
        assert_eq!(packet.protocol(), 17);
        assert_eq!(packet.source(), IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)));
        assert_eq!(
            packet.destination(),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2))
        );
    }

    #[test]
    fn rejects_bad_checksum_and_trailing_bytes() {
        let mut bytes = ipv4_packet(
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(100, 64, 0, 2),
            b"payload",
        )
        .to_vec();
        bytes[10] ^= 1;
        assert_eq!(
            IpPacket::parse(bytes.clone()).unwrap_err(),
            IpError::InvalidChecksum
        );
        bytes.push(0);
        assert!(matches!(
            IpPacket::parse(bytes),
            Err(IpError::LengthMismatch { .. })
        ));
    }
}
