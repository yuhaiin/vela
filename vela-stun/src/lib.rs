//! Small STUN Binding client. It intentionally implements only the client-side
//! Binding transaction needed for server-reflexive candidates.

use async_trait::async_trait;
use rand::RngCore;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use thiserror::Error;
use tokio::{net::UdpSocket, time::timeout};
use tracing::debug;

pub use vela_dns::DEFAULT_DOH_SERVER;

pub fn default_doh_servers() -> Vec<String> {
    vela_dns::default_servers()
}

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAPPED_ADDRESS: u16 = 0x0001;

#[derive(Clone, Debug)]
pub struct StunConfig {
    /// STUN endpoints in `host:port` form. Hostnames are resolved when a
    /// binding refresh runs, so a changed DNS answer is picked up too.
    pub servers: Vec<String>,
    /// DNS-over-HTTPS endpoints used to resolve STUN hostnames.
    pub doh_servers: Vec<String>,
    pub timeout: Duration,
}

impl Default for StunConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            doh_servers: default_doh_servers(),
            timeout: Duration::from_secs(3),
        }
    }
}

#[async_trait]
pub trait StunSocket: Send + Sync {
    async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> std::io::Result<usize>;
    async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
}

#[async_trait]
impl StunSocket for UdpSocket {
    async fn send_to(&self, bytes: &[u8], target: SocketAddr) -> std::io::Result<usize> {
        UdpSocket::send_to(self, bytes, target).await
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buffer).await
    }
}

pub async fn binding<S: StunSocket + ?Sized>(
    socket: &S,
    config: &StunConfig,
) -> Result<Vec<SocketAddr>, StunError> {
    let mut results = Vec::new();
    let mut last_error = None;
    for server in &config.servers {
        let (host, port) = match split_server(server) {
            Ok(value) => value,
            Err(source) => {
                last_error = Some(StunError::Resolve {
                    server: server.clone(),
                    source,
                });
                continue;
            }
        };
        let addresses = match vela_dns::resolve(host, &config.doh_servers).await {
            Ok(addresses) => addresses
                .into_iter()
                .map(|address| SocketAddr::new(address, port))
                .collect::<Vec<_>>(),
            Err(error) => {
                last_error = Some(StunError::Resolve {
                    server: server.clone(),
                    source: std::io::Error::other(error),
                });
                continue;
            }
        };
        debug!(
            debug_marker = "vela-stun",
            server = %server,
            resolved_addresses = ?addresses,
            "resolved STUN server addresses"
        );
        let mut resolved = false;
        let mut server_error = None;
        for address in addresses {
            resolved = true;
            match binding_address(socket, config.timeout, address).await {
                Ok(mapped_address) if !results.contains(&mapped_address) => {
                    debug!(
                        debug_marker = "vela-stun",
                        server_address = %address,
                        mapped_address = %mapped_address,
                        "STUN binding succeeded"
                    );
                    results.push(mapped_address);
                }
                Ok(mapped_address) => {
                    debug!(
                        debug_marker = "vela-stun",
                        server_address = %address,
                        mapped_address = %mapped_address,
                        "STUN binding returned a duplicate mapped address"
                    );
                }
                Err(error) => {
                    debug!(
                        debug_marker = "vela-stun",
                        server_address = %address,
                        error = %error,
                        "STUN binding failed"
                    );
                    server_error = Some(error);
                }
            }
        }
        if !resolved {
            last_error = Some(StunError::Resolve {
                server: server.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    "STUN hostname resolved to no addresses",
                ),
            });
        } else if let Some(error) = server_error {
            last_error = Some(error);
        }
    }
    if results.is_empty() && !config.servers.is_empty() {
        return Err(last_error.unwrap_or(StunError::NoServersResponded));
    }
    Ok(results)
}

fn split_server(server: &str) -> Result<(&str, u16), std::io::Error> {
    let (host, port) = if let Some(value) = server.strip_prefix('[') {
        let (host, port) = value.split_once("]:").ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "STUN endpoint must be host:port",
            )
        })?;
        (host, port)
    } else {
        server.rsplit_once(':').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "STUN endpoint must be host:port",
            )
        })?
    };
    if host.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "STUN endpoint host is empty",
        ));
    }
    let port = port.parse().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "STUN endpoint port is invalid",
        )
    })?;
    Ok((host, port))
}

async fn binding_address<S: StunSocket + ?Sized>(
    socket: &S,
    request_timeout: Duration,
    server: SocketAddr,
) -> Result<SocketAddr, StunError> {
    let transaction = transaction_id();
    let request = binding_request(transaction);
    socket.send_to(&request, server).await?;
    let mut response = [0u8; 1500];
    let (length, source) = timeout(request_timeout, socket.recv_from(&mut response))
        .await
        .map_err(|_| StunError::Timeout)??;
    let address = parse_binding_response(&response[..length], transaction)?;
    if source.ip().is_unspecified() {
        return Err(StunError::InvalidResponse);
    }
    Ok(address)
}

fn transaction_id() -> [u8; 12] {
    let mut id = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

fn binding_request(transaction: [u8; 12]) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    out[2..4].copy_from_slice(&0u16.to_be_bytes());
    out[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    out[8..].copy_from_slice(&transaction);
    out
}

fn parse_binding_response(input: &[u8], transaction: [u8; 12]) -> Result<SocketAddr, StunError> {
    if input.len() < 20
        || input[0] & 0xc0 != 0
        || u32::from_be_bytes(input[4..8].try_into().unwrap()) != MAGIC_COOKIE
        || input[8..20] != transaction
    {
        return Err(StunError::InvalidResponse);
    }
    let message_len = u16::from_be_bytes([input[2], input[3]]) as usize;
    if input.len() < 20 + message_len {
        return Err(StunError::InvalidResponse);
    }
    let mut offset = 20;
    while offset + 4 <= 20 + message_len {
        let attribute = u16::from_be_bytes([input[offset], input[offset + 1]]);
        let length = u16::from_be_bytes([input[offset + 2], input[offset + 3]]) as usize;
        offset += 4;
        if offset + length > input.len() {
            return Err(StunError::InvalidResponse);
        }
        let value = &input[offset..offset + length];
        if attribute == XOR_MAPPED_ADDRESS || attribute == MAPPED_ADDRESS {
            if let Some(address) = parse_address(attribute, value, transaction) {
                return Ok(address);
            }
        }
        offset += (length + 3) & !3;
    }
    Err(StunError::NoMappedAddress)
}

fn parse_address(attribute: u16, value: &[u8], transaction: [u8; 12]) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]])
        ^ if attribute == XOR_MAPPED_ADDRESS {
            (MAGIC_COOKIE >> 16) as u16
        } else {
            0
        };
    match family {
        0x01 if value.len() >= 8 => {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&value[4..8]);
            if attribute == XOR_MAPPED_ADDRESS {
                for (byte, mask) in bytes.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
                    *byte ^= mask;
                }
            }
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(bytes)), port))
        }
        0x02 if value.len() >= 20 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&value[4..20]);
            if attribute == XOR_MAPPED_ADDRESS {
                let mut mask = [0u8; 16];
                mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
                mask[4..].copy_from_slice(&transaction);
                for (byte, mask) in bytes.iter_mut().zip(mask) {
                    *byte ^= mask;
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(bytes)), port))
        }
        _ => None,
    }
}

#[derive(Debug, Error)]
pub enum StunError {
    #[error("STUN I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to resolve STUN server {server}: {source}")]
    Resolve {
        server: String,
        #[source]
        source: std::io::Error,
    },
    #[error("STUN request timed out")]
    Timeout,
    #[error("invalid STUN response")]
    InvalidResponse,
    #[error("STUN response has no mapped address")]
    NoMappedAddress,
    #[error("no STUN server responded")]
    NoServersResponded,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn parses_xor_mapped_ipv4() {
        let tx = [1u8; 12];
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 4567);
        let mut value = vec![0, 1];
        value.extend_from_slice(&(address.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        let mut ip = address
            .ip()
            .to_string()
            .parse::<Ipv4Addr>()
            .unwrap()
            .octets();
        for (byte, mask) in ip.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
            *byte ^= mask;
        }
        value.extend_from_slice(&ip);
        assert_eq!(parse_address(XOR_MAPPED_ADDRESS, &value, tx), Some(address));
    }

    #[test]
    fn parses_xor_mapped_ipv6() {
        let tx = [1u8; 12];
        let address: SocketAddr = "[2001:db8::7]:4567".parse().unwrap();
        let mut value = vec![0, 2];
        value.extend_from_slice(&(address.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
        let mut ip = match address.ip() {
            IpAddr::V6(ip) => ip.octets(),
            IpAddr::V4(_) => unreachable!(),
        };
        let mut mask = [0u8; 16];
        mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        mask[4..].copy_from_slice(&tx);
        for (byte, mask) in ip.iter_mut().zip(mask) {
            *byte ^= mask;
        }
        value.extend_from_slice(&ip);
        assert_eq!(parse_address(XOR_MAPPED_ADDRESS, &value, tx), Some(address));
    }

    struct MockSocket {
        response: Mutex<Option<Vec<u8>>>,
    }

    #[async_trait]
    impl StunSocket for MockSocket {
        async fn send_to(&self, bytes: &[u8], _target: SocketAddr) -> std::io::Result<usize> {
            let transaction: [u8; 12] = bytes[8..20].try_into().unwrap();
            let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 4567);
            let mut value = vec![0, 1];
            value.extend_from_slice(&(address.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
            let mut ip = address
                .ip()
                .to_string()
                .parse::<Ipv4Addr>()
                .unwrap()
                .octets();
            for (byte, mask) in ip.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
                *byte ^= mask;
            }
            value.extend_from_slice(&ip);
            let mut response = vec![0u8; 20];
            response[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
            response[2..4].copy_from_slice(&(12u16).to_be_bytes());
            response[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            response[8..20].copy_from_slice(&transaction);
            response.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
            response.extend_from_slice(&(value.len() as u16).to_be_bytes());
            response.extend_from_slice(&value);
            *self.response.lock().unwrap() = Some(response);
            Ok(bytes.len())
        }

        async fn recv_from(&self, buffer: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            let response = self.response.lock().unwrap().take().unwrap();
            buffer[..response.len()].copy_from_slice(&response);
            Ok((response.len(), "127.0.0.1:3478".parse().unwrap()))
        }
    }

    #[tokio::test]
    async fn binding_uses_literal_servers_without_system_resolution() {
        let socket = MockSocket {
            response: Mutex::new(None),
        };
        let candidates = binding(
            &socket,
            &StunConfig {
                servers: vec!["127.0.0.1:3478".to_owned()],
                doh_servers: default_doh_servers(),
                timeout: Duration::from_secs(1),
            },
        )
        .await
        .unwrap();
        assert_eq!(candidates, vec!["203.0.113.7:4567".parse().unwrap()]);
    }
}
