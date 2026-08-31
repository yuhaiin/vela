//! Minimal DNS-over-HTTPS resolver used by Vela's network control paths.
//!
//! The resolver speaks the RFC 8484 wire format directly so callers never
//! need to use the platform resolver for the hostnames they are looking up.

use serde::Deserialize;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use thiserror::Error;
use url::Url;

pub const DEFAULT_DOH_SERVER: &str = "https://doh.pub";
const DOH_PUB_BOOTSTRAP: [SocketAddr; 2] = [
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 12, 12, 12)), 443),
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(120, 53, 53, 53)), 443),
];

pub fn default_servers() -> Vec<String> {
    vec![DEFAULT_DOH_SERVER.to_owned()]
}

/// Resolve a hostname through the configured DNS-over-HTTPS endpoints.
/// Literal IPv4 and IPv6 addresses are returned without making a request.
pub async fn resolve(host: &str, servers: &[String]) -> Result<Vec<IpAddr>, DnsError> {
    if let Ok(address) = host.parse() {
        return Ok(vec![address]);
    }
    if host.is_empty() {
        return Err(DnsError::InvalidHost);
    }
    let servers = if servers.is_empty() {
        default_servers()
    } else {
        servers.to_vec()
    };
    let mut last_error = None;
    let mut addresses = Vec::new();
    for server in servers {
        let mut server_had_response = false;
        for record_type in [1u16, 28u16] {
            match query(&server, host, record_type).await {
                Ok(values) => {
                    server_had_response = true;
                    for address in values {
                        if !addresses.contains(&address) {
                            addresses.push(address);
                        }
                    }
                }
                Err(error) => last_error = Some(error),
            }
        }
        if server_had_response && !addresses.is_empty() {
            return Ok(addresses);
        }
    }
    Err(last_error.unwrap_or(DnsError::NoRecords {
        host: host.to_owned(),
    }))
}

async fn query(server: &str, host: &str, record_type: u16) -> Result<Vec<IpAddr>, DnsError> {
    let endpoint = endpoint(server, host, record_type)?;
    let client = client_for_endpoint(&endpoint).await?;
    query_with_client(&client, endpoint, record_type).await
}

async fn query_with_client(
    client: &reqwest::Client,
    endpoint: Url,
    record_type: u16,
) -> Result<Vec<IpAddr>, DnsError> {
    let response = client
        .get(endpoint)
        .header(reqwest::header::ACCEPT, "application/dns-message")
        .send()
        .await
        .map_err(|error| DnsError::Request(error.to_string()))?
        .error_for_status()
        .map_err(|error| DnsError::Request(error.to_string()))?;
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = response
        .bytes()
        .await
        .map_err(|error| DnsError::Request(error.to_string()))?;
    if content_type.contains("json") || bytes.first() == Some(&b'{') {
        parse_json_response(&bytes, record_type)
    } else {
        parse_response(&bytes, record_type)
    }
}

fn endpoint(server: &str, host: &str, record_type: u16) -> Result<Url, DnsError> {
    let mut endpoint = Url::parse(server).map_err(|error| DnsError::InvalidEndpoint {
        server: server.to_owned(),
        reason: error.to_string(),
    })?;
    if endpoint.scheme() != "https" {
        return Err(DnsError::InvalidEndpoint {
            server: server.to_owned(),
            reason: "DoH endpoint must use https".to_owned(),
        });
    }
    if endpoint.path().is_empty() || endpoint.path() == "/" {
        endpoint.set_path(if endpoint.host_str() == Some("doh.pub") {
            "/resolve"
        } else {
            "/dns-query"
        });
    }
    endpoint
        .query_pairs_mut()
        .append_pair("name", host)
        .append_pair("type", if record_type == 1 { "A" } else { "AAAA" });
    Ok(endpoint)
}

async fn client_for_endpoint(endpoint: &Url) -> Result<reqwest::Client, DnsError> {
    let host = endpoint
        .host_str()
        .ok_or_else(|| DnsError::InvalidEndpoint {
            server: endpoint.to_string(),
            reason: "endpoint has no host".to_owned(),
        })?;
    let port = endpoint
        .port_or_known_default()
        .ok_or_else(|| DnsError::InvalidEndpoint {
            server: endpoint.to_string(),
            reason: "endpoint has no port".to_owned(),
        })?;
    let addresses = if let Ok(address) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(address, port)]
    } else if host.eq_ignore_ascii_case("doh.pub") && port == 443 {
        DOH_PUB_BOOTSTRAP.to_vec()
    } else {
        resolve_with_default_doh(host)
            .await?
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .collect()
    };
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .no_proxy();
    if host.parse::<IpAddr>().is_err() {
        builder = builder.resolve_to_addrs(host, &addresses);
    }
    builder
        .build()
        .map_err(|error| DnsError::Client(error.to_string()))
}

async fn resolve_with_default_doh(host: &str) -> Result<Vec<IpAddr>, DnsError> {
    let client = bootstrap_client()?;
    let mut addresses = Vec::new();
    let mut last_error = None;
    for record_type in [1u16, 28u16] {
        let endpoint = endpoint(DEFAULT_DOH_SERVER, host, record_type)?;
        match query_with_client(&client, endpoint, record_type).await {
            Ok(values) => {
                for address in values {
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                }
            }
            Err(error) => last_error = Some(error),
        }
    }
    if addresses.is_empty() {
        Err(last_error.unwrap_or(DnsError::NoRecords {
            host: host.to_owned(),
        }))
    } else {
        Ok(addresses)
    }
}

fn bootstrap_client() -> Result<reqwest::Client, DnsError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .resolve_to_addrs("doh.pub", &DOH_PUB_BOOTSTRAP)
        .build()
        .map_err(|error| DnsError::Client(error.to_string()))
}

#[derive(Deserialize)]
struct JsonResponse {
    #[serde(default)]
    status: u16,
    #[serde(default, rename = "Answer")]
    answers: Vec<JsonAnswer>,
}

#[derive(Deserialize)]
struct JsonAnswer {
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

fn parse_json_response(input: &[u8], record_type: u16) -> Result<Vec<IpAddr>, DnsError> {
    let response: JsonResponse = serde_json::from_slice(input)
        .map_err(|error| DnsError::InvalidResponse(format!("invalid DNS JSON: {error}")))?;
    if response.status != 0 {
        return Err(DnsError::InvalidResponse(format!(
            "DNS response code is {}",
            response.status
        )));
    }
    Ok(response
        .answers
        .into_iter()
        .filter(|answer| answer.record_type == record_type)
        .filter_map(|answer| answer.data.parse().ok())
        .collect())
}

fn parse_response(input: &[u8], record_type: u16) -> Result<Vec<IpAddr>, DnsError> {
    if input.len() < 12 {
        return Err(DnsError::InvalidResponse(
            "DNS header is truncated".to_owned(),
        ));
    }
    let flags = u16::from_be_bytes([input[2], input[3]]);
    if flags & 0x8000 == 0 {
        return Err(DnsError::InvalidResponse(
            "DNS response bit is not set".to_owned(),
        ));
    }
    let response_code = flags & 0x000f;
    if response_code != 0 {
        return Err(DnsError::InvalidResponse(format!(
            "DNS response code is {response_code}"
        )));
    }
    let questions = u16::from_be_bytes([input[4], input[5]]) as usize;
    let answers = u16::from_be_bytes([input[6], input[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(input, offset)?;
        if offset.checked_add(4).is_none_or(|end| end > input.len()) {
            return Err(DnsError::InvalidResponse(
                "DNS question is truncated".to_owned(),
            ));
        }
        offset += 4;
    }
    let mut addresses = Vec::new();
    for _ in 0..answers {
        offset = skip_name(input, offset)?;
        if offset.checked_add(10).is_none_or(|end| end > input.len()) {
            return Err(DnsError::InvalidResponse(
                "DNS answer is truncated".to_owned(),
            ));
        }
        let answer_type = u16::from_be_bytes([input[offset], input[offset + 1]]);
        let class = u16::from_be_bytes([input[offset + 2], input[offset + 3]]);
        let length = u16::from_be_bytes([input[offset + 8], input[offset + 9]]) as usize;
        offset += 10;
        let end = offset
            .checked_add(length)
            .ok_or_else(|| DnsError::InvalidResponse("DNS answer length overflow".to_owned()))?;
        if end > input.len() {
            return Err(DnsError::InvalidResponse(
                "DNS answer data is truncated".to_owned(),
            ));
        }
        if class == 1 && answer_type == record_type {
            let address = match (record_type, length) {
                (1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
                    input[offset],
                    input[offset + 1],
                    input[offset + 2],
                    input[offset + 3],
                ))),
                (28, 16) => {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&input[offset..end]);
                    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
                }
                _ => None,
            };
            if let Some(address) = address {
                addresses.push(address);
            }
        }
        offset = end;
    }
    Ok(addresses)
}

fn skip_name(input: &[u8], mut offset: usize) -> Result<usize, DnsError> {
    loop {
        let length = *input
            .get(offset)
            .ok_or_else(|| DnsError::InvalidResponse("DNS name is truncated".to_owned()))?;
        if length & 0xc0 == 0xc0 {
            if offset + 1 >= input.len() {
                return Err(DnsError::InvalidResponse(
                    "DNS name pointer is truncated".to_owned(),
                ));
            }
            return Ok(offset + 2);
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(DnsError::InvalidResponse(
                "invalid DNS name label".to_owned(),
            ));
        }
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        offset = offset
            .checked_add(length as usize)
            .ok_or_else(|| DnsError::InvalidResponse("DNS name length overflow".to_owned()))?;
        if offset > input.len() {
            return Err(DnsError::InvalidResponse(
                "DNS name label is truncated".to_owned(),
            ));
        }
    }
}

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("invalid DNS hostname")]
    InvalidHost,
    #[error("invalid DoH endpoint {server}: {reason}")]
    InvalidEndpoint { server: String, reason: String },
    #[error("failed to create DoH client: {0}")]
    Client(String),
    #[error("DoH request failed: {0}")]
    Request(String),
    #[error("invalid DoH response: {0}")]
    InvalidResponse(String),
    #[error("DoH returned no address for {host}")]
    NoRecords { host: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_answer() {
        let mut packet = vec![0; 12];
        packet[2..4].copy_from_slice(&0x8000u16.to_be_bytes());
        packet[4..6].copy_from_slice(&1u16.to_be_bytes());
        packet[6..8].copy_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1]);
        packet.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 192, 0, 2, 7]);
        assert_eq!(
            parse_response(&packet, 1).unwrap(),
            vec!["192.0.2.7".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn default_endpoint_uses_dns_query_path() {
        let endpoint = endpoint(DEFAULT_DOH_SERVER, "example.test", 28).unwrap();
        assert_eq!(
            endpoint.as_str(),
            "https://doh.pub/resolve?name=example.test&type=AAAA"
        );
    }

    #[test]
    fn parses_doh_json_answer() {
        let json = br#"{"Status":0,"Answer":[{"type":28,"data":"2001:db8::7"}]}"#;
        assert_eq!(
            parse_json_response(json, 28).unwrap(),
            vec!["2001:db8::7".parse::<IpAddr>().unwrap()]
        );
    }
}
