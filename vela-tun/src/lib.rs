//! Layer-3 TUN adapter and platform route leases.
//!
//! The adapter intentionally contains no Vela session logic. A full node can
//! connect its `recv`/`send` methods to `VelaNode::send_ip` and
//! `VelaEvent::IpPacket`, while `RouteManager` owns only the host routes it
//! installed for the current snapshot.

use bytes::Bytes;
use std::{io, net::IpAddr};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct TunConfig {
    /// Empty on macOS lets the kernel choose an available `utunN` interface.
    pub name: String,
    pub mtu: usize,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: if cfg!(target_os = "macos") {
                ""
            } else {
                "vela0"
            }
            .into(),
            mtu: 1200,
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use futures_util::StreamExt;
    use rtnetlink::{LinkUnspec, RouteMessageBuilder, new_connection};
    use std::{
        collections::HashMap,
        ffi::CString,
        net::{Ipv4Addr, Ipv6Addr},
        os::fd::{AsRawFd, RawFd},
        sync::Arc,
    };
    use tokio::{io::unix::AsyncFd, sync::Mutex};

    const IFNAMSIZ: usize = 16;
    const IFF_TUN: libc::c_short = 0x0001;
    const IFF_NO_PI: libc::c_short = 0x1000;

    #[repr(C)]
    struct IfReq {
        name: [libc::c_char; IFNAMSIZ],
        flags: libc::c_short,
        padding: [u8; 22],
    }

    struct TunFd(RawFd);

    impl AsRawFd for TunFd {
        fn as_raw_fd(&self) -> RawFd {
            self.0
        }
    }

    impl Drop for TunFd {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    pub struct TunDevice {
        fd: AsyncFd<TunFd>,
        name: String,
        mtu: usize,
    }

    impl TunDevice {
        pub fn open(config: TunConfig) -> Result<Self, TunError> {
            if config.name.is_empty() || config.name.len() >= IFNAMSIZ {
                return Err(TunError::InvalidName);
            }
            if config.mtu < 576 {
                return Err(TunError::InvalidMtu);
            }
            let path = CString::new("/dev/net/tun").expect("static path has no NUL");
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
            if fd < 0 {
                return Err(TunError::Io(io::Error::last_os_error()));
            }
            let mut request = IfReq {
                name: [0; IFNAMSIZ],
                flags: IFF_TUN | IFF_NO_PI,
                padding: [0; 22],
            };
            for (slot, byte) in request.name.iter_mut().zip(config.name.bytes()) {
                *slot = byte as libc::c_char;
            }
            let result = unsafe { libc::ioctl(fd, libc::TUNSETIFF as libc::Ioctl, &request) };
            if result < 0 {
                let error = io::Error::last_os_error();
                unsafe {
                    libc::close(fd);
                }
                return Err(TunError::Io(error));
            }
            Ok(Self {
                fd: AsyncFd::new(TunFd(fd)).map_err(TunError::Io)?,
                name: config.name,
                mtu: config.mtu,
            })
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn mtu(&self) -> usize {
            self.mtu
        }

        pub async fn recv(&self) -> Result<Bytes, TunError> {
            let mut buffer = vec![0; self.mtu];
            loop {
                let mut guard = self.fd.readable().await.map_err(TunError::Io)?;
                match guard.try_io(|inner| {
                    let result = unsafe {
                        libc::read(
                            inner.get_ref().as_raw_fd(),
                            buffer.as_mut_ptr().cast(),
                            buffer.len(),
                        )
                    };
                    if result < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(result as usize)
                    }
                }) {
                    Ok(Ok(length)) if length > 0 => {
                        buffer.truncate(length);
                        return Ok(Bytes::from(buffer));
                    }
                    Ok(Ok(_)) => return Err(TunError::Closed),
                    Ok(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Ok(Err(error)) => return Err(TunError::Io(error)),
                    Err(_would_block) => continue,
                }
            }
        }

        pub async fn send(&self, packet: &[u8]) -> Result<(), TunError> {
            if packet.is_empty() || packet.len() > self.mtu {
                return Err(TunError::PacketTooLarge);
            }
            let mut offset = 0;
            while offset < packet.len() {
                let mut guard = self.fd.writable().await.map_err(TunError::Io)?;
                let result = guard.try_io(|inner| {
                    let result = unsafe {
                        libc::write(
                            inner.get_ref().as_raw_fd(),
                            packet[offset..].as_ptr().cast(),
                            packet.len() - offset,
                        )
                    };
                    if result < 0 {
                        Err(io::Error::last_os_error())
                    } else {
                        Ok(result as usize)
                    }
                });
                match result {
                    Ok(Ok(length)) if length > 0 => offset += length,
                    Ok(Ok(_)) => return Err(TunError::Closed),
                    Ok(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => continue,
                    Ok(Err(error)) => return Err(TunError::Io(error)),
                    Err(_would_block) => continue,
                }
            }
            Ok(())
        }
    }

    #[derive(Clone)]
    pub struct RouteManager {
        handle: rtnetlink::Handle,
        interface_index: u32,
        owned: Arc<Mutex<HashMap<RouteKey, usize>>>,
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    enum RouteKey {
        V4(Ipv4Addr),
        V6(Ipv6Addr),
    }

    impl RouteManager {
        pub async fn for_tun(tun: &TunDevice) -> Result<Self, TunError> {
            Self::for_interface(tun.name()).await
        }

        pub async fn for_interface(name: impl AsRef<str>) -> Result<Self, TunError> {
            let (connection, handle, _) = new_connection().map_err(netlink_error)?;
            tokio::spawn(connection);
            let mut links = handle.link().get().match_name(name.as_ref()).execute();
            let link = links
                .next()
                .await
                .ok_or_else(|| TunError::InterfaceNotFound(name.as_ref().to_owned()))?
                .map_err(netlink_error)?;
            let interface_index = link.header.index;
            handle
                .link()
                .set(LinkUnspec::new_with_index(interface_index).up().build())
                .execute()
                .await
                .map_err(netlink_error)?;
            Ok(Self {
                handle,
                interface_index,
                owned: Arc::new(Mutex::new(HashMap::new())),
            })
        }

        pub fn interface_index(&self) -> u32 {
            self.interface_index
        }

        pub async fn set_mtu(&self, mtu: usize) -> Result<(), TunError> {
            let mtu = u32::try_from(mtu).map_err(|_| TunError::InvalidMtu)?;
            self.handle
                .link()
                .set(
                    LinkUnspec::new_with_index(self.interface_index)
                        .mtu(mtu)
                        .build(),
                )
                .execute()
                .await
                .map_err(netlink_error)
        }

        pub async fn add_local_address(
            &self,
            address: IpAddr,
            prefix_len: u8,
        ) -> Result<(), TunError> {
            self.handle
                .address()
                .add(self.interface_index, address, prefix_len)
                .replace()
                .execute()
                .await
                .map_err(netlink_error)
        }

        pub async fn claim_host_route(&self, address: IpAddr) -> Result<RouteLease, TunError> {
            let key = match address {
                IpAddr::V4(address) => RouteKey::V4(address),
                IpAddr::V6(address) => RouteKey::V6(address),
            };
            let mut owned = self.owned.lock().await;
            if let Some(count) = owned.get_mut(&key) {
                *count += 1;
                return Ok(RouteLease {
                    manager: self.clone(),
                    key,
                    released: false,
                });
            }
            owned.insert(key, 1);
            let result = match key {
                RouteKey::V4(address) => {
                    self.handle
                        .route()
                        .add(
                            RouteMessageBuilder::<Ipv4Addr>::new()
                                .destination_prefix(address, 32)
                                .output_interface(self.interface_index)
                                .build(),
                        )
                        .execute()
                        .await
                }
                RouteKey::V6(address) => {
                    self.handle
                        .route()
                        .add(
                            RouteMessageBuilder::<Ipv6Addr>::new()
                                .destination_prefix(address, 128)
                                .output_interface(self.interface_index)
                                .build(),
                        )
                        .execute()
                        .await
                }
            };
            if let Err(error) = result {
                owned.remove(&key);
                return Err(netlink_error(error));
            }
            Ok(RouteLease {
                manager: self.clone(),
                key,
                released: false,
            })
        }

        async fn release(&self, key: RouteKey) -> Result<(), TunError> {
            let mut owned = self.owned.lock().await;
            if let Some(count) = owned.get_mut(&key) {
                if *count > 1 {
                    *count -= 1;
                    return Ok(());
                }
            }
            let route = match key {
                RouteKey::V4(address) => RouteMessageBuilder::<Ipv4Addr>::new()
                    .destination_prefix(address, 32)
                    .output_interface(self.interface_index)
                    .build(),
                RouteKey::V6(address) => RouteMessageBuilder::<Ipv6Addr>::new()
                    .destination_prefix(address, 128)
                    .output_interface(self.interface_index)
                    .build(),
            };
            let result = self.handle.route().del(route).execute().await;
            owned.remove(&key);
            result.map_err(netlink_error)
        }
    }

    pub struct RouteLease {
        manager: RouteManager,
        key: RouteKey,
        released: bool,
    }

    impl RouteLease {
        pub async fn release(mut self) -> Result<(), TunError> {
            if !self.released {
                self.manager.release(self.key).await?;
                self.released = true;
            }
            Ok(())
        }
    }

    impl Drop for RouteLease {
        fn drop(&mut self) {
            if self.released {
                return;
            }
            self.released = true;
            let manager = self.manager.clone();
            let key = self.key;
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let _ = manager.release(key).await;
                });
            }
        }
    }

    fn netlink_error(error: impl std::fmt::Display) -> TunError {
        TunError::Netlink(error.to_string())
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
mod platform {
    use super::*;
    use std::{
        collections::HashMap,
        net::{Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };
    use tokio::sync::Mutex;
    use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

    #[derive(Clone)]
    pub struct TunDevice {
        device: Arc<AsyncDevice>,
        name: String,
        mtu: usize,
    }

    impl TunDevice {
        pub fn open(config: TunConfig) -> Result<Self, TunError> {
            #[cfg(not(target_os = "macos"))]
            if config.name.is_empty() {
                return Err(TunError::InvalidName);
            }
            if config.mtu < 576 {
                return Err(TunError::InvalidMtu);
            }
            let mtu = u16::try_from(config.mtu).map_err(|_| TunError::InvalidMtu)?;

            #[cfg(target_os = "macos")]
            if !config.name.is_empty()
                && (!config.name.starts_with("utun") || config.name[4..].parse::<u32>().is_err())
            {
                return Err(TunError::InvalidName);
            }

            let mut builder = DeviceBuilder::new().mtu(mtu).layer(Layer::L3);
            if !config.name.is_empty() {
                builder = builder.name(config.name.clone());
            }
            #[cfg(target_os = "macos")]
            {
                builder = builder.with(|options| {
                    options.associate_route(false).packet_information(false);
                });
            }
            #[cfg(target_os = "windows")]
            {
                builder = builder.with(|options| {
                    options.description("Vela TUN");
                });
            }

            let device = Arc::new(builder.build_async().map_err(TunError::Io)?);
            let name = device.name().map_err(TunError::Io)?;
            Ok(Self {
                device,
                name,
                mtu: config.mtu,
            })
        }

        pub fn name(&self) -> &str {
            &self.name
        }

        pub fn mtu(&self) -> usize {
            self.mtu
        }

        pub async fn recv(&self) -> Result<Bytes, TunError> {
            let mut buffer = vec![0; self.mtu];
            let length = self.device.recv(&mut buffer).await.map_err(TunError::Io)?;
            if length == 0 {
                return Err(TunError::Closed);
            }
            if length > buffer.len() {
                return Err(TunError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TUN returned a packet larger than the configured MTU",
                )));
            }
            buffer.truncate(length);
            Ok(Bytes::from(buffer))
        }

        pub async fn send(&self, packet: &[u8]) -> Result<(), TunError> {
            if packet.is_empty() || packet.len() > self.mtu {
                return Err(TunError::PacketTooLarge);
            }
            let mut offset = 0;
            while offset < packet.len() {
                let length = self
                    .device
                    .send(&packet[offset..])
                    .await
                    .map_err(TunError::Io)?;
                if length == 0 {
                    return Err(TunError::Closed);
                }
                if length > packet.len() - offset {
                    return Err(TunError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "TUN sent more bytes than requested",
                    )));
                }
                offset += length;
            }
            Ok(())
        }

        fn set_mtu(&self, mtu: usize) -> Result<(), TunError> {
            let mtu = u16::try_from(mtu).map_err(|_| TunError::InvalidMtu)?;
            self.device.set_mtu(mtu).map_err(TunError::Io)
        }

        fn add_local_address(&self, address: IpAddr, prefix_len: u8) -> Result<(), TunError> {
            match address {
                IpAddr::V4(address) => self
                    .device
                    .add_address_v4(address, prefix_len)
                    .map_err(TunError::Io),
                IpAddr::V6(address) => self
                    .device
                    .add_address_v6(address, prefix_len)
                    .map_err(TunError::Io),
            }
        }

        fn interface_index(&self) -> Result<u32, TunError> {
            self.device.if_index().map_err(TunError::Io)
        }
    }

    #[derive(Clone)]
    pub struct RouteManager {
        tun: TunDevice,
        interface_index: u32,
        owned: Arc<Mutex<HashMap<RouteKey, usize>>>,
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    enum RouteKey {
        V4(Ipv4Addr),
        V6(Ipv6Addr),
    }

    impl RouteManager {
        pub async fn for_tun(tun: &TunDevice) -> Result<Self, TunError> {
            Ok(Self {
                tun: tun.clone(),
                interface_index: tun.interface_index()?,
                owned: Arc::new(Mutex::new(HashMap::new())),
            })
        }

        pub async fn for_interface(_name: impl AsRef<str>) -> Result<Self, TunError> {
            Err(TunError::Unsupported)
        }

        pub fn interface_index(&self) -> u32 {
            self.interface_index
        }

        pub async fn set_mtu(&self, mtu: usize) -> Result<(), TunError> {
            self.tun.set_mtu(mtu)
        }

        pub async fn add_local_address(
            &self,
            address: IpAddr,
            prefix_len: u8,
        ) -> Result<(), TunError> {
            self.tun.add_local_address(address, prefix_len)
        }

        pub async fn claim_host_route(&self, address: IpAddr) -> Result<RouteLease, TunError> {
            let key = match address {
                IpAddr::V4(address) => RouteKey::V4(address),
                IpAddr::V6(address) => RouteKey::V6(address),
            };
            let mut owned = self.owned.lock().await;
            if let Some(count) = owned.get_mut(&key) {
                *count += 1;
                return Ok(RouteLease {
                    manager: self.clone(),
                    key,
                    released: false,
                });
            }
            owned.insert(key, 1);
            if let Err(error) = self.change_route(key, true).await {
                owned.remove(&key);
                return Err(error);
            }
            Ok(RouteLease {
                manager: self.clone(),
                key,
                released: false,
            })
        }

        async fn release(&self, key: RouteKey) -> Result<(), TunError> {
            let mut owned = self.owned.lock().await;
            if let Some(count) = owned.get_mut(&key) {
                if *count > 1 {
                    *count -= 1;
                    return Ok(());
                }
            }
            let result = self.change_route(key, false).await;
            owned.remove(&key);
            result
        }

        async fn change_route(&self, key: RouteKey, add: bool) -> Result<(), TunError> {
            let (address, prefix_len) = match key {
                RouteKey::V4(address) => (IpAddr::V4(address), 32),
                RouteKey::V6(address) => (IpAddr::V6(address), 128),
            };
            let route =
                route_manager::Route::new(address, prefix_len).with_if_index(self.interface_index);
            #[cfg(target_os = "macos")]
            let route = route.with_gateway(address).with_if_scope(true);
            tokio::task::spawn_blocking(move || {
                let mut manager = route_manager::RouteManager::new()
                    .map_err(|error| TunError::Netlink(error.to_string()))?;
                if add {
                    manager
                        .add(&route)
                        .map_err(|error| TunError::Netlink(error.to_string()))
                } else {
                    manager
                        .delete(&route)
                        .map_err(|error| TunError::Netlink(error.to_string()))
                }
            })
            .await
            .map_err(|error| TunError::Netlink(error.to_string()))?
        }
    }

    pub struct RouteLease {
        manager: RouteManager,
        key: RouteKey,
        released: bool,
    }

    impl RouteLease {
        pub async fn release(mut self) -> Result<(), TunError> {
            if !self.released {
                self.manager.release(self.key).await?;
                self.released = true;
            }
            Ok(())
        }
    }

    impl Drop for RouteLease {
        fn drop(&mut self) {
            if self.released {
                return;
            }
            self.released = true;
            let manager = self.manager.clone();
            let key = self.key;
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let _ = manager.release(key).await;
                });
            }
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
mod platform {
    use super::*;

    pub struct TunDevice;
    impl TunDevice {
        pub fn open(_config: TunConfig) -> Result<Self, TunError> {
            Err(TunError::Unsupported)
        }
        pub fn name(&self) -> &str {
            ""
        }
        pub fn mtu(&self) -> usize {
            0
        }
        pub async fn recv(&self) -> Result<Bytes, TunError> {
            Err(TunError::Unsupported)
        }
        pub async fn send(&self, _packet: &[u8]) -> Result<(), TunError> {
            Err(TunError::Unsupported)
        }
    }

    pub struct RouteManager;
    impl RouteManager {
        pub async fn for_interface(_name: impl AsRef<str>) -> Result<Self, TunError> {
            Err(TunError::Unsupported)
        }
        pub async fn set_mtu(&self, _mtu: usize) -> Result<(), TunError> {
            Err(TunError::Unsupported)
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use platform::RouteLease;
pub use platform::RouteManager;
pub use platform::TunDevice;

/// Installs one `/32` or `/128` host route for each remote member in a signed
/// snapshot. The returned leases must be released when the snapshot is
/// replaced or the node shuts down.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub async fn install_snapshot_routes(
    manager: &RouteManager,
    snapshot: &vela_proto::NetworkSnapshot,
    local: vela_proto::NodeId,
) -> Result<Vec<RouteLease>, TunError> {
    snapshot
        .validate()
        .map_err(|error| TunError::Snapshot(error.to_string()))?;
    let mut leases = Vec::new();
    for peer in &snapshot.peers {
        if peer.node_id == local {
            continue;
        }
        if let Some(address) = peer.virtual_ipv4 {
            leases.push(manager.claim_host_route(address.into()).await?);
        }
        if let Some(address) = peer.virtual_ipv6 {
            leases.push(manager.claim_host_route(address.into()).await?);
        }
    }
    Ok(leases)
}

/// Bridges a kernel TUN device and a Vela node. Every TUN read is one complete
/// IP packet; every received Vela IP event is written back as one packet.
pub async fn run_bridge(node: vela_core::VelaNode, tun: TunDevice) -> Result<(), TunError> {
    loop {
        tokio::select! {
            packet = tun.recv() => {
                match node.send_ip(packet?.to_vec()).await {
                    Ok(()) => {}
                    Err(vela_core::SendError::Ip(error)) => {
                        tracing::debug!(error = %error, "dropping invalid or unrouted packet from TUN");
                    }
                    Err(vela_core::SendError::QueueFull) => {
                        tracing::debug!("dropping packet because the peer send queue is full");
                    }
                    Err(error) => return Err(TunError::Core(error.to_string())),
                }
            }
            event = node.next_event() => {
                match event {
                    Some(vela_core::VelaEvent::IpPacket { packet, .. }) => {
                        tun.send(packet.as_bytes()).await?;
                    }
                    Some(_) => {}
                    None => return Err(TunError::Closed),
                }
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum TunError {
    #[error("I/O error: {0}")]
    Io(#[source] io::Error),
    #[error("invalid TUN interface name")]
    InvalidName,
    #[error("invalid TUN MTU")]
    InvalidMtu,
    #[error("TUN packet is empty or exceeds the MTU")]
    PacketTooLarge,
    #[error("TUN device is closed")]
    Closed,
    #[error("TUN is unsupported on this platform")]
    Unsupported,
    #[error("network interface was not found: {0}")]
    InterfaceNotFound(String),
    #[error("netlink error: {0}")]
    Netlink(String),
    #[error("Vela core error: {0}")]
    Core(String),
    #[error("invalid network snapshot: {0}")]
    Snapshot(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn rejects_invalid_tun_configuration_before_opening_device() {
        assert!(matches!(
            TunDevice::open(TunConfig {
                name: "vela-interface-name-is-too-long".into(),
                mtu: 1200,
            }),
            Err(TunError::InvalidName)
        ));
        assert!(matches!(
            TunDevice::open(TunConfig {
                name: "vela0".into(),
                mtu: 575,
            }),
            Err(TunError::InvalidMtu)
        ));
    }
}
