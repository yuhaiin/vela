//! Layer-3 TUN adapter and platform route leases.
//!
//! The adapter intentionally contains no Vela session logic. A full node can
//! connect its `recv`/`send` methods to `VelaNode::send_ip` and
//! `VelaEvent::IpPacket`, while `RouteManager` owns only the host routes it
//! installed for the current snapshot.

use bytes::Bytes;
use std::{io, net::IpAddr, sync::Arc};
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

        fn try_recv(&self) -> Result<Option<Bytes>, TunError> {
            let mut buffer = vec![0; self.mtu];
            let result = unsafe {
                libc::read(
                    self.fd.get_ref().as_raw_fd(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Ok(None);
                }
                return Err(TunError::Io(error));
            }
            let length = result as usize;
            if length == 0 {
                return Err(TunError::Closed);
            }
            buffer.truncate(length);
            Ok(Some(Bytes::from(buffer)))
        }

        pub async fn recv_many(
            &self,
            packets: &mut Vec<Bytes>,
            limit: usize,
        ) -> Result<usize, TunError> {
            packets.clear();
            if limit == 0 {
                return Ok(0);
            }
            packets.push(self.recv().await?);
            while packets.len() < limit {
                let Some(packet) = self.try_recv()? else {
                    break;
                };
                packets.push(packet);
            }
            Ok(packets.len())
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

        pub async fn recv_many(
            &self,
            packets: &mut Vec<Bytes>,
            limit: usize,
        ) -> Result<usize, TunError> {
            packets.clear();
            if limit == 0 {
                return Ok(0);
            }
            packets.push(self.recv().await?);
            #[cfg(target_os = "macos")]
            for _ in 1..limit {
                let mut buffer = vec![0; self.mtu];
                match self.device.try_recv(&mut buffer) {
                    Ok(length) => {
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
                        packets.push(Bytes::from(buffer));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(TunError::Io(error)),
                }
            }
            Ok(packets.len())
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

    fn host_route(address: IpAddr, interface_index: u32) -> route_manager::Route {
        let prefix_len = if address.is_ipv4() { 32 } else { 128 };
        // Keep the route attached to the TUN interface, but leave
        // RTF_IFSCOPE unset so normal route lookups can select it.
        route_manager::Route::new(address, prefix_len).with_if_index(interface_index)
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
            let address = match key {
                RouteKey::V4(address) => IpAddr::V4(address),
                RouteKey::V6(address) => IpAddr::V6(address),
            };
            let route = host_route(address, self.interface_index);
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

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn host_routes_use_the_tun_interface_without_a_gateway() {
            let route = host_route("10.254.0.2".parse().unwrap(), 7);
            assert_eq!(route.gateway(), None);
            assert_eq!(route.if_index(), Some(7));
            #[cfg(target_os = "macos")]
            assert!(!route.if_scope());
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
        pub async fn recv_many(
            &self,
            _packets: &mut Vec<Bytes>,
            _limit: usize,
        ) -> Result<usize, TunError> {
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
/// snapshot. `online_peers` is deliberately ignored: a route belongs to a
/// server membership record, not to the peer's current connection status.
pub fn snapshot_route_addresses(
    snapshot: &vela_proto::NetworkSnapshot,
    local: vela_proto::NodeId,
) -> Result<Vec<IpAddr>, TunError> {
    snapshot
        .validate()
        .map_err(|error| TunError::Snapshot(error.to_string()))?;
    let mut addresses = Vec::new();
    for peer in &snapshot.peers {
        if peer.node_id == local {
            continue;
        }
        if let Some(address) = peer.virtual_ipv4 {
            addresses.push(address.into());
        }
        if let Some(address) = peer.virtual_ipv6 {
            addresses.push(address.into());
        }
    }
    Ok(addresses)
}

/// Installs one `/32` or `/128` host route for each remote member in a signed
/// snapshot. The returned leases must be released when the snapshot is
/// replaced or the node shuts down.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub async fn install_snapshot_routes(
    manager: &RouteManager,
    snapshot: &vela_proto::NetworkSnapshot,
    local: vela_proto::NodeId,
) -> Result<Vec<RouteLease>, TunError> {
    let mut leases = Vec::new();
    for address in snapshot_route_addresses(snapshot, local)? {
        leases.push(manager.claim_host_route(address).await?);
    }
    Ok(leases)
}

/// Bridges a kernel TUN device and a Vela node. Every TUN read is one complete
/// IP packet; every received Vela IP event is written back as one packet.
pub async fn run_bridge(node: vela_core::VelaNode, tun: TunDevice) -> Result<(), TunError> {
    let tun = Arc::new(tun);
    let reader_tun = Arc::clone(&tun);
    let reader_node = node.clone();
    let mut tun_to_vela = tokio::spawn(async move {
        let mut packets = Vec::with_capacity(64);
        loop {
            reader_tun.recv_many(&mut packets, 64).await?;
            for result in reader_node.send_ip_batch(&packets).await {
                match result {
                    Ok(()) => {}
                    Err(vela_core::SendError::Ip(error)) => {
                        tracing::debug!(error = %error, "dropping invalid or unrouted packet from TUN");
                    }
                    Err(vela_core::SendError::QueueFull) => {
                        tracing::debug!("dropping packet because the peer send queue is full");
                    }
                    Err(error) => {
                        tracing::debug!(
                            error = %error,
                            "dropping TUN packet after a transient Vela send failure"
                        );
                    }
                }
            }
        }
    });
    let writer_tun = Arc::clone(&tun);
    let mut vela_to_tun = tokio::spawn(async move {
        let mut events = Vec::with_capacity(64);
        loop {
            if node.next_event_batch(&mut events, 64).await == 0 {
                return Err(TunError::Closed);
            }
            for event in events.drain(..) {
                if let vela_core::VelaEvent::IpPacket { packet, .. } = event {
                    writer_tun.send(packet.as_bytes()).await?;
                }
            }
        }
    });
    let result = tokio::select! {
        result = &mut tun_to_vela => result
            .map_err(|error| TunError::Core(error.to_string()))
            .and_then(|result| result),
        result = &mut vela_to_tun => result
            .map_err(|error| TunError::Core(error.to_string()))
            .and_then(|result| result),
    };
    tun_to_vela.abort();
    vela_to_tun.abort();
    result
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

    #[test]
    fn snapshot_routes_include_offline_members_until_membership_removal() {
        let local_signing = [1; 32];
        let remote_signing = [2; 32];
        let local = vela_proto::NodeId::new(*blake3::hash(&local_signing).as_bytes());
        let remote = vela_proto::NodeId::new(*blake3::hash(&remote_signing).as_bytes());
        let snapshot = vela_proto::NetworkSnapshot {
            network_id: [0; 16],
            generation: 1,
            virtual_ipv4: Some(vela_proto::Ipv4Cidr {
                address: "10.254.0.0".parse().unwrap(),
                prefix_len: 16,
            }),
            virtual_ipv6: None,
            doh_servers: Vec::new(),
            stun_servers: Vec::new(),
            peers: vec![
                vela_proto::PeerInfo {
                    node_id: local,
                    incarnation: 1,
                    signing_public: local_signing,
                    noise_public: [3; 32],
                    candidates: Vec::new(),
                    virtual_ipv4: Some("10.254.0.1".parse().unwrap()),
                    virtual_ipv6: None,
                    credential: Vec::new(),
                    capabilities: Vec::new(),
                },
                vela_proto::PeerInfo {
                    node_id: remote,
                    incarnation: 1,
                    signing_public: remote_signing,
                    noise_public: [4; 32],
                    candidates: Vec::new(),
                    virtual_ipv4: Some("10.254.0.2".parse().unwrap()),
                    virtual_ipv6: None,
                    credential: Vec::new(),
                    capabilities: Vec::new(),
                },
            ],
            online_peers: Vec::new(),
            expires_at: u64::MAX,
            signature: Vec::new(),
        };
        assert_eq!(
            snapshot_route_addresses(&snapshot, local).unwrap(),
            vec!["10.254.0.2".parse::<IpAddr>().unwrap()]
        );
    }

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
