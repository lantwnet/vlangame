use crate::deduper::{Deduper, IpKey, TcpKey, UdpKey};
use crate::nat::MyNatInfo;
use anyhow::Context;
use bytes::{Bytes, BytesMut};
use common::codec::protocol::{MsgType, NetPacket};
use dashmap::DashMap;
use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocols;
use rust_p2p_core::route::route_table::RouteTable;
use rust_p2p_core::tunnel::SocketManager;
use std::net::Ipv4Addr;
use std::ops::Add;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{Receiver, Sender};
use tun_rs::{AsyncDevice, DeviceBuilder};

/// TUN 设备初始化
pub async fn init_device(
    ip: Ipv4Addr,
    mask: u8,
    tun_name: Option<String>,
) -> anyhow::Result<(flume::Sender<BytesMut>, flume::Receiver<(u64, BytesMut)>)> {
    let (s, receiver) = flume::bounded(1024);
    let (sender, r) = flume::bounded(1024);
    let mut builder = DeviceBuilder::new().ipv4(ip, mask, None);
    if let Some(tun_name) = &tun_name {
        builder = builder.name(tun_name);
    }
    #[cfg(windows)]
    {
        if let Some(tun_name) = &tun_name {
            _ = delete_adapter_info_from_reg(tun_name);
            builder = builder.description(tun_name);
        }
        builder = builder.metric(0).ring_capacity(8 * 1024 * 1024)
        // .device_guid(
        //     tun_name
        //         .map(hash_str_to_u128)
        //         .unwrap_or(213076489527406181848273591423880201356),
        // );
    }
    let (tun_s, tun_r) = tokio::sync::oneshot::channel();
    thread::spawn(move || match builder.build_sync() {
        Ok(dev) => {
            _ = tun_s.send(dev);
        }
        Err(e) => {
            log::error!("create tun {:?}", e);
        }
    });
    let device = tokio::time::timeout(Duration::from_secs(5), tun_r)
        .await
        .context("timed out waiting for device")?
        .context("failed to create sync device")?;
    let device = AsyncDevice::new(device).context("failed to create async device")?;
    let _ = device.set_mtu(1500);
    #[cfg(windows)]
    let _ = device.set_mtu_v6(1500);
    let device = Arc::new(device);
    let device_ = device.clone();
    tokio::spawn(async move {
        device_recv(device_, sender).await;
    });
    tokio::spawn(async move {
        device_send(device, receiver).await;
    });
    Ok((s, r))
}
// #[cfg(windows)]
// fn hash_str_to_u128(opt: String) -> u128 {
//     use std::collections::hash_map::DefaultHasher;
//     use std::hash::{Hash, Hasher};
//     let mut hasher1 = DefaultHasher::new();
//     let mut hasher2 = DefaultHasher::new();
//
//     // 这里做两次哈希合并为一个 u128（64 + 64 位）
//     opt.hash(&mut hasher1);
//     213076489.hash(&mut hasher1);
//     opt.hash(&mut hasher2);
//     527940631.hash(&mut hasher2);
//
//     let high = hasher1.finish();
//     let low = hasher2.finish();
//
//     ((high as u128) << 64) | (low as u128)
// }

async fn device_recv(device: Arc<AsyncDevice>, sender: flume::Sender<(u64, BytesMut)>) {
    let mut buf = vec![0u8; 65536];
    loop {
        match device.recv(&mut buf).await {
            Ok(len) => {
                if len == 0 || (buf[0] >> 4) != 4 {
                    continue;
                }
                if let Err(e) = sender
                    .send_async((crate::util::now_secs(), buf[..len].into()))
                    .await
                {
                    log::error!("device_recv failed to send packet: {}", e);
                    break;
                }
            }
            Err(e) => {
                log::error!("device_recv {:?}", e);
                break;
            }
        }
    }
}
async fn device_send(device: Arc<AsyncDevice>, receiver: flume::Receiver<BytesMut>) {
    while let Ok(buf) = receiver.recv_async().await {
        if let Err(e) = device.send(&buf).await {
            log::error!("device_send failed to send packet: {}", e);
        }
    }
}

/// 设备数据接收任务
pub async fn device_recv_task(
    ip: Ipv4Addr,
    receiver: flume::Receiver<(u64, BytesMut)>,
    tx1: Sender<(u64, Bytes)>,
    route_table: Option<RouteTable<u32>>,
    socket_manager: Option<SocketManager>,
    my_nat_info: Option<MyNatInfo>,
    broadcast: Ipv4Addr,
) {
    let time_map = DashMap::<Ipv4Addr, (Instant, u64)>::new();
    let allow_port = 6000..7000;
    let punch_port = 6112..=6112;
    loop {
        match receiver.recv_async().await {
            Ok((time, buf)) => {
                let len = buf.len();
                if buf.len() == 0 || (buf[0] >> 4) != 4 {
                    continue;
                }
                let Some(ipv4_packet) = pnet_packet::ipv4::Ipv4Packet::new(&buf) else {
                    continue;
                };
                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if let Some(tcp_packet) =
                            pnet_packet::tcp::TcpPacket::new(ipv4_packet.payload())
                        {
                            if !allow_port.contains(&tcp_packet.get_destination())
                                && !allow_port.contains(&tcp_packet.get_source())
                            {
                                continue;
                            }
                        }
                    }
                    IpNextHeaderProtocols::Udp => {
                        if let Some(udp_packet) =
                            pnet_packet::udp::UdpPacket::new(ipv4_packet.payload())
                        {
                            if !allow_port.contains(&udp_packet.get_destination())
                                && !allow_port.contains(&udp_packet.get_source())
                            {
                                continue;
                            }
                        }
                    }
                    _ => continue,
                }
                let dest = ipv4_packet.get_destination();
                let mut bytes_mut = BytesMut::with_capacity(12 + len);
                bytes_mut.resize(12, 0);
                let mut packet = NetPacket::new(bytes_mut).unwrap();
                if dest.is_multicast() {
                    continue;
                }
                let is_broadcast = dest.is_broadcast() || dest == broadcast;
                if is_broadcast {
                    packet.set_msg_type(MsgType::Broadcast.into());
                } else {
                    packet.set_msg_type(MsgType::Turn.into());
                }
                packet.set_src_id(ipv4_packet.get_source().into());
                packet.set_dest_id(dest.into());
                let mut bytes_mut = packet.into_buffer();
                bytes_mut.extend_from_slice(&buf[..len]);
                let bytes = bytes_mut.freeze();
                if is_broadcast {
                    _ = tx1.send((crate::util::now_secs(), bytes.clone())).await;
                    continue;
                }
                let mut exists_route = false;
                if let (Some(route_table), Some(socket_manager)) = (&route_table, &socket_manager) {
                    if let Ok(route) = route_table.get_route_by_id(&dest.into()) {
                        exists_route = true;
                        time_map.remove(&dest);
                        if socket_manager
                            .send_to(bytes.clone(), &route.route_key())
                            .await
                            .is_ok()
                        {
                            continue;
                        }
                    }
                }

                // 判断是否需要打洞
                if !exists_route
                    && ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp
                {
                    if let (Some(tcp_packet), Some(my_nat_info)) = (
                        pnet_packet::tcp::TcpPacket::new(ipv4_packet.payload()),
                        &my_nat_info,
                    ) {
                        if allow_port.contains(&tcp_packet.get_destination())
                            && punch_port.contains(&tcp_packet.get_destination())
                        {
                            let instant = Instant::now();
                            let punch = if let Some(mut v) = time_map.get_mut(&dest) {
                                if instant > v.value().0 {
                                    if v.value().1 < 15 {
                                        v.value_mut().0 =
                                            instant.add(Duration::from_secs(3 + v.value().1));
                                    } else {
                                        v.value_mut().0 = instant.add(Duration::from_secs(
                                            3 + (v.value().1 - 15) * (v.value().1 - 15),
                                        ));
                                    }

                                    v.value_mut().1 += 1;
                                    true
                                } else {
                                    false
                                }
                            } else {
                                time_map.insert(dest, (instant, 1));
                                true
                            };
                            if punch {
                                // 尝试打洞
                                let nat_info = my_nat_info.get();
                                let data = serde_json::to_string(&nat_info).unwrap();
                                let mut request = NetPacket::new(BytesMut::zeroed(12)).unwrap();
                                request.set_msg_type(MsgType::PunchStart1.into());
                                request.set_src_id(ip.into());
                                request.set_dest_id(dest.into());
                                let mut punch_bytes = request.into_buffer();
                                punch_bytes.extend_from_slice(data.as_bytes());
                                _ = tx1.send((time, punch_bytes.freeze())).await;
                                log::info!("punch peer_id={}", dest)
                            }
                        }
                    }
                }
                _ = tx1.send((time, bytes)).await;
            }
            Err(e) => {
                log::error!("{:?}", e);
                break;
            }
        }
    }
}

/// 设备数据发送任务
pub async fn device_send_task(sender: flume::Sender<BytesMut>, mut rx2: Receiver<BytesMut>) {
    let mut dedup = Deduper::new();

    while let Some(buf) = rx2.recv().await {
        // buf 是ipv4数据，分为tcp和其他数据，执行数据去重,忽略重复的数据
        let Some(ip) = pnet_packet::ipv4::Ipv4Packet::new(&buf) else {
            continue;
        };
        match ip.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let Some(tcp) = pnet_packet::tcp::TcpPacket::new(ip.payload()) else {
                    continue;
                };
                let key = TcpKey {
                    src: ip.get_source().octets(),
                    dst: ip.get_destination().octets(),
                    sport: tcp.get_source(),
                    dport: tcp.get_destination(),
                    seq: tcp.get_sequence(),
                    ack: tcp.get_acknowledgement(),
                    flags: tcp.get_flags(),
                    plen: tcp.payload().len().min(u16::MAX as usize) as u16,
                };
                if dedup.seen_tcp(key) {
                    // 重复，丢弃
                    continue;
                }
            }
            IpNextHeaderProtocols::Udp => {
                let Some(udp) = pnet_packet::udp::UdpPacket::new(ip.payload()) else {
                    continue;
                };
                let key = UdpKey {
                    src: ip.get_source().octets(),
                    dst: ip.get_destination().octets(),
                    sport: udp.get_source(),
                    dport: udp.get_destination(),
                    checksum: udp.get_checksum(),
                };
                if dedup.seen_udp(key) {
                    continue;
                }
            }
            _ => {
                let key = IpKey {
                    src: ip.get_source().octets(),
                    dst: ip.get_destination().octets(),
                    id: ip.get_identification(),
                    total_length: ip.get_total_length(),
                };
                if dedup.seen_ip(key) {
                    continue;
                }
            }
        }
        if let Err(e) = sender.send_async(buf).await {
            log::error!("device_send_task {}", e);
            break;
        }
    }
}

#[cfg(windows)]
pub(crate) fn delete_adapter_info_from_reg(dev_name: &str) -> std::io::Result<()> {
    use std::collections::HashSet;
    use winreg::{RegKey, enums::HKEY_LOCAL_MACHINE, enums::KEY_ALL_ACCESS};
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let profiles_key = hklm.open_subkey_with_flags(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles",
        KEY_ALL_ACCESS,
    )?;
    let mut profile_guid_set = HashSet::new();
    for sub_key_name in profiles_key.enum_keys().filter_map(Result::ok) {
        let sub_key = profiles_key.open_subkey(&sub_key_name)?;
        match sub_key.get_value::<String, _>("Description") {
            Ok(profile_name) => {
                if dev_name == profile_name {
                    match profiles_key.delete_subkey_all(&sub_key_name) {
                        Ok(_) => {
                            log::info!("deleted Profiles sub_key: {}", sub_key_name);
                            profile_guid_set.insert(sub_key_name);
                        }
                        Err(e) => {
                            log::warn!("Failed to delete Profiles sub_key {}: {}", sub_key_name, e)
                        }
                    }
                }
            }
            Err(e) => log::warn!(
                "Failed to read Description for sub_key {}: {}",
                sub_key_name,
                e
            ),
        }
    }
    let unmanaged_key = hklm.open_subkey_with_flags(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged",
        KEY_ALL_ACCESS,
    )?;
    for sub_key_name in unmanaged_key.enum_keys().filter_map(Result::ok) {
        let sub_key = unmanaged_key.open_subkey(&sub_key_name)?;
        match sub_key.get_value::<String, _>("ProfileGuid") {
            Ok(profile_guid) => {
                if profile_guid_set.contains(&profile_guid) {
                    match unmanaged_key.delete_subkey_all(&sub_key_name) {
                        Ok(_) => log::info!("deleted Unmanaged sub_key: {}", sub_key_name),
                        Err(e) => {
                            log::warn!("Failed to delete Unmanaged sub_key {}: {}", sub_key_name, e)
                        }
                    }
                }
            }
            Err(e) => log::warn!(
                "Failed to read Description for sub_key {}: {}",
                sub_key_name,
                e
            ),
        }
    }
    Ok(())
}

/// 删注册表，这样 Get-NetConnectionProfile 看不到网络
#[cfg(windows)]
#[allow(unused)]
pub(crate) fn delete_nla_profile_for_interface(dev_name: &str) -> std::io::Result<()> {
    use std::collections::HashSet;
    use winreg::{RegKey, enums::*};

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let profiles_path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles";
    let profiles_key = hklm.open_subkey_with_flags(profiles_path, KEY_ALL_ACCESS)?;

    let mut matched_profile_guids = HashSet::new();

    // 删除匹配 Description 的 Profile
    for guid in profiles_key.enum_keys().filter_map(Result::ok) {
        if let Ok(profile_key) = profiles_key.open_subkey_with_flags(&guid, KEY_ALL_ACCESS) {
            let desc: Result<String, _> = profile_key.get_value("Description");
            if let Ok(name) = desc {
                if name == dev_name {
                    profiles_key.delete_subkey_all(&guid)?;
                    log::info!(
                        "Deleted profile GUID {} (Description matches {})",
                        guid,
                        dev_name
                    );
                    matched_profile_guids.insert(guid);
                }
            }
        }
    }

    // 检查 Signatures 中是否绑定了对应 ProfileGuid
    let sig_paths = [
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed",
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Default",
    ];

    for sig_path in sig_paths.iter() {
        if let Ok(sig_key) = hklm.open_subkey_with_flags(sig_path, KEY_ALL_ACCESS) {
            for sig_name in sig_key.enum_keys().filter_map(Result::ok) {
                if let Ok(sub_key) = sig_key.open_subkey_with_flags(&sig_name, KEY_ALL_ACCESS) {
                    let profile_guid: Result<String, _> = sub_key.get_value("ProfileGuid");
                    if let Ok(guid) = profile_guid {
                        if matched_profile_guids.contains(&guid) {
                            sig_key.delete_subkey_all(&sig_name)?;
                            log::info!("Deleted signature entry {} in {}", sig_name, sig_path);
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
