use anyhow::{Context, anyhow};
use bytes::BytesMut;
use ipnet::{IpNet, Ipv4Net};
use netconfig_rs::sys::InterfaceExt;
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet_packet::tcp::MutableTcpPacket;
use pnet_packet::udp::MutableUdpPacket;
use pnet_packet::{MutablePacket, Packet, udp};
use std::borrow::Cow;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::Arc;
use std::thread;
use windivert::WinDivert;
use windivert::address::WinDivertAddress;
use windivert::layer::NetworkLayer;
use windivert::packet::WinDivertPacket;

pub struct NetAdapterInfo {
    pub index: u32,
    pub name: String,
    pub mac: [u8; 6],
}
impl NetAdapterInfo {
    pub fn mac_str(&self) -> String {
        self.mac
            .iter()
            .map(|b| format!("{:02X}", b)) // 每个字节转大写十六进制，两位补零
            .collect::<Vec<_>>()
            .join("-")
    }
}
pub fn default_ipv4_device() -> anyhow::Result<NetAdapterInfo> {
    let mut manager = route_manager::RouteManager::new()?;
    let mut list_index = Vec::new();
    let mut list_name = Vec::new();
    let mut index_map = HashMap::new();
    for x in manager.list()? {
        if x.destination().is_unspecified() && x.prefix() == 0 {
            list_index.push(x.if_index().unwrap());
            list_name.push(x.if_name().cloned().unwrap());
            index_map.insert(x.if_name().cloned().unwrap(), x.if_index().unwrap());
        }
    }
    #[cfg(target_os = "windows")]
    {
        let vec = ipconfig::get_adapters()?;
        for x in vec {
            // if x.if_type() == ipconfig::IfType::EthernetCsmacd
            //     || x.if_type() == ipconfig::IfType::Ieee80211
            {
                if x.oper_status() == ipconfig::OperStatus::IfOperStatusUp
                    && (list_index.contains(&x.ipv6_if_index())
                        || list_name.contains(&x.friendly_name().to_string()))
                {
                    let Some(physical_address) = x.physical_address() else {
                        continue;
                    };
                    let index = if x.ipv6_if_index() == 0 {
                        index_map
                            .get(&x.friendly_name().to_string())
                            .cloned()
                            .unwrap()
                    } else {
                        x.ipv6_if_index()
                    };
                    let adapter_info = NetAdapterInfo {
                        index,
                        name: x.friendly_name().to_string(),
                        mac: physical_address.try_into().context("invalid MAC address")?,
                    };
                    return Ok(adapter_info);
                }
            }
        }
    }
    Err(anyhow!("no adapters"))
}
pub fn add_all_arp(if_index: u32, mac: &str, src: Ipv4Addr, dst: Ipv4Net) {
    let network = u32::from(dst.network());
    let broadcast = u32::from(dst.broadcast());
    for ip in network + 1..broadcast {
        let ip = Ipv4Addr::from(ip);
        if ip == src {
            continue;
        }
        if let Err(e) = add_arp(if_index, ip, mac) {
            log::error!("add arp failed: {e:?} {ip}");
        }
    }
}
pub fn add_arp(if_index: u32, ip: Ipv4Addr, mac: &str) -> std::io::Result<()> {
    use std::os::windows::process::CommandExt;
    let output = Command::new("netsh")
        .args(&[
            "interface",
            "ipv4",
            "add",
            "neighbors",
            &if_index.to_string(),
            &ip.to_string(),
            mac,
        ])
        .creation_flags(134217728u32)
        .output()?;

    if output.status.success() {
        log::debug!("arp: {ip} -> {mac}");
    } else {
        log::debug!(
            "arp 添加失败: {ip},{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

pub struct IpRelease {
    name: String,
    interface: netconfig_rs::Interface,
    ip_net: IpNet,
}
impl Drop for IpRelease {
    fn drop(&mut self) {
        if let Err(e) = self.interface.remove_address(self.ip_net) {
            log::warn!("remove netconfig failed: {e:?},ip={}", self.ip_net);
            let mut child = Command::new("netsh");
            child.args(&[
                "interface",
                "ipv4",
                "delete",
                "address",
                &self.name,
                &self.ip_net.addr().to_string(),
            ]);

            #[cfg(windows)]
            child.creation_flags(0x08000000); // CREATE_NO_WINDOW

            let output = child.output();
            if let Ok(out) = output {
                if !out.status.success() {
                    log::error!("执行失败: {:?}", self.ip_net);
                }
            }
        }
    }
}
pub fn add_ipv4_address(
    index: u32,
    name: &str,
    ip: Ipv4Addr,
    mask: u8,
) -> anyhow::Result<IpRelease> {
    let interface = match netconfig_rs::Interface::try_from_index(index) {
        Ok(interface) => interface,
        Err(_) => netconfig_rs::Interface::try_from_alias(name).map_err(|e| anyhow!("{e:?}"))?,
    };
    let list = interface.addresses().map_err(|e| anyhow!("{e:?}"))?;
    for x in list {
        if x.addr() == IpAddr::V4(ip) {
            log::info!("IP[{ip}] 已存在，跳过添加");
            return Ok(IpRelease {
                name: name.to_string(),
                interface,
                ip_net: IpNet::V4(Ipv4Net::new_assert(ip, mask)),
            });
        }
    }
    interface
        .add_address(IpNet::V4(Ipv4Net::new_assert(ip, mask)))
        .map_err(|e| anyhow!("{e:?}"))?;
    Ok(IpRelease {
        name: name.to_string(),
        interface,
        ip_net: IpNet::V4(Ipv4Net::new_assert(ip, mask)),
    })
}
pub fn build_windivert_net_filter(src: Ipv4Addr, dst: Ipv4Net) -> String {
    let network = u32::from(dst.network());
    let broadcast = network | (!u32::from(dst.netmask()));

    let dst_min_ip = Ipv4Addr::from(network);
    let dst_max_ip = Ipv4Addr::from(broadcast);
    format!(
        "((tcp and ((tcp.DstPort >= 6000 and tcp.DstPort <= 6999) or (tcp.SrcPort >= 6000 and tcp.SrcPort <= 6999))) or \
        (udp and ((udp.DstPort >= 6000 and udp.DstPort <= 6999) or (udp.SrcPort >= 6000 and udp.SrcPort <= 6999)))) and \
        (ip.DstAddr == 255.255.255.255 or (ip.SrcAddr == {src} and (ip.DstAddr >= {dst_min_ip} and ip.DstAddr <= {dst_max_ip})))",
    )
}
pub async fn start_dev_threads(
    ip: Ipv4Addr,
    mask: u8,
) -> anyhow::Result<(
    flume::Sender<BytesMut>,
    flume::Receiver<(u64, BytesMut)>,
    IpRelease,
)> {
    let net = Ipv4Net::new_assert(ip, mask);
    let (s, receiver) = flume::bounded(1024);
    let (sender, r) = flume::bounded(1024);
    let adapter_info = default_ipv4_device()?;
    let if_index = adapter_info.index;
    let mac = adapter_info.mac_str();
    // 添加IP
    let ip_release = add_ipv4_address(adapter_info.index, &adapter_info.name, ip, mask)?;
    let net_filter = build_windivert_net_filter(ip, net);
    let net_filter = format!("outbound and ({})", net_filter);
    log::info!("windivert netfilter: {}", net_filter);
    let mut count = 0;
    // 打开 WinDivert 捕获句柄
    let divert = loop {
        let divert = windivert::WinDivert::network(
            &net_filter,                                               // filter 表达式
            0,                                                         // priority
            windivert::prelude::WinDivertFlags::new().set_fragments(), // flags
        );
        match divert {
            Ok(divert) => {
                break divert;
            }
            Err(e) => {
                count += 1;
                if count > 3 {
                    return Err(e)?;
                }
                log::warn!("create WinDivert {}", e);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
    };
    if let Err(e) = divert.set_param(windivert::prelude::WinDivertParam::QueueLength, 8192) {
        log::error!("set_param QueueLength {e:?}");
    }
    if let Err(e) = divert.set_param(
        windivert::prelude::WinDivertParam::QueueSize,
        32 * 1024 * 1024,
    ) {
        log::error!("set_param QueueSize {e:?}");
    }
    let divert = Arc::new(divert);
    {
        let divert = divert.clone();
        let sender = sender.clone();
        thread::spawn(move || {
            recv(divert, ip, sender);
        });
    }
    thread::spawn(move || {
        send(divert, if_index, mac, receiver);
    });
    Ok((s, r, ip_release))
}

pub fn recv(
    divert: Arc<WinDivert<NetworkLayer>>,
    ip: Ipv4Addr,
    sender: flume::Sender<(u64, BytesMut)>,
) {
    let mut packet_buf = vec![0u8; 65536 * 16];

    loop {
        let packets = match divert.recv_ex(Some(&mut packet_buf), 16) {
            Ok(v) => v,
            Err(e) => {
                log::error!("windivert recv error: {:?}", e);
                continue;
            }
        };
        for packet in packets {
            let buf = packet.data.as_ref();
            if buf.len() < 20 {
                continue;
            }
            let version = buf[0] >> 4;
            if version != 4 {
                continue;
            }
            let mut buf: BytesMut = buf.into();
            if let Some(mut ipv4_packet) = MutableIpv4Packet::new(&mut buf) {
                log::debug!(
                    "windivert recv {} -> {}",
                    ipv4_packet.get_source(),
                    ipv4_packet.get_destination()
                );
                if ipv4_packet.get_destination().is_broadcast() && ip != ipv4_packet.get_source() {
                    // 需要修改源IP
                    if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        ipv4_packet.set_source(ip);
                        ipv4_packet
                            .set_checksum(pnet_packet::ipv4::checksum(&ipv4_packet.to_immutable()));
                        let src = ipv4_packet.get_source();
                        let dest = ipv4_packet.get_destination();
                        let Some(mut udp_packet) = MutableUdpPacket::new(ipv4_packet.payload_mut())
                        else {
                            continue;
                        };

                        udp_packet.set_checksum(udp::ipv4_checksum(
                            &udp_packet.to_immutable(),
                            &src,
                            &dest,
                        ));
                    } else {
                        continue;
                    }
                } else if !is_fragmented(&ipv4_packet.to_immutable()) {
                    ipv4_packet
                        .set_checksum(pnet_packet::ipv4::checksum(&ipv4_packet.to_immutable()));
                    let src = ipv4_packet.get_source();
                    let dest = ipv4_packet.get_destination();
                    if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Udp {
                        let Some(mut udp_packet) = MutableUdpPacket::new(ipv4_packet.payload_mut())
                        else {
                            continue;
                        };
                        udp_packet.set_checksum(udp::ipv4_checksum(
                            &udp_packet.to_immutable(),
                            &src,
                            &dest,
                        ));
                    } else if ipv4_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                        let Some(mut tcp_packet) = MutableTcpPacket::new(ipv4_packet.payload_mut())
                        else {
                            continue;
                        };
                        tcp_packet.set_checksum(pnet_packet::tcp::ipv4_checksum(
                            &tcp_packet.to_immutable(),
                            &src,
                            &dest,
                        ));
                    }
                }
                if let Err(e) = sender.send((crate::util::now_secs(), ipv4_packet.packet().into()))
                {
                    log::error!("error sending packet: {}", e);
                }
            }
        }
    }
}

fn is_fragmented(packet: &Ipv4Packet) -> bool {
    let offset = packet.get_fragment_offset();
    let flags = packet.get_flags();
    let mf = flags & 0x1 != 0;
    offset > 0 || mf
}
pub fn send(
    divert: Arc<WinDivert<NetworkLayer>>,
    if_index: u32,
    mac: String,
    receiver: flume::Receiver<BytesMut>,
) {
    let mut map = HashMap::new();
    while let Ok(packet) = receiver.recv() {
        let Some(ipv4_packet) = Ipv4Packet::new(&packet) else {
            continue;
        };
        if map.insert(ipv4_packet.get_source(), if_index).is_none() {
            if let Err(e) = add_arp(if_index, ipv4_packet.get_source(), &mac) {
                log::warn!("windivert add arp error: {:?}", e);
            }
        }
        log::debug!(
            "send ({}) {}->{}",
            ipv4_packet.get_next_level_protocol(),
            ipv4_packet.get_source(),
            ipv4_packet.get_destination()
        );
        unsafe {
            let mut packet_res = WinDivertPacket {
                address: WinDivertAddress::<NetworkLayer>::new(),
                data: Cow::from(packet.as_ref()),
            };
            packet_res.address.set_outbound(false);
            packet_res.address.set_interface_index(if_index);
            if let Err(e) = divert.send(&packet_res) {
                log::error!("WinDivert send {:?}", e);
            }
        }
    }
}
