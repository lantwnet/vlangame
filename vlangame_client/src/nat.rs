use parking_lot::Mutex;
use rust_p2p_core::nat::NatInfo;
use rust_p2p_core::route::Index;
use rust_p2p_core::tunnel::SocketManager;
use rust_p2p_core::tunnel::udp::UDPIndex;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
#[derive(Clone)]
pub struct MyNatInfo {
    nat_info: Arc<Mutex<NatInfo>>,
}
impl MyNatInfo {
    pub fn get(&self) -> NatInfo {
        self.nat_info.lock().clone()
    }
    pub fn update_public_addr(&self, index: Index, addr: SocketAddr) {
        let (ip, port) = if let Some(r) = mapping_addr(addr) {
            r
        } else {
            return;
        };
        log::info!("public_addr:{},{},index={index:?}", ip, port);
        let mut nat_info = self.nat_info.lock();

        if rust_p2p_core::extend::addr::is_ipv4_global(&ip) {
            if !nat_info.public_ips.contains(&ip) {
                nat_info.public_ips.push(ip);
            }
            match index {
                Index::Udp(index) => {
                    let index = match index {
                        UDPIndex::MainV4(index) => index,
                        UDPIndex::MainV6(index) => index,
                        UDPIndex::SubV4(_) => return,
                    };
                    if let Some(p) = nat_info.public_udp_ports.get_mut(index) {
                        *p = port;
                    }
                }
                Index::Tcp(_) => {
                    nat_info.public_tcp_port = port;
                }
                _ => {}
            }
        } else {
            log::debug!("not public addr: {addr:?}")
        }
    }
}
pub async fn my_nat_info(socket_manager: &SocketManager) -> MyNatInfo {
    let stun_server = vec![
        // "stun.miwifi.com:3478".to_string(),
        // "stun.chat.bilibili.com:3478".to_string(),
        // "stun.hitv.com:3478".to_string(),
        "stun.l.google.com:19302".to_string(),
        "stun1.l.google.com:19302".to_string(),
        "stun2.l.google.com:19302".to_string(),
    ];
    let (nat_type, public_ips, port_range) = rust_p2p_core::stun::stun_test_nat(stun_server, None)
        .await
        .unwrap();
    log::info!("nat_type:{nat_type:?},public_ips:{public_ips:?},port_range={port_range}");
    let local_ipv4 = rust_p2p_core::extend::addr::local_ipv4().await.unwrap();
    let local_udp_ports = socket_manager
        .udp_socket_manager_as_ref()
        .unwrap()
        .local_ports()
        .unwrap();
    let local_tcp_port = socket_manager
        .tcp_socket_manager_as_ref()
        .unwrap()
        .local_addr()
        .port();
    let mut public_ports = local_udp_ports.clone();
    public_ports.fill(0);
    let nat_info = NatInfo {
        nat_type,
        public_ips,
        public_udp_ports: public_ports,
        mapping_tcp_addr: vec![],
        mapping_udp_addr: vec![],
        public_port_range: port_range,
        local_ipv4,
        local_ipv4s: vec![local_ipv4],
        ipv6: None,
        local_udp_ports,
        local_tcp_port,
        public_tcp_port: 0,
    };
    MyNatInfo {
        nat_info: Arc::new(Mutex::new(nat_info)),
    }
}

pub async fn query_udp_public_addr_loop(nat_info: MyNatInfo, socket_manager: SocketManager) {
    let udp_stun_servers = vec![
        // "stun.miwifi.com:3478".to_string(),
        // "stun.chat.bilibili.com:3478".to_string(),
        // "stun.hitv.com:3478".to_string(),
        "stun.l.google.com:19302".to_string(),
        "stun1.l.google.com:19302".to_string(),
        "stun2.l.google.com:19302".to_string(),
    ];
    let udp_len = udp_stun_servers.len();
    let mut udp_count = 0;
    let stun_request = rust_p2p_core::stun::send_stun_request();
    loop {
        let stun = &udp_stun_servers[udp_count % udp_len];
        udp_count += 1;
        match stun.to_socket_addrs() {
            Ok(mut addr) => {
                if let Some(addr) = addr.next() {
                    if let Some(w) = socket_manager.udp_socket_manager_as_ref() {
                        if let Err(e) = w.detect_pub_addrs(&stun_request, addr).await {
                            log::info!("detect_pub_addrs {e:?} {addr:?}");
                        }
                    }
                }
            }
            Err(e) => {
                log::info!("query_public_addr to_socket_addrs {e:?} {stun:?}",);
            }
        }
        let not_port = nat_info.nat_info.lock().public_udp_ports.contains(&0);
        if not_port {
            tokio::time::sleep(Duration::from_secs(2)).await;
        } else {
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    }
}

fn mapping_addr(addr: SocketAddr) -> Option<(Ipv4Addr, u16)> {
    match addr {
        SocketAddr::V4(addr) => Some((*addr.ip(), addr.port())),
        SocketAddr::V6(addr) => addr.ip().to_ipv4_mapped().map(|ip| (ip, addr.port())),
    }
}
