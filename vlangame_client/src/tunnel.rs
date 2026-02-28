use crate::handler::ClientContextHandler;
use crate::nat::MyNatInfo;
use rust_p2p_core::idle::IdleRouteManager;
use rust_p2p_core::punch::Puncher;
use rust_p2p_core::route::route_table::RouteTable;
use rust_p2p_core::tunnel::TunnelDispatcher;
pub use rust_p2p_core::tunnel::{SocketManager, new_tunnel_component};
use std::time::Duration;

pub async fn init_tunnel() -> (
    TunnelDispatcher,
    Puncher,
    SocketManager,
    RouteTable<u32>,
    IdleRouteManager<u32>,
) {
    let udp_config = rust_p2p_core::tunnel::config::UdpTunnelConfig::default();
    let tcp_config = rust_p2p_core::tunnel::config::TcpTunnelConfig::new(Box::new(
        rust_p2p_core::tunnel::tcp::LengthPrefixedInitCodec,
    ));
    let config = rust_p2p_core::tunnel::config::TunnelConfig::empty()
        .set_udp_tunnel_config(udp_config)
        .set_tcp_tunnel_config(tcp_config)
        .major_socket_count(2);
    let (tunnel_factory, puncher) = new_tunnel_component(config).unwrap();
    let route_table = RouteTable::<u32>::default();
    let idle_route_manager = IdleRouteManager::new(Duration::from_secs(30), route_table.clone());
    let socket_manager = tunnel_factory.socket_manager();
    (
        tunnel_factory,
        puncher,
        socket_manager,
        route_table,
        idle_route_manager,
    )
}

pub async fn route_timeout_task(idle_route_manager: IdleRouteManager<u32>) {
    loop {
        let (peer_id, route, time) = idle_route_manager.next_idle().await;
        log::info!(
            "route timeout peer_id={peer_id},route={route:?},time={:?}",
            time.elapsed()
        );
        idle_route_manager.remove_route(&peer_id, &route.route_key());
    }
}

/// 隧道收发调度与数据分发
pub async fn tunnel_dispatch_task(
    mut tunnel_factory: TunnelDispatcher,
    client_context_handler: ClientContextHandler,
    nat_info: MyNatInfo,
) {
    loop {
        let nat_info = nat_info.clone();
        let mut tunnel = tunnel_factory.dispatch().await.unwrap();
        let client_context_handler = client_context_handler.clone();
        tokio::spawn(async move {
            let mut buf = vec![0; 65536];
            while let Some(rs) = tunnel.recv_from(&mut buf).await {
                let (len, route_key) = match rs {
                    Ok(rs) => rs,
                    Err(e) => {
                        log::warn!("{e:?}");
                        if tunnel.protocol().is_udp() {
                            continue;
                        }
                        break;
                    }
                };
                // STUN 数据判断
                if rust_p2p_core::stun::is_stun_response(&buf[..len]) {
                    if let Some(pub_addr) = rust_p2p_core::stun::recv_stun_response(&buf[..len]) {
                        nat_info.update_public_addr(route_key.index(), pub_addr);
                        continue;
                    }
                }
                // 协议包转发处理
                if let Ok(Some(rs)) = client_context_handler
                    .next_handle(&buf[..len], route_key)
                    .await
                {
                    if tunnel.send_to(rs, route_key.addr()).await.is_err() {
                        break;
                    }
                }
            }
        });
    }
}
