use bytes::{Bytes, BytesMut};
use clap::Parser;
use env_logger::Env;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::net::TcpStream;
use vlangame_client::windivert_dev::IpRelease;
use vlangame_client::{device, handler, nat, tunnel, util, windivert_dev};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// 地址和掩码，不指定则服务端生成
    /// example: --local 10.26.0.2/24
    #[arg(short, long)]
    local: Option<String>,
    /// 虚拟网卡名称
    #[arg(short, long)]
    tun_name: Option<String>,
    /// 服务器地址
    #[arg(short, long)]
    server: String,
    /// 转发服务器地址，不填时使用--server的值
    #[arg(long)]
    turn_server: Vec<String>,
    /// 是否开启打洞
    #[arg(short, long, default_value_t = false)]
    enable_nat_punch: bool,
    /// 使用windivert
    #[arg(short, long, default_value_t = false)]
    #[cfg(windows)]
    use_windivert: bool,
}
fn main() {
    main0();
}
#[tokio::main]
async fn main0() {
    let args = Args::parse();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    let stream = TcpStream::connect(&args.server).await.unwrap();
    let (mut read, mut write) = handler::tcp_stream_to_framed(stream);
    handler::send_key(&mut write).await.unwrap();
    let (ip, mask) = util::parse_or_dhcp(args.local.clone(), &mut read, &mut write).await;
    let broadcast = util::calculate_broadcast(ip, mask);

    let (tx2, rx2) = tokio::sync::mpsc::channel::<BytesMut>(1024);
    let enable_nat_punch = args.enable_nat_punch;
    let (puncher, my_nat_info, route_table, socket_manager) = if enable_nat_punch {
        let (tunnel_factory, puncher, socket_manager, route_table, idle_route_manager) =
            tunnel::init_tunnel().await;
        let my_nat_info = nat::my_nat_info(&socket_manager).await;
        let client_context_handler =
            handler::ClientContextHandler::new(tx2.clone(), ip, route_table.clone());
        // 路由超时处理
        tokio::spawn(tunnel::route_timeout_task(idle_route_manager));
        // 数据转发/打洞通道分发
        tokio::spawn(tunnel::tunnel_dispatch_task(
            tunnel_factory,
            client_context_handler.clone(),
            my_nat_info.clone(),
        ));
        // 定时探测公网UDP端口
        tokio::spawn(nat::query_udp_public_addr_loop(
            my_nat_info.clone(),
            socket_manager.clone(),
        ));
        (
            Some(puncher),
            Some(my_nat_info),
            Some(route_table),
            Some(socket_manager),
        )
    } else {
        (None, None, None, None)
    };

    let context_handler =
        handler::ContextHandler::new(tx2.clone(), ip, puncher.clone(), my_nat_info.clone());
    let (mut tx1, rx1) = tokio::sync::mpsc::channel::<(u64, Bytes)>(1024);
    if !args.turn_server.is_empty() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(u64, Bytes)>(1024);
        let back_tx = tx1;
        tx1 = tx;
        let mut turn_tx_list = Vec::new();
        for turn_server in args.turn_server {
            if turn_server == args.server {
                continue;
            }
            let (turn_tx, turn_rx) = tokio::sync::mpsc::channel::<(u64, Bytes)>(1024);
            let status = Arc::new(AtomicBool::default());
            let turn_handler =
                handler::ContextHandler::new(tx2.clone(), ip, puncher.clone(), my_nat_info.clone());
            let latency = turn_handler.latency_ms.clone();
            tokio::spawn(handler::msg_sync_task(
                turn_handler,
                turn_rx,
                status.clone(),
                turn_server,
                None,
                None,
            ));
            turn_tx_list.push((turn_tx, status, latency));
        }
        let main_latency_c = context_handler.latency_ms.clone();
        tokio::spawn(async move {
            while let Some(buf) = rx.recv().await {
                let best = turn_tx_list
                    .iter()
                    .filter(|(_, status, _)| status.load(std::sync::atomic::Ordering::Acquire))
                    .min_by_key(|(_, _, lat)| lat.load(std::sync::atomic::Ordering::Relaxed));
                let sent = if let Some((tx, _, lat)) = best {
                    let turn_lat = lat.load(std::sync::atomic::Ordering::Relaxed);
                    let main_lat = main_latency_c.load(std::sync::atomic::Ordering::Relaxed);
                    if turn_lat < main_lat {
                        tx.try_send(buf.clone()).is_ok()
                    } else {
                        false
                    }
                } else {
                    false
                };
                if !sent {
                    _ = back_tx.try_send(buf);
                }
            }
        });
    }
    // 消息同步
    tokio::spawn(handler::msg_sync_task(
        context_handler,
        rx1,
        Arc::new(AtomicBool::default()),
        args.server.clone(),
        Some(read),
        Some(write),
    ));
    #[cfg(windows)]
    let mut ip_release = None;
    #[cfg(windows)]
    let Some((s, r)) = enhanced_init_device(
        args.use_windivert,
        ip,
        mask,
        args.tun_name.clone(),
        &mut ip_release,
    )
    .await
    else {
        return;
    };
    #[cfg(not(windows))]
    let (s, r) = match device::init_device(ip, mask, args.tun_name.clone()).await {
        Ok(rs) => rs,
        Err(e) => {
            log::error!("tun error:{e:?}");
            return;
        }
    };
    log::info!("Device initialized");
    // 设备数据接收->协议封装->tx1发送
    tokio::spawn(device::device_recv_task(
        ip,
        r,
        tx1.clone(),
        route_table.clone(),
        socket_manager.clone(),
        my_nat_info.clone(),
        broadcast,
    ));
    // 设备发送
    tokio::spawn(device::device_send_task(s, rx2));
    // 等待ctrl-c退出
    tokio::signal::ctrl_c().await.unwrap();
}
#[cfg(windows)]
async fn enhanced_init_device(
    use_windivert: bool,
    ip: Ipv4Addr,
    mask: u8,
    tun_name: Option<String>,
    ip_release: &mut Option<IpRelease>,
) -> Option<(flume::Sender<BytesMut>, flume::Receiver<(u64, BytesMut)>)> {
    if use_windivert {
        match windivert_dev::start_dev_threads(ip, mask).await {
            Ok((s, r, ip_)) => {
                ip_release.replace(ip_);
                return Some((s, r));
            }
            Err(e) => {
                log::error!("windivert error:{e:?}");
                return None;
            }
        }
    }
    match device::init_device(ip, mask, tun_name.clone()).await {
        Ok(rs) => Some(rs),
        Err(e) => {
            log::error!("tun error:{e:?}");
            #[cfg(windows)]
            match windivert_dev::start_dev_threads(ip, mask).await {
                Ok((s, r, ip_)) => {
                    ip_release.replace(ip_);
                    Some((s, r))
                }
                Err(e) => {
                    log::error!("windivert error:{e:?}");
                    None
                }
            }
        }
    }
}
