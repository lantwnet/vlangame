use crate::{device, handler, nat, tunnel, util};
use bytes::{Bytes, BytesMut};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

#[cfg(windows)]
use crate::windivert_dev::{self, IpRelease};
#[cfg(windows)]
use windivert::WinDivert;
#[cfg(windows)]
use windivert::layer::NetworkLayer;

pub struct ClientConfig {
    pub local: Option<String>,
    pub tun_name: Option<String>,
    pub server: String,
    pub turn_server: Vec<String>,
    pub enable_nat_punch: bool,
    #[cfg(windows)]
    pub use_windivert: bool,
}

/// 客户端运行句柄，调用 [`ClientHandle::shutdown`] 优雅停机：
/// 1. abort 全部 tokio 任务（含 TURN/主服务器同步、路由、设备收发）
/// 2. WinDivert 模式额外调用 `WinDivert::shutdown`，解除阻塞的 recv 线程
///    （send 线程会因 tokio 任务 abort 后 flume sender 被 drop 而自然退出）
/// 3. 释放虚拟 IP（`IpRelease` drop）
pub struct ClientHandle {
    tasks: Vec<JoinHandle<()>>,
    #[cfg(windows)]
    windivert: Option<Arc<WinDivert<NetworkLayer>>>,
    #[cfg(windows)]
    _ip_release: Option<IpRelease>,
}

impl ClientHandle {
    pub fn shutdown(self) {
        // 1. 停止所有异步任务
        for task in self.tasks {
            task.abort();
        }
        // 2. 解除 WinDivert recv 线程的阻塞
        // SAFETY: WinDivert 文档明确说明 WinDivertShutdown 可在任意线程调用，
        // 包括与 WinDivertRecv 并发执行，Rust wrapper 的 &mut self 限制过于保守。
        #[cfg(windows)]
        if let Some(divert) = &self.windivert {
            unsafe {
                let ptr = Arc::as_ptr(divert) as *mut WinDivert<NetworkLayer>;
                if let Err(e) =
                    (*ptr).shutdown(windivert::prelude::WinDivertShutdownMode::Both)
                {
                    log::warn!("WinDivert shutdown: {e:?}");
                }
            }
        }
        // 3. _ip_release 在此 drop，自动移除虚拟 IP
    }
}

pub async fn start(config: ClientConfig) -> anyhow::Result<ClientHandle> {
    let stream = TcpStream::connect(&config.server).await?;
    let (mut read, mut write) = handler::tcp_stream_to_framed(stream);
    handler::send_key(&mut write).await?;
    let (ip, mask) = util::parse_or_dhcp(config.local, &mut read, &mut write).await;
    let broadcast = util::calculate_broadcast(ip, mask);

    let mut tasks: Vec<JoinHandle<()>> = Vec::new();

    let (tx2, rx2) = tokio::sync::mpsc::channel::<BytesMut>(1024);
    let (puncher, my_nat_info, route_table, socket_manager) = if config.enable_nat_punch {
        let (tunnel_factory, puncher, socket_manager, route_table, idle_route_manager) =
            tunnel::init_tunnel().await;
        let my_nat_info = nat::my_nat_info(&socket_manager).await;
        let client_context_handler =
            handler::ClientContextHandler::new(tx2.clone(), ip, route_table.clone());
        tasks.push(tokio::spawn(tunnel::route_timeout_task(idle_route_manager)));
        tasks.push(tokio::spawn(tunnel::tunnel_dispatch_task(
            tunnel_factory,
            client_context_handler,
            my_nat_info.clone(),
        )));
        tasks.push(tokio::spawn(nat::query_udp_public_addr_loop(
            my_nat_info.clone(),
            socket_manager.clone(),
        )));
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
    if !config.turn_server.is_empty() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(u64, Bytes)>(1024);
        let back_tx = tx1;
        tx1 = tx;
        let mut turn_tx_list = Vec::new();
        for turn_server in config.turn_server {
            if turn_server == config.server {
                continue;
            }
            let (turn_tx, turn_rx) = tokio::sync::mpsc::channel::<(u64, Bytes)>(1024);
            let status = Arc::new(AtomicBool::default());
            let turn_handler =
                handler::ContextHandler::new(tx2.clone(), ip, puncher.clone(), my_nat_info.clone());
            let latency = turn_handler.latency_ms.clone();
            tasks.push(tokio::spawn(handler::msg_sync_task(
                turn_handler,
                turn_rx,
                status.clone(),
                turn_server,
                None,
                None,
            )));
            turn_tx_list.push((turn_tx, status, latency));
        }
        let main_latency_c = context_handler.latency_ms.clone();
        tasks.push(tokio::spawn(async move {
            while let Some(buf) = rx.recv().await {
                let best = turn_tx_list
                    .iter()
                    .filter(|(_, s, _)| s.load(std::sync::atomic::Ordering::Acquire))
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
        }));
    }
    tasks.push(tokio::spawn(handler::msg_sync_task(
        context_handler,
        rx1,
        Arc::new(AtomicBool::default()),
        config.server,
        Some(read),
        Some(write),
    )));

    #[cfg(windows)]
    let (windivert, ip_release, s, r) =
        init_device_windows(config.use_windivert, ip, mask, config.tun_name).await?;
    #[cfg(not(windows))]
    let (s, r) = device::init_device(ip, mask, config.tun_name).await?;

    log::info!("Device initialized");
    tasks.push(tokio::spawn(device::device_recv_task(
        ip,
        r,
        tx1,
        route_table,
        socket_manager,
        my_nat_info,
        broadcast,
    )));
    // device_send_task 持有 flume Sender<BytesMut>；abort 后 sender drop，
    // WinDivert send 线程的 receiver.recv() 会返回 Err 并自然退出
    tasks.push(tokio::spawn(device::device_send_task(s, rx2)));

    Ok(ClientHandle {
        tasks,
        #[cfg(windows)]
        windivert,
        #[cfg(windows)]
        _ip_release: ip_release,
    })
}

/// Windows 下的设备初始化：优先 WinDivert，失败后回退到 TUN。
#[cfg(windows)]
async fn init_device_windows(
    use_windivert: bool,
    ip: Ipv4Addr,
    mask: u8,
    tun_name: Option<String>,
) -> anyhow::Result<(
    Option<Arc<WinDivert<NetworkLayer>>>,
    Option<IpRelease>,
    flume::Sender<BytesMut>,
    flume::Receiver<(u64, BytesMut)>,
)> {
    if use_windivert {
        let (s, r, ip_release, divert) = windivert_dev::start_dev_threads(ip, mask).await?;
        return Ok((Some(divert), Some(ip_release), s, r));
    }
    match device::init_device(ip, mask, tun_name).await {
        Ok((s, r)) => Ok((None, None, s, r)),
        Err(e) => {
            log::error!("tun error:{e:?}, falling back to WinDivert");
            let (s, r, ip_release, divert) = windivert_dev::start_dev_threads(ip, mask).await?;
            Ok((Some(divert), Some(ip_release), s, r))
        }
    }
}
