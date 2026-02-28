use bytes::BytesMut;
use common::cipher::AesGcmCipher;
use common::codec::protocol::{MsgType, NetPacket};
use dashmap::DashMap;
use futures::SinkExt;
use futures::stream::StreamExt;
use parking_lot::Mutex;
use rand::seq::SliceRandom;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::tcp::OwnedReadHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::Sender;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

#[derive(Debug, Copy, Clone)]
pub struct AppInfo {
    pub network: Ipv4Addr,
    pub mask: u8,
}

pub struct NetServer {
    app_info: AppInfo,
    clients: ClientsInfo,
}
#[derive(Clone, Default)]
pub struct ClientsInfo {
    lock: Arc<Mutex<()>>,
    client_map: Arc<DashMap<SocketAddr, (Sender<BytesMut>, Sender<BytesMut>, Option<Ipv4Addr>)>>,
    client_ip_map: Arc<DashMap<Ipv4Addr, (Sender<BytesMut>, Sender<BytesMut>, SocketAddr)>>,
    disconnect_map: Arc<DashMap<Ipv4Addr, (SocketAddr, Instant)>>,
}
impl ClientsInfo {
    pub fn insert_connect(
        &self,
        address: SocketAddr,
        sender: Sender<BytesMut>,
        timeout_sender: Sender<BytesMut>,
    ) {
        self.client_map
            .insert(address, (sender, timeout_sender, None));
        log::info!(
            "Client connected: {}, current connected count:{}",
            address,
            self.client_map.len()
        );
    }
    pub fn insert(
        &self,
        ip: Ipv4Addr,
        address: SocketAddr,
        sender: &Sender<BytesMut>,
        timeout_sender: &Sender<BytesMut>,
    ) {
        if let Some(mut v) = self.client_map.get_mut(&address) {
            v.value_mut().0 = sender.clone();
            v.value_mut().1 = timeout_sender.clone();
            if let Some(old_ip) = v.value_mut().2.replace(ip) {
                if old_ip != ip {
                    self.client_ip_map.remove(&old_ip);
                }
            }
            self.client_ip_map
                .insert(ip, (sender.clone(), timeout_sender.clone(), address));
        } else {
            self.client_map
                .insert(address, (sender.clone(), timeout_sender.clone(), Some(ip)));
            self.client_ip_map
                .insert(ip, (sender.clone(), timeout_sender.clone(), address));
        }
        log::info!(
            "Client connected sync: {} ({}) , current client count: {}",
            ip,
            address,
            self.client_ip_map.len()
        );
    }
    pub fn disconnect(&self, address: SocketAddr) {
        let _guard = self.lock.lock();
        log::info!("Client disconnect: {}", address);
        if let Some((_, (_, _, ip))) = self.client_map.remove(&address) {
            if let Some(ip) = ip {
                log::info!("Client disconnect: {}-{}", address, ip);
                self.disconnect_map.insert(ip, (address, Instant::now()));
                self.client_ip_map.remove(&ip);
            }
        }
        log::info!(
            "current connected count: {},client count: {}",
            self.client_map.len(),
            self.client_ip_map.len()
        );
    }
}

impl NetServer {
    pub fn new(app_info: AppInfo) -> Self {
        Self {
            app_info,
            clients: ClientsInfo::default(),
        }
    }
    pub async fn start(&self, bind_addr: SocketAddr) -> io::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        loop {
            let (stream, addr) = listener.accept().await?;
            stream.set_nodelay(true)?;
            let clients = self.clients.clone();
            tokio::spawn(handle_client(addr, stream, clients, self.app_info));
        }
    }
}
async fn check_key(
    read_framed: &mut FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
) -> anyhow::Result<()> {
    if let Some(rs) = read_framed.next().await {
        let packet = NetPacket::new(rs?)?;
        if packet.msg_type() != <MsgType as Into<u8>>::into(MsgType::Key) {
            anyhow::bail!("key error");
        }
        let encrypted = String::from_utf8(packet.payload().to_vec())?;
        log::info!("key received: {}", encrypted);
        AesGcmCipher::new().check(&encrypted)?;
        Ok(())
    } else {
        anyhow::bail!("Client disconnected")
    }
}
async fn handle_client(
    socket_addr: SocketAddr,
    stream: TcpStream,
    clients_info: ClientsInfo,
    app_info: AppInfo,
) {
    let (read, write) = stream.into_split();
    let mut read_framed = FramedRead::new(read, LengthDelimitedCodec::new());
    let mut write_framed = FramedWrite::new(write, LengthDelimitedCodec::new());
    if let Err(e) = check_key(&mut read_framed).await {
        log::error!("Error checking key: {e},addr={socket_addr}");
        return;
    }
    let (tx1, mut rx1) = tokio::sync::mpsc::channel(2048);
    let (tx2, mut rx2) = tokio::sync::mpsc::channel(2048);
    let (timeout_tx, mut timeout_rx) = tokio::sync::mpsc::channel(1024);
    clients_info.insert_connect(socket_addr, tx1.clone(), timeout_tx.clone());
    {
        let tx1 = tx1.clone();
        tokio::spawn(async move {
            while let Some(buf) = timeout_rx.recv().await {
                _ = tokio::time::timeout(Duration::from_millis(500), tx1.send(buf)).await;
            }
        });
    }
    tokio::spawn(async move {
        loop {
            let next = read_framed.next().await;
            if let Some(Ok(msg)) = next {
                if tx2.send(msg).await.is_err() {
                    break;
                }
            } else {
                break;
            }
        }
    });
    tokio::spawn(async move {
        loop {
            let recv = rx2.recv().await;
            if let Some(msg) = recv {
                match next_handle(
                    socket_addr,
                    msg,
                    &clients_info,
                    &tx1,
                    &timeout_tx,
                    &app_info,
                )
                .await
                {
                    Ok(Some(rs)) => {
                        if tx1.send(rs).await.is_err() {
                            break;
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        log::warn!("Error handling client: {}", e);
                    }
                }
            } else {
                break;
            }
        }
        clients_info.disconnect(socket_addr);
    });
    tokio::spawn(async move {
        loop {
            let recv = rx1.recv().await;
            if let Some(msg) = recv {
                if write_framed.send(msg.freeze()).await.is_err() {
                    break;
                }
            } else {
                break;
            }
        }
        _ = write_framed.close().await;
    });
}
async fn next_handle(
    socket_addr: SocketAddr,
    msg: BytesMut,
    clients_info: &ClientsInfo,
    sender: &Sender<BytesMut>,
    timeout_sender: &Sender<BytesMut>,
    app_info: &AppInfo,
) -> anyhow::Result<Option<BytesMut>> {
    let packet = NetPacket::new(msg)?;
    let msg_type = MsgType::try_from(packet.msg_type())?;
    match msg_type {
        MsgType::Sync => {
            let ipv4addr = Ipv4Addr::from(packet.src_id());
            let _guard = clients_info.lock.lock();
            clients_info.insert(ipv4addr, socket_addr, sender, timeout_sender);
        }
        MsgType::Turn | MsgType::PunchStart1 | MsgType::PunchStart2 => {
            let dest = Ipv4Addr::from(packet.dest_id());
            let peer_sender = if let Some(v) = clients_info.client_ip_map.get(&dest) {
                v.value().0.clone()
            } else {
                return Ok(None);
            };
            match peer_sender.try_send(packet.into_buffer()) {
                Ok(_) => {}
                Err(TrySendError::Full(buf)) => {
                    _ = timeout_sender.try_send(buf);
                }
                Err(_) => {}
            }
        }
        MsgType::Broadcast => {
            let ipv4addr = Ipv4Addr::from(packet.src_id());
            let mut list: Vec<Sender<BytesMut>> = clients_info
                .client_map
                .iter()
                .filter(|x| *x.key() != socket_addr && x.value().2 != Some(ipv4addr))
                .map(|x| x.value().0.clone())
                .collect();
            list.shuffle(&mut rand::rng());
            for x in list {
                let buf = packet.buffer().into();
                match x.try_send(buf) {
                    Ok(_) => {}
                    Err(TrySendError::Full(buf)) => {
                        _ = timeout_sender.try_send(buf);
                    }
                    Err(TrySendError::Closed(_)) => {}
                }
            }
        }
        MsgType::DHCPReq => {
            let _guard = clients_info.lock.lock();
            if let Some(ip) = find_unused_ip(
                &clients_info.client_ip_map,
                &clients_info.disconnect_map,
                app_info.network,
                app_info.mask,
            ) {
                clients_info.insert(ip, socket_addr, sender, timeout_sender);
                let mut packet = NetPacket::new(BytesMut::zeroed(13))?;
                packet.set_msg_type(MsgType::DHCPRes.into());
                packet.set_dest_id(ip.into());
                packet.set_payload(&[app_info.mask])?;
                return Ok(Some(packet.into_buffer()));
            } else {
                log::warn!(
                    "IP address exhaustion {}/{} {socket_addr}",
                    app_info.network,
                    app_info.mask
                );
            }
        }
        MsgType::DHCPRes => {}
        MsgType::PunchReq => {}
        MsgType::PunchRes => {}
        MsgType::Key => {}
        MsgType::Ping => {
            let src = packet.src_id();
            let buf = packet.into_buffer();
            let mut pong = NetPacket::new(buf)?;
            pong.set_msg_type(MsgType::Pong.into());
            pong.set_src_id(0);
            pong.set_dest_id(src);
            return Ok(Some(pong.into_buffer()));
        }
        MsgType::Pong => {}
    }
    Ok(None)
}

pub fn find_unused_ip(
    ip_map: &Arc<DashMap<Ipv4Addr, (Sender<BytesMut>, Sender<BytesMut>, SocketAddr)>>,
    dis_map: &Arc<DashMap<Ipv4Addr, (SocketAddr, Instant)>>,
    network: Ipv4Addr,
    mask: u8,
) -> Option<Ipv4Addr> {
    let base = u32::from(network);
    let netmask = if mask == 0 {
        0
    } else {
        u32::MAX << (32 - mask)
    };
    let network_base = base & netmask;
    let broadcast = network_base | !netmask;
    let mut list: Vec<u32> = ((network_base + 1)..broadcast).collect();
    list.shuffle(&mut rand::rng());
    // 通常跳过 .0 和 .255，即 network 和 broadcast 地址
    for host in list {
        let ip = Ipv4Addr::from(host);
        if let Some(v) = dis_map.get(&ip) {
            if Instant::now() < v.value().1 + Duration::from_secs(10 * 60) {
                continue;
            }
        }
        if !ip_map.contains_key(&ip) {
            return Some(ip);
        }
    }

    None // 没有可用 IP
}
