use crate::handler;
use crate::nat::MyNatInfo;
use bytes::{Buf, Bytes, BytesMut};
use common::cipher::AesGcmCipher;
use common::codec::protocol::{MsgType, NetPacket};
use futures::{SinkExt, StreamExt};
use rust_p2p_core::nat::NatInfo;
use rust_p2p_core::punch::{PunchInfo, PunchModel, Puncher};
use rust_p2p_core::route::RouteKey;
use rust_p2p_core::route::route_table::RouteTable;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

pub async fn msg_sync_task(
    context_handler: ContextHandler,
    mut rx1: Receiver<(u64, Bytes)>,
    status: Arc<AtomicBool>,
    server: String,
    read_framed: Option<FramedRead<OwnedReadHalf, LengthDelimitedCodec>>,
    write_framed: Option<FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>>,
) {
    let (mut read_framed, mut write_framed) =
        if let (Some(r), Some(w)) = (read_framed, write_framed) {
            (r, w)
        } else {
            loop {
                let stream = match TcpStream::connect(&server).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        log::warn!("could not connect to server: {server},err={e:?}");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                };
                let (read, mut write) = handler::tcp_stream_to_framed(stream);
                match send_key(&mut write).await {
                    Ok(_) => {
                        break (read, write);
                    }
                    Err(e) => {
                        log::warn!("could not send key: {e:?},server: {server},");
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                }
            }
        };
    loop {
        log::info!(
            "===== 🚀🚀🚀  Successfully connected to server {}  🚀🚀🚀 =====",
            server
        );
        status.store(true, std::sync::atomic::Ordering::Release);
        msg_sync(
            &context_handler,
            &mut rx1,
            context_handler.ip,
            read_framed,
            write_framed,
        )
        .await;
        status.store(false, std::sync::atomic::Ordering::Release);
        context_handler
            .latency_ms
            .store(u64::MAX, Ordering::Release);
        log::info!("reconnect {}", server);
        (read_framed, write_framed) = loop {
            let (r, mut w) = match TcpStream::connect(&server).await {
                Ok(stream) => tcp_stream_to_framed(stream),
                Err(e) => {
                    log::error!("{:?} {server}", e);
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    continue;
                }
            };
            match send_key(&mut w).await {
                Ok(_) => break (r, w),
                Err(_) => {}
            }
        };
    }
}
pub fn tcp_stream_to_framed(
    stream: TcpStream,
) -> (
    FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
    FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
) {
    if let Err(e) = stream.set_nodelay(true) {
        log::warn!("set_nodelay {:?}", e);
    }
    let (read, write) = stream.into_split();
    let read_framed = FramedRead::new(read, LengthDelimitedCodec::new());
    let write_framed = FramedWrite::new(write, LengthDelimitedCodec::new());
    (read_framed, write_framed)
}
pub async fn send_key(
    write: &mut FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
) -> anyhow::Result<()> {
    let cipher = AesGcmCipher::new();
    let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let data = format!("time={ts}");

    let encrypted = cipher.encrypt(&data);

    let mut packet = NetPacket::new(BytesMut::zeroed(12 + encrypted.len()))?;
    packet.set_msg_type(MsgType::Key.into());
    packet.set_payload(encrypted.as_bytes())?;
    write.send(packet.into_buffer().freeze()).await?;
    Ok(())
}
async fn msg_sync(
    context_handler: &ContextHandler,
    rx1: &mut Receiver<(u64, Bytes)>,
    ipv4addr: Ipv4Addr,
    mut read_framed: FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
    mut write_framed: FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
) {
    let (tx2, mut rx2) = tokio::sync::mpsc::channel::<Bytes>(1024);
    {
        let mut packet = NetPacket::new(BytesMut::zeroed(12)).unwrap();
        packet.set_msg_type(MsgType::Sync.into());
        packet.set_src_id(ipv4addr.into());
        if write_framed
            .send(packet.into_buffer().freeze())
            .await
            .is_err()
        {
            return;
        }
    }
    tokio::spawn(async move {
        while let Some(packet) = rx2.recv().await {
            if write_framed.send(packet).await.is_err() {
                break;
            }
        }
    });
    let mut ping_interval = tokio::time::interval_at(
        tokio::time::Instant::now() + Duration::from_secs(60),
        Duration::from_secs(60),
    );
    loop {
        tokio::select! {
            next = read_framed.next() => {
                if let Some(Ok(msg)) = next {
                    match context_handler.next_handle(msg).await {
                        Ok(None) => {}
                        Ok(Some(rs)) => {
                            if tx2.send(rs).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            log::error!("{:?}", e);
                            break;
                        }
                    }
                } else {
                    break;
                }
            }
            recv = rx1.recv() => {
                if let Some((ts, msg)) = recv {
                    if crate::util::now_secs().saturating_sub(ts) > 10 {
                        continue;
                    }
                    if tx2.send(msg).await.is_err(){
                        break;
                    }
                }else{
                    break;
                }
            }
            _ = ping_interval.tick() => {
                let now_ms = crate::util::now_millis();
                if let Ok(mut packet) = NetPacket::new(BytesMut::zeroed(20)) {
                    packet.set_msg_type(MsgType::Ping.into());
                    packet.set_src_id(ipv4addr.into());
                    let _ = packet.set_payload(&now_ms.to_be_bytes());
                    let _ = tx2.send(packet.into_buffer().freeze()).await;
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct ContextHandler {
    sender: Sender<BytesMut>,
    ip: Ipv4Addr,
    puncher: Option<Puncher>,
    my_nat_info: Option<MyNatInfo>,
    pub latency_ms: Arc<AtomicU64>,
}
impl ContextHandler {
    pub fn new(
        sender: Sender<BytesMut>,
        ip: Ipv4Addr,
        puncher: Option<Puncher>,
        my_nat_info: Option<MyNatInfo>,
    ) -> ContextHandler {
        Self {
            sender,
            ip,
            puncher,
            my_nat_info,
            latency_ms: Arc::new(AtomicU64::new(u64::MAX)),
        }
    }
    pub async fn next_handle(&self, msg: BytesMut) -> anyhow::Result<Option<Bytes>> {
        let packet = NetPacket::new(msg)?;
        let msg_type = MsgType::try_from(packet.msg_type())?;
        let src_id = packet.src_id();
        let ip: u32 = self.ip.into();
        if src_id == ip {
            log::info!("ContextHandler src_id == ip {}", packet.msg_type());
            return Ok(None);
        }
        match msg_type {
            MsgType::Sync => {}
            MsgType::Turn | MsgType::Broadcast => {
                let mut bytes_mut = packet.into_buffer();
                bytes_mut.advance(12);
                _ = self.sender.send(bytes_mut).await;
            }
            MsgType::DHCPReq => {}
            MsgType::DHCPRes => {}
            MsgType::PunchStart1 => {
                if let Ok(str) = core::str::from_utf8(packet.payload()) {
                    if let Ok(peer_nat_info) = serde_json::from_str::<NatInfo>(str) {
                        let Some(my_nat_info) = &self.my_nat_info else {
                            return Ok(None);
                        };
                        let nat_info = my_nat_info.get();
                        let data = serde_json::to_string(&nat_info)?;
                        let mut request = NetPacket::new(BytesMut::zeroed(12))?;
                        request.set_msg_type(MsgType::PunchStart2.into());
                        request.set_src_id(self.ip.into());
                        request.set_dest_id(src_id);
                        let mut bytes_mut = request.into_buffer();
                        bytes_mut.extend_from_slice(data.as_bytes());
                        let Some(puncher) = self.puncher.clone() else {
                            return Ok(None);
                        };
                        let mut punch_req = NetPacket::new(BytesMut::zeroed(12))?;
                        punch_req.set_msg_type(MsgType::PunchReq.into());
                        punch_req.set_src_id(self.ip.into());
                        punch_req.set_dest_id(src_id);
                        tokio::spawn(async move {
                            let rs = puncher
                                .punch(
                                    punch_req.buffer(),
                                    PunchInfo::new(PunchModel::all(), peer_nat_info),
                                )
                                .await;
                            log::info!("punch1 peer_id={},{rs:?}", Ipv4Addr::from(src_id))
                        });
                        return Ok(Some(bytes_mut.freeze()));
                    }
                }
            }
            MsgType::PunchStart2 => {
                if let Ok(str) = core::str::from_utf8(packet.payload()) {
                    if let Ok(peer_nat_info) = serde_json::from_str::<NatInfo>(str) {
                        let mut punch_req = NetPacket::new(BytesMut::zeroed(12))?;
                        punch_req.set_msg_type(MsgType::PunchReq.into());
                        punch_req.set_src_id(self.ip.into());
                        punch_req.set_dest_id(src_id);
                        let Some(puncher) = self.puncher.clone() else {
                            return Ok(None);
                        };

                        tokio::spawn(async move {
                            let rs = puncher
                                .punch(
                                    punch_req.buffer(),
                                    PunchInfo::new(PunchModel::all(), peer_nat_info),
                                )
                                .await;
                            log::info!("punch2 peer_id={},{rs:?}", Ipv4Addr::from(src_id))
                        });
                    }
                }
            }
            MsgType::PunchReq => {}
            MsgType::PunchRes => {}
            MsgType::Key => {}
            MsgType::Ping => {}
            MsgType::Pong => {
                if packet.payload().len() >= 8 {
                    let sent_ms = u64::from_be_bytes(packet.payload()[..8].try_into()?);
                    let rtt = crate::util::now_millis().saturating_sub(sent_ms);
                    self.latency_ms.store(rtt, Ordering::Relaxed);
                    log::info!("server RTT: {}ms", rtt);
                }
            }
        }
        Ok(None)
    }
}
#[derive(Clone)]
pub struct ClientContextHandler {
    sender: Sender<BytesMut>,
    ip: Ipv4Addr,
    route_table: RouteTable<u32>,
}
impl ClientContextHandler {
    pub fn new(
        sender: Sender<BytesMut>,
        ip: Ipv4Addr,
        route_table: RouteTable<u32>,
    ) -> ClientContextHandler {
        Self {
            sender,
            ip,
            route_table,
        }
    }
    pub async fn next_handle(
        &self,
        msg: &[u8],
        route_key: RouteKey,
    ) -> anyhow::Result<Option<Bytes>> {
        let packet = NetPacket::new(msg)?;
        let msg_type = MsgType::try_from(packet.msg_type())?;
        let src_id = packet.src_id();
        let ip: u32 = self.ip.into();
        if src_id == ip {
            log::info!("ClientContextHandler src_id == ip");
            return Ok(None);
        }
        match msg_type {
            MsgType::Sync => {}
            MsgType::Turn | MsgType::Broadcast => {
                self.route_table.update_read_time(&src_id, &route_key);
                _ = self.sender.send(packet.payload().into()).await;
            }
            MsgType::DHCPReq => {}
            MsgType::DHCPRes => {}
            MsgType::PunchStart1 => {}
            MsgType::PunchStart2 => {}
            MsgType::PunchReq => {
                let protocol = route_key.protocol();
                log::info!(
                    "============= PUNCH_REQ ({protocol:?}-{}) =============",
                    Ipv4Addr::from(src_id)
                );
                let mut punch_res = NetPacket::new(BytesMut::zeroed(12))?;
                punch_res.set_msg_type(MsgType::PunchRes.into());
                punch_res.set_src_id(self.ip.into());
                punch_res.set_dest_id(src_id);
                self.route_table.add_route(src_id, (route_key, 1));
                return Ok(Some(punch_res.into_buffer().freeze()));
            }
            MsgType::PunchRes => {
                let protocol = route_key.protocol();
                log::info!(
                    "============= PUNCH_RES ({protocol:?}-{}) =============",
                    Ipv4Addr::from(src_id)
                );
                self.route_table.add_route(src_id, (route_key, 1));
            }
            MsgType::Key => {}
            MsgType::Ping => {}
            MsgType::Pong => {}
        }
        Ok(None)
    }
}
