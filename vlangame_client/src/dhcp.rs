use bytes::BytesMut;
use common::codec::protocol::{MsgType, NetPacket};
use futures::{SinkExt, StreamExt};
use std::io;
use std::net::Ipv4Addr;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

pub async fn dhcp(
    read_framed: &mut FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
    write_framed: &mut FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
) -> io::Result<(Ipv4Addr, u8)> {
    let mut packet = NetPacket::new(BytesMut::zeroed(12))?;
    packet.set_msg_type(MsgType::DHCPReq.into());
    write_framed.send(packet.into_buffer().freeze()).await?;
    let rs = read_framed
        .next()
        .await
        .ok_or(std::io::Error::from(io::ErrorKind::UnexpectedEof))??;
    let packet = NetPacket::new(rs)?;
    if packet.msg_type() != <MsgType as Into<u8>>::into(MsgType::DHCPRes) {
        return Err(io::Error::other("dhcp error"));
    }
    if packet.payload().len() < 1 {
        return Err(io::Error::other("dhcp error"));
    }
    Ok((packet.dest_id().into(), packet.payload()[0]))
}
