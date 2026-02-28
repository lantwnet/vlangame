use crate::dhcp::dhcp;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

pub fn calculate_broadcast(ip: Ipv4Addr, mask: u8) -> Ipv4Addr {
    let ip_u32 = u32::from(ip);
    let netmask = if mask == 0 {
        0
    } else {
        u32::MAX << (32 - mask)
    };
    let broadcast_u32 = ip_u32 | !netmask;
    Ipv4Addr::from(broadcast_u32)
}

pub async fn parse_or_dhcp(
    local: Option<String>,
    read_framed: &mut FramedRead<OwnedReadHalf, LengthDelimitedCodec>,
    write_framed: &mut FramedWrite<OwnedWriteHalf, LengthDelimitedCodec>,
) -> (Ipv4Addr, u8) {
    if let Some(local) = local {
        let mut split = local.split('/');
        let ip = Ipv4Addr::from_str(split.next().expect("--local error")).expect("--local error");
        let mask = u8::from_str(split.next().expect("--local error")).expect("--local error");
        (ip, mask)
    } else {
        let (ip, mask) = dhcp(read_framed, write_framed).await.unwrap();
        log::info!("DHCP {ip}/{mask}");
        (ip, mask)
    }
}

#[inline]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs()
}

#[inline]
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
