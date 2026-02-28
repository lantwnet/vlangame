use lru::LruCache;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

const DEDUP_TTL: Duration = Duration::from_secs(10);
const TCP_CACHE_CAP: usize = 64 * 1024;
const UDP_CACHE_CAP: usize = 64 * 1024;
const IP_CACHE_CAP: usize = 64 * 1024;

#[derive(Clone, Copy, Eq)]
pub struct IpKey {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub id: u16,
    pub total_length: u16,
}
impl PartialEq for IpKey {
    fn eq(&self, other: &Self) -> bool {
        self.src == other.src
            && self.dst == other.dst
            && self.id == other.id
            && self.total_length == other.total_length
    }
}
impl Hash for IpKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.src);
        state.write(&self.dst);
        state.write_u16(self.id);
        state.write_u16(self.total_length);
    }
}

#[derive(Clone, Copy, Eq)]
pub struct UdpKey {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub sport: u16,
    pub dport: u16,
    pub checksum: u16,
}
impl PartialEq for UdpKey {
    fn eq(&self, other: &Self) -> bool {
        self.src == other.src
            && self.dst == other.dst
            && self.sport == other.sport
            && self.dport == other.dport
            && self.checksum == other.checksum
    }
}
impl Hash for UdpKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.src);
        state.write(&self.dst);
        state.write_u16(self.sport);
        state.write_u16(self.dport);
        state.write_u16(self.checksum);
    }
}

#[derive(Clone, Copy, Eq)]
pub struct TcpKey {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub plen: u16,
}
impl PartialEq for TcpKey {
    fn eq(&self, other: &Self) -> bool {
        self.src == other.src
            && self.dst == other.dst
            && self.sport == other.sport
            && self.dport == other.dport
            && self.seq == other.seq
            && self.ack == other.ack
            && self.flags == other.flags
            && self.plen == other.plen
    }
}
impl Hash for TcpKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.src);
        state.write(&self.dst);
        state.write_u16(self.sport);
        state.write_u16(self.dport);
        state.write_u32(self.seq);
        state.write_u32(self.ack);
        state.write_u8(self.flags);
        state.write_u16(self.plen);
    }
}

pub struct Deduper {
    tcp: LruCache<TcpKey, Instant>,
    udp: LruCache<UdpKey, Instant>,
    ip: LruCache<IpKey, Instant>,
}
impl Deduper {
    pub fn new() -> Self {
        Self {
            tcp: LruCache::new(NonZeroUsize::new(TCP_CACHE_CAP).unwrap()),
            udp: LruCache::new(NonZeroUsize::new(UDP_CACHE_CAP).unwrap()),
            ip: LruCache::new(NonZeroUsize::new(IP_CACHE_CAP).unwrap()),
        }
    }

    #[inline]
    pub fn seen_tcp(&mut self, k: TcpKey) -> bool {
        match self.tcp.get(&k) {
            Some(&ts) if ts.elapsed() < DEDUP_TTL => true,
            _ => {
                self.tcp.put(k, Instant::now());
                false
            }
        }
    }
    #[inline]
    pub fn seen_udp(&mut self, k: UdpKey) -> bool {
        match self.udp.get(&k) {
            Some(&ts) if ts.elapsed() < DEDUP_TTL => true,
            _ => {
                self.udp.put(k, Instant::now());
                false
            }
        }
    }
    #[inline]
    pub fn seen_ip(&mut self, k: IpKey) -> bool {
        match self.ip.get(&k) {
            Some(&ts) if ts.elapsed() < DEDUP_TTL => true,
            _ => {
                self.ip.put(k, Instant::now());
                false
            }
        }
    }
}
