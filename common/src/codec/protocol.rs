/*
   0                                            15                                              31
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5  6  7  8  9  0  1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | 1 |    reserve(7)     |  msg_type(8)        |                      reserve(16)              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                         src ID(32)                                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                         dest ID(32)                                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                         payload(n)                                          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
use std::io;

pub enum MsgType {
    Sync = 1,
    Turn = 2,
    Broadcast = 3,
    DHCPReq = 4,
    DHCPRes = 5,
    PunchStart1 = 6,
    PunchStart2 = 7,
    PunchReq = 8,
    PunchRes = 9,
    Key = 10,
    Ping = 11,
    Pong = 12,
}
impl Into<u8> for MsgType {
    fn into(self) -> u8 {
        self as u8
    }
}
impl TryFrom<u8> for MsgType {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let val = match value {
            1 => MsgType::Sync,
            2 => MsgType::Turn,
            3 => MsgType::Broadcast,
            4 => MsgType::DHCPReq,
            5 => MsgType::DHCPRes,
            6 => MsgType::PunchStart1,
            7 => MsgType::PunchStart2,
            8 => MsgType::PunchReq,
            9 => MsgType::PunchRes,
            10 => MsgType::Key,
            11 => MsgType::Ping,
            12 => MsgType::Pong,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid msg type:{value}"),
                ));
            }
        };
        Ok(val)
    }
}

pub struct NetPacket<B> {
    buffer: B,
}
impl<B: AsRef<[u8]>> NetPacket<B> {
    pub fn new(buffer: B) -> io::Result<NetPacket<B>> {
        if buffer.as_ref().len() < 12 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(NetPacket { buffer })
    }

    pub fn buffer(&self) -> &[u8] {
        self.buffer.as_ref()
    }
    pub fn into_buffer(self) -> B {
        self.buffer
    }
    /// 获取 msg_type (第1字节)
    pub fn msg_type(&self) -> u8 {
        self.buffer.as_ref()[1]
    }

    /// 获取 src_id (4 字节，大端)
    pub fn src_id(&self) -> u32 {
        let bytes = &self.buffer.as_ref()[4..8];
        u32::from_be_bytes(bytes.try_into().unwrap())
    }

    /// 获取 dest_id (4 字节，大端)
    pub fn dest_id(&self) -> u32 {
        let bytes = &self.buffer.as_ref()[8..12];
        u32::from_be_bytes(bytes.try_into().unwrap())
    }

    /// 获取 payload（从字节 12 起）
    pub fn payload(&self) -> &[u8] {
        &self.buffer.as_ref()[12..]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> NetPacket<B> {
    pub fn set_msg_type(&mut self, msg_type: u8) {
        self.buffer.as_mut()[0] = 0x80;
        self.buffer.as_mut()[1] = msg_type;
    }

    pub fn set_src_id(&mut self, id: u32) {
        self.buffer.as_mut()[4..8].copy_from_slice(&id.to_be_bytes());
    }

    pub fn set_dest_id(&mut self, id: u32) {
        self.buffer.as_mut()[8..12].copy_from_slice(&id.to_be_bytes());
    }

    pub fn set_payload(&mut self, data: &[u8]) -> io::Result<()> {
        let buf = self.buffer.as_mut();
        if buf.len() < 12 + data.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid message length",
            ));
        }
        buf[12..12 + data.len()].copy_from_slice(data);
        Ok(())
    }
}
