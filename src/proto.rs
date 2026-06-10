use crate::Result;

#[derive(Clone, Copy, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Messages exchanged over the encrypted Noise channels.
///
/// Control channel (client -> server): `Hello`, then periodic `Ping`.
/// Control channel (server -> client): `Pong` in reply to each `Ping`, and
/// `Open` for each new public connection.
/// Data channel (client -> server, first message): `Data` carrying the stream id.
#[derive(Debug)]
pub enum Msg {
    Hello,
    Ping,
    Open { proto: Proto, port: u16, id: u64 },
    Data { id: u64 },
    Pong,
}

impl Msg {
    pub fn encode(&self) -> Vec<u8> {
        match *self {
            Msg::Hello => vec![0],
            Msg::Ping => vec![1],
            Msg::Open { proto, port, id } => {
                let mut b = Vec::with_capacity(12);
                b.push(2);
                b.push(match proto {
                    Proto::Tcp => 1,
                    Proto::Udp => 2,
                });
                b.extend_from_slice(&port.to_be_bytes());
                b.extend_from_slice(&id.to_be_bytes());
                b
            }
            Msg::Data { id } => {
                let mut b = Vec::with_capacity(9);
                b.push(3);
                b.extend_from_slice(&id.to_be_bytes());
                b
            }
            Msg::Pong => vec![4],
        }
    }

    pub fn decode(b: &[u8]) -> Result<Msg> {
        match b.first() {
            Some(0) => Ok(Msg::Hello),
            Some(1) => Ok(Msg::Ping),
            Some(2) if b.len() == 12 => {
                let proto = match b[1] {
                    1 => Proto::Tcp,
                    2 => Proto::Udp,
                    n => return Err(format!("unknown proto byte {n}").into()),
                };
                let port = u16::from_be_bytes([b[2], b[3]]);
                let id = u64::from_be_bytes(b[4..12].try_into().unwrap());
                Ok(Msg::Open { proto, port, id })
            }
            Some(3) if b.len() == 9 => {
                let id = u64::from_be_bytes(b[1..9].try_into().unwrap());
                Ok(Msg::Data { id })
            }
            Some(4) => Ok(Msg::Pong),
            _ => Err(format!("malformed message ({} bytes)", b.len()).into()),
        }
    }
}
