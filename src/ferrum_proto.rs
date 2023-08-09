use anyhow::{anyhow, Ok, Result};
use common::generate_random_string;
use futures::{SinkExt, StreamExt};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use quinn::{IdleTimeout, RecvStream, SendStream, TransportConfig, VarInt};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};

#[path = "common.rs"]
mod common;

pub struct FerrumProto {
    read_data: BytesMut,
    read_data_wait_len: usize,
    read_data_type: u8,
}
pub struct FerrumFrameStr {
    pub data: String,
}
pub struct FerrumFrameBytes {
    pub data: Vec<u8>,
}

pub enum FerrumFrame {
    FrameNone,
    FrameStr(FerrumFrameStr),
    FrameBytes(FerrumFrameBytes),
}
use FerrumFrame::{FrameBytes, FrameNone, FrameStr};

impl FerrumProto {
    pub fn new(buf_size: usize) -> Self {
        FerrumProto {
            read_data: BytesMut::with_capacity(buf_size),
            read_data_wait_len: 0,
            read_data_type: 0,
        }
    }
    pub fn write(self: &mut Self, buf: &[u8]) {
        self.read_data.extend_from_slice(buf);
    }

    pub fn decode_frame(self: &mut Self) -> Result<FerrumFrame> {
        if self.read_data_wait_len == 0 {
            if self.read_data.len() < 3 {
                return Ok(FrameNone);
            }
            self.read_data_type = self.read_data.get_u8();
            let len = usize::from(self.read_data.get_u16());
            self.read_data_wait_len = len;
        }
        match self.read_data_wait_len {
            //emptyp string and empty array
            0 => match self.read_data_type {
                1 => Ok(FrameStr(FerrumFrameStr {
                    data: "".to_string(),
                })),

                _ => Ok(FrameBytes(FerrumFrameBytes { data: [].to_vec() })),
            },
            // not empty string and array
            len => {
                let p = self.read_data.split_to(self.read_data_wait_len);
                debug!("read frame buf splitted len {}", p.len());
                self.read_data_wait_len = 0;

                if self.read_data_type == 1 {
                    Ok(FrameStr(FerrumFrameStr {
                        data: String::from_utf8(p.to_vec()).unwrap_or(String::from("unknown")),
                    }))
                } else {
                    Ok(FrameBytes(FerrumFrameBytes { data: p.to_vec() }))
                }
            }
        }
    }

    pub fn encode_frame_str(self: &Self, val: &str) -> Result<FerrumFrameBytes> {
        let bytes_len_bytes = u16::try_from(val.len()).ok().unwrap().to_be_bytes();
        let mut d = BytesMut::with_capacity(1 + val.len() + bytes_len_bytes.len());
        d.put_u8(1u8);
        d.extend_from_slice(bytes_len_bytes.as_slice());
        d.extend_from_slice(val.as_bytes());

        Ok(FerrumFrameBytes { data: d.to_vec() })
    }

    pub fn encode_frame_bytes(self: &Self, val: &[u8]) -> Result<FerrumFrameBytes> {
        let bytes_len_bytes = u16::try_from(val.len()).ok().unwrap().to_be_bytes();
        let mut d = BytesMut::with_capacity(1 + val.len() + bytes_len_bytes.len());
        d.put_u8(2u8);
        d.extend_from_slice(bytes_len_bytes.as_slice());
        d.extend_from_slice(val);

        Ok(FerrumFrameBytes { data: d.to_vec() })
    }
}

#[allow(unused)]
#[cfg(test)]
mod tests {
    use super::*;

    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;

    #[test]
    fn encode_decode_str() {
        let mut proto = FerrumProto::new(1024);
        let frame = proto.encode_frame_str("hello").unwrap();

        assert_eq!(frame.data.len(), 8);
        let bytes = &mut bytes::Bytes::from(frame.data);

        let ptype = bytes.get_u8();
        assert_eq!(ptype, 1);
        let len = bytes.get_u16();
        assert_eq!(len, 5);
        assert_eq!(bytes.to_vec(), b"hello");

        let frame = proto.encode_frame_str("hello").unwrap();

        proto.write(&frame.data);
        let res = proto.decode_frame().unwrap();
        match res {
            FrameNone => unreachable!("imposibble"),
            FrameBytes(data) => unreachable!("imposibble"),
            FrameStr(data) => assert_eq!(data.data, "hello"),
        }
    }
}
