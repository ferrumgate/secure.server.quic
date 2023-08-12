use anyhow::{Ok, Result};
use bytes::{Buf, BufMut, BytesMut};
use tracing::debug;

pub const FERRUM_FRAME_STR_TYPE: u8 = 0x1;
pub const FERRUM_FRAME_BYTES_TYPE: u8 = 0x2;
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
pub use FerrumFrame::{FrameBytes, FrameNone, FrameStr};

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
                FERRUM_FRAME_STR_TYPE => Ok(FrameStr(FerrumFrameStr {
                    data: "".to_string(),
                })),

                _ => Ok(FrameBytes(FerrumFrameBytes { data: [].to_vec() })),
            },
            // not empty string and array
            _len => {
                if self.read_data.len() < self.read_data_wait_len {
                    return Ok(FrameNone);
                }
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
        d.put_u8(FERRUM_FRAME_BYTES_TYPE);
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
    fn decode_none() {
        let mut proto = FerrumProto::new(1024);
        let frame = proto.decode_frame();
        assert_eq!(frame.is_ok(), true);
        let frame = frame.unwrap();
        let res = match frame {
            FrameBytes(a) => unreachable!("not possible"),
            FrameStr(a) => unreachable!("not possible"),
            FrameNone => Ok(()),
        };

        proto.write(&[FERRUM_FRAME_BYTES_TYPE]);
        //check again
        let frame = proto.decode_frame();
        assert_eq!(frame.is_ok(), true);
        let frame = frame.unwrap();
        let res = match frame {
            FrameBytes(a) => unreachable!("not possible"),
            FrameStr(a) => unreachable!("not possible"),
            FrameNone => Ok(()),
        };
        let mut bytes = BytesMut::new();
        bytes.reserve(16);
        bytes.put_u16(0x0005);
        proto.write(&bytes);
        let frame = proto.decode_frame();
        assert_eq!(frame.is_ok(), true);
        let frame = frame.unwrap();
        let res = match frame {
            FrameBytes(a) => unreachable!("not possible"),
            FrameStr(a) => unreachable!("not possible"),
            FrameNone => Ok(()),
        };

        bytes.clear();
        bytes.extend_from_slice(&[0, 1, 2, 3, 4]);
        proto.write(&bytes);
        let frame = proto.decode_frame();
        assert_eq!(frame.is_ok(), true);
        let frame = frame.unwrap();
        let res = match frame {
            FrameBytes(a) => a,
            FrameStr(a) => unreachable!("not possible"),
            FrameNone => unreachable!("not possible"),
        };
        assert_eq!(res.data, [0, 1, 2, 3, 4])
    }
    #[test]
    fn encode_decode_str() {
        let mut proto = FerrumProto::new(1024);
        let frame = proto.encode_frame_str("hello").unwrap();

        assert_eq!(frame.data.len(), 8);
        let bytes = &mut bytes::Bytes::from(frame.data);

        let ptype = bytes.get_u8();
        assert_eq!(ptype, FERRUM_FRAME_STR_TYPE);
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

    fn encode_decode_bytes() {
        let mut proto = FerrumProto::new(1024);
        let frame = proto.encode_frame_bytes(b"hello").unwrap();

        assert_eq!(frame.data.len(), 8);
        let bytes = &mut bytes::Bytes::from(frame.data);

        let ptype = bytes.get_u8();
        assert_eq!(ptype, FERRUM_FRAME_BYTES_TYPE);
        let len = bytes.get_u16();
        assert_eq!(len, 5);
        assert_eq!(bytes.to_vec(), b"hello");

        let frame = proto.encode_frame_bytes(b"hello").unwrap();

        proto.write(&frame.data);
        let res = proto.decode_frame().unwrap();
        match res {
            FrameNone => unreachable!("imposibble"),
            FrameBytes(data) => assert_eq!(data.data, b"hello"),
            FrameStr(data) => unreachable!("imposibble"),
        }
    }
}
