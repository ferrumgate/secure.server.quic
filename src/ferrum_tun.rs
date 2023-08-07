use anyhow::{anyhow, Ok, Result};
use common::generate_random_string;
use futures::{SinkExt, StreamExt};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_util::codec::Framed;
use tracing::{debug, error, info, warn};
use tun::{TunPacket, TunPacketCodec};
#[path = "common.rs"]
mod common;

pub struct FerrumTun {
    pub name: String,
    stream: Framed<tun::AsyncDevice, TunPacketCodec>,
    pub frame_bytes: BytesMut,
    pub frame_wait_len: usize,
}
pub struct FerrumTunFrame {
    pub data: BytesMut,
}

impl FerrumTun {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn new(capacity: usize) -> Result<Self>
    where
        Self: Sized,
    {
        let mut config = tun::Configuration::default();
        config.platform(|config| {
            config.packet_information(false);
        });
        //config.up();
        let devname = format!("ferrum{}", generate_random_string(8));
        config.name(devname.clone());
        let dev = tun::create_as_async(&config)?;

        Ok(FerrumTun {
            frame_bytes: BytesMut::with_capacity(capacity),
            frame_wait_len: 0,
            name: devname,
            stream: dev.into_framed(),
        })
    }
    pub async fn read_frame(self: &mut Self) -> Result<FerrumTunFrame> {
        let res = self.stream.next().await;
        match res {
            None => Err(anyhow!("tun data is empty")),
            Some(data) => match data {
                Err(e) => Err(e.into()),
                packet => {
                    let packet_data = packet.unwrap();
                    let packet_bytes = packet_data.get_bytes();
                    let packet_bytes_len = packet_bytes.len();
                    let bytes_len_bytes =
                        u16::try_from(packet_bytes_len).ok().unwrap().to_be_bytes();

                    let mut d = BytesMut::with_capacity(packet_bytes_len + bytes_len_bytes.len());
                    d.extend_from_slice(bytes_len_bytes.as_slice());
                    d.extend_from_slice(packet_bytes);
                    Ok(FerrumTunFrame { data: d })
                }
            },
        }
    }

    pub fn parse_frame(self: &mut Self) -> Result<Option<FerrumTunFrame>> {
        let mut buf = &mut self.frame_bytes;
        debug!("read frame buf len {}", buf.len());
        let mut lenu = 0;
        if self.frame_wait_len == 0 {
            if buf.len() < 2 {
                return Ok(None);
            }

            let len = buf.get_u16();
            if len == 0 {
                debug!("read frame total len {}", len);
                return Ok(None);
            }
            lenu = usize::from(len);
        } else {
            lenu = self.frame_wait_len;
        }
        if buf.len() < lenu {
            debug!("read frame total len is smaller {}< {}", lenu, buf.len());
            return Ok(None);
        }
        let p = buf.split_to(lenu);
        debug!("read frame buf splitted len {}", p.len());
        self.frame_wait_len = 0;
        let data = Some(FerrumTunFrame { data: p });
        Ok(data)
    }

    pub async fn write(self: &mut Self, buf: &[u8]) -> Result<(), std::io::Error> {
        self.stream.send(TunPacket::new(buf.to_vec())).await
    }
}

#[cfg(target_os = "linux")]
#[allow(unused)]
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;
    #[tokio::test]
    async fn test_tun_linux_new() {
        let uid = std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap();
        if uid != 0 {
            eprintln!("user is not root");
            return;
        }

        let tun_result = FerrumTun::new(4096);
        if let Err(e) = tun_result {
            eprintln!("create tun failed :{}", e);
            assert_eq!(false, true);
            return;
        }
        assert_eq!(tun_result.is_ok(), true);
        let tun = tun_result.unwrap();
        tokio::time::sleep(Duration::from_millis(1000)).await;
    }
    #[tokio::test]
    async fn test_tun_linux_drop() {
        {
            let uid = std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap();
            if uid != 0 {
                eprintln!("user is not root");
                return;
            }

            let tun_result = FerrumTun::new(4096);
            if let Err(e) = tun_result {
                eprintln!("create tun failed :{}", e);
                assert_eq!(false, true);
                return;
            }
            assert_eq!(tun_result.is_ok(), true);
            let tun = tun_result.unwrap();
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }
        eprintln!("tun droped");
        tokio::time::sleep(Duration::from_millis(10000)).await;
    }

    #[test]
    fn test_read_frame() {
        let arr = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut bytes = Bytes::from(arr);
        assert_eq!(bytes.len(), 10);
        let l = bytes.get_u16_le();
        assert_eq!(bytes.len(), 8);
        let mut part1 = bytes.split_to(4);
        assert_eq!(part1.len(), 4);
        assert_eq!(part1.get_u8(), 2u8);
        assert_eq!(bytes.get_u8(), 6);
    }
    #[test]
    fn test_read_frame_mut() {
        let arr = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];

        let bytes_len_bytes = u16::try_from(arr.len()).ok().unwrap().to_ne_bytes();

        let mut d = BytesMut::with_capacity(arr.len() + bytes_len_bytes.len());
        assert_eq!(d.len(), 0);
        assert_eq!(d.capacity(), 12);
        d.extend_from_slice(bytes_len_bytes.as_slice());
        d.extend_from_slice(&arr);
        assert_eq!(d.len(), 12);
        assert_eq!(d.capacity(), 12);
        assert_eq!(d[2], 0);
        let a = d.get_u8();
        assert_eq!(a, 10u8);
        let b = d.get_u8();
        assert_eq!(b, 0u8);
    }
}
