#[path = "common.rs"]
mod common;

use anyhow::{anyhow, Ok, Result};
use common::generate_random_string;
use futures::{SinkExt, StreamExt};

use bytes::BytesMut;
use tokio_util::codec::Framed;

use tun::{TunPacket, TunPacketCodec};

// we need this for testing
use async_trait::async_trait;

#[async_trait]
pub trait FerrumTun: Send {
    fn get_name(self: &Self) -> &str;
    async fn read(self: &mut Self) -> Result<FerrumTunFrame>;
    async fn write(self: &mut Self, buf: &[u8]) -> Result<()>;
}
pub struct FerrumTunPosix {
    pub name: String,
    stream: Framed<tun::AsyncDevice, TunPacketCodec>,
    pub frame_bytes: BytesMut,
    pub frame_wait_len: usize,
}
pub struct FerrumTunFrame {
    pub data: BytesMut,
}
impl FerrumTunPosix {
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

        Ok(FerrumTunPosix {
            frame_bytes: BytesMut::with_capacity(capacity),
            frame_wait_len: 0,
            name: devname,
            stream: dev.into_framed(),
        })
    }
}

#[async_trait]
impl FerrumTun for FerrumTunPosix {
    #[allow(unused)]
    fn get_name(self: &Self) -> &str {
        self.name.as_str()
    }
    #[allow(unused)]
    async fn read(self: &mut Self) -> Result<FerrumTunFrame> {
        let res = self.stream.next().await;
        match res {
            None => Err(anyhow!("tun data is empty")),
            Some(data) => match data {
                Err(e) => Err(e.into()),
                packet => {
                    let packet_data = packet.unwrap();
                    let packet_bytes = packet_data.get_bytes();

                    let mut d = BytesMut::with_capacity(packet_bytes.len());
                    d.extend_from_slice(packet_bytes);
                    Ok(FerrumTunFrame { data: d })
                }
            },
        }
    }

    #[allow(unused)]
    async fn write(self: &mut Self, buf: &[u8]) -> Result<()> {
        self.stream
            .send(TunPacket::new(buf.to_vec()))
            .await
            .map_err(|err| anyhow!(err.to_string()))
    }
}

#[cfg(target_os = "linux")]
#[allow(unused)]
#[cfg(test)]
mod tests {
    use bytes::{Buf, Bytes};

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

        let tun_result = FerrumTunPosix::new(4096);
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

            let tun_result = FerrumTunPosix::new(4096);
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
