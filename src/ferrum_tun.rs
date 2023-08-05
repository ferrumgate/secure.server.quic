use anyhow::{anyhow, Ok, Result};
use common::generate_random_string;
use futures::{SinkExt, StreamExt};
use std::io::Error;

use tokio_util::codec::Framed;
use tun::{Configuration, TunPacket, TunPacketCodec};
#[path = "common.rs"]
mod common;

pub struct FerrumTun {
    pub name: String,
    stream: Framed<tun::AsyncDevice, TunPacketCodec>,
}

impl FerrumTun {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn new() -> Result<Self>
    where
        Self: Sized,
    {
        let mut config = tun::Configuration::default();
        config.platform(|config| {
            config.packet_information(false);
        });
        let devname = format!("ferrum{}", generate_random_string(8));
        config.name(devname.clone());
        let dev = tun::create_as_async(&config)?;

        Ok(FerrumTun {
            name: devname,
            stream: dev.into_framed(),
        })
    }
    pub async fn read(self: &mut Self) -> Result<tun::TunPacket> {
        let res = self.stream.next().await;
        match res {
            None => Err(anyhow!("tun data is empty")),
            Some(data) => Ok(data?),
        }
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

        let tun_result = FerrumTun::new();
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

            let tun_result = FerrumTun::new();
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
}
