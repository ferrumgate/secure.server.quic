#[path = "ferrum_proto.rs"]
mod ferrum_proto;

use anyhow::{anyhow, Error, Result};
//use async_trait::async_trait;
use bytes::BytesMut;
pub use ferrum_proto::{
    FerrumFrame, FerrumFrameBytes, FerrumFrameStr, FerrumProto, FrameBytes, FrameNone, FrameStr,
    FERRUM_FRAME_BYTES_TYPE, FERRUM_FRAME_STR_TYPE,
};
use quinn::ReadError;
use quinn::{RecvStream, SendStream};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Level};

// we need this for testing
use async_trait::async_trait;

#[async_trait]
pub trait FerrumReadStream {
    async fn read_ext(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError>;
}

#[async_trait]
impl FerrumReadStream for RecvStream {
    async fn read_ext(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
        self.read(buf).await
    }
}

pub struct FerrumStream {}
impl FerrumStream {
    pub async fn read_next_frame(
        read_buf: &mut Vec<u8>,
        proto: &mut FerrumProto,
        read_stream: &mut impl FerrumReadStream,
        cancel_token: &CancellationToken,
    ) -> Result<FerrumFrame> {
        let frame = proto.decode_frame()?;
        if let FerrumFrame::FrameBytes(a) = frame {
            return Ok(FerrumFrame::FrameBytes(a));
        }
        if let FerrumFrame::FrameStr(a) = frame {
            return Ok(FerrumFrame::FrameStr(a));
        }

        loop {
            select! {
                _=cancel_token.cancelled()=>{
                    warn!("cancelled");
                    return Err(anyhow!("cancelled"));
                },
                resp = read_stream.read_ext(read_buf.as_mut())=>{

                    match resp {
                        Err(e) =>{
                            error!("stream read error {}", e);
                            return Err(anyhow!("stream read error"));
                        },
                        Ok(data)=>{
                        debug!("received data");
                            match data {
                                Some(0) => {
                                    info!("stream closed");
                                    return Err(anyhow!("stream closed"));
                                }
                                Some(data) => {
                                    debug!("data received bytes {}", data);
                                    proto.write(&read_buf[0..data]);

                                    let frame = proto.decode_frame()?;

                                    if let FerrumFrame::FrameBytes(a) = frame {
                                        return Ok(FerrumFrame::FrameBytes(a));
                                    }
                                    if let FerrumFrame::FrameStr(a) = frame {
                                        return Ok(FerrumFrame::FrameStr(a));
                                    }

                                }
                                None => {
                                    info!("stream finished");
                                    return Err(anyhow!("stream finished"));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub async fn read_next_frame_str(
        read_buf: &mut Vec<u8>,
        proto: &mut FerrumProto,
        read_stream: &mut RecvStream,
        cancel_token: &CancellationToken,
    ) -> Result<FerrumFrameStr> {
        let msg = FerrumStream::read_next_frame(read_buf, proto, read_stream, cancel_token).await?;
        match msg {
            FerrumFrame::FrameNone => {
                return Err(anyhow!("frame is none"));
            }
            FerrumFrame::FrameBytes(_) => {
                return Err(anyhow!("frame is byte"));
            }
            FerrumFrame::FrameStr(a) => return Ok(a),
        }
    }
    pub async fn write_str(
        val: &str,
        proto: &mut FerrumProto,
        send: &mut SendStream,
    ) -> Result<()> {
        let frame = proto.encode_frame_str(val)?;
        send.write_all(&frame.data).await?;
        Ok(())
    }
    pub async fn write_bytes(
        val: &[u8],
        proto: &mut FerrumProto,
        send: &mut SendStream,
    ) -> Result<()> {
        let frame = proto.encode_frame_bytes(val)?;
        send.write_all(&frame.data).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufReader;

    use bytes::{BufMut, BytesMut};

    use super::*;
    struct MockRecvStream {
        buf: Vec<u8>,
        res: Result<Option<usize>, quinn::ReadError>,
    }

    #[async_trait]
    impl FerrumReadStream for MockRecvStream {
        async fn read_ext(&mut self, buf: &mut [u8]) -> Result<Option<usize>, ReadError> {
            buf.copy_from_slice(self.buf.as_slice());
            self.res.clone()
        }
    }
    #[tokio::test]
    async fn read_next_frame_bytes() {
        let read_buf = &mut Vec::<u8>::new();
        let proto = &mut FerrumProto::new(1024);
        let cancel_token = &CancellationToken::new();

        proto.write(&[FERRUM_FRAME_BYTES_TYPE]);
        let mut bytes = BytesMut::new();
        bytes.put_u16(5u16);
        bytes.extend_from_slice(&[0, 1, 2, 3, 4]);

        let mut mock_stream = MockRecvStream {
            buf: Vec::new(),
            res: Result::Ok(Some(0usize)),
        };

        let frame =
            FerrumStream::read_next_frame(read_buf, proto, &mut mock_stream, cancel_token).await;

        match frame {
            Err(e) => unreachable!("imposibble"),
            Ok(a) => match a {
                FrameBytes(b) => {}
                _ => unreachable!("imposibble"),
            },
        }
    }
}
