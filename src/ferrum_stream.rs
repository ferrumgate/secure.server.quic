#[path = "ferrum_proto.rs"]
mod ferrum_proto;

use anyhow::{anyhow, Result};
//use async_trait::async_trait;

pub use ferrum_proto::{
    FerrumFrame, FerrumFrameBytes, FerrumFrameStr, FerrumProto, FerrumProtoDefault, FrameBytes,
    FrameNone, FrameStr, FERRUM_FRAME_BYTES_TYPE, FERRUM_FRAME_STR_TYPE,
};
use quinn::{RecvStream, SendStream};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

// we need this for testing
use async_trait::async_trait;

#[async_trait]
pub trait FerrumReadStream: Send + Sync {
    async fn read_ext(&mut self, buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error>;
}

#[async_trait]
impl FerrumReadStream for RecvStream {
    async fn read_ext(&mut self, buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
        self.read(buf).await.map_err(|err| anyhow!(err.to_string()))
    }
}

#[async_trait]
pub trait FerrumWriteStream: Send + Sync {
    async fn write_ext(&mut self, buf: &mut [u8]) -> Result<(), anyhow::Error>;
}

#[async_trait]
impl FerrumWriteStream for SendStream {
    async fn write_ext(&mut self, buf: &mut [u8]) -> Result<(), anyhow::Error> {
        self.write_all(buf)
            .await
            .map_err(|err| anyhow!(err.to_string()))
    }
}

pub enum FerrumStreamFrame {
    FrameStr(FerrumFrameStr),
    FrameBytes(FerrumFrameBytes),
}

pub struct FerrumStream {}
impl FerrumStream {
    pub async fn read_next_frame(
        read_buf: &mut Vec<u8>,
        proto: &mut dyn FerrumProto,
        read_stream: &mut dyn FerrumReadStream,
        cancel_token: &CancellationToken,
    ) -> Result<FerrumStreamFrame> {
        //returns STR or BYTES frame, not NONE frame
        let frame = proto.decode_frame()?;
        // test a1
        if let FerrumFrame::FrameBytes(a) = frame {
            return Ok(FerrumStreamFrame::FrameBytes(a));
        }
        // test a2
        if let FerrumFrame::FrameStr(a) = frame {
            return Ok(FerrumStreamFrame::FrameStr(a));
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
                            // test b1
                            error!("stream read error {}", e);
                            return Err(anyhow!("stream read error"));
                        },
                        Ok(data)=>{
                        debug!("received data");
                            match data {
                                Some(0) => {
                                    // test b2
                                    info!("stream closed");
                                    return Err(anyhow!("stream closed"));
                                }
                                Some(data) => {

                                    debug!("data received bytes {}", data);
                                    proto.write(&read_buf[0..data]);

                                    let frame = proto.decode_frame()?;

                                    match frame {
                                    FerrumFrame::FrameBytes(a) =>{
                                        // test b3
                                        return Ok(FerrumStreamFrame::FrameBytes(a));
                                    }
                                    FerrumFrame::FrameStr(a) => {
                                        // test b4
                                        return Ok(FerrumStreamFrame::FrameStr(a));
                                    }
                                    _=>{}
                                    // this breaks loop
                                    // we need to wait for much
                                    /* FerrumFrame::FrameNone => {
                                        // test bb1
                                        return Ok(FerrumFrame::FrameNone);
                                    } */
                                }

                                }
                                None => {
                                    //test b5
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

    #[allow(unused)]
    pub async fn read_next_frame_str(
        read_buf: &mut Vec<u8>,
        proto: &mut dyn FerrumProto,
        read_stream: &mut dyn FerrumReadStream,
        cancel_token: &CancellationToken,
    ) -> Result<FerrumFrameStr> {
        let msg = FerrumStream::read_next_frame(read_buf, proto, read_stream, cancel_token).await?;
        match msg {
            FerrumStreamFrame::FrameBytes(_) => {
                // test d2
                return Err(anyhow!("frame is byte"));
            }
            // test d3
            FerrumStreamFrame::FrameStr(a) => return Ok(a),
        }
    }

    #[allow(unused)]
    pub async fn write_str(
        val: &str,
        proto: &mut dyn FerrumProto,
        send: &mut dyn FerrumWriteStream,
    ) -> Result<()> {
        let mut frame = proto.encode_frame_str(val)?;
        send.write_ext(frame.data.as_mut()).await?;
        Ok(())
    }

    #[allow(unused)]
    pub async fn write_bytes(
        val: &[u8],
        proto: &mut dyn FerrumProto,
        send: &mut dyn FerrumWriteStream,
    ) -> Result<()> {
        let mut frame = proto.encode_frame_bytes(val)?;
        send.write_ext(frame.data.as_mut()).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use bytes::{BufMut, BytesMut};

    use super::*;
    struct MockRecvStream {
        buf: Vec<u8>,
        res: Result<Option<usize>, anyhow::Error>,
    }

    #[async_trait]
    impl FerrumReadStream for MockRecvStream {
        async fn read_ext(&mut self, buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
            buf.clone_from_slice(&self.buf);
            match self.res.as_mut() {
                Ok(a) => Ok(a.clone()),
                Err(e) => Err(anyhow!(e.to_string())),
            }
        }
    }
    #[tokio::test]
    async fn read_next_frame_bytes() {
        // test a1
        let read_buf = &mut Vec::<u8>::new();

        let proto = &mut FerrumProtoDefault::new(1024);
        let cancel_token = &CancellationToken::new();

        proto.write(&[FERRUM_FRAME_BYTES_TYPE]);
        let mut bytes = BytesMut::new();
        bytes.put_u16(5u16);
        bytes.extend_from_slice(&[0, 1, 2, 3, 4]);
        proto.write(bytes.as_mut());

        let mut mock_stream = MockRecvStream {
            buf: Vec::new(),
            res: Result::Ok(Some(0usize)),
        };

        let frame =
            FerrumStream::read_next_frame(read_buf, proto, &mut mock_stream, cancel_token).await;

        match frame {
            Err(_) => unreachable!("imposibble"),
            Ok(a) => match a {
                FerrumStreamFrame::FrameBytes(_) => {}
                _ => unreachable!("imposibble"),
            },
        }
    }
    #[tokio::test]
    async fn read_next_frame_str() {
        // test a2
        let read_buf = &mut Vec::<u8>::new();
        let proto = &mut FerrumProtoDefault::new(1024);
        let cancel_token = &CancellationToken::new();

        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        let mut bytes = BytesMut::new();
        bytes.put_u16(5u16);
        bytes.extend_from_slice(b"hello");
        proto.write(bytes.as_mut());

        let mut mock_stream = MockRecvStream {
            buf: Vec::new(),
            res: Result::Ok(Some(0usize)),
        };

        let frame =
            FerrumStream::read_next_frame(read_buf, proto, &mut mock_stream, cancel_token).await;

        match frame {
            Err(_) => unreachable!("imposibble"),
            Ok(a) => match a {
                FerrumStreamFrame::FrameStr(_) => {}
                _ => unreachable!("imposibble"),
            },
        }
    }

    #[tokio::test]
    async fn read_next_frame_bytes_and_stream_read_error() {
        // test b1
        let read_buf = &mut vec![0, 1, 2, 3, 4];

        let proto = &mut FerrumProtoDefault::new(1024);
        let cancel_token = &CancellationToken::new();

        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        let mut bytes = BytesMut::new();
        bytes.put_u16(5u16);

        let mut mock_stream = MockRecvStream {
            buf: vec![0, 1, 2, 3, 4],
            res: Result::Err(anyhow!("fake error")),
        };

        let frame =
            FerrumStream::read_next_frame(read_buf, proto, &mut mock_stream, cancel_token).await;

        match frame {
            Err(_) => {}
            Ok(_) => unreachable!("impossible"),
        }
    }
    #[tokio::test]
    async fn read_next_frame_bytes_stream_read_0_length() {
        // test b2
        let read_buf = &mut vec![0, 1, 2, 3, 4];

        let proto = &mut FerrumProtoDefault::new(1024);
        let cancel_token = &CancellationToken::new();

        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        let mut bytes = BytesMut::new();
        bytes.put_u16(5u16);

        let mut mock_stream = MockRecvStream {
            buf: vec![0, 1, 2, 3, 4],
            res: Result::Ok(Some(0)),
        };

        let frame =
            FerrumStream::read_next_frame(read_buf, proto, &mut mock_stream, cancel_token).await;

        match frame {
            Err(_) => {}
            Ok(_) => unreachable!("impossible"),
        }
    }

    #[tokio::test]
    async fn read_next_frame_bytes_stream_read_some_data() {
        //test b3
        let read_buf = &mut vec![0, 1, 2, 3, 4];

        let proto = &mut FerrumProtoDefault::new(1024);
        let cancel_token = &CancellationToken::new();

        proto.write(&[FERRUM_FRAME_BYTES_TYPE]);
        let mut bytes = BytesMut::new();
        bytes.put_u16(5u16);

        let mut mock_stream = MockRecvStream {
            buf: vec![0, 1, 2, 3, 4],
            res: Result::Ok(Some(5)),
        };

        let frame =
            FerrumStream::read_next_frame(read_buf, proto, &mut mock_stream, cancel_token).await;

        match frame {
            Err(_) => unreachable!("impossible"),
            Ok(a) => match a {
                FerrumStreamFrame::FrameBytes(_) => {}
                _ => unreachable!("impossible"),
            },
        }
    }

    #[tokio::test]
    async fn read_next_frame_bytes_stream_read_some_data2() {
        //test b4
        let read_buf = &mut vec![0, 1, 2, 3, 4];

        let proto = &mut FerrumProtoDefault::new(1024);
        let cancel_token = &CancellationToken::new();

        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        let mut bytes = BytesMut::new();
        bytes.put_u16(5u16);

        let mut mock_stream = MockRecvStream {
            buf: b"hello".to_vec(),
            res: Result::Ok(Some(5)),
        };

        let frame =
            FerrumStream::read_next_frame(read_buf, proto, &mut mock_stream, cancel_token).await;

        match frame {
            Err(_) => unreachable!("impossible"),
            Ok(a) => match a {
                FerrumStreamFrame::FrameStr(_) => {}
                _ => unreachable!("impossible"),
            },
        }
    }

    #[tokio::test]
    async fn read_next_frame_bytes_stream_read_none() {
        //test b4
        let read_buf = &mut vec![0, 1, 2, 3, 4];

        let proto = &mut FerrumProtoDefault::new(1024);
        let cancel_token = &CancellationToken::new();

        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        let mut bytes = BytesMut::new();
        bytes.put_u16(5u16);

        let mut mock_stream = MockRecvStream {
            buf: b"hello".to_vec(),
            res: Result::Ok(None),
        };

        let frame =
            FerrumStream::read_next_frame(read_buf, proto, &mut mock_stream, cancel_token).await;

        match frame {
            Err(_) => {}
            Ok(_a) => unreachable!("impossible"),
        }
    }

    #[tokio::test]
    async fn read_next_frame_str_err() {
        //test d2
        let read_buf = &mut vec![0, 1, 2, 3, 4];

        let proto = &mut FerrumProtoDefault::new(1024);
        let cancel_token = &CancellationToken::new();

        proto.write(&[FERRUM_FRAME_BYTES_TYPE]);
        let mut bytes = BytesMut::new();
        bytes.put_u16(5u16);

        let mut mock_stream = MockRecvStream {
            buf: b"hello".to_vec(),
            res: Result::Ok(None),
        };

        let frame =
            FerrumStream::read_next_frame_str(read_buf, proto, &mut mock_stream, cancel_token)
                .await;

        match frame {
            Err(_) => {}
            Ok(_a) => unreachable!("impossible"),
        }
    }

    #[tokio::test]
    async fn read_next_frame_str2() {
        //test d3
        let read_buf = &mut vec![0, 1, 2, 3, 4];

        let proto = &mut FerrumProtoDefault::new(1024);
        let cancel_token = &CancellationToken::new();

        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        let mut bytes = BytesMut::new();
        bytes.put_u16(5u16);

        let mut mock_stream = MockRecvStream {
            buf: b"hello".to_vec(),
            res: Result::Ok(Some(5)),
        };

        let frame =
            FerrumStream::read_next_frame_str(read_buf, proto, &mut mock_stream, cancel_token)
                .await;

        match frame {
            Err(_) => unreachable!("impossible"),
            Ok(_a) => {}
        }
    }
}
