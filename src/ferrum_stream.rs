#[path = "ferrum_proto.rs"]
mod ferrum_proto;

use anyhow::{anyhow, Error, Result};
use ferrum_proto::{FerrumFrame, FerrumFrameBytes, FerrumFrameStr, FerrumProto};
use quinn::{RecvStream, SendStream};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Level};

pub struct FerrumStream {}
impl FerrumStream {
    pub async fn read_next_frame(
        read_buf: &mut Vec<u8>,
        proto: &mut FerrumProto,
        read_stream: &mut RecvStream,
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
                resp = read_stream.read(read_buf.as_mut())=>{

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
}
