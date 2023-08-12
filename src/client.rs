#![cfg_attr(debug_assertions, allow(dead_code, unused_imports))]

#[path = "client_config.rs"]
mod client_config;

#[path = "common.rs"]
mod common;
#[path = "ferrum_tun.rs"]
mod ferrum_tun;

#[path = "ferrum_stream.rs"]
mod ferrum_stream;

use anyhow::{anyhow, Error, Result};
use bytes::BytesMut;
use clap::Parser;
use std::{
    borrow::BorrowMut,
    fs,
    io::{self, Write},
    net::{SocketAddr, ToSocketAddrs},
    ops::{Deref, DerefMut},
    path::PathBuf,
    str,
    sync::Arc,
    time::{Duration, Instant},
};

pub use client_config::FerrumClientConfig;
use common::{get_log_level, handle_as_stdin};
use ferrum_tun::FerrumTun;
use quinn::{IdleTimeout, RecvStream, SendStream, TransportConfig, VarInt};
use rustls::{OwnedTrustAnchor, RootCertStore};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::runtime::Builder;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio::{select, signal};
use tokio_test::block_on;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Level};
use webpki_roots::TLS_SERVER_ROOTS;

use ferrum_stream::{
    FerrumFrame,
    FerrumFrame::{FrameBytes, FrameNone, FrameStr},
    FerrumFrameBytes, FerrumFrameStr, FerrumProto, FerrumReadStream, FerrumStream,
    FerrumWriteStream,
};

// Implementation of `ServerCertVerifier` that verifies everything as trustworthy.
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn create_root_certs(config: &FerrumClientConfig) -> Result<RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();

    roots.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    if let Some(ca_path) = config.ca.clone() {
        roots.add(&rustls::Certificate(fs::read(ca_path)?))?;
    }
    Ok(roots)
}

pub struct FerrumClient {
    read_buf: Vec<u8>,
    options: FerrumClientConfig,
    crypto: rustls::client::ClientConfig,
    connection: Option<Box<quinn::Connection>>,
    read_stream: Option<Box<dyn FerrumReadStream>>,
    write_stream: Option<Box<dyn FerrumWriteStream>>,
    proto: Option<FerrumProto>,
}
impl FerrumClient {
    pub fn new(options: FerrumClientConfig, certs: RootCertStore) -> Self {
        let mut client = FerrumClient {
            options,
            crypto: rustls::ClientConfig::builder()
                .with_safe_defaults()
                .with_root_certificates(certs)
                .with_no_client_auth(),
            connection: None,
            read_stream: None,
            write_stream: None,
            proto: None,
            read_buf: vec![0; 1024],
        };

        if client.options.insecure {
            client
                .crypto
                .dangerous()
                .set_certificate_verifier(SkipServerVerification::new());
        }

        client.crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
        if client.options.keylog {
            client.crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        }
        client
    }

    async fn internal_connect(&mut self) -> Result<()> {
        let crypto = self.crypto.clone();
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport_config = TransportConfig::default();

        transport_config.max_concurrent_uni_streams(0_u8.into());
        transport_config.max_concurrent_bidi_streams(1_u8.into());
        transport_config.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(
            self.options.idle_timeout,
        ))));
        transport_config
            .keep_alive_interval(Some(Duration::from_millis(self.options.connect_timeout)));

        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
        endpoint.set_default_client_config(client_config);

        let start = Instant::now();
        let host = self.options.host.as_str();
        let remote = self.options.ip.clone();

        info!("connecting to {host} at {remote}");
        let connection = endpoint
            .connect(remote, host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;

        info!("connected at {:?}", start.elapsed());
        let (mut send, recv) = connection.open_bi().await?;
        let mut protocol = FerrumProto::new(32);

        //protocol starting
        FerrumStream::write_str("hello", protocol.borrow_mut(), send.borrow_mut()).await?; //write hello to server for protocol starting

        if self.options.rebind {
            let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
            let addr = socket.local_addr().unwrap();
            error!("rebinding to {addr}");
            endpoint.rebind(socket).expect("rebind failed");
        }
        self.connection = Some(Box::new(connection));

        self.read_stream = Some(Box::new(recv));
        self.write_stream = Some(Box::new(send));
        self.proto = Some(protocol);
        info!("stream opened");

        Ok(())
    }

    pub async fn connect(&mut self) -> Result<()> {
        let result = timeout(
            Duration::from_millis(self.options.connect_timeout),
            self.internal_connect(),
        )
        .await?;
        result
    }
    pub fn close(&mut self) {
        if self.connection.is_some() {
            self.connection
                .as_mut()
                .unwrap()
                .close(0u32.into(), b"done");
        }
    }
    pub fn create_root_certs(config: &FerrumClientConfig) -> Result<RootCertStore> {
        create_root_certs(config)
    }

    pub async fn process(&mut self, cancel_token: CancellationToken) -> Result<()> {
        if self.options.stdinout {
            /* handle_as_stdin(
                self.write_stream.as_mut().unwrap().as_mut(),
                self.read_stream.as_mut().unwrap().as_mut(),
                &cancel_token,
            )
            .await */
            Ok(())
        } else {
            self.handle_client(cancel_token).await
        }
    }
    pub async fn handle_open(self: &mut Self, cancel_token: CancellationToken) -> Result<String> {
        let mut stderr = tokio::io::stderr();

        let frame = FerrumStream::read_next_frame_str(
            self.read_buf.as_mut(),
            self.proto.as_mut().unwrap(),
            self.read_stream.as_mut().unwrap().as_mut(),
            &cancel_token,
        )
        .await
        .map_err(|err| {
            error!("protocol error {}", err);
            err
        })?;
        let res = stderr.write_all(frame.data.as_bytes()).await;
        if let Err(e) = res {
            error!("stdout write failed {}", e);
            return Err(e.into());
        }
        return Ok(frame.data);
    }

    async fn handle_open_confirmed(
        self: &mut Self,
        cancel_token: &CancellationToken,
    ) -> Result<String> {
        let mut stderr = tokio::io::stderr();
        let frame = FerrumStream::read_next_frame_str(
            self.read_buf.as_mut(),
            self.proto.as_mut().unwrap(),
            self.read_stream.as_mut().unwrap().as_mut(),
            &cancel_token,
        )
        .await
        .map_err(|err| {
            error!("protocol error {}", err);
            err
        })?;
        let res = stderr.write_all(frame.data.as_bytes()).await;
        if let Err(e) = res {
            error!("stdout write failed {}", e);
            return Err(e.into());
        }
        return Ok(frame.data);
    }

    #[allow(dead_code)]
    async fn handle_client(self: &mut Self, cancel_token: CancellationToken) -> Result<()> {
        let ctoken1 = cancel_token.clone();

        //wait for ferrum_open
        let result = timeout(
            Duration::from_millis(5000),
            self.handle_open(cancel_token.clone()),
        )
        .await
        .map_err(|err| {
            error!("handle open failed {}", err);
            err
        })?;

        if !result.unwrap().starts_with("ferrum_open:") {
            error!("waits for ferrum_open");
            return Err(anyhow!("ferrum protocol invalid"));
        }

        //wait for ferrum_confirm
        let result = timeout(
            Duration::from_millis(90000),
            self.handle_open_confirmed(&cancel_token.clone()),
        )
        .await?;
        if let Err(e) = result {
            error!("handle confirm failed {}", e);
            return Err(e);
        }
        if !result.unwrap().starts_with("ferrum_tunnel_confirmed:") {
            error!("waits for ferrum_open");
            return Err(anyhow!("ferrum protocol invalid"));
        }

        let mut ftun = FerrumTun::new(4096).map_err(|e| {
            error!("tun create failed: {}", e);
            e
        })?;
        eprintln!("ferrum_tunnel_opened: {}", ftun.name.as_str());

        //output
        let array = &mut [0u8; 4096];

        loop {
            debug!("waiting for input");
            select! {
                _= ctoken1.cancelled()=>{

                    warn!("cancelled");
                    break;
                },
                tunresp=ftun.read()=>{//tun interface readed

                    match tunresp {

                        Err(e) => {

                            error!("tun read error {}", e);
                            break;
                        }
                        Ok(data)=>{

                            debug!("readed from tun {} and streamed",data.data.len());
                            let res=FerrumStream::write_bytes(data.data.as_ref(),
                            self.proto.as_mut().unwrap(),
                            self.write_stream.as_mut().unwrap().as_mut()).await;

                            if let Err(e) =res {
                                    error!("stream write error {}", e);
                                    break;
                            }
                        }
                    }

                },
                resp = self.read_stream.as_mut().unwrap().as_mut().read_ext(array)=>{

                    match resp{
                        Err(e) => {
                            error!("stream read error {}", e);
                            break;
                        },
                        Ok(response) =>{

                            match response {
                                None | Some(0) => {
                                    info!("stream finished");
                                    break;
                                },
                                Some(data) => {
                                    debug!("data received from stream {}", data);
                                    self.proto.as_mut().unwrap().write(&self.read_buf[..data]);


                                    let mut break_loop=true;
                                    loop
                                    {
                                        let res=self.proto.as_mut().unwrap().decode_frame();
                                        match res{
                                            Err(e) =>{
                                                error!("tun parse frame failed {}", e);
                                                break;
                                            }
                                            Ok(res_frame)=>{
                                                match res_frame {
                                                    FrameNone=> {//no frame detected
                                                        break;
                                                    },
                                                    FrameStr(_)=>{
                                                        warn!("not valid frame");
                                                        break;

                                                    },
                                                    FrameBytes(res_data)=>{

                                                        debug!("write tun packet size is: {}",res_data.data.len());
                                                        let res=ftun.write(&res_data.data).await;
                                                        match res{
                                                            Err(e) => {
                                                                error!("tun write failed {}", e);
                                                                break;
                                                            },
                                                            _=>{
                                                                break_loop=false;
                                                            }
                                                        }

                                                    }
                                                }
                                            }
                                        }
                                    }
                                 if break_loop {//error occured
                                    break;
                                 }
                                }

                            }
                        }
                    }
                }
            }
        }

        //debug!("connection closed");
        debug!("closing everything");
        Ok(())
    }
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}

#[cfg(test)]
mod tests {

    use std::{fs::create_dir, net::ToSocketAddrs};

    use clap::Parser;

    use super::*;

    #[test]
    fn test_create_root_certs() {
        let config: FerrumClientConfig = FerrumClientConfig {
            ca: None,
            host: "localhost".to_string(),
            host_port: "localhost:8443".to_string(),
            ip: "127.0.0.1:8443".parse().unwrap(),
            keylog: false,
            rebind: false,
            insecure: false,
            stdinout: false,
            loglevel: "debug".to_string(),
            idle_timeout: 15000,
            connect_timeout: 3000,
        };
        let roots = create_root_certs(&config);
        assert_eq!(roots.is_ok(), true);
    }
}
