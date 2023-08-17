#![cfg_attr(debug_assertions, allow(dead_code, unused_imports))]

#[path = "client_config.rs"]
mod client_config;

use anyhow::{anyhow, Result};

use std::{
    fs,
    sync::Arc,
    time::{Duration, Instant},
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::ferrum_tun::{FerrumTun, FerrumTunPosix};

#[cfg(any(target_os = "windows"))]
use crate::ferrum_tun::{FerrumTun, FerrumTunWin32};

pub use client_config::FerrumClientConfig;
use quinn::{IdleTimeout, TransportConfig, VarInt};
use rustls::{OwnedTrustAnchor, RootCertStore};
use tokio::io::AsyncWriteExt;
use tokio::select;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
//use webpki_roots::TLS_SERVER_ROOTS;

use crate::ferrum_stream::{
    FerrumFrame::{FrameBytes, FrameNone, FrameStr},
    FerrumProto, FerrumProtoDefault, FerrumReadStream, FerrumStream, FerrumWriteStream,
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
    proto: Option<Box<dyn FerrumProto>>,
    tun: Option<Box<dyn FerrumTun>>,
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
            read_buf: vec![0; 1600],
            tun: None,
        };

        if client.options.insecure {
            client
                .crypto
                .dangerous()
                .set_certificate_verifier(SkipServerVerification::new());
        }

        client.crypto.alpn_protocols = crate::common::ALPN_QUIC_HTTP
            .iter()
            .map(|&x| x.into())
            .collect();
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
        let remote = self.options.ip;

        info!("connecting to {host} at {remote}");
        let connection = endpoint
            .connect(remote, host)?
            .await
            .map_err(|e| anyhow!("failed to connect: {}", e))?;

        info!("connected at {:?}", start.elapsed());
        let (send, recv) = connection.open_bi().await?;
        let protocol = FerrumProtoDefault::new(1600);

        if self.options.rebind {
            let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
            let addr = socket.local_addr().unwrap();
            error!("rebinding to {addr}");
            endpoint.rebind(socket).expect("rebind failed");
        }
        self.connection = Some(Box::new(connection));

        self.read_stream = Some(Box::new(recv));
        self.write_stream = Some(Box::new(send));
        self.proto = Some(Box::new(protocol));
        debug!("stream opened");

        FerrumStream::write_str(
            "hello",
            self.proto.as_mut().unwrap().as_mut(),
            self.write_stream.as_mut().unwrap().as_mut(),
        )
        .await?; //write hello to server for protocol starting
                 //protocol starting
        debug!("sending hello msg");
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<()> {
        timeout(
            Duration::from_millis(self.options.connect_timeout),
            self.internal_connect(),
        )
        .await?
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
            self.handle_client(cancel_token, 5000).await
        }
    }
    pub async fn handle_open(&mut self, cancel_token: CancellationToken) -> Result<String> {
        let mut stderr = tokio::io::stderr();

        let frame = FerrumStream::read_next_frame_str(
            self.read_buf.as_mut(),
            self.proto.as_mut().unwrap().as_mut(),
            self.read_stream.as_mut().unwrap().as_mut(),
            &cancel_token,
        )
        .await
        .map_err(|err| {
            //test a1
            error!("protocol error {}", err);
            err
        })?;

        let res = stderr.write_all(frame.data.as_bytes()).await;
        if let Err(e) = res {
            error!("stdout write failed {}", e);
            return Err(e.into());
        }
        let _res = stderr.write_all(b"\n").await;
        let _res = stderr.flush().await;
        //test a2
        Ok(frame.data)
    }

    async fn handle_open_confirmed(&mut self, cancel_token: &CancellationToken) -> Result<String> {
        let mut stderr = tokio::io::stderr();
        let frame = FerrumStream::read_next_frame_str(
            self.read_buf.as_mut(),
            self.proto.as_mut().unwrap().as_mut(),
            self.read_stream.as_mut().unwrap().as_mut(),
            cancel_token,
        )
        .await
        .map_err(|err| {
            //test b1
            error!("protocol error {}", err);
            err
        })?;
        let res = stderr.write_all(frame.data.as_bytes()).await;
        if let Err(e) = res {
            error!("stdout write failed {}", e);
            return Err(e.into());
        }
        let _res = stderr.write_all(b"\n").await;
        let _res = stderr.flush().await;
        //test b2
        Ok(frame.data)
    }

    fn create_tun_device(&mut self) -> Result<()> {
        if self.tun.is_some() {
            return Ok(());
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let tun = FerrumTunPosix::new(4096).map_err(|e| {
            error!("tun create failed: {}", e);
            e
        })?;
        #[cfg(any(target_os = "windows"))]
        let tun = FerrumTunWin32::new(4096).map_err(|e| {
            error!("tun create failed: {}", e);
            e
        })?;
        self.tun = Some(Box::new(tun));
        eprintln!(
            "ferrum_tunnel_opened: {}",
            self.tun.as_ref().unwrap().get_name()
        );
        Ok(())
    }

    #[allow(dead_code)]
    async fn handle_client(
        &mut self,
        cancel_token: CancellationToken,
        timeout_ms: u64,
    ) -> Result<()> {
        let ctoken1 = cancel_token.clone();

        //wait for ferrum_open
        let result = timeout(
            Duration::from_millis(timeout_ms),
            self.handle_open(cancel_token.clone()),
        )
        .await
        .map_err(|err| {
            //test h1
            error!("handle open failed {}", err);
            err
        })?;
        if result.is_err() {
            let err = result.unwrap_err();
            error!("handle open failed {}", err);
            return Err(err);
        }

        if !result.unwrap().starts_with("ferrum_open:") {
            //test h2
            error!("waits for ferrum_open");
            return Err(anyhow!("ferrum protocol invalid"));
        }

        //wait for ferrum_confirm
        let result = timeout(
            Duration::from_millis(90000),
            self.handle_open_confirmed(&cancel_token.clone()),
        )
        .await
        .map_err(|err| {
            //test h1
            error!("handle open confirmed failed {}", err);
            err
        })?;

        if result.is_err() {
            let err = result.unwrap_err();
            error!("handle open confirmed failed {}", err);
            return Err(err);
        }

        if !result.unwrap().starts_with("ferrum_tunnel_confirmed:") {
            error!("ferrum tunnel confirm failed");
            return Err(anyhow!("ferrum protocol invalid"));
        }

        self.create_tun_device()?;

        //output

        let mut last_error: Option<anyhow::Error> = None;
        loop {
            debug!("waiting for input");
            select! {
                _= ctoken1.cancelled()=>{

                    warn!("cancelled");
                    //last_error=Some(anyhow!("wait canceled"));
                    break;
                },
                tunresp=self.tun.as_mut().unwrap().read()=>{//tun interface readed

                    match tunresp {

                        Err(e) => {
                            //test h6
                            error!("tun read error {}", e);
                            last_error=Some(e);
                            break;
                        }
                        Ok(data)=>{
                            //test h7
                            debug!("readed from tun {} and streamed",data.data.len());
                            let res=FerrumStream::write_bytes(data.data.as_ref(),
                            self.proto.as_mut().unwrap().as_mut(),
                            self.write_stream.as_mut().unwrap().as_mut()).await;

                            if let Err(e) =res {
                                //test h8
                                    error!("stream write error {}", e);
                                    last_error=Some(e);
                                    break;
                            }
                        }
                    }

                },
                resp = self.read_stream.as_mut().unwrap().as_mut().read_ext(self.read_buf.as_mut())=>{

                    match resp{
                        Err(e) => {
                            //test h9
                            error!("stream read error {}", e);
                            last_error=Some(e);
                            break;
                        },
                        Ok(response) =>{

                            match response {
                                None | Some(0) => {
                                    //test h10
                                    info!("stream finished");
                                    last_error=Some(anyhow!("stream closed"));
                                    break;
                                },
                                Some(data) => {
                                    debug!("data received from stream {}", data);
                                    self.proto.as_mut().unwrap().write(&self.read_buf[..data]);


                                    let mut break_main_loop=true;
                                    loop
                                    {
                                        let res=self.proto.as_mut().unwrap().decode_frame();
                                        match res{
                                            Err(e) =>{
                                                //test h11
                                                error!("tun parse frame failed {}", e);
                                                last_error=Some(e);
                                                break;
                                            }
                                            Ok(res_frame)=>{
                                                match res_frame {
                                                    FrameNone=> {//no frame detected, follow stream
                                                        //test h12
                                                        //last_error=Some(anyhow!("no frame"));
                                                        break_main_loop=false;
                                                        break;
                                                    },
                                                    FrameStr(_)=>{
                                                        //test h13
                                                        warn!("not valid frame");
                                                        last_error=Some(anyhow!("str frame"));
                                                        break;

                                                    },
                                                    FrameBytes(res_data)=>{

                                                        debug!("write tun packet size is: {}",res_data.data.len());
                                                        let res=self.tun.as_mut().unwrap().write(&res_data.data).await;
                                                        match res{
                                                            Err(e) => {
                                                                //test h14
                                                                error!("tun write failed {}", e);
                                                                last_error=Some(e);
                                                                break;
                                                            },
                                                            _=>{
                                                                //test h15
                                                                break_main_loop=false;
                                                            }
                                                        }

                                                    }
                                                }
                                            }
                                        }
                                    }
                                 if break_main_loop {//error occured
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
        if last_error.is_none() {
            Ok(())
        } else {
            let err = last_error.unwrap();
            if cfg!(debug_assertions) {
                eprintln!("{}", err);
            } else {
                debug!("{}", err);
            }
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use std::{borrow::BorrowMut, fs::create_dir, net::ToSocketAddrs, rc::Rc};

    use super::*;
    use crate::ferrum_proto::{
        FerrumFrame, FerrumFrameBytes, FerrumFrameStr, FERRUM_FRAME_BYTES_TYPE,
        FERRUM_FRAME_STR_TYPE,
    };
    use crate::ferrum_tun::FerrumTunFrame;
    use bytes::BytesMut;
    use bytes::{Buf, BufMut, Bytes};
    use clap::Parser;
    use std::sync::Mutex;
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

    struct MockSendStream {}

    #[async_trait]
    impl FerrumWriteStream for MockSendStream {
        async fn write_ext(&mut self, _buf: &mut [u8]) -> Result<(), anyhow::Error> {
            Ok(())
        }
    }

    pub fn create_config() -> FerrumClientConfig {
        FerrumClientConfig {
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
        }
    }

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

    #[tokio::test]
    async fn test_handle_open_err() {
        //test a1
        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(FerrumProtoDefault::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {
            buf: vec![0, 1, 2, 3, 4, 5],
            res: Ok(Some(0)),
        }));

        proto.write(&[FERRUM_FRAME_BYTES_TYPE]);
        proto.write(&5u16.to_be_bytes());
        proto.write(b"ferrum_open:");

        client.write_stream = Some(Box::new(MockSendStream {}));

        let cancel_token = CancellationToken::new();
        let res = client.handle_open(cancel_token).await;
        assert_eq!(res.is_err(), true);
    }
    #[tokio::test]
    async fn test_handle_open_ok() {
        //test a2
        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(FerrumProtoDefault::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {
            buf: vec![0, 1, 2, 3, 4, 5],
            res: Ok(Some(0)),
        }));

        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");

        client.write_stream = Some(Box::new(MockSendStream {}));

        let cancel_token = CancellationToken::new();
        let res = client.handle_open(cancel_token).await;
        assert_eq!(res.is_err(), false);
        assert_eq!(res.unwrap(), "ferrum_open:");
    }

    #[tokio::test]
    async fn test_handle_open_confirmed_err() {
        //test b1
        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(FerrumProtoDefault::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {
            buf: vec![0, 1, 2, 3, 4, 5],
            res: Ok(Some(0)),
        }));

        proto.write(&[FERRUM_FRAME_BYTES_TYPE]);
        proto.write(&5u16.to_be_bytes());
        proto.write(b"ferrum_open:");

        client.write_stream = Some(Box::new(MockSendStream {}));

        let cancel_token = CancellationToken::new();
        let res = client.handle_open_confirmed(&cancel_token).await;
        assert_eq!(res.is_err(), true);
    }
    #[tokio::test]
    async fn test_handle_open_confirmed_ok() {
        //test b2
        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(FerrumProtoDefault::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {
            buf: vec![0, 1, 2, 3, 4, 5],
            res: Ok(Some(0)),
        }));

        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");

        client.write_stream = Some(Box::new(MockSendStream {}));

        let cancel_token = CancellationToken::new();
        let res = client.handle_open_confirmed(&cancel_token).await;
        assert_eq!(res.is_err(), false);
        assert_eq!(res.unwrap(), "ferrum_open:");
    }

    struct MockRecvStreamTimeout {}
    #[async_trait]
    impl FerrumReadStream for MockRecvStreamTimeout {
        async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
            tokio::time::sleep(Duration::from_millis(150)).await;
            Ok(Some(5))
        }
    }

    #[tokio::test]
    async fn test_handle_client_timeout() {
        //test h1
        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(FerrumProtoDefault::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStreamTimeout {}));

        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        //proto.write(b"ferrum_open:");

        client.write_stream = Some(Box::new(MockSendStream {}));

        let cancel_token = CancellationToken::new();
        let res = client.handle_client(cancel_token, 10u64).await;

        assert_eq!(res.is_err(), true);
        let err = res.err().unwrap().to_string();
        eprintln!("{}", err);
        assert_eq!(err.starts_with("deadline has elapsed"), true);
    }

    #[tokio::test]
    async fn test_handle_client_invalid_protocol() {
        //test h2
        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(FerrumProtoDefault::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStreamTimeout {}));

        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrudd_openn");

        client.write_stream = Some(Box::new(MockSendStream {}));

        let cancel_token = CancellationToken::new();
        let res = client.handle_client(cancel_token, 10u64).await;

        assert_eq!(res.is_err(), true);
        let err = res.err().unwrap().to_string();
        eprintln!("{}", err);
        assert_eq!(err.starts_with("ferrum protocol invalid"), true);
    }

    #[tokio::test]
    async fn test_handle_client_tun_err() {
        //test h6
        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                tokio::time::sleep(Duration::from_millis(10000000)).await;
                Ok(Some(0))
            }
        }

        struct MockSendStream {}

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, _buf: &mut [u8]) -> Result<(), anyhow::Error> {
                Ok(())
            }
        }

        struct MockTun {}
        #[async_trait]
        impl FerrumTun for MockTun {
            fn get_name(&self) -> &str {
                "mocktun"
            }
            async fn read(&mut self) -> Result<FerrumTunFrame> {
                Err(anyhow!("fake error"))
            }
            async fn write(&mut self, _buf: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(FerrumProtoDefault::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.tun = Some(Box::new(MockTun {}));
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&24u16.to_be_bytes());
        proto.write(b"ferrum_tunnel_confirmed:");

        client.write_stream = Some(Box::new(MockSendStream {}));

        let cancel_token = CancellationToken::new();
        let res = client.handle_client(cancel_token, 10u64).await;

        assert_eq!(res.is_err(), true);
        let err = res.err().unwrap().to_string();
        assert_eq!(err.starts_with("fake error"), true);
    }

    #[tokio::test]
    async fn test_handle_client_tun_read() {
        //test h7
        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                tokio::time::sleep(Duration::from_millis(10000000)).await;
                Ok(Some(0))
            }
        }

        struct MockSendStream {
            buf: Arc<Mutex<Vec<u8>>>,
        }

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, buf: &mut [u8]) -> Result<(), anyhow::Error> {
                self.buf.lock().unwrap().extend_from_slice(buf);
                Ok(())
            }
        }

        struct MockTun {
            sended: bool,
        }
        #[async_trait]
        impl FerrumTun for MockTun {
            fn get_name(&self) -> &str {
                "mocktun"
            }
            async fn read(&mut self) -> Result<FerrumTunFrame> {
                if self.sended {
                    tokio::time::sleep(Duration::from_millis(10000000)).await;
                }
                let mut by = BytesMut::new();
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                self.sended = true;
                Ok(FerrumTunFrame { data: by })
            }
            async fn write(&mut self, _buf: &[u8]) -> Result<()> {
                Ok(())
            }
        }
        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(FerrumProtoDefault::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.tun = Some(Box::new(MockTun { sended: false }));
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&24u16.to_be_bytes());
        proto.write(b"ferrum_tunnel_confirmed:");

        let rc = Arc::new(Mutex::new(Vec::<u8>::new()));
        client.write_stream = Some(Box::new(MockSendStream { buf: rc.clone() }));

        let cancel_token = CancellationToken::new();
        let cancel_token2 = cancel_token.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel_token2.cancel();
        });
        let res = client.handle_client(cancel_token, 50u64).await;
        let _ = tokio::join!(task);
        assert_eq!(res.is_ok(), true);
        let abc = rc.lock().unwrap();
        let arr = abc.as_slice();
        let data = &mut BytesMut::new();
        data.put_u8(2);
        data.put_u16(5u16);
        data.put_slice(&[0, 1, 2, 3, 4]);
        assert_eq!(arr, data.to_vec());
    }

    #[tokio::test]
    async fn test_handle_client_tunread_stream_write_error() {
        //test h8
        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                tokio::time::sleep(Duration::from_millis(10000000)).await;
                Ok(Some(0))
            }
        }

        struct MockSendStream {
            buf: Arc<Mutex<Vec<u8>>>,
        }

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, _buf: &mut [u8]) -> Result<(), anyhow::Error> {
                Err(anyhow!("fake error"))
            }
        }

        struct MockTun {
            sended: bool,
        }
        #[async_trait]
        impl FerrumTun for MockTun {
            fn get_name(&self) -> &str {
                "mocktun"
            }
            async fn read(&mut self) -> Result<FerrumTunFrame> {
                if self.sended {
                    tokio::time::sleep(Duration::from_millis(10000000)).await;
                }
                let mut by = BytesMut::new();
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                self.sended = true;
                Ok(FerrumTunFrame { data: by })
            }
            async fn write(&mut self, _buf: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(FerrumProtoDefault::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.tun = Some(Box::new(MockTun { sended: false }));
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&24u16.to_be_bytes());
        proto.write(b"ferrum_tunnel_confirmed:");

        let rc = Arc::new(Mutex::new(Vec::<u8>::new()));
        client.write_stream = Some(Box::new(MockSendStream { buf: rc.clone() }));

        let cancel_token = CancellationToken::new();

        let res = client.handle_client(cancel_token, 10u64).await;
        assert_eq!(res.is_err(), true);
        let err = res.unwrap_err().to_string();
        eprintln!("{}", err);
        assert_eq!(err.starts_with("fake error"), true);
    }

    #[tokio::test]
    async fn test_handle_client_read_stream_error() {
        //test h9
        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                Err(anyhow!("fake error"))
            }
        }

        struct MockSendStream {
            buf: Arc<Mutex<Vec<u8>>>,
        }

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, _buf: &mut [u8]) -> Result<(), anyhow::Error> {
                Err(anyhow!("fake error"))
            }
        }

        struct MockTun {
            sended: bool,
        }
        #[async_trait]
        impl FerrumTun for MockTun {
            fn get_name(&self) -> &str {
                "mocktun"
            }
            async fn read(&mut self) -> Result<FerrumTunFrame> {
                tokio::time::sleep(Duration::from_millis(10000000)).await;

                let mut by = BytesMut::new();
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                self.sended = true;
                Ok(FerrumTunFrame { data: by })
            }
            async fn write(&mut self, _buf: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(FerrumProtoDefault::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.tun = Some(Box::new(MockTun { sended: false }));
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&24u16.to_be_bytes());
        proto.write(b"ferrum_tunnel_confirmed:");

        let rc = Arc::new(Mutex::new(Vec::<u8>::new()));
        client.write_stream = Some(Box::new(MockSendStream { buf: rc.clone() }));

        let cancel_token = CancellationToken::new();

        let res = client.handle_client(cancel_token, 10u64).await;
        assert_eq!(res.is_err(), true);
        let err = res.unwrap_err().to_string();
        eprintln!("{}", err);
        assert_eq!(err.starts_with("fake error"), true);
    }

    #[tokio::test]
    async fn test_handle_client_read_stream_closed() {
        //test h10
        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                Ok(Some(0))
            }
        }

        struct MockSendStream {
            buf: Arc<Mutex<Vec<u8>>>,
        }

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, _buf: &mut [u8]) -> Result<(), anyhow::Error> {
                Err(anyhow!("fake error"))
            }
        }

        struct MockTun {
            sended: bool,
        }
        #[async_trait]
        impl FerrumTun for MockTun {
            fn get_name(&self) -> &str {
                "mocktun"
            }
            async fn read(&mut self) -> Result<FerrumTunFrame> {
                tokio::time::sleep(Duration::from_millis(10000000)).await;

                let mut by = BytesMut::new();
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                self.sended = true;
                Ok(FerrumTunFrame { data: by })
            }
            async fn write(&mut self, _buf: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(FerrumProtoDefault::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.tun = Some(Box::new(MockTun { sended: false }));
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&24u16.to_be_bytes());
        proto.write(b"ferrum_tunnel_confirmed:");

        let rc = Arc::new(Mutex::new(Vec::<u8>::new()));
        client.write_stream = Some(Box::new(MockSendStream { buf: rc.clone() }));

        let cancel_token = CancellationToken::new();

        let res = client.handle_client(cancel_token, 10u64).await;
        assert_eq!(res.is_err(), true);
        let err = res.unwrap_err().to_string();
        eprintln!("{}", err);
        assert_eq!(err.starts_with("stream closed"), true);
    }

    #[tokio::test]
    async fn test_handle_client_read_stream_() {
        //test h10
        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                Ok(Some(0))
            }
        }

        struct MockSendStream {
            buf: Arc<Mutex<Vec<u8>>>,
        }

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, _buf: &mut [u8]) -> Result<(), anyhow::Error> {
                Err(anyhow!("fake error"))
            }
        }

        struct MockTun {
            sended: bool,
        }
        #[async_trait]
        impl FerrumTun for MockTun {
            fn get_name(&self) -> &str {
                "mocktun"
            }
            async fn read(&mut self) -> Result<FerrumTunFrame> {
                tokio::time::sleep(Duration::from_millis(10000000)).await;

                let mut by = BytesMut::new();
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                self.sended = true;
                Ok(FerrumTunFrame { data: by })
            }
            async fn write(&mut self, _buf: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(FerrumProtoDefault::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.tun = Some(Box::new(MockTun { sended: false }));
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&24u16.to_be_bytes());
        proto.write(b"ferrum_tunnel_confirmed:");

        let rc = Arc::new(Mutex::new(Vec::<u8>::new()));
        client.write_stream = Some(Box::new(MockSendStream { buf: rc.clone() }));

        let cancel_token = CancellationToken::new();

        let res = client.handle_client(cancel_token, 10u64).await;
        assert_eq!(res.is_err(), true);
        let err = res.unwrap_err().to_string();
        eprintln!("{}", err);
        assert_eq!(err.starts_with("stream closed"), true);
    }

    #[tokio::test]
    async fn test_handle_client_proto_error() {
        //test h11
        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                let mut by = BytesMut::new();
                by.put_u8(FERRUM_FRAME_BYTES_TYPE);
                by.put_u16(5u16);
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                _buf[..8].clone_from_slice(&by);
                Ok(Some(8))
            }
        }

        struct MockSendStream {
            buf: Arc<Mutex<Vec<u8>>>,
        }

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, _buf: &mut [u8]) -> Result<(), anyhow::Error> {
                Err(anyhow!("fake error"))
            }
        }

        struct MockTun {
            sended: bool,
        }
        #[async_trait]
        impl FerrumTun for MockTun {
            fn get_name(&self) -> &str {
                "mocktun"
            }
            async fn read(&mut self) -> Result<FerrumTunFrame> {
                tokio::time::sleep(Duration::from_millis(10000000)).await;

                let mut by = BytesMut::new();
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                self.sended = true;
                Ok(FerrumTunFrame { data: by })
            }
            async fn write(&mut self, _buf: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        struct MockFerrumProto {
            real: FerrumProtoDefault,
            count: i32,
        }
        impl MockFerrumProto {
            pub fn new(buf_size: usize) -> Self {
                MockFerrumProto {
                    real: FerrumProtoDefault::new(buf_size),
                    count: 0,
                }
            }
        }
        impl FerrumProto for MockFerrumProto {
            fn write(&mut self, buf: &[u8]) {
                self.real.write(buf);
            }
            fn decode_frame(&mut self) -> Result<FerrumFrame> {
                if self.count < 2 {
                    self.count += 1;
                    return self.real.borrow_mut().decode_frame();
                }

                Err(anyhow!("fake error"))
            }
            fn encode_frame_str(&self, _val: &str) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_str(_val)
            }
            fn encode_frame_bytes(&self, _val: &[u8]) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_bytes(_val)
            }
        }

        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(MockFerrumProto::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.tun = Some(Box::new(MockTun { sended: false }));
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&24u16.to_be_bytes());
        proto.write(b"ferrum_tunnel_confirmed:");

        let rc = Arc::new(Mutex::new(Vec::<u8>::new()));
        client.write_stream = Some(Box::new(MockSendStream { buf: rc.clone() }));

        let cancel_token = CancellationToken::new();

        let res = client.handle_client(cancel_token, 10u64).await;
        assert_eq!(res.is_err(), true);
        let err = res.unwrap_err().to_string();
        eprintln!("{}", err);
        assert_eq!(err.starts_with("fake error"), true);
    }

    #[tokio::test]
    async fn test_handle_client_proto_frame_none() {
        //test h12
        struct MockRecvStream {
            count: i32,
        }
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                if self.count > 0 {
                    tokio::time::sleep(Duration::from_millis(10000000)).await;
                }
                self.count += 1;
                let mut by = BytesMut::new();
                by.put_u8(FERRUM_FRAME_BYTES_TYPE);
                by.put_u16(5u16);
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                _buf[..8].clone_from_slice(&by);
                Ok(Some(8))
            }
        }

        struct MockSendStream {
            buf: Arc<Mutex<Vec<u8>>>,
        }

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, _buf: &mut [u8]) -> Result<(), anyhow::Error> {
                Err(anyhow!("fake error"))
            }
        }

        struct MockTun {
            sended: bool,
        }
        #[async_trait]
        impl FerrumTun for MockTun {
            fn get_name(&self) -> &str {
                "mocktun"
            }
            async fn read(&mut self) -> Result<FerrumTunFrame> {
                tokio::time::sleep(Duration::from_millis(10000000)).await;

                let mut by = BytesMut::new();
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                self.sended = true;
                Ok(FerrumTunFrame { data: by })
            }
            async fn write(&mut self, _buf: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        struct MockFerrumProto {
            real: FerrumProtoDefault,
            count: i32,
        }
        impl MockFerrumProto {
            pub fn new(buf_size: usize) -> Self {
                MockFerrumProto {
                    real: FerrumProtoDefault::new(buf_size),
                    count: 0,
                }
            }
        }
        impl FerrumProto for MockFerrumProto {
            fn write(&mut self, buf: &[u8]) {
                self.real.write(buf);
            }
            fn decode_frame(&mut self) -> Result<FerrumFrame> {
                if self.count < 2 {
                    self.count += 1;
                    return self.real.decode_frame();
                }

                Ok(FerrumFrame::FrameNone)
            }
            fn encode_frame_str(&self, _val: &str) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_str(_val)
            }
            fn encode_frame_bytes(&self, _val: &[u8]) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_bytes(_val)
            }
        }

        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(MockFerrumProto::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream { count: 0 }));
        client.tun = Some(Box::new(MockTun { sended: false }));
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&24u16.to_be_bytes());
        proto.write(b"ferrum_tunnel_confirmed:");

        let rc = Arc::new(Mutex::new(Vec::<u8>::new()));
        client.write_stream = Some(Box::new(MockSendStream { buf: rc.clone() }));

        let cancel_token = CancellationToken::new();
        let cancel_token2 = cancel_token.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel_token2.cancel();
        });
        let res = client.handle_client(cancel_token, 10u64).await;
        let _ = tokio::join!(task);
        assert_eq!(res.is_ok(), true);
        //let err = res.unwrap_err().to_string();
        //eprintln!("{}", err);
        // assert_eq!(err.starts_with("no frame"), true);
    }

    #[tokio::test]
    async fn test_handle_client_proto_frame_str() {
        //test h13
        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                let mut by = BytesMut::new();
                by.put_u8(FERRUM_FRAME_BYTES_TYPE);
                by.put_u16(5u16);
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                _buf[..8].clone_from_slice(&by);
                Ok(Some(8))
            }
        }

        struct MockSendStream {
            buf: Arc<Mutex<Vec<u8>>>,
        }

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, _buf: &mut [u8]) -> Result<(), anyhow::Error> {
                Err(anyhow!("fake error"))
            }
        }

        struct MockTun {
            sended: bool,
        }
        #[async_trait]
        impl FerrumTun for MockTun {
            fn get_name(&self) -> &str {
                "mocktun"
            }
            async fn read(&mut self) -> Result<FerrumTunFrame> {
                tokio::time::sleep(Duration::from_millis(10000000)).await;

                let mut by = BytesMut::new();
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                self.sended = true;
                Ok(FerrumTunFrame { data: by })
            }
            async fn write(&mut self, _buf: &[u8]) -> Result<()> {
                Ok(())
            }
        }

        struct MockFerrumProto {
            real: FerrumProtoDefault,
            count: i32,
        }
        impl MockFerrumProto {
            pub fn new(buf_size: usize) -> Self {
                MockFerrumProto {
                    real: FerrumProtoDefault::new(buf_size),
                    count: 0,
                }
            }
        }
        impl FerrumProto for MockFerrumProto {
            fn write(&mut self, buf: &[u8]) {
                self.real.write(buf);
            }
            fn decode_frame(&mut self) -> Result<FerrumFrame> {
                if self.count < 2 {
                    self.count += 1;
                    return self.real.decode_frame();
                }

                Ok(FerrumFrame::FrameStr(FerrumFrameStr {
                    data: "test".to_string(),
                }))
            }
            fn encode_frame_str(&self, _val: &str) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_str(_val)
            }
            fn encode_frame_bytes(&self, _val: &[u8]) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_bytes(_val)
            }
        }

        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(MockFerrumProto::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.tun = Some(Box::new(MockTun { sended: false }));
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&24u16.to_be_bytes());
        proto.write(b"ferrum_tunnel_confirmed:");

        let rc = Arc::new(Mutex::new(Vec::<u8>::new()));
        client.write_stream = Some(Box::new(MockSendStream { buf: rc.clone() }));

        let cancel_token = CancellationToken::new();

        let res = client.handle_client(cancel_token, 10u64).await;
        assert_eq!(res.is_err(), true);
        let err = res.unwrap_err().to_string();
        eprintln!("{}", err);
        assert_eq!(err.starts_with("str frame"), true);
    }

    #[tokio::test]
    async fn test_handle_client_proto_tun_err() {
        //test h14
        struct MockRecvStream {}
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                let mut by = BytesMut::new();
                by.put_u8(FERRUM_FRAME_BYTES_TYPE);
                by.put_u16(5u16);
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                _buf[..8].clone_from_slice(&by);
                Ok(Some(8))
            }
        }

        struct MockSendStream {
            buf: Arc<Mutex<Vec<u8>>>,
        }

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, _buf: &mut [u8]) -> Result<(), anyhow::Error> {
                Err(anyhow!("fake error"))
            }
        }

        struct MockTun {
            sended: bool,
        }
        #[async_trait]
        impl FerrumTun for MockTun {
            fn get_name(&self) -> &str {
                "mocktun"
            }
            async fn read(&mut self) -> Result<FerrumTunFrame> {
                tokio::time::sleep(Duration::from_millis(10000000)).await;

                let mut by = BytesMut::new();
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                self.sended = true;
                Ok(FerrumTunFrame { data: by })
            }
            async fn write(&mut self, _buf: &[u8]) -> Result<()> {
                Err(anyhow!("fake error"))
            }
        }

        struct MockFerrumProto {
            real: FerrumProtoDefault,
            count: i32,
        }
        impl MockFerrumProto {
            pub fn new(buf_size: usize) -> Self {
                MockFerrumProto {
                    real: FerrumProtoDefault::new(buf_size),
                    count: 0,
                }
            }
        }
        impl FerrumProto for MockFerrumProto {
            fn write(&mut self, buf: &[u8]) {
                self.real.write(buf);
            }
            fn decode_frame(&mut self) -> Result<FerrumFrame> {
                return self.real.decode_frame();
            }
            fn encode_frame_str(&self, _val: &str) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_str(_val)
            }
            fn encode_frame_bytes(&self, _val: &[u8]) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_bytes(_val)
            }
        }

        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(MockFerrumProto::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream {}));
        client.tun = Some(Box::new(MockTun { sended: false }));
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&24u16.to_be_bytes());
        proto.write(b"ferrum_tunnel_confirmed:");

        let rc = Arc::new(Mutex::new(Vec::<u8>::new()));
        client.write_stream = Some(Box::new(MockSendStream { buf: rc.clone() }));

        let cancel_token = CancellationToken::new();

        let res = client.handle_client(cancel_token, 10u64).await;
        assert_eq!(res.is_err(), true);
        let err = res.unwrap_err().to_string();
        eprintln!("{}", err);
        assert_eq!(err.starts_with("fake error"), true);
    }

    #[tokio::test]
    async fn test_handle_client_proto_tun_ok() {
        //test h15
        struct MockRecvStream {
            count: i32,
        }
        #[async_trait]
        impl FerrumReadStream for MockRecvStream {
            async fn read_ext(&mut self, _buf: &mut [u8]) -> Result<Option<usize>, anyhow::Error> {
                if self.count > 0 {
                    tokio::time::sleep(Duration::from_millis(10000000)).await;
                }
                self.count += 1;
                let mut by = BytesMut::new();
                by.put_u8(FERRUM_FRAME_BYTES_TYPE);
                by.put_u16(5u16);
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                _buf[..8].clone_from_slice(&by);
                Ok(Some(8))
            }
        }

        struct MockSendStream {
            buf: Arc<Mutex<Vec<u8>>>,
        }

        #[async_trait]
        impl FerrumWriteStream for MockSendStream {
            async fn write_ext(&mut self, _buf: &mut [u8]) -> Result<(), anyhow::Error> {
                Err(anyhow!("fake error"))
            }
        }

        struct MockTun {
            sended: bool,
            buf: Arc<Mutex<BytesMut>>,
        }

        #[async_trait]
        impl FerrumTun for MockTun {
            fn get_name(&self) -> &str {
                "mocktun"
            }
            async fn read(&mut self) -> Result<FerrumTunFrame> {
                tokio::time::sleep(Duration::from_millis(10000000)).await;

                let mut by = BytesMut::new();
                by.extend_from_slice(&[0, 1, 2, 3, 4]);
                self.sended = true;
                Ok(FerrumTunFrame { data: by })
            }
            async fn write(&mut self, _buf: &[u8]) -> Result<()> {
                self.buf.lock().unwrap().extend_from_slice(_buf);
                Ok(())
            }
        }

        struct MockFerrumProto {
            real: FerrumProtoDefault,
            count: i32,
        }
        impl MockFerrumProto {
            pub fn new(buf_size: usize) -> Self {
                MockFerrumProto {
                    real: FerrumProtoDefault::new(buf_size),
                    count: 0,
                }
            }
        }
        impl FerrumProto for MockFerrumProto {
            fn write(&mut self, buf: &[u8]) {
                self.real.write(buf);
            }
            fn decode_frame(&mut self) -> Result<FerrumFrame> {
                return self.real.decode_frame();
            }
            fn encode_frame_str(&self, _val: &str) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_str(_val)
            }
            fn encode_frame_bytes(&self, _val: &[u8]) -> Result<FerrumFrameBytes> {
                self.real.encode_frame_bytes(_val)
            }
        }

        let config = create_config();
        let certs = create_root_certs(&config).unwrap();
        let mut client = FerrumClient::new(config, certs);
        client.proto = Some(Box::new(MockFerrumProto::new(1024)));
        let proto = client.proto.as_mut().unwrap();

        client.read_stream = Some(Box::new(MockRecvStream { count: 0 }));
        let buf = Arc::new(Mutex::new(BytesMut::new()));
        client.tun = Some(Box::new(MockTun {
            sended: false,
            buf: buf.clone(),
        }));
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&12u16.to_be_bytes());
        proto.write(b"ferrum_open:");
        proto.write(&[FERRUM_FRAME_STR_TYPE]);
        proto.write(&24u16.to_be_bytes());
        proto.write(b"ferrum_tunnel_confirmed:");

        let rc = Arc::new(Mutex::new(Vec::<u8>::new()));
        client.write_stream = Some(Box::new(MockSendStream { buf: rc.clone() }));

        let cancel_token = CancellationToken::new();
        let cancel_token2 = cancel_token.clone();
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(100)).await;
            cancel_token2.cancel();
        });
        let res = client.handle_client(cancel_token, 10u64).await;
        let _ = tokio::join!(task);
        assert_eq!(res.is_ok(), true);
        assert_eq!(buf.lock().unwrap().to_vec(), vec![0u8, 1, 2, 3, 4]);
    }
}
