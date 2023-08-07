#![cfg_attr(debug_assertions, allow(dead_code, unused_imports))]

#[path = "common.rs"]
mod common;
#[path = "ferrum_tun.rs"]
mod ferrum_tun;

use anyhow::{anyhow, Error, Result};
use bytes::BytesMut;
use clap::Parser;
use std::{
    borrow::BorrowMut,
    fs,
    io::{self, Write},
    net::{SocketAddr, ToSocketAddrs},
    ops::Deref,
    path::PathBuf,
    str,
    sync::Arc,
    time::{Duration, Instant},
};

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

pub struct FerrumClientConfig {
    pub host: String,
    pub host_port: String,
    pub ip: SocketAddr,
    pub ca: Option<PathBuf>,
    pub keylog: bool,
    pub rebind: bool,
    pub insecure: bool,
    pub stdinout: bool,
    pub loglevel: String,
    pub idle_timeout: u32,
    pub connect_timeout: u64,
}

#[derive(Parser, Debug)]
#[clap(name = "client")]
pub struct ClientConfigOpt {
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[clap(long = "keylog")]
    pub keylog: bool,

    #[clap(long = "insecure")]
    pub insecure: bool,

    #[clap(long = "host", default_value = "localhost:8443")]
    pub host: String,

    /// Custom certificate authority to trust, in DER format
    #[clap(long = "ca")]
    pub ca: Option<PathBuf>,

    /// Simulate NAT rebinding after connecting
    #[clap(long = "rebind")]
    pub rebind: bool,
    #[clap(long = "stdinout")]
    pub stdinout: bool,
    #[clap(long = "loglevel", default_value = "info")]
    pub loglevel: String,
}
#[allow(unused)]
pub fn parse_config(opt: ClientConfigOpt) -> Result<FerrumClientConfig> {
    let mut abc = opt.host.to_socket_addrs()?;
    let ip = abc.next();
    if ip.is_none() {
        return Err(anyhow!("not resolved"));
    }
    let sockaddr = ip.unwrap();
    let just_hostname: Vec<_> = opt.host.split(":").collect();
    //let port = sockaddr.port();
    let config: FerrumClientConfig = FerrumClientConfig {
        host: just_hostname[0].to_string(),
        host_port: opt.host,
        ip: sockaddr,
        ca: opt.ca,
        keylog: opt.keylog,
        rebind: opt.rebind,
        insecure: opt.insecure,
        stdinout: opt.stdinout,
        loglevel: opt.loglevel.clone(),
        connect_timeout: 3000,
        idle_timeout: 15000,
    };

    Ok(config)
}

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

pub fn create_root_certs(config: &FerrumClientConfig) -> Result<RootCertStore> {
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
    options: FerrumClientConfig,
    crypto: rustls::client::ClientConfig,
    connection: Option<quinn::Connection>,
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

    async fn internal_connect(&mut self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
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
        send.write_all(b"hello").await?;
        if self.options.rebind {
            let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
            let addr = socket.local_addr().unwrap();
            error!("rebinding to {addr}");
            endpoint.rebind(socket).expect("rebind failed");
        }
        self.connection = Some(connection);
        info!("stream opened");
        Ok((send, recv))
    }

    pub async fn connect(&mut self) -> Result<(quinn::SendStream, quinn::RecvStream)> {
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

    pub async fn process(
        &mut self,
        send: SendStream,
        recv: RecvStream,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        if self.options.stdinout {
            handle_as_stdin(send, recv, cancel_token).await
        } else {
            self.handle_client(send, recv, cancel_token).await
        }
    }
    pub async fn handle_open(
        self: &mut Self,
        recv: &mut RecvStream,
        cancel_token: CancellationToken,
    ) -> Result<String> {
        let mut array: Vec<u8> = vec![0; 1024];
        let mut stdout = tokio::io::stderr();
        select! {
            _=cancel_token.cancelled()=>{
                warn!("cancelled");
                return Err(anyhow!("cancelled"));
            },

            resp = recv
                    .read(array.as_mut())=>{

                if let Err(e) = resp {
                    error!("stream read error {}", e);
                    return Err(anyhow!("stream read error"));
                }

                debug!("received data");
                let response = resp.unwrap();
                match response {
                    Some(0) => {
                        info!("stream closed");
                        return Err(anyhow!("stream closed"));
                    }
                    Some(data) => {
                        debug!("data received bytes {}", data);

                        let res = stdout.write_all(&array[0..data]).await;
                        if let Err(e) = res {
                            error!("stdout write failed {}", e);
                            return Err(e.into());
                        }
                        let val=str::from_utf8(&array[0..data]);
                        if val.is_err() {
                            return Err(anyhow!("string conversion failed"));
                        }
                        return  Ok(val.unwrap().to_string());
                    }
                    None => {
                        info!("stream finished");
                        return Err(anyhow!("stream finished"));
                    }
                }
            }
        }
    }

    pub async fn handle_open_confirmed(
        self: &mut Self,
        recv: &mut RecvStream,
        cancel_token: CancellationToken,
    ) -> Result<String> {
        let mut array: Vec<u8> = vec![0; 1024];
        let mut stdout = tokio::io::stderr();
        select! {
            _=cancel_token.cancelled()=>{
                warn!("cancelled");
                return Err(anyhow!("cancelled"));
            },

            resp = recv
                    .read(array.as_mut())=>{

                if let Err(e) = resp {
                    error!("stream read error {}", e);
                    return Err(anyhow!("stream read error"));
                }

                debug!("received data");
                let response = resp.unwrap();
                match response {
                    Some(0) => {
                        info!("stream closed");
                        return Err(anyhow!("stream closed"));
                    }
                    Some(data) => {
                        debug!("data received bytes {}", data);

                        let res = stdout.write_all(&array[0..data]).await;
                        if let Err(e) = res {
                            error!("stdout write failed {}", e);
                            return Err(e.into());
                        }
                        let val=str::from_utf8(&array[0..data]);
                        if val.is_err() {
                            return Err(anyhow!("string conversion failed"));
                        }
                        return  Ok(val.unwrap().to_string());
                    }
                    None => {
                        info!("stream finished");
                        return Err(anyhow!("stream finished"));
                    }
                }
            }
        }
    }

    #[allow(dead_code)]
    pub async fn handle_client(
        self: &mut Self,
        mut send: SendStream,
        mut recv: RecvStream,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        let stdin = tokio::io::stdin();
        let ctoken1 = cancel_token.clone();

        //input read
        let _reader = BufReader::with_capacity(2048, stdin);
        let _line = String::new();
        //wait for ferrum_open
        let result = timeout(
            Duration::from_millis(5000),
            self.handle_open(&mut recv, cancel_token.clone()),
        )
        .await?;
        if let Err(e) = result {
            error!("handle open failed {}", e);
            return Err(e);
        }
        if !result.unwrap().starts_with("ferrum_open:") {
            error!("waits for ferrum_open");
            return Err(anyhow!("ferrum protocol invalid"));
        }

        //wait for ferrum_confirm
        let result = timeout(
            Duration::from_millis(90000),
            self.handle_open_confirmed(&mut recv, cancel_token.clone()),
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

        send.flush().await?;

        let mut ftun = FerrumTun::new(4096).map_err(|e| {
            error!("tun create failed: {}", e);
            e
        })?;
        eprintln!("ferrum_tunnel_opened: {}", ftun.name.as_str());

        //output
        let array = &mut [0u8; 4096];
        //let mut stdout = tokio::io::stderr();

        loop {
            debug!("waiting for input");
            select! {
                _=ctoken1.cancelled()=>{
                    warn!("cancelled");
                    break;
                },
                tunresp=ftun.read_frame()=>{

                    match tunresp {
                        Err(e) => {
                            error!("tun read error {}", e);
                            break;
                        }
                        Ok(data)=>{
                            debug!("readed from tun {} and streamed",data.data.len());
                            let res=send.write_all(&data.data).await;
                            if let Err(e)= res{
                                error!("send write error {}", e);
                                break;
                            }
                        }
                    }

                },
                resp = recv.read(array)=>{

                    match resp{
                        Err(e) => {
                            error!("stream read error {}", e);

                            break;
                        },
                        Ok(response) =>{

                            match response {
                                Some(0) => {

                                    info!("stream closed");
                                    break;
                                }
                                Some(data) => {
                                    debug!("data received from stream {}", data);
                                    ftun.frame_bytes.extend_from_slice(&array[..data]);
                                    debug!("remaining data len is {}",ftun.frame_bytes.len());
                                    let mut break_loop=false;
                                    loop{
                                        let res_frame=ftun.parse_frame();
                                        match res_frame {
                                            Err(e) =>{
                                                error!("tun parse frame failed {}", e);
                                                break_loop=true;
                                                break;
                                            }
                                            Ok(res_data)=>{
                                                match res_data {
                                                    None=> {
                                                        break;
                                                    },
                                                    Some(res_data)=>{

                                                        debug!("write tun packet size is: {}",res_data.data.len());
                                                        let res=ftun.write(&res_data.data).await;
                                                        match res{
                                                            Err(e) => {
                                                                error!("tun write failed {}", e);
                                                                break_loop=true;
                                                                break;
                                                            },
                                                            _=>{}
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
                                None => {
                                    info!("stream finished");
                                    break;
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
    fn test_parse_config() {
        let opt: ClientConfigOpt = ClientConfigOpt {
            keylog: false,
            host: String::from("localhost:543"),
            ca: None,
            rebind: true,
            insecure: true,
            stdinout: false,
            loglevel: "debug".to_string(),
        };

        let config_result1 = parse_config(opt);
        assert_eq!(config_result1.is_err(), false);
        let config1 = config_result1.unwrap();
        assert_eq!(config1.host_port, "localhost:543");
        assert_eq!(config1.host, "localhost");
        assert_eq!(config1.ip, "127.0.0.1:543".parse().unwrap());
        assert_eq!(config1.ca, None);
        assert_eq!(
            config1.ip,
            "localhost:543".to_socket_addrs().unwrap().next().unwrap()
        );
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
}
