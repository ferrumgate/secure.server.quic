#[path = "common.rs"]
mod common;
#[path = "ferrum_tun.rs"]
mod ferrum_tun;
#[path = "redis_client.rs"]
mod redis_client;

#[path = "ferrum_stream.rs"]
mod ferrum_stream;

#[path = "server_config.rs"]
mod server_config;

use std::{fs, sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};

use common::handle_as_stdin;

use quinn::{Connection, Endpoint, IdleTimeout, RecvStream, SendStream, VarInt};

use rustls::{Certificate, PrivateKey};

use crate::{common::generate_random_string, server::redis_client::RedisClient};

use ferrum_stream::{
    FerrumFrame, FerrumFrameBytes, FerrumFrameStr, FerrumProto, FerrumReadStream, FerrumStream,
    FerrumStreamFrame, FerrumWriteStream,
};
use ferrum_tun::FerrumTun;

pub use server_config::FerrumServerConfig;

use tokio::select;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

pub struct FerrumClient {
    read_buf: Vec<u8>,
    client_ip: String,
    redis_host: String,
    redis_user: Option<String>,
    redis_pass: Option<String>,
    gateway_id: String,
    read_stream: Option<Box<dyn FerrumReadStream>>,
    write_stream: Option<Box<dyn FerrumWriteStream>>,
    proto: Option<FerrumProto>,
    connection: Option<quinn::Connection>,
}
impl FerrumClient {
    pub fn close(&mut self) {
        if self.connection.is_some() {
            self.connection
                .as_mut()
                .unwrap()
                .close(0u32.into(), b"done");
        }
        self.connection = None;
    }
}

pub struct FerrumServerCertChain {
    certs: Vec<Certificate>,
    key: PrivateKey,
}

fn create_certs_chain(options: &FerrumServerConfig) -> Result<FerrumServerCertChain> {
    let (certs, key) = if let (Some(key_path), Some(cert_path)) = (&options.key, &options.cert) {
        let key = fs::read(key_path).context("failed to read private key")?;
        let key = if key_path.extension().map_or(false, |x| x == "der") {
            rustls::PrivateKey(key)
        } else {
            let pkcs8 = rustls_pemfile::pkcs8_private_keys(&mut &*key)
                .context("malformed PKCS #8 private key")?;
            match pkcs8.into_iter().next() {
                Some(x) => rustls::PrivateKey(x),
                None => {
                    let rsa = rustls_pemfile::rsa_private_keys(&mut &*key)
                        .context("malformed PKCS #1 private key")?;
                    match rsa.into_iter().next() {
                        Some(x) => rustls::PrivateKey(x),
                        None => {
                            return Err(anyhow!("no private keys found"));
                        }
                    }
                }
            }
        };
        let cert_chain = fs::read(cert_path).context("failed to read certificate chain")?;
        let cert_chain = if cert_path.extension().map_or(false, |x| x == "der") {
            vec![rustls::Certificate(cert_chain)]
        } else {
            rustls_pemfile::certs(&mut &*cert_chain)
                .context("invalid PEM-encoded certificate")?
                .into_iter()
                .map(rustls::Certificate)
                .collect()
        };

        (cert_chain, key)
    } else {
        let dirs = directories_next::ProjectDirs::from("org", "ferrum", "cert").unwrap();
        let path = dirs.data_local_dir();
        let cert_path = path.join("cert.der");
        let key_path = path.join("key.der");

        info!("generating self-signed certificate");
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();

        let key = cert.serialize_private_key_der();
        let cert = cert.serialize_der().unwrap();
        fs::create_dir_all(path).context("failed to create certificate directory")?;
        fs::write(&cert_path, &cert).context("failed to write certificate")?;
        fs::write(&key_path, &key).context("failed to write private key")?;

        let key = rustls::PrivateKey(key);
        let cert = rustls::Certificate(cert);
        (vec![cert], key)
    };
    Ok(FerrumServerCertChain { certs, key })
}
pub struct FerrumServer {
    options: FerrumServerConfig,
    endpoint: Endpoint,
}

impl FerrumServer {
    pub fn new(options: FerrumServerConfig, certs: FerrumServerCertChain) -> Result<Self> {
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs.certs, certs.key)?;
        server_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
        if options.keylog {
            server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        let transport_config_option = Arc::get_mut(&mut server_config.transport);
        if transport_config_option.is_none() {
            return Err(anyhow!("could not get config"));
        }
        let transport_config = transport_config_option.unwrap();
        transport_config.max_concurrent_uni_streams(0_u8.into());
        transport_config.max_concurrent_bidi_streams(1_u8.into());
        transport_config.keep_alive_interval(Some(Duration::from_secs(7)));
        transport_config.max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(
            options.idle_timeout,
        ))));

        let endpoint = quinn::Endpoint::server(server_config, options.listen)?;
        Ok(FerrumServer {
            options: options,
            endpoint: endpoint,
        })
    }

    #[allow(unused)]
    pub fn create_server_cert_chain(option: &FerrumServerConfig) -> Result<FerrumServerCertChain> {
        create_certs_chain(option)
    }

    pub async fn listen(self: &Self, cancel_token: CancellationToken) {
        info!("starting listening on {}", self.options.listen);
        let is_stdin_out = self.options.stdinout;
        let cancel_token = cancel_token.clone();

        while let Some(conn) = select! {
            conn=self.endpoint.accept()=>{conn},
            _=cancel_token.cancelled()=>{None}
        } {
            //TODO!("check from rate limit list");
            debug!("connection incoming");
            let options = self.options.clone();
            let cancel_token = cancel_token.clone();
            tokio::spawn(async move {
                let mut client = FerrumClient {
                    client_ip: conn.remote_address().to_string(),
                    redis_host: options.redis_host,
                    redis_user: options.redis_user,
                    redis_pass: options.redis_pass,
                    gateway_id: options.gateway_id,
                    proto: None,
                    read_stream: None,
                    write_stream: None,
                    connection: None,
                    read_buf: Vec::with_capacity(1024),
                };
                let fut = timeout(
                    Duration::from_millis(options.connect_timeout),
                    FerrumServer::handle_connection(conn),
                );

                let res = fut.await;
                match res {
                    Err(err) => {
                        //TODO("add to rate limit list");
                        error!("timeout occured {}", err);
                    }
                    Ok(res2) => match res2 {
                        Err(err) => {
                            //TODO!("add to rate limit list");
                            error!("connection failed: {reason}", reason = err.to_string())
                        }
                        Ok((mut send, mut recv, conn)) => {
                            if is_stdin_out {
                                let _ = handle_as_stdin(&mut send, &mut recv, &cancel_token).await;
                                conn.close(0u32.into(), b"done");
                            } else {
                                client.proto = Some(FerrumProto::new(1600));
                                client.read_stream = Some(Box::new(recv));
                                client.write_stream = Some(Box::new(send));
                                client.connection = Some(conn);

                                let _ =
                                    FerrumServer::handle_client(&mut client, cancel_token).await;
                                client.close();
                            }
                        }
                    },
                }
            });
        }
    }
    async fn handle_connection(
        conn: quinn::Connecting,
    ) -> Result<(SendStream, RecvStream, Connection)> {
        let connection = conn.await?;

        info!("established {}", connection.remote_address());

        // Each stream initiated by the client constitutes a new request.

        let (send, recv) = connection.accept_bi().await?;
        info!("stream opened {}", connection.remote_address());
        Ok((send, recv, connection))
    }

    #[allow(dead_code)]
    pub async fn handle_client(
        client: &mut FerrumClient,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        let hello_msg = timeout(
            Duration::from_millis(5000),
            FerrumStream::read_next_frame(
                client.read_buf.as_mut(),
                client.proto.as_mut().unwrap(),
                client.read_stream.as_mut().unwrap().as_mut(),
                &cancel_token,
            ),
        )
        .await
        .map_err(|err| {
            error!("hello msg timeout {}", err);
            err
        })?;
        let hello_msg = hello_msg.map_err(|err| {
            error!("parsing error");
            err
        })?;
        match hello_msg {
            FerrumStreamFrame::FrameBytes(_a) => {
                error!("protocol error");
                return Err(anyhow!("protocol error"));
            }
            FerrumStreamFrame::FrameStr(a) => {
                if a.data != "hello" {
                    error!("protocol error");
                    return Err(anyhow!("protocol error"));
                }
            }
        }

        //let _stdin = tokio::io::stdin();
        let ctoken1 = cancel_token.clone();

        //this block is important for droping
        {
            let mut redis = RedisClient::new(
                client.redis_host.as_str(),
                client.redis_user.clone(),
                client.redis_pass.clone(),
            );
            let _ = redis.connect().await.map_err(|err| {
                error!("connecting to redis failed {}", err);
                err
            })?;
            let tunnel = generate_random_string(63);

            redis
                .execute(
                    tunnel.as_str(),
                    client.client_ip.as_str(),
                    client.gateway_id.as_str(),
                    300000,
                )
                .await?;
            let mut frame = client
                .proto
                .as_ref()
                .unwrap()
                .encode_frame_str(format!("ferrum_open:tunnel= {}\n", tunnel).as_str())?;

            client
                .write_stream
                .as_mut()
                .unwrap()
                .write_ext(frame.data.as_mut())
                .await?;
            let _res = redis
                .subscribe(
                    format!("/tunnel/authentication/{}", tunnel).as_str(),
                    Duration::from_millis(60000),
                )
                .await?;
            if _res != "ok:" {
                error!("could not authenticate {}", client.client_ip)
            }
        }
        debug!("authentication completed for {}", client.client_ip);
        let ftun = FerrumTun::new(2000).map_err(|e| {
            error!("tun create failed: {}", e);
            e
        })?;
        info!("tun opened: {}", ftun.name);

        let mut frame = client
            .proto
            .as_ref()
            .unwrap()
            .encode_frame_str("ferrum_tunnel_confirmed:\n")?;

        client
            .write_stream
            .as_mut()
            .unwrap()
            .write_ext(frame.data.as_mut())
            .await?;

        //output

        let _array = &mut [0u8; 1024];

        //let mut stdout = tokio::io::stderr();

        loop {
            debug!("waiting for input");
            select! {
                _=ctoken1.cancelled()=>{
                    warn!("cancelled");
                    break;
                },
             /*    tunresp=ftun.read_frame()=>{

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
                                    //println!("Array {:?}", &array[..data]);
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
            */
            }
        }

        //let _ = tokio::io::stdout().flush().await;

        //debug!("connection closed");
        debug!("closing everything");
        Ok(())
    }

    #[allow(unused)]
    pub fn close(self: &Self) {
        self.endpoint.wait_idle();
        self.endpoint.close(VarInt::from_u32(0_u32), b"close");
    }
}
