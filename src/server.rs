//! This example demonstrates an HTTP server that serves files from a directory.
//!
//! Checkout the `README.md` for guidance.

#[path = "common.rs"]
mod common;

#[path = "ferrum_tun.rs"]
mod ferrum_tun;

#[path = "redis_client.rs"]
mod redis_client;

use std::{
    fs,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use common::handle_as_stdin;
use quinn::{Connection, Endpoint, IdleTimeout, RecvStream, SendStream, VarInt};

use redis::Client;
use rustls::{Certificate, PrivateKey};

use tokio::select;
use tokio::time::timeout;

use crate::{common::generate_random_string, server::redis_client::RedisClient};
use ferrum_tun::FerrumTun;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

pub struct FerrumServerConfig {
    pub listen: SocketAddr,
    pub ip: String,
    pub stdinout: bool,
    pub loglevel: String,
    pub keylog: bool,
    pub key: Option<PathBuf>,
    pub cert: Option<PathBuf>,
    pub connect_timeout: u64,
    pub idle_timeout: u32,
    pub gateway_id: String,
    pub redis_host: String,
    pub redis_user: Option<String>,
    pub redis_pass: Option<String>,
}

#[derive(Parser, Debug)]
#[clap(name = "server")]
pub struct ServerOpt {
    /// file to log TLS keys to for debugging
    #[clap(long = "keylog")]
    pub keylog: bool,

    /// TLS private key in PEM format
    #[clap(short = 'k', long = "key", requires = "cert")]
    pub key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(short = 'c', long = "cert", requires = "key")]
    pub cert: Option<PathBuf>,
    /// Enable stateless retries
    #[clap(long = "stateless-retry")]
    pub stateless_retry: bool,
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::]:8443")]
    pub listen: Option<String>,

    #[clap(long = "port", default_value = "8443")]
    pub port: u16,
    #[clap(long = "stdinout")]
    pub stdinout: bool,

    #[clap(long = "loglevel", default_value = "info")]
    pub loglevel: String,
    #[clap(long = "gateway_id", default_value = "gateway_id")]
    pub gateway_id: String,
    #[clap(long = "redis_host", default_value = "localhost:6379")]
    pub redis_host: String,
    #[clap(long = "redis_user")]
    pub redis_user: Option<String>,
    #[clap(long = "redis_pass")]
    pub redis_pass: Option<String>,
}

#[allow(unused)]
pub fn parse_config(opt: ServerOpt) -> Result<FerrumServerConfig> {
    let mut ip = "".to_owned();
    match opt.listen {
        None => {
            ip.push_str("[::]");
            let port_str = format!(":{}", opt.port);
            ip.push_str(port_str.as_str());
        }
        Some(x) => ip = x.clone(),
    }

    let mut sockaddr = ip.to_socket_addrs()?;
    let sockaddr_v = sockaddr.next();
    if sockaddr_v.is_none() {
        return Err(anyhow!("could not parse listen"));
    }
    let sockaddrs = sockaddr_v.unwrap();

    let config: FerrumServerConfig = FerrumServerConfig {
        listen: sockaddrs,
        ip: ip.clone(),
        stdinout: opt.stdinout,
        loglevel: opt.loglevel,
        cert: opt.cert,
        key: opt.key,
        keylog: opt.keylog,
        connect_timeout: 3000,
        idle_timeout: 15000,
        gateway_id: opt.gateway_id,
        redis_host: opt.redis_host,
        redis_pass: opt.redis_pass,
        redis_user: opt.redis_user,
    };
    Ok(config)
}

pub struct ClientData {
    client_ip: String,
    redis_host: String,
    redis_user: Option<String>,
    redis_pass: Option<String>,
    gateway_id: String,
}

pub struct FerrumServerCertChain {
    certs: Vec<Certificate>,
    key: PrivateKey,
}

pub fn create_certs_chain(options: &FerrumServerConfig) -> Result<FerrumServerCertChain> {
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

    async fn handle_connection(
        conn: quinn::Connecting,
    ) -> Result<(SendStream, RecvStream, Connection)> {
        let connection = conn.await?;
        /*  info!(
            "connection remote: {} {}",
            connection.remote_address(),
            connection
                .handshake_data()
                .unwrap()
                .downcast::<quinn::crypto::rustls::HandshakeData>()
                .unwrap()
                .protocol
                .map_or_else(
                    || "<none>".into(),
                    |x| String::from_utf8_lossy(&x).into_owned()
                )
        ); */

        info!("established {}", connection.remote_address());

        // Each stream initiated by the client constitutes a new request.

        let (send, recv) = connection.accept_bi().await?;
        info!("stream opened {}", connection.remote_address());
        Ok((send, recv, connection))
    }
    #[allow(unused)]
    pub fn create_server_cert_chain(option: &FerrumServerConfig) -> Result<FerrumServerCertChain> {
        create_certs_chain(option)
    }

    #[allow(dead_code)]
    pub async fn handle_client(
        cd: ClientData,
        mut send: SendStream,
        mut recv: RecvStream,
        cancel_token: CancellationToken,
    ) -> Result<()> {
        let _stdin = tokio::io::stdin();
        let ctoken1 = cancel_token.clone();
        //this block is important for droping
        {
            let mut redis = RedisClient::new(
                cd.redis_host.as_str(),
                cd.redis_user.clone(),
                cd.redis_pass.clone(),
            );
            let _ = redis.connect().await.map_err(|err| {
                error!("connecting to redis failed {}", err);
                err
            })?;
            let tunnel = generate_random_string(63);

            redis
                .execute(
                    tunnel.as_str(),
                    cd.client_ip.as_str(),
                    cd.gateway_id.as_str(),
                    300000,
                )
                .await?;
            send.write_all(format!("ferrum_open:tunnel={}\n", tunnel).as_bytes())
                .await?;
            let _res = redis
                .subscribe(
                    format!("/tunnel/authentication/{}", tunnel).as_str(),
                    Duration::from_millis(60000),
                )
                .await?;
            if _res != "ok:" {
                error!("could not authenticate {}", cd.client_ip)
            }
        }
        debug!("authentication completed for {}", cd.client_ip);
        let mut ftun = FerrumTun::new().map_err(|e| {
            error!("tun create failed: {}", e);
            e
        })?;

        send.write_all(format!("ferrum_tunnel_confirmed:\n").as_bytes())
            .await?;

        //output
        let mut array: Vec<u8> = vec![0; 2048];

        //let mut stdout = tokio::io::stdout();

        loop {
            debug!("waiting for input");
            select! {
                _=ctoken1.cancelled()=>{
                    warn!("cancelled");
                    break;
                },
                tunresp=ftun.read()=>{
                    debug!("tun readed");
                    if let Err(e) = tunresp {
                        error!("tun read error {}", e);
                        break;
                    }
                    let res=send.write_all(tunresp.unwrap().get_bytes()).await;
                    if let Err(e)= res{
                        error!("tun read error {}", e);
                        break;
                    }
                },
                resp = recv
                        .read(array.as_mut())=>{

                    if let Err(e) = resp {
                        error!("stream read error {}", e);
                        break;
                    }

                    debug!("stream received data");
                    let response = resp.unwrap();
                    match response {
                        Some(0) => {
                            info!("stream closed");
                            break;
                        }
                        Some(data) => {
                            debug!("data received bytes {}", data);
                            let res=ftun.write(&array[0..data]).await;
                            //let res = stdout.write_all(&array[0..data]).await;
                            if let Err(e) = res {
                                error!("tun write failed {}", e);
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

        //let _ = tokio::io::stdout().flush().await;

        //debug!("connection closed");
        debug!("closing everything");
        Ok(())
    }

    pub async fn listen(self: &Self, cancel_token: CancellationToken) {
        info!("starting listening on {}", self.options.listen);
        let is_stdin_out = self.options.stdinout;
        let cancel_token = cancel_token.clone();

        while let Some(conn) = select! {
            conn=self.endpoint.accept()=>{conn},
            _=cancel_token.cancelled()=>{None}
        } {
            let client_data = ClientData {
                client_ip: conn.remote_address().to_string(),
                redis_host: self.options.redis_host.clone(),
                redis_user: self.options.redis_user.clone(),
                redis_pass: self.options.redis_pass.clone(),
                gateway_id: self.options.gateway_id.clone(),
            };
            //TODO!("check from rate limit list");
            debug!("connection incoming");
            let fut = timeout(
                Duration::from_millis(self.options.connect_timeout),
                FerrumServer::handle_connection(conn),
            );

            let cancel_token = cancel_token.clone();
            tokio::spawn(async move {
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
                        Ok((send, recv, conn)) => {
                            if is_stdin_out {
                                let _ = handle_as_stdin(send, recv, cancel_token).await;
                            } else {
                                let _ = FerrumServer::handle_client(
                                    client_data,
                                    send,
                                    recv,
                                    cancel_token,
                                )
                                .await;
                            }
                            conn.close(0u32.into(), b"done");
                        }
                    },
                }
            });
        }
    }
    #[allow(unused)]
    pub fn close(self: &Self) {
        self.endpoint.wait_idle();
        self.endpoint.close(VarInt::from_u32(0_u32), b"close");
    }
}
