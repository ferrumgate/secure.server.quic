//! This example demonstrates an HTTP server that serves files from a directory.
//!
//! Checkout the `README.md` for guidance.

use std::{
    fs,
    io::Bytes,
    net::{SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
    sync::Mutex,
};

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use common::{get_log_level, handle_as_stdin};
use quinn::{Connecting, Connection, RecvStream, SendStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

mod common;

struct FerrumServerConfig {
    listen: SocketAddr,
    ip: String,
    stdinout: bool,
    loglevel: String,
    keylog: bool,
    key: Option<PathBuf>,
    cert: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[clap(name = "server")]
struct Opt {
    /// file to log TLS keys to for debugging
    #[clap(long = "keylog")]
    keylog: bool,

    /// TLS private key in PEM format
    #[clap(short = 'k', long = "key", requires = "cert")]
    key: Option<PathBuf>,
    /// TLS certificate in PEM format
    #[clap(short = 'c', long = "cert", requires = "key")]
    cert: Option<PathBuf>,
    /// Enable stateless retries
    #[clap(long = "stateless-retry")]
    stateless_retry: bool,
    /// Address to listen on
    #[clap(long = "listen", default_value = "[::]:8443")]
    listen: Option<String>,

    #[clap(long = "port", default_value = "8443")]
    port: u16,
    #[clap(long = "stdinout")]
    stdinout: bool,

    #[clap(long = "loglevel", default_value = "info")]
    loglevel: String,
}

#[allow(unused)]
fn parse_config(opt: Opt) -> Result<FerrumServerConfig> {
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
    };
    Ok(config)
}

fn main() {
    let copt = Opt::parse();
    tracing::subscriber::set_global_default(
        tracing_subscriber::FmtSubscriber::builder()
            .with_max_level(get_log_level(&copt.loglevel))
            .finish(),
    )
    .unwrap();

    let opt = parse_config(copt);
    if let Err(e) = opt {
        error!("ERROR: parse failed: {}", e);
        ::std::process::exit(1);
    }

    let code = {
        if let Err(e) = run(opt.unwrap()) {
            error!("ERROR: {e}");

            1
        } else {
            0
        }
    };
    ::std::process::exit(code);
}

#[tokio::main]
async fn run(options: FerrumServerConfig) -> Result<()> {
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

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    server_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    if options.keylog {
        server_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());
    transport_config.max_concurrent_bidi_streams(1_u8.into());

    /*  if options.stateless_retry {
           server_config.use_retry(true);
       }
    */
    /*  let root = Arc::<Path>::from(options.root.clone());
    if !root.exists() {
        bail!("root path does not exist");
    } */

    let endpoint = quinn::Endpoint::server(server_config, options.listen)?;
    eprintln!("listening on {}", endpoint.local_addr()?);

    while let Some(conn) = endpoint.accept().await {
        info!("connection incoming");
        let fut = handle_connection(conn);
        tokio::spawn(async move {
            if let Err(e) = fut.await {
                error!("connection failed: {reason}", reason = e.to_string())
            }
        });
    }

    Ok(())
}

async fn handle_connection(conn: quinn::Connecting) -> Result<()> {
    let connection = conn.await?;
    info!(
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
    );

    info!("established");

    // Each stream initiated by the client constitutes a new request.

    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;
    let cancel_token = CancellationToken::new();
    let result = handle_as_stdin(send, recv, connection, cancel_token.clone()).await;
    result
}
