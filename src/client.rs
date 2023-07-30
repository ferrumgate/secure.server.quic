#![cfg_attr(debug_assertions, allow(dead_code, unused_imports))]

use std::{
    fs,
    io::{self, Write},
    net::{SocketAddr, ToSocketAddrs},
    ops::Deref,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use clap::Parser;

use common::{get_log_level, handle_as_stdin};
use rustls::{OwnedTrustAnchor, RootCertStore};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::runtime::Builder;
use tokio::task::JoinSet;
use tokio::{select, signal};

use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Level};
use webpki_roots::TLS_SERVER_ROOTS;

mod common;

struct FerrumClientConfig {
    host: String,
    host_port: String,
    ip: SocketAddr,
    ca: Option<PathBuf>,
    keylog: bool,
    rebind: bool,
    insecure: bool,
    stdinout: bool,
    loglevel: String,
}
/// HTTP/0.9 over QUIC client
#[derive(Parser, Debug)]
#[clap(name = "client")]
struct ClientConfigOpt {
    /// Perform NSS-compatible TLS key logging to the file specified in `SSLKEYLOGFILE`.
    #[clap(long = "keylog")]
    keylog: bool,

    #[clap(long = "insecure")]
    insecure: bool,

    #[clap(long = "host", default_value = "localhost:8443")]
    host: String,

    /// Custom certificate authority to trust, in DER format
    #[clap(long = "ca")]
    ca: Option<PathBuf>,

    /// Simulate NAT rebinding after connecting
    #[clap(long = "rebind")]
    rebind: bool,
    #[clap(long = "stdinout")]
    stdinout: bool,
    #[clap(long = "loglevel", default_value = "info")]
    loglevel: String,
}
#[allow(unused)]
fn parse_config(opt: ClientConfigOpt) -> Result<FerrumClientConfig> {
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
    };

    Ok(config)
}

fn main() {
    let copt = ClientConfigOpt::parse();
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

    roots.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
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

#[tokio::main]
async fn run(options: FerrumClientConfig) -> Result<()> {
    let _rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let remote = options.ip;
    info!("connect to {}", remote);
    let roots = create_root_certs(&options)?;

    let mut client_crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(roots)
        .with_no_client_auth();

    if options.insecure {
        client_crypto
            .dangerous()
            .set_certificate_verifier(SkipServerVerification::new());
    }

    client_crypto.alpn_protocols = common::ALPN_QUIC_HTTP.iter().map(|&x| x.into()).collect();
    if options.keylog {
        client_crypto.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    let client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
    let mut endpoint = quinn::Endpoint::client("[::]:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    let start = Instant::now();
    let rebind = options.rebind;
    let host = options.host.as_str();

    info!("connecting to {host} at {remote}");
    let connection = endpoint
        .connect(remote, host)?
        .await
        .map_err(|e| anyhow!("failed to connect: {}", e))?;
    info!("connected at {:?}", start.elapsed());
    let (send, recv) = connection
        .open_bi()
        .await
        .map_err(|e| anyhow!("failed to open stream: {}", e))?;
    if rebind {
        let socket = std::net::UdpSocket::bind("[::]:0").unwrap();
        let addr = socket.local_addr().unwrap();
        error!("rebinding to {addr}");
        endpoint.rebind(socket).expect("rebind failed");
    }

    let token = CancellationToken::new();
    select! {
        result=handle_as_stdin(send, recv, connection, token.clone())=>{
            result
        },
        signal=signal::ctrl_c()=>{
            match signal {
            Ok(()) => {
                token.cancel();
            },
            Err(err) => {
                error!("Unable to listen for shutdown signal: {}", err);
                // we also shut down in case of error
            },
            }
            Ok(())

        }
    }
}

fn duration_secs(x: &Duration) -> f32 {
    x.as_secs() as f32 + x.subsec_nanos() as f32 * 1e-9
}

#[cfg(test)]
mod tests {
    use std::{fs::create_dir, net::ToSocketAddrs};

    use clap::Parser;

    use crate::{create_root_certs, parse_config, ClientConfigOpt, FerrumClientConfig};

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
        };
        let roots = create_root_certs(&config);
        assert_eq!(roots.is_ok(), true);
    }
}
