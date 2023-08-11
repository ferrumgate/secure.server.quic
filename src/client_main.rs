mod client;
mod common;

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

use anyhow::{anyhow, Error, Result};
use bytes::BytesMut;
use clap::Parser;

use client::{FerrumClient, FerrumClientConfig};

use common::get_log_level;

use tokio::{select, signal};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

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

fn main() {
    let _rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

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
        eprintln!("ferrum_exit: client exit");
        ::std::process::exit(1);
    }
    _rt.block_on(async {
        let code = {
            if let Err(e) = run(opt.unwrap()).await {
                error!("ERROR: {e}");
                1
            } else {
                0
            }
        };
        eprintln!("ferrum_exit: client exit");
        ::std::process::exit(code);
    });
}

async fn run(options: FerrumClientConfig) -> Result<()> {
    let process_id = std::process::id();
    eprintln!("ferrum_pid:{}", process_id);
    let remote = options.ip;
    info!("connecting to {}", remote);
    let roots = FerrumClient::create_root_certs(&options)?;

    let mut client: FerrumClient = FerrumClient::new(options, roots);
    let result = client.connect().await.map_err(|err| {
        error!("could not connect {}", err);
        err
    })?;

    let token = CancellationToken::new();

    let result = select! {
        result=client.process(token.clone()) =>{
             result
        },
        signal=signal::ctrl_c()=>{
            match signal {
            Ok(()) => {
                info!("canceling");
                token.cancel();

            },
            Err(err) => {
                error!("Unable to listen for shutdown signal: {}", err);
                // we also shut down in case of error
            }
            }
            Ok(())

        }
    };

    client.close();
    result
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
}
