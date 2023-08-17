use std::{net::ToSocketAddrs, path::PathBuf};

use anyhow::{anyhow, Result};

use clap::Parser;

use ferrum::server::FerrumServer;

use tokio::select;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use tokio::signal::{unix::signal, unix::SignalKind};

use ferrum::common::get_log_level;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use ferrum::server::FerrumServerConfig;

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
    #[clap(long = "ratelimit")]
    pub ratelimit: Option<i32>,
    #[clap(long = "ratelimit_window")]
    pub ratelimit_window: Option<i32>,
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
        ratelimit: opt.ratelimit.unwrap_or(120),
        ratelimit_window: opt.ratelimit_window.unwrap_or(60000),
    };
    Ok(config)
}

#[cfg(any(target_os = "unix"))]
#[allow(dead_code)]

fn main() {
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    println!("version: {}", VERSION);

    let _rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let copt = ServerOpt::parse();
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

    _rt.block_on(async {
        let code = {
            if let Err(e) = run(opt.unwrap()).await {
                error!("ERROR: {e}");
                1
            } else {
                0
            }
        };
        ::std::process::exit(code);
    });
}

#[cfg(not(target_os = "unix"))]
fn main() {}

#[cfg(any(target_os = "unix"))]
#[allow(dead_code)]
async fn run(options: FerrumServerConfig) -> Result<()> {
    let cert_chain = FerrumServer::create_server_cert_chain(&options)
        .map_err(|e| error!("create certs failed {}", e))
        .unwrap();

    let mut server = FerrumServer::new(options, cert_chain)?;
    let signal_ctrlc = tokio::signal::ctrl_c();
    let mut signal_sigint = signal(SignalKind::interrupt())?;
    let cancel_token = CancellationToken::new();
    let cancel_token_cloned = cancel_token.clone();
    let cancel_token_cloned2 = cancel_token.clone();
    select! {
        result=server.listen(cancel_token)=>result,
        signal=signal_ctrlc=>{
            match signal {
                Ok(()) => {
                    info!("canceling");
                    cancel_token_cloned.cancel();

                },
                Err(err) => {
                    error!("Unable to listen for shutdown signal: {}", err);
                    // we also shut down in case of error
                }
            }

        },
        signal= signal_sigint.recv()=>{
            match signal {
                Some(()) => {
                    info!("canceling");
                    cancel_token_cloned2.cancel();

                },
                _ => {
                    error!("Unable to listen for interrupt signal");
                    // we also shut down in case of error
                }
            }

        }
    };

    Ok(())
}

#[cfg(any(target_os = "unix"))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_config() {
        let opt: ServerOpt = ServerOpt {
            keylog: false,
            cert: None,
            gateway_id: "gateway_id".to_string(),
            key: None,
            listen: Some("127.0.0.1:543".to_string()),
            port: 8443,
            redis_host: "localhost".to_string(),
            redis_pass: None,
            redis_user: None,
            stateless_retry: false,

            stdinout: false,
            loglevel: "debug".to_string(),
            ratelimit: None,
            ratelimit_window: None,
        };

        let config_result1 = parse_config(opt);
        assert_eq!(config_result1.is_err(), false);
        let config1 = config_result1.unwrap();
        assert_eq!(config1.cert, None);
        assert_eq!(config1.gateway_id, "gateway_id");
        assert_eq!(config1.listen, "127.0.0.1:543".parse().unwrap());
        assert_eq!(config1.loglevel, "debug");
        assert_eq!(config1.redis_host, "localhost");
        assert_eq!(config1.redis_user, None);
        assert_eq!(config1.redis_pass, None);
    }
}
