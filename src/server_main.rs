use anyhow::{Result};
use clap::Parser;
use common::get_log_level;
use server::{create_certs_chain, parse_config, FerrumServer, FerrumServerConfig, ServerOpt};

use tokio::select;
use tokio::signal::{unix::signal, unix::SignalKind};

use tokio_util::sync::CancellationToken;
use tracing::{error, info};

mod common;
mod server;

#[allow(dead_code)]

fn main() {
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

#[allow(dead_code)]
async fn run(options: FerrumServerConfig) -> Result<()> {
    let cert_chain = create_certs_chain(&options)
        .map_err(|e| error!("create certs failed {}", e))
        .unwrap();

    let server = FerrumServer::new(options, cert_chain)?;
    let signal_ctrlc = tokio::signal::ctrl_c();
    let mut signal_sigint = signal(SignalKind::interrupt())?;
    let cancel_token = CancellationToken::new();
    let cancel_token_cloned = cancel_token.clone();
    let cancel_token_cloned2 = cancel_token.clone();
    let _ = select! {
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
            ()
        },
        signal= signal_sigint.recv()=>{
            match signal {
            Some(()) => {
                info!("canceling");
                cancel_token_cloned2.cancel();

            },
            _ => {
                error!("Unable to listen for integrrap signal");
                // we also shut down in case of error
            }
            }
            ()
        }
    };

    Ok(())
}
