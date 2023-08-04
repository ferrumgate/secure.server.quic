mod client;
mod common;
use anyhow::{Result};
use clap::Parser;

use client::{create_root_certs, parse_config, ClientConfigOpt, FerrumClient, FerrumClientConfig};
use common::get_log_level;

use tokio::{select, signal};
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

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

async fn run(options: FerrumClientConfig) -> Result<()> {
    let remote = options.ip;
    info!("connecting to {}", remote);
    let roots = create_root_certs(&options)?;

    let mut client: FerrumClient = FerrumClient::new(options, roots);
    let result = client.connect().await.map_err(|err| {
        error!("could not connect {}", err);
        err
    })?;

    let (send, recv) = result;
    let token = CancellationToken::new();

    let result = select! {
        result=client.process(send, recv, token.clone()) =>{
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
