use anyhow::{anyhow, Result};
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig};
use std::{error::Error, net::SocketAddr, sync::Arc};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::select;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Level};

#[allow(unused)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];
#[allow(unused)]
pub const ALPN_QUIC: &[&[u8]] = &[b"hq-29"];
/// Constructs a QUIC endpoint configured for use a client only.
///
/// ## Args
///
/// - server_certs: list of trusted certificates.
#[allow(unused)]
pub fn make_client_endpoint(
    bind_addr: SocketAddr,
    server_certs: &[&[u8]],
) -> Result<Endpoint, Box<dyn Error>> {
    let client_cfg = configure_client(server_certs)?;
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_cfg);
    Ok(endpoint)
}

/// Constructs a QUIC endpoint configured to listen for incoming connections on a certain address
/// and port.
///
/// ## Returns
///
/// - a stream of incoming QUIC connections
/// - server certificate serialized into DER format
#[allow(unused)]
pub fn make_server_endpoint(bind_addr: SocketAddr) -> Result<(Endpoint, Vec<u8>), Box<dyn Error>> {
    let (server_config, server_cert) = configure_server()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok((endpoint, server_cert))
}

/// Builds default quinn client config and trusts given certificates.
///
/// ## Args
///
/// - server_certs: a list of trusted certificates in DER format.
fn configure_client(server_certs: &[&[u8]]) -> Result<ClientConfig, Box<dyn Error>> {
    let mut certs = rustls::RootCertStore::empty();
    for cert in server_certs {
        certs.add(&rustls::Certificate(cert.to_vec()))?;
    }

    let client_config = ClientConfig::with_root_certificates(certs);
    Ok(client_config)
}

/// Returns default server configuration along with its certificate.
fn configure_server() -> Result<(ServerConfig, Vec<u8>), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];

    let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(0_u8.into());

    Ok((server_config, cert_der))
}

pub fn get_log_level(level: &String) -> Level {
    if level.to_ascii_lowercase() == "trace" {
        return Level::TRACE;
    }
    if level.to_ascii_lowercase() == "debug" {
        return Level::DEBUG;
    }
    if level.to_ascii_lowercase() == "info" {
        return Level::INFO;
    }
    if level.to_ascii_lowercase() == "warn" {
        return Level::WARN;
    }
    if level.to_ascii_lowercase() == "error" {
        return Level::ERROR;
    }

    return Level::INFO;
}

pub async fn handle_as_stdin(
    mut send: SendStream,
    mut recv: RecvStream,
    connection: Connection,
    cancel_token: CancellationToken,
) -> Result<()> {
    let stdin = tokio::io::stdin();
    let ctoken1 = cancel_token.clone();
    let input_task = tokio::spawn(async move {
        let mut reader = BufReader::with_capacity(2048, stdin);
        let mut line = String::new();
        loop {
            debug!("waiting for input");
            select! {
                _=ctoken1.cancelled()=>{
                    warn!("cancelled");
                    break;
                },
                result=reader.read_line(&mut line)=>{
                    match result {
                        Err(e) => {
                            error!("recv read failed {}", e);
                            break;
                        }
                        Ok(0) => {
                            warn!("stdin finished");
                            break;
                        }
                        Ok(b) => {
                            debug!("data sended bytes {}", b);
                            let res = send
                                .write_all(line.as_bytes())
                                .await
                                .map_err(|e| anyhow!("failed to send input:{}", e));
                            if res.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        }
    });

    let output_task = tokio::spawn(async move {
        let mut array: Vec<u8> = vec![0; 1024];
        let mut stdout = tokio::io::stdout();
        loop {
            debug!("waiting for recv");
            let resp = recv
                .read(array.as_mut())
                .await
                .map_err(|e| anyhow!("failed to read response: {}", e));
            if let Err(e) = resp {
                error!("stream read error {}", e);
                break;
            }

            debug!("received data");
            let response = resp.unwrap();
            match response {
                Some(0) => {
                    info!("stream closed");
                    break;
                }
                Some(data) => {
                    debug!("data received bytes {}", data);
                    let res = stdout.write_all(&array[0..data]).await;
                    if let Err(e) = res {
                        error!("stdout write failed {}", e);
                        break;
                    }
                }
                None => {
                    info!("stream finished");
                    break;
                }
            }
        }
    });

    let _ = tokio::join!(output_task);
    let _ = tokio::join!(input_task);

    let _ = tokio::io::stdout().flush().await;
    connection.close(0u32.into(), b"done");
    //debug!("connection closed");
    debug!("closing evertthing");
    Ok(())
}
